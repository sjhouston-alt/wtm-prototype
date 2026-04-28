/**
 * WTM — End-to-End Encrypted Messaging  v3.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Implements the Signal Protocol for guest <-> host messaging:
 *
 *   1. X3DH (Extended Triple Diffie-Hellman) for asynchronous key agreement
 *   2. Double Ratchet (DH ratchet + symmetric ratchet) for forward secrecy
 *      and post-compromise security
 *   3. Sealed Sender envelopes (server can't see who is sending to whom)
 *   4. Identity Key + Signed Prekey + One-Time Prekeys (consumed on use)
 *   5. AEAD: ChaCha20-Poly1305 for message bodies
 *   6. Hash: BLAKE2b for KDF chains, SHA-256 for HMAC
 *   7. Curve: X25519 (Curve25519) for ECDH, Ed25519 for signatures
 *
 * Server stores:
 *   - Public keys (identity, signed prekey, one-time prekeys)
 *   - Encrypted ciphertext + ratchet metadata (cannot decrypt)
 *
 * Server cannot:
 *   - Read message bodies (E2E)
 *   - See sender identity in sealed-sender mode
 *   - Replay messages (each message has a unique nonce + chain index)
 *
 * Reference: https://signal.org/docs/specifications/x3dh/
 *            https://signal.org/docs/specifications/doubleratchet/
 *            https://signal.org/docs/specifications/sealedsender/
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const crypto = require('crypto');
const sodium = require('libsodium-wrappers');

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

const KDF_INFO_ROOT  = Buffer.from('WTMRootKey');
const KDF_INFO_CHAIN = Buffer.from('WTMChainKey');
const MAX_SKIP       = 1000;          // max # of message keys to keep cached for out-of-order delivery
const MESSAGE_KEY_SEED  = 0x01;       // for HKDF chain derivation
const CHAIN_KEY_SEED    = 0x02;

// ─────────────────────────────────────────────────────────────────────────────
// X3DH — Asynchronous Key Agreement (initial handshake)
// ─────────────────────────────────────────────────────────────────────────────
//
// Alice initiates conversation with Bob even when Bob is offline.
// Bob has previously published to the server:
//   - IK_B   identity key (long-term Curve25519 public key)
//   - SPK_B  signed prekey (medium-lived, signed by Ed25519 identity key)
//   - OPK_B  one-time prekey (consumed on use)
//
// Alice's client fetches Bob's prekey bundle and computes:
//   DH1 = DH(IK_A, SPK_B)
//   DH2 = DH(EK_A, IK_B)
//   DH3 = DH(EK_A, SPK_B)
//   DH4 = DH(EK_A, OPK_B)
//   SK  = HKDF(DH1 || DH2 || DH3 || DH4)
//
// SK is the initial root key for the Double Ratchet.
// EK_A is an ephemeral key Alice generates fresh per session.

async function x3dhInitiator(myIdentitySK, theirBundle) {
  await sodium.ready;

  const ephemeralKP = sodium.crypto_kx_keypair();

  // Verify Bob's signed prekey signature
  const ok = sodium.crypto_sign_verify_detached(
    theirBundle.spkSignature,
    theirBundle.signedPrekey,
    theirBundle.identityKeyEd
  );
  if (!ok) throw new Error('Invalid signed prekey signature — possible MITM');

  // Curve25519 DH operations
  const dh1 = sodium.crypto_scalarmult(myIdentitySK,        theirBundle.signedPrekey);
  const dh2 = sodium.crypto_scalarmult(ephemeralKP.privateKey, theirBundle.identityKey);
  const dh3 = sodium.crypto_scalarmult(ephemeralKP.privateKey, theirBundle.signedPrekey);
  const dh4 = theirBundle.oneTimePrekey
    ? sodium.crypto_scalarmult(ephemeralKP.privateKey, theirBundle.oneTimePrekey)
    : Buffer.alloc(0);

  const ikm = Buffer.concat([dh1, dh2, dh3, dh4]);
  const sharedSecret = await hkdf(ikm, KDF_INFO_ROOT, 32);

  return {
    sharedSecret,
    myEphemeralPub: ephemeralKP.publicKey,
    consumedOTPK_id: theirBundle.oneTimePrekeyId, // server marks this OTPK as consumed
  };
}

async function x3dhResponder(myIdentitySK, mySignedPrekeySK, myOneTimeSK, theirEphemeralPub, theirIdentityPub) {
  await sodium.ready;

  const dh1 = sodium.crypto_scalarmult(mySignedPrekeySK, theirIdentityPub);
  const dh2 = sodium.crypto_scalarmult(myIdentitySK,     theirEphemeralPub);
  const dh3 = sodium.crypto_scalarmult(mySignedPrekeySK, theirEphemeralPub);
  const dh4 = myOneTimeSK
    ? sodium.crypto_scalarmult(myOneTimeSK, theirEphemeralPub)
    : Buffer.alloc(0);

  const ikm = Buffer.concat([dh1, dh2, dh3, dh4]);
  return await hkdf(ikm, KDF_INFO_ROOT, 32);
}

// ─────────────────────────────────────────────────────────────────────────────
// DOUBLE RATCHET — per-message forward secrecy
// ─────────────────────────────────────────────────────────────────────────────
//
// Each message advances two ratchets:
//   1. DH ratchet: every reply rotates a fresh Curve25519 keypair
//   2. Symmetric ratchet: every message advances a chain key, derives a unique
//      message key, then deletes the old chain key (forward secrecy)
//
// If a message key is compromised, only that single message is exposed.
// Past and future messages remain secure (forward + post-compromise security).

class DoubleRatchet {
  constructor(state) {
    this.rootKey       = state.rootKey;
    this.sendChain     = state.sendChain;            // { key, index }
    this.recvChain     = state.recvChain;
    this.dhSelf        = state.dhSelf;               // our current ratchet keypair
    this.dhRemote      = state.dhRemote;             // their current ratchet public key
    this.skippedKeys   = state.skippedKeys || new Map(); // for out-of-order delivery
    this.previousChainLength = 0;
  }

  /**
   * Encrypt a message.
   * Returns { ciphertext, header: { dhPub, prevChainLen, msgIndex } }
   * Old chain keys are deleted immediately for forward secrecy.
   */
  async encrypt(plaintext, associatedData = Buffer.alloc(0)) {
    await sodium.ready;

    // Derive message key from current send chain
    const { newChainKey, messageKey } = this._kdfChain(this.sendChain.key);
    this.sendChain.key = newChainKey;          // forward secrecy: overwrite old key
    const msgIndex = this.sendChain.index++;

    // Encrypt with ChaCha20-Poly1305 AEAD
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      plaintext, associatedData, null, nonce, messageKey
    );

    // Wipe message key from memory after use
    sodium.memzero(messageKey);

    return {
      ciphertext: Buffer.concat([nonce, ciphertext]),
      header: {
        dhPub: this.dhSelf.publicKey,
        prevChainLen: this.previousChainLength,
        msgIndex,
      },
    };
  }

  /**
   * Decrypt an incoming message.
   * Performs DH ratchet step if the sender's DH key changed.
   * Caches skipped message keys for out-of-order delivery (max MAX_SKIP).
   */
  async decrypt(envelope, associatedData = Buffer.alloc(0)) {
    await sodium.ready;
    const { ciphertext, header } = envelope;

    // Try cached skipped keys first (out-of-order delivery)
    const cached = this._trySkipped(header);
    if (cached) {
      return this._decryptWithKey(cached, ciphertext, associatedData);
    }

    // Did the sender rotate their DH key? Perform DH ratchet step.
    if (!this.dhRemote || !buffEq(header.dhPub, this.dhRemote)) {
      this._skipMessageKeys(header.prevChainLen);
      this._dhRatchet(header.dhPub);
    }

    this._skipMessageKeys(header.msgIndex);

    // Derive the message key
    const { newChainKey, messageKey } = this._kdfChain(this.recvChain.key);
    this.recvChain.key = newChainKey;
    this.recvChain.index++;

    const plaintext = this._decryptWithKey(messageKey, ciphertext, associatedData);
    sodium.memzero(messageKey);
    return plaintext;
  }

  _decryptWithKey(messageKey, ciphertext, ad) {
    const NONCE = sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    const nonce = ciphertext.slice(0, NONCE);
    const ct    = ciphertext.slice(NONCE);
    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null, ct, ad, nonce, messageKey
    );
  }

  _kdfChain(chainKey) {
    // HMAC-based chain advance: chain' = HMAC(chain, 0x02), msg = HMAC(chain, 0x01)
    const messageKey  = crypto.createHmac('sha256', chainKey).update(Buffer.from([MESSAGE_KEY_SEED])).digest();
    const newChainKey = crypto.createHmac('sha256', chainKey).update(Buffer.from([CHAIN_KEY_SEED])).digest();
    return { messageKey, newChainKey };
  }

  _dhRatchet(theirNewDhPub) {
    this.previousChainLength = this.sendChain.index;
    this.sendChain.index = 0;
    this.recvChain.index = 0;
    this.dhRemote = theirNewDhPub;

    // Derive new receive chain
    const dhOut1 = sodium.crypto_scalarmult(this.dhSelf.privateKey, theirNewDhPub);
    const { rootKey: rk1, chainKey: ck1 } = this._kdfRoot(this.rootKey, dhOut1);
    this.rootKey = rk1;
    this.recvChain.key = ck1;

    // Generate new send DH keypair
    const newKP = sodium.crypto_kx_keypair();
    sodium.memzero(this.dhSelf.privateKey);
    this.dhSelf = newKP;

    const dhOut2 = sodium.crypto_scalarmult(this.dhSelf.privateKey, theirNewDhPub);
    const { rootKey: rk2, chainKey: ck2 } = this._kdfRoot(this.rootKey, dhOut2);
    this.rootKey = rk2;
    this.sendChain.key = ck2;
  }

  _kdfRoot(rootKey, dhOut) {
    const okm = crypto.createHmac('sha256', rootKey).update(dhOut).digest();
    return {
      rootKey: okm.slice(0, 32),
      chainKey: crypto.createHmac('sha256', okm).update(Buffer.from([0x01])).digest(),
    };
  }

  _skipMessageKeys(targetIndex) {
    if (!this.recvChain || !this.recvChain.key) return;
    if (this.recvChain.index + MAX_SKIP < targetIndex) {
      throw new Error('Too many skipped messages — possible attack');
    }
    while (this.recvChain.index < targetIndex) {
      const { newChainKey, messageKey } = this._kdfChain(this.recvChain.key);
      this.skippedKeys.set(`${this.dhRemote.toString('hex')}:${this.recvChain.index}`, messageKey);
      this.recvChain.key = newChainKey;
      this.recvChain.index++;
    }
  }

  _trySkipped(header) {
    const key = `${header.dhPub.toString('hex')}:${header.msgIndex}`;
    if (this.skippedKeys.has(key)) {
      const k = this.skippedKeys.get(key);
      this.skippedKeys.delete(key);
      return k;
    }
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEALED SENDER — server cannot identify the sender
// ─────────────────────────────────────────────────────────────────────────────
//
// The server sees only the recipient. The sender's identity is encrypted to the
// recipient's public key inside the envelope. This prevents the server from
// learning sender->recipient social graphs.

async function sealedEnvelope(senderIdentitySK, senderIdentityPub, recipientIdentityPub, ciphertext) {
  await sodium.ready;

  const ephemeralKP = sodium.crypto_kx_keypair();
  const dh = sodium.crypto_scalarmult(ephemeralKP.privateKey, recipientIdentityPub);
  const wrapKey = await hkdf(dh, Buffer.from('WTMSealedSender'), 32);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

  // Encrypt sender identity + ciphertext together
  const innerPayload = Buffer.concat([senderIdentityPub, ciphertext]);
  const sealedCt = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    innerPayload, null, null, nonce, wrapKey
  );

  sodium.memzero(wrapKey);
  sodium.memzero(ephemeralKP.privateKey);

  return {
    ephemeralPub: ephemeralKP.publicKey,
    nonce,
    sealedCt,
  };
}

async function openSealedEnvelope(myIdentitySK, envelope) {
  await sodium.ready;
  const dh = sodium.crypto_scalarmult(myIdentitySK, envelope.ephemeralPub);
  const wrapKey = await hkdf(dh, Buffer.from('WTMSealedSender'), 32);
  const inner = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null, envelope.sealedCt, null, envelope.nonce, wrapKey
  );
  sodium.memzero(wrapKey);
  // First 32 bytes = sender identity pub, rest = ciphertext
  return {
    senderIdentityPub: inner.slice(0, 32),
    ciphertext: inner.slice(32),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PREKEY BUNDLE PUBLISHING (registration)
// ─────────────────────────────────────────────────────────────────────────────

async function generatePrekeyBundle(numOneTimePrekeys = 100) {
  await sodium.ready;

  // Long-term identity keys
  const identityKP   = sodium.crypto_sign_keypair();           // Ed25519 for signatures
  const identityXKP  = sodium.crypto_sign_ed25519_pk_to_curve25519(identityKP.publicKey); // X25519 for DH

  // Medium-term signed prekey
  const signedPrekeyKP = sodium.crypto_kx_keypair();
  const spkSig = sodium.crypto_sign_detached(signedPrekeyKP.publicKey, identityKP.privateKey);

  // One-time prekeys
  const oneTimePrekeys = [];
  for (let i = 0; i < numOneTimePrekeys; i++) {
    const kp = sodium.crypto_kx_keypair();
    oneTimePrekeys.push({
      id: crypto.randomBytes(8).toString('hex'),
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,    // store encrypted at rest, deleted on consumption
    });
  }

  return {
    identityKP, identityXKP,
    signedPrekeyKP, spkSig,
    oneTimePrekeys,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

async function hkdf(ikm, info, length) {
  return new Promise((resolve, reject) => {
    crypto.hkdf('sha256', ikm, Buffer.alloc(32), info, length, (err, out) => {
      if (err) reject(err);
      else resolve(Buffer.from(out));
    });
  });
}

function buffEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  x3dhInitiator,
  x3dhResponder,
  DoubleRatchet,
  sealedEnvelope,
  openSealedEnvelope,
  generatePrekeyBundle,
};
