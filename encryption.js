/**
 * WTM — Data Encryption
 * Covers: AES-256-GCM field-level encryption at rest,
 *         key derivation, and encryption helpers
 *
 * ENV REQUIRED:
 *   ENCRYPTION_KEY — 64 hex chars (32 bytes)
 *   Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */

'use strict';

const crypto = require('crypto');

const ALGORITHM  = 'aes-256-gcm';
const IV_LENGTH  = 16;  // bytes
const TAG_LENGTH = 16;  // bytes

function getKey() {
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be 64 hex characters (32 bytes).');
  }
  return Buffer.from(hex, 'hex');
}

// ─────────────────────────────────────────────
// FIELD-LEVEL ENCRYPTION
// Format: iv_hex:authTag_hex:ciphertext_hex
// AES-256-GCM provides authenticated encryption —
// tampering with ciphertext is detected on decrypt.
// ─────────────────────────────────────────────
function encrypt(plaintext) {
  if (plaintext == null) return null;
  const key        = getKey();
  const iv         = crypto.randomBytes(IV_LENGTH);
  const cipher     = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted  = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return [
    iv.toString('hex'),
    authTag.toString('hex'),
    encrypted.toString('hex'),
  ].join(':');
}

function decrypt(ciphertext) {
  if (ciphertext == null) return null;
  const parts = ciphertext.split(':');
  if (parts.length !== 3) throw new Error('Invalid ciphertext format.');
  const [ivHex, tagHex, dataHex] = parts;
  const key      = getKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(dataHex, 'hex')),
    decipher.final(),
  ]).toString('utf8');
}

// ─────────────────────────────────────────────
// DETERMINISTIC ENCRYPTION (for searchable fields)
// Uses a separate HMAC key so encrypted values
// can be matched without decrypting.
// Use ONLY for lookup fields like email — never
// for high-entropy secrets.
// ─────────────────────────────────────────────
function hmacField(value) {
  const key = process.env.HMAC_KEY;
  if (!key || key.length < 32) throw new Error('HMAC_KEY must be at least 32 chars.');
  return crypto
    .createHmac('sha256', key)
    .update(String(value).toLowerCase().trim())
    .digest('hex');
}

// ─────────────────────────────────────────────
// SECURE RANDOM TOKENS
// Used for: email verification, password reset,
// booking confirmation codes, API keys
// ─────────────────────────────────────────────
function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function generateBookingCode() {
  // Format: WTM-XXXX-XXXX (uppercase alphanumeric)
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no O,0,I,1 to avoid confusion
  let code = '';
  const rand = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) {
    code += chars[rand[i] % chars.length];
    if (i === 3) code += '-';
  }
  return `WTM-${code}`;
}

// ─────────────────────────────────────────────
// HASH COMPARISON (timing-safe)
// Use this instead of === when comparing tokens
// to prevent timing attacks.
// ─────────────────────────────────────────────
function safeCompare(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// ─────────────────────────────────────────────
// PASSWORD RESET TOKEN
// Hash before storing — the raw token is only
// ever sent to the user's email once.
// ─────────────────────────────────────────────
function hashResetToken(rawToken) {
  return crypto
    .createHash('sha256')
    .update(rawToken)
    .digest('hex');
}

module.exports = {
  encrypt,
  decrypt,
  hmacField,
  generateToken,
  generateBookingCode,
  safeCompare,
  hashResetToken,
};
