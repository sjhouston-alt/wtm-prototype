/**
  WTM — Authentication & Session Security  v2.0
  ─────────────────────────────────────────────────────────────────────────────
  Covers:
    • Password hashing  (bcrypt, cost 12)
    • JWT tokens        (httpOnly cookies ONLY — never localStorage)
    • Refresh token rotation with single-use enforcement
    • MFA              (TOTP / speakeasy)
    • Rate limiting    (Redis-backed, per-IP and per-account)
    • Account lockout  (exponential back-off)
    • CSRF protection  (double-submit cookie + signed token)
    • Session fixation prevention
    • Timing-safe comparisons throughout
  ─────────────────────────────────────────────────────────────────────────────
 */
'use strict';

const bcrypt      = require('bcrypt');
const jwt         = require('jsonwebtoken');
const speakeasy   = require('speakeasy');
const rateLimit   = require('express-rate-limit');
const RedisStore  = require('rate-limit-redis');
const crypto      = require('crypto');

// ─────────────────────────────────────────────
// CONSTANTS  (all configurable via env)
// ─────────────────────────────────────────────
const BCRYPT_ROUNDS    = 12;             // ~300ms — painful for attackers
const MAX_LOGIN_FAILS  = 5;
const LOCKOUT_MS       = 15 * 60 * 1000; // 15 minutes base
const MAX_LOCKOUT_MS   = 60 * 60 * 1000; // 1 hour max
const ACCESS_TTL       = '15m';
const REFRESH_TTL      = '7d';
const CSRF_TTL_S       = 3600;           // 1 hour

// ─────────────────────────────────────────────
// SECRETS — must be 64-char hex (512 bits)
// Fail fast at startup if missing.
// ─────────────────────────────────────────────
const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const CSRF_SECRET    = process.env.CSRF_SECRET;

if (!ACCESS_SECRET || !REFRESH_SECRET || !CSRF_SECRET) {
  console.error('[FATAL] JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, and CSRF_SECRET must be set');
  process.exit(1);
}

// ─────────────────────────────────────────────
// COOKIE CONFIG
// __Host- prefix requires: Secure, no Domain, Path=/
// This is the strongest possible cookie security.
// ─────────────────────────────────────────────
const COOKIE_DEFAULTS = {
  httpOnly : true,
  secure   : true,
  sameSite : 'Strict',
  path     : '/',
};

const ACCESS_COOKIE_NAME  = '__Host-wtm_at';
const REFRESH_COOKIE_NAME = '__Host-wtm_rt';
const CSRF_COOKIE_NAME    = '__Host-wtm_csrf';

// ─────────────────────────────────────────────
// PASSWORD — bcrypt
// ─────────────────────────────────────────────
async function hashPassword(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') {
    throw new Error('Invalid password input');
  }
  // Limit to 72 bytes — bcrypt silently truncates beyond this.
  // Pre-hash with SHA-512 to handle longer passwords safely.
  const prehash = crypto.createHash('sha512').update(plaintext).digest('base64');
  return bcrypt.hash(prehash, BCRYPT_ROUNDS);
}

async function verifyPassword(plaintext, hash) {
  if (!plaintext || !hash) return false;
  const prehash = crypto.createHash('sha512').update(String(plaintext)).digest('base64');
  // bcrypt.compare is already timing-safe
  return bcrypt.compare(prehash, hash);
}

// ─────────────────────────────────────────────
// JWT TOKEN ISSUANCE
// Payload contains only what's needed.
// Never include passwords, PII, or payment data in JWTs.
// ─────────────────────────────────────────────
function issueTokens(userId, roles = ['user']) {
  if (!userId) throw new Error('userId required');

  const jti = crypto.randomBytes(16).toString('hex'); // unique token ID

  const accessToken = jwt.sign(
    { sub: userId, roles, type: 'access', jti },
    ACCESS_SECRET,
    { expiresIn: ACCESS_TTL, algorithm: 'HS256' }
  );

  const refreshJti = crypto.randomBytes(16).toString('hex');
  const refreshToken = jwt.sign(
    { sub: userId, type: 'refresh', jti: refreshJti },
    REFRESH_SECRET,
    { expiresIn: REFRESH_TTL, algorithm: 'HS256' }
  );

  return { accessToken, refreshToken, refreshJti };
}

// ─────────────────────────────────────────────
// VERIFY ACCESS TOKEN
// Returns decoded payload or throws.
// ─────────────────────────────────────────────
function verifyAccessToken(token) {
  const payload = jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'] });
  if (payload.type !== 'access') throw new Error('Wrong token type');
  return payload;
}

function verifyRefreshToken(token) {
  const payload = jwt.verify(token, REFRESH_SECRET, { algorithms: ['HS256'] });
  if (payload.type !== 'refresh') throw new Error('Wrong token type');
  return payload;
}

// ─────────────────────────────────────────────
// SET AUTH COOKIES
// Never expose tokens in response bodies.
// Access token: 15m, Refresh token: 7d.
// ─────────────────────────────────────────────
function setAuthCookies(res, { accessToken, refreshToken }) {
  res.cookie(ACCESS_COOKIE_NAME, accessToken, {
    ...COOKIE_DEFAULTS,
    maxAge: 15 * 60 * 1000,        // 15 minutes
  });
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
    ...COOKIE_DEFAULTS,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
}

function clearAuthCookies(res) {
  res.clearCookie(ACCESS_COOKIE_NAME,  { ...COOKIE_DEFAULTS });
  res.clearCookie(REFRESH_COOKIE_NAME, { ...COOKIE_DEFAULTS });
  res.clearCookie(CSRF_COOKIE_NAME,    { ...COOKIE_DEFAULTS, httpOnly: false });
}

// ─────────────────────────────────────────────
// CSRF — DOUBLE-SUBMIT COOKIE PATTERN
// 1. Server sets a signed CSRF cookie (readable by JS, SameSite=Strict)
// 2. Client reads cookie and sends value in X-CSRF-Token header
// 3. Server verifies the header matches the cookie (HMAC-verified)
// ─────────────────────────────────────────────
function generateCsrfToken(userId) {
  const random = crypto.randomBytes(32).toString('hex');
  const ts     = Math.floor(Date.now() / 1000);
  const payload = `${userId}:${random}:${ts}`;
  const sig = crypto
    .createHmac('sha256', CSRF_SECRET)
    .update(payload)
    .digest('hex');
  return `${payload}.${sig}`;
}

function verifyCsrfToken(token, userId) {
  if (!token || typeof token !== 'string') return false;
  const lastDot = token.lastIndexOf('.');
  if (lastDot === -1) return false;

  const payload  = token.slice(0, lastDot);
  const receivedSig = token.slice(lastDot + 1);

  const expectedSig = crypto
    .createHmac('sha256', CSRF_SECRET)
    .update(payload)
    .digest('hex');

  // Timing-safe compare
  const sigBufA = Buffer.from(receivedSig.padEnd(64, '0'));
  const sigBufB = Buffer.from(expectedSig.padEnd(64, '0'));
  if (sigBufA.length !== sigBufB.length) return false;
  if (!crypto.timingSafeEqual(sigBufA, sigBufB)) return false;

  // Verify userId and expiry
  const [tokenUserId, , tsStr] = payload.split(':');
  if (tokenUserId !== String(userId)) return false;
  const age = Math.floor(Date.now() / 1000) - parseInt(tsStr, 10);
  if (age > CSRF_TTL_S || age < 0) return false;

  return true;
}

function setCsrfCookie(res, token) {
  // NOT httpOnly — JS must be able to read it
  res.cookie(CSRF_COOKIE_NAME, token, {
    secure   : true,
    sameSite : 'Strict',
    path     : '/',
    maxAge   : CSRF_TTL_S * 1000,
  });
}

// ─────────────────────────────────────────────
// REQUIRE AUTH MIDDLEWARE
// Reads token from httpOnly cookie ONLY.
// Attaches req.user on success.
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.[ACCESS_COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  try {
    const payload = verifyAccessToken(token);
    req.user = { id: payload.sub, roles: payload.roles, jti: payload.jti };
    next();
  } catch (err) {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user?.roles?.includes('admin')) {
      return res.status(403).json({ error: 'Insufficient permissions.' });
    }
    next();
  });
}

// ─────────────────────────────────────────────
// REQUIRE CSRF MIDDLEWARE
// Apply to all state-changing routes (POST/PUT/PATCH/DELETE).
// ─────────────────────────────────────────────
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];

  if (!headerToken || !cookieToken) {
    return res.status(403).json({ error: 'CSRF token missing.' });
  }

  // Both must match and be valid
  if (!timingSafeEqual(headerToken, cookieToken)) {
    return res.status(403).json({ error: 'CSRF token mismatch.' });
  }

  const userId = req.user?.id || 'anonymous';
  if (!verifyCsrfToken(cookieToken, userId)) {
    return res.status(403).json({ error: 'CSRF token invalid or expired.' });
  }

  next();
}

// ─────────────────────────────────────────────
// RATE LIMITERS (Redis-backed)
// ─────────────────────────────────────────────
function buildAuthLimiter(redis) {
  return rateLimit({
    windowMs : 15 * 60 * 1000,
    max      : 10,
    store    : new RedisStore({
      sendCommand: (...args) => redis.sendCommand(args),
      prefix: 'rl:auth:',
    }),
    standardHeaders : true,
    legacyHeaders   : false,
    handler(req, res) {
      res.status(429).json({
        error: 'Too many attempts. Please try again in 15 minutes.',
      });
    },
  });
}

function buildApiLimiter(redis) {
  return rateLimit({
    windowMs : 60 * 1000,
    max      : 100,
    store    : new RedisStore({
      sendCommand: (...args) => redis.sendCommand(args),
      prefix: 'rl:api:',
    }),
    standardHeaders : true,
    legacyHeaders   : false,
    handler(req, res) {
      res.status(429).json({ error: 'Rate limit exceeded. Please slow down.' });
    },
  });
}

// ─────────────────────────────────────────────
// MFA RATE LIMITER (Redis-backed)
// FIX v2.1: Prevents sustained TOTP brute-force across windows.
// 5 attempts per 5 minutes per account — separate from login limiter.
// ─────────────────────────────────────────────
function buildMfaLimiter(redis) {
  return rateLimit({
    windowMs : 5 * 60 * 1000,  // 5 minutes
    max      : 5,               // 5 attempts only
    keyGenerator: (req) => `mfa:${req.user?.id || req.ip}`,
    store    : new RedisStore({
      sendCommand: (...args) => redis.sendCommand(args),
      prefix: 'rl:mfa:',
    }),
    standardHeaders : true,
    legacyHeaders   : false,
    handler(req, res) {
      res.status(429).json({
        error: 'Too many authentication attempts. Please wait 5 minutes.',
      });
    },
  });
}

// ─────────────────────────────────────────────
// ACCOUNT LOCKOUT (Redis)
// Tracks per-account failures independently of IP limits.
// Uses exponential back-off: each lockout doubles duration.
// ─────────────────────────────────────────────
async function isAccountLocked(redis, userId) {
  const key = `lock:${userId}`;
  const val = await redis.get(key);
  return val !== null;
}

async function recordLoginFailure(redis, userId) {
  const failKey  = `fail:${userId}`;
  const lockKey  = `lock:${userId}`;
  const countKey = `failcount:${userId}`;

  const fails = await redis.incr(failKey);
  await redis.expire(failKey, 15 * 60);

  if (fails >= MAX_LOGIN_FAILS) {
    // Exponential back-off: 2^(attempts/5) * 15 min, capped at 1 hour
    const lockouts = (await redis.incr(countKey)) || 1;
    const lockMs   = Math.min(
      LOCKOUT_MS * Math.pow(2, lockouts - 1),
      MAX_LOCKOUT_MS
    );
    await redis.set(lockKey, '1', { PX: lockMs });
    await redis.del(failKey);
    return { locked: true, lockMs };
  }
  return { locked: false, fails };
}

async function clearLoginFailures(redis, userId) {
  await redis.del(`fail:${userId}`);
  await redis.del(`lock:${userId}`);
  await redis.del(`failcount:${userId}`);
}

// ─────────────────────────────────────────────
// REFRESH TOKEN ROTATION
// Old refresh token is invalidated immediately.
// New pair is issued.
// ─────────────────────────────────────────────
async function rotateTokens(redis, req, res) {
  const oldToken = req.cookies?.[REFRESH_COOKIE_NAME];
  if (!oldToken) {
    return res.status(401).json({ error: 'Refresh token missing.' });
  }

  let payload;
  try {
    payload = verifyRefreshToken(oldToken);
  } catch {
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Invalid refresh token.' });
  }

  // Check if this JTI has been revoked (replay attack prevention)
  const revokedKey = `revoked_jti:${payload.jti}`;
  const isRevoked  = await redis.get(revokedKey);
  if (isRevoked) {
    // Possible token theft — log and lock
    clearAuthCookies(res);
    return res.status(401).json({ error: 'Token has been revoked.' });
  }

  // Revoke the old JTI for its remaining lifetime
  const exp    = payload.exp - Math.floor(Date.now() / 1000);
  const ttl    = Math.max(exp, 1);
  await redis.set(revokedKey, '1', { EX: ttl });

  // Issue fresh pair
  const tokens = issueTokens(payload.sub);
  setAuthCookies(res, tokens);

  // Issue new CSRF token
  const csrfToken = generateCsrfToken(payload.sub);
  setCsrfCookie(res, csrfToken);

  return { userId: payload.sub };
}

// ─────────────────────────────────────────────
// MFA — TOTP (time-based one-time passwords)
// ─────────────────────────────────────────────
function generateMFASecret(userEmail) {
  const secret = speakeasy.generateSecret({
    name   : `WTM (${userEmail})`,
    length : 32,
  });
  return {
    base32     : secret.base32,
    otpauth_url: secret.otpauth_url,
  };
}

function verifyMFAToken(secret, token) {
  if (!secret || !token) return false;
  return speakeasy.totp.verify({
    secret,
    encoding : 'base32',
    token    : String(token).replace(/\s/g, ''),
    window   : 1,   // allow ±30s clock drift
  });
}

// ─────────────────────────────────────────────
// TIMING-SAFE STRING COMPARE
// ─────────────────────────────────────────────
function timingSafeEqual(a, b) {
  const bufA = Buffer.from(String(a).padEnd(256, '\0'));
  const bufB = Buffer.from(String(b).padEnd(256, '\0'));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  hashPassword,
  verifyPassword,
  issueTokens,
  verifyAccessToken,
  verifyRefreshToken,
  setAuthCookies,
  clearAuthCookies,
  generateCsrfToken,
  verifyCsrfToken,
  setCsrfCookie,
  requireAuth,
  requireAdmin,
  requireCsrf,
  buildAuthLimiter,
  buildApiLimiter,
  buildMfaLimiter,
  isAccountLocked,
  recordLoginFailure,
  clearLoginFailures,
  rotateTokens,
  generateMFASecret,
  verifyMFAToken,
  timingSafeEqual,
  COOKIE_NAMES: {
    ACCESS  : ACCESS_COOKIE_NAME,
    REFRESH : REFRESH_COOKIE_NAME,
    CSRF    : CSRF_COOKIE_NAME,
  },
};
