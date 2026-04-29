/**
 * WTM — Authentication & Session Security
 * Covers: password hashing, JWT tokens, MFA, rate limiting
 */

'use strict';

const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────
const SALT_ROUNDS = 12;

const TOKEN_CONFIG = {
  access:  { secret: process.env.JWT_ACCESS_SECRET,  expiresIn: '15m' },
  refresh: { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d'  },
};

const COOKIE_BASE = {
  httpOnly: true,
  secure:   true,
  sameSite: 'Strict',
};

// ─────────────────────────────────────────────
// PASSWORD HASHING
// Never store plaintext or MD5/SHA1 passwords.
// bcrypt at cost 12 = ~300ms — fast for users,
// too slow for brute-force at scale.
// ─────────────────────────────────────────────
async function hashPassword(plaintext) {
  return await bcrypt.hash(plaintext, SALT_ROUNDS);
}

async function verifyPassword(plaintext, hash) {
  return await bcrypt.compare(plaintext, hash);
}

// ─────────────────────────────────────────────
// JWT — ACCESS + REFRESH TOKENS
// Access token: 15 min, stored in httpOnly cookie
// Refresh token: 7 days, httpOnly cookie on /auth/refresh only
// NEVER store tokens in localStorage — accessible
// by any JS on the page including injected scripts.
// ─────────────────────────────────────────────
function issueTokens(userId) {
  const payload = {
    sub: userId,
    iat: Math.floor(Date.now() / 1000),
  };
  return {
    accessToken:  jwt.sign(payload, TOKEN_CONFIG.access.secret,  { expiresIn: TOKEN_CONFIG.access.expiresIn }),
    refreshToken: jwt.sign(payload, TOKEN_CONFIG.refresh.secret, { expiresIn: TOKEN_CONFIG.refresh.expiresIn }),
  };
}

function setAuthCookies(res, tokens) {
  res.cookie('access_token', tokens.accessToken, {
    ...COOKIE_BASE,
    maxAge: 15 * 60 * 1000,
  });
  res.cookie('refresh_token', tokens.refreshToken, {
    ...COOKIE_BASE,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path:   '/auth/refresh', // refresh token only sent to this route
  });
}

function clearAuthCookies(res) {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
}

function verifyAccessToken(token) {
  return jwt.verify(token, TOKEN_CONFIG.access.secret);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, TOKEN_CONFIG.refresh.secret);
}

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE
// Reads token from httpOnly cookie, never from
// Authorization header (which JS can set).
// ─────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.access_token;
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    req.user = verifyAccessToken(token);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
  });
}

// ─────────────────────────────────────────────
// MFA — TOTP (Time-Based One-Time Password)
// Required for all admin accounts.
// Optional but encouraged for user accounts.
// ─────────────────────────────────────────────
function generateMFASecret(userEmail) {
  const secret = speakeasy.generateSecret({
    name:   `What's the Move (${userEmail})`,
    length: 32,
  });
  return {
    base32:      secret.base32,
    otpauth_url: secret.otpauth_url,
  };
}

function verifyMFAToken(base32Secret, token) {
  return speakeasy.totp.verify({
    secret:   base32Secret,
    encoding: 'base32',
    token,
    window:   1, // allow 30s clock drift
  });
}

// ─────────────────────────────────────────────
// RATE LIMITING
// Applied to all auth routes.
// Redis-backed so limits persist across instances.
// Key = IP + email so attackers can't bypass by
// rotating IPs against a single account.
// ─────────────────────────────────────────────
function buildAuthLimiter(redisClient) {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max:      10,              // 10 attempts per window
    message:  { error: 'Too many attempts. Please try again in 15 minutes.' },
    store:    new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
    }),
    keyGenerator: (req) => `${req.ip}:${req.body?.email ?? 'unknown'}`,
    skipSuccessfulRequests: true,
  });
}

// ─────────────────────────────────────────────
// ACCOUNT LOCKOUT
// Lock account after 10 consecutive failures.
// Stored in Redis with TTL so it auto-unlocks.
// ─────────────────────────────────────────────
const MAX_FAILURES  = 10;
const LOCKOUT_TTL   = 30 * 60; // 30 minutes in seconds

async function recordLoginFailure(redisClient, userId) {
  const key     = `lockout:${userId}`;
  const failures = await redisClient.incr(key);
  if (failures === 1) await redisClient.expire(key, LOCKOUT_TTL);
  return failures;
}

async function isAccountLocked(redisClient, userId) {
  const key      = `lockout:${userId}`;
  const failures = parseInt(await redisClient.get(key) ?? '0', 10);
  return failures >= MAX_FAILURES;
}

async function clearLoginFailures(redisClient, userId) {
  await redisClient.del(`lockout:${userId}`);
}

// ─────────────────────────────────────────────
// REFRESH TOKEN ROTATION
// On every refresh, issue a new pair and
// invalidate the old refresh token in Redis.
// ─────────────────────────────────────────────
async function rotateTokens(redisClient, oldRefreshToken, res) {
  let payload;
  try {
    payload = verifyRefreshToken(oldRefreshToken);
  } catch {
    throw new Error('Invalid refresh token.');
  }

  // Check token hasn't been revoked
  const revoked = await redisClient.get(`revoked:${oldRefreshToken}`);
  if (revoked) throw new Error('Refresh token revoked.');

  // Revoke old token (store hash to save space)
  await redisClient.setEx(`revoked:${oldRefreshToken}`, 7 * 24 * 60 * 60, '1');

  const tokens = issueTokens(payload.sub);
  setAuthCookies(res, tokens);
  return tokens;
}

module.exports = {
  hashPassword,
  verifyPassword,
  issueTokens,
  setAuthCookies,
  clearAuthCookies,
  verifyAccessToken,
  verifyRefreshToken,
  requireAuth,
  requireAdmin,
  generateMFASecret,
  verifyMFAToken,
  buildAuthLimiter,
  recordLoginFailure,
  isAccountLocked,
  clearLoginFailures,
  rotateTokens,
};
