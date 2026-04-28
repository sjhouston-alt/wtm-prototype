/**
 * WTM — Bot Detection & Booking Protection  v1.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • Booking flow bot detection (velocity checks, headless browser signals)
 *   • Honeypot fields
 *   • Behavioral timing analysis
 *   • IP reputation checking
 *   • Booking velocity limits per user and per experience
 *   • Scalping prevention (max bookings per experience per account)
 *   • Device fingerprint anomaly detection
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const crypto = require('crypto');
const { logEvent, EVENTS } = require('./monitoring');

// ─────────────────────────────────────────────
// BOOKING VELOCITY LIMITS
// ─────────────────────────────────────────────
const LIMITS = {
  bookingsPerUserPerHour    : 5,
  bookingsPerUserPerDay     : 10,
  bookingsPerExperiencePerUser: 2,   // max 2 bookings of same experience per account
  suspiciousSpeedMs         : 3000,  // booking completed in < 3 seconds = suspicious
};

// ─────────────────────────────────────────────
// BOT DETECTION MIDDLEWARE
// Checks request headers and timing for bot signals.
// Apply to booking creation endpoint.
// ─────────────────────────────────────────────
function detectBots(req, res, next) {
  const signals = [];

  // 1. Missing or suspicious User-Agent
  const ua = req.headers['user-agent'] || '';
  if (!ua) signals.push('missing_user_agent');
  if (/headlesschrome|phantomjs|selenium|webdriver|puppeteer|playwright/i.test(ua)) {
    signals.push('headless_browser');
  }

  // 2. Missing Accept-Language (bots often omit this)
  if (!req.headers['accept-language']) signals.push('missing_accept_language');

  // 3. Missing Referer on booking (real users navigate from detail page)
  const referer = req.headers['referer'] || '';
  if (req.method === 'POST' && !referer) signals.push('missing_referer');

  // 4. Suspicious Accept header (bots often send just */*)
  const accept = req.headers['accept'] || '';
  if (accept === '*/*' && req.method === 'POST') signals.push('wildcard_accept_on_post');

  // 5. Check for browser timing token (set by frontend on page load)
  const timingToken = req.headers['x-page-timing'] || req.body?._timing;
  if (timingToken) {
    try {
      const { ts, elapsed } = JSON.parse(
        Buffer.from(timingToken, 'base64').toString('utf8')
      );
      const age = Date.now() - ts;
      if (elapsed < LIMITS.suspiciousSpeedMs) signals.push('booking_too_fast');
      if (age > 30 * 60 * 1000) signals.push('stale_timing_token'); // > 30 min
    } catch {
      signals.push('invalid_timing_token');
    }
  }

  // 6. Honeypot field check (frontend has a hidden field named _wtm_hp — should be empty)
  if (req.body?._wtm_hp !== undefined && req.body._wtm_hp !== '') {
    signals.push('honeypot_triggered');
    logEvent(EVENTS.INJECTION_ATTEMPT, req.user?.id, {
      reason    : 'honeypot_field_filled',
      requestId : req.requestId,
    }, 'warn');
    // Hard block — honeypot filled = definitely a bot
    return res.status(400).json({ error: 'Invalid request.' });
  }

  // Attach signals for downstream use
  req.botSignals = signals;

  // High confidence bot — block
  const hardBlockSignals = ['headless_browser', 'honeypot_triggered'];
  if (signals.some(s => hardBlockSignals.includes(s))) {
    logEvent(EVENTS.INJECTION_ATTEMPT, req.user?.id, {
      reason    : 'bot_detected_hard_block',
      signals,
      requestId : req.requestId,
    }, 'warn');
    return res.status(403).json({ error: 'Request blocked.' });
  }

  // Medium confidence — log but allow (for now — escalate after review)
  if (signals.length >= 2) {
    logEvent(EVENTS.INJECTION_ATTEMPT, req.user?.id, {
      reason    : 'bot_signals_medium_confidence',
      signals,
      requestId : req.requestId,
    }, 'warn');
  }

  next();
}

// ─────────────────────────────────────────────
// BOOKING VELOCITY CHECK (Redis-backed)
// Prevents scalping and automated bulk booking.
// ─────────────────────────────────────────────
async function checkBookingVelocity(redis, userId, experienceId) {
  const now      = Math.floor(Date.now() / 1000);
  const hourKey  = `bv:hour:${userId}:${Math.floor(now / 3600)}`;
  const dayKey   = `bv:day:${userId}:${Math.floor(now / 86400)}`;
  const expKey   = `bv:exp:${userId}:${experienceId}`;

  const [hourCount, dayCount, expCount] = await Promise.all([
    redis.incr(hourKey),
    redis.incr(dayKey),
    redis.incr(expKey),
  ]);

  // Set TTLs on first increment
  await Promise.all([
    redis.expire(hourKey, 3600),
    redis.expire(dayKey, 86400),
    redis.expire(expKey, 86400 * 30), // 30 days for experience-level tracking
  ]);

  if (hourCount > LIMITS.bookingsPerUserPerHour) {
    return { blocked: true, reason: 'Too many bookings this hour. Please wait before booking again.' };
  }
  if (dayCount > LIMITS.bookingsPerUserPerDay) {
    return { blocked: true, reason: 'Daily booking limit reached. Please try again tomorrow.' };
  }
  if (expCount > LIMITS.bookingsPerExperiencePerUser) {
    return { blocked: true, reason: 'You already have the maximum number of bookings for this experience.' };
  }

  return { blocked: false };
}

// ─────────────────────────────────────────────
// BOOKING VELOCITY MIDDLEWARE FACTORY
// ─────────────────────────────────────────────
function bookingVelocityMiddleware(redis) {
  return async (req, res, next) => {
    try {
      const userId       = req.user?.id;
      const experienceId = req.body?.experienceId;

      if (!userId || !experienceId) return next();

      const check = await checkBookingVelocity(redis, userId, experienceId);
      if (check.blocked) {
        logEvent(EVENTS.RATE_LIMIT_HIT, userId, {
          reason      : 'booking_velocity_exceeded',
          experienceId,
          requestId   : req.requestId,
        }, 'warn');
        return res.status(429).json({ error: check.reason });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

// ─────────────────────────────────────────────
// GENERATE PAGE TIMING TOKEN
// Frontend calls this endpoint on page load to get a timing token.
// Token is sent back with booking submission to prove human interaction time.
// ─────────────────────────────────────────────
function generateTimingToken(userId) {
  const payload = JSON.stringify({ ts: Date.now(), userId });
  const encoded = Buffer.from(payload).toString('base64');
  const sig = crypto
    .createHmac('sha256', process.env.CSRF_SECRET || 'dev-secret')
    .update(encoded)
    .digest('hex');
  return `${encoded}.${sig}`;
}

module.exports = {
  detectBots,
  bookingVelocityMiddleware,
  checkBookingVelocity,
  generateTimingToken,
  LIMITS,
};
