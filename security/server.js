/**
 * WTM — Server Entry Point  v2.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Middleware order is critical — do NOT reorder without review.
 * Raw body for Stripe MUST be registered before express.json().
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

require('dotenv').config();

const express      = require('express');
const cookieParser = require('cookie-parser');
const { createClient } = require('redis');

const {
  corsMiddleware,
  securityHeaders,
  permissionsPolicy,
  requestId,
  enforceJsonContentType,
  hppMiddleware,
  validate,
  validateUuidParam,
  errorHandler,
  notFoundHandler,
} = require('./security/api');

const {
  requireAuth,
  requireAdmin,
  requireCsrf,
  buildAuthLimiter,
  buildApiLimiter,
  isAccountLocked,
  recordLoginFailure,
  clearLoginFailures,
  rotateTokens,
  setAuthCookies,
  clearAuthCookies,
  generateCsrfToken,
  setCsrfCookie,
  issueTokens,
  hashPassword,
  verifyPassword,
  generateMFASecret,
  verifyMFAToken,
  COOKIE_NAMES,
} = require('./security/auth');

const {
  logEvent,
  auditLog,
  EVENTS,
  checkSuspiciousLogin,
  trackPaymentResult,
  checkInjectionAttempt,
} = require('./security/monitoring');

const {
  verifyWebhookSignature,
  handleWebhookEvent,
  chargeBooking,
  calculateBookingTotal,
  createSetupIntent,
  savePaymentMethod,
  createStripeCustomer,
  refundPayment,
} = require('./security/payments');

const {
  hashPassword: hashPw,
  verifyPassword: verifyPw,
  issueTokens: issue,
  hashResetToken,
  generateResetToken,
  generateBookingCode,
  hmacField,
} = require('./security/encryption');

const {
  getUserByEmailHmac,
  getUserById,
  createUser,
  updateUserProfile,
  storeResetToken,
  consumeResetToken,
  updatePasswordHash,
  createBooking,
  confirmBooking,
  getUserBookings,
  createReview,
  deleteUserAccount,
  storeMfaSecret,
  enableMfa,
  saveStripeCustomerId,
} = require('./security/database');

const app = express();

// ─────────────────────────────────────────────
// REDIS
// ─────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redis.connect().catch(err => {
  console.error('[FATAL] Redis connection failed:', err.message);
  process.exit(1);
});

// ─────────────────────────────────────────────
// RATE LIMITERS
// ─────────────────────────────────────────────
const authLimiter = buildAuthLimiter(redis);
const apiLimiter  = buildApiLimiter(redis);

// ─────────────────────────────────────────────
// MIDDLEWARE — ORDER IS CRITICAL
// ─────────────────────────────────────────────
app.set('trust proxy', 1);      // trust load balancer's X-Forwarded-For
app.use(requestId);             // 1. attach request ID (trace all requests)
app.use(securityHeaders);       // 2. Helmet headers before any response
app.use(permissionsPolicy);     // 3. Permissions-Policy header
app.use(corsMiddleware);        // 4. CORS check
app.use(cookieParser());        // 5. parse httpOnly cookies
app.use(auditLog);              // 6. log all requests
app.use(checkInjectionAttempt); // 7. log injection patterns (non-blocking)
app.use(hppMiddleware);         // 8. HTTP parameter pollution prevention

// ─────────────────────────────────────────────
// STRIPE WEBHOOK — raw body, BEFORE express.json()
// ─────────────────────────────────────────────
app.post(
  '/webhooks/stripe',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = verifyWebhookSignature(req.body, sig);
    } catch (err) {
      logEvent('webhook_signature_failure', null, { error: err.message }, 'error');
      return res.status(400).json({ error: 'Webhook signature verification failed.' });
    }

    logEvent(EVENTS.WEBHOOK_RECEIVED, null, { type: event.type, id: event.id });
    const { getPool } = require('./security/database');
    await handleWebhookEvent(event, getPool());
    res.json({ received: true });
  }
);

// ─────────────────────────────────────────────
// JSON PARSING — AFTER stripe webhook route
// ─────────────────────────────────────────────
app.use(express.json({ limit: '100kb' }));   // reject oversized payloads
app.use(enforceJsonContentType);
app.use(apiLimiter);

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// ── REGISTER ──
app.post('/auth/register', authLimiter, validate('register'), async (req, res, next) => {
  try {
    const { email, password, name, city } = req.body;

    const passwordHash = await hashPassword(password);
    const user = await createUser({ email, passwordHash, name, city });

    // Create Stripe customer
    const stripeId = await createStripeCustomer(user.id, email, name);
    await saveStripeCustomerId(user.id, stripeId);

    // Issue tokens
    const tokens = issueTokens(user.id);
    setAuthCookies(res, tokens);

    const csrfToken = generateCsrfToken(user.id);
    setCsrfCookie(res, csrfToken);

    logEvent(EVENTS.USER_CREATED, user.id, { requestId: req.requestId });

    res.status(201).json({
      user : { id: user.id, name: user.name, city: user.city },
      csrf : csrfToken,
    });
  } catch (err) {
    next(err);
  }
});

// ── LOGIN ──
app.post('/auth/login', authLimiter, validate('login'), async (req, res, next) => {
  try {
    const { email, password, mfaToken } = req.body;
    const emailHmac = hmacField(email);
    const user      = await getUserByEmailHmac(emailHmac);

    // Always perform bcrypt compare to prevent user enumeration via timing
    const dummyHash = '$2b$12$dummyhashfortimingprotectiononly000000000000000000000000';
    const hash      = user?.password_hash || dummyHash;

    const locked = user && await isAccountLocked(redis, user.id);
    if (locked) {
      return res.status(429).json({ error: 'Account temporarily locked. Please try again later.' });
    }

    const valid = await verifyPassword(password, hash);

    if (!user || !valid) {
      if (user) await recordLoginFailure(redis, user.id);
      logEvent(EVENTS.LOGIN_FAILURE, user?.id || null, { requestId: req.requestId }, 'warn');
      return res.status(401).json({ error: 'Incorrect email or password.' });
    }

    // MFA check
    if (user.mfa_enabled) {
      if (!mfaToken) return res.status(200).json({ mfaRequired: true });
      if (!verifyMFAToken(user.mfa_secret, mfaToken)) {
        logEvent(EVENTS.MFA_FAILURE, user.id, { requestId: req.requestId }, 'warn');
        return res.status(401).json({ error: 'Invalid authentication code.' });
      }
    }

    await clearLoginFailures(redis, user.id);
    await checkSuspiciousLogin(redis, user.id, req);

    const tokens = issueTokens(user.id, [user.role]);
    setAuthCookies(res, tokens);

    const csrfToken = generateCsrfToken(user.id);
    setCsrfCookie(res, csrfToken);

    logEvent(EVENTS.LOGIN_SUCCESS, user.id, { requestId: req.requestId });

    res.json({
      user : { id: user.id, name: user.name, city: user.city, role: user.role },
      csrf : csrfToken,
    });
  } catch (err) {
    next(err);
  }
});

// ── LOGOUT ──
app.post('/auth/logout', requireAuth, requireCsrf, (req, res) => {
  clearAuthCookies(res);
  logEvent(EVENTS.LOGOUT, req.user.id, { requestId: req.requestId });
  res.json({ message: 'Signed out successfully.' });
});

// ── REFRESH TOKENS ──
app.post('/auth/refresh', async (req, res, next) => {
  try {
    const result = await rotateTokens(redis, req, res);
    if (!result?.userId) return; // rotateTokens already sent response
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ── ME ──
app.get('/auth/me', requireAuth, async (req, res, next) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ user: { id: user.id, name: user.name, city: user.city, role: user.role, preferences: user.preferences } });
  } catch (err) {
    next(err);
  }
});

// ── PASSWORD RESET REQUEST ──
app.post('/auth/password-reset', authLimiter, validate('passwordReset'), async (req, res, next) => {
  try {
    const emailHmac = hmacField(req.body.email);
    const user      = await getUserByEmailHmac(emailHmac);

    // Always return same response — prevents user enumeration
    if (user) {
      const rawToken  = generateResetToken();
      const tokenHash = hashResetToken(rawToken);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await storeResetToken(user.id, tokenHash, expiresAt);
      logEvent(EVENTS.PASSWORD_RESET_REQUEST, user.id, { requestId: req.requestId });
      // TODO: Send email with rawToken (implement email service)
      // sendPasswordResetEmail(user.email, rawToken);
    }

    res.json({ message: 'If that email exists, a reset link has been sent.' });
  } catch (err) {
    next(err);
  }
});

// ── PASSWORD CHANGE (via reset token) ──
app.post('/auth/password-change', authLimiter, validate('passwordChange'), async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;
    const tokenHash = hashResetToken(token);
    const userId    = await consumeResetToken(tokenHash);

    if (!userId) {
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    const newHash = await hashPassword(newPassword);
    await updatePasswordHash(userId, newHash);

    logEvent(EVENTS.PASSWORD_CHANGED, userId, { requestId: req.requestId });
    res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    next(err);
  }
});

// ── PROFILE UPDATE ──
app.patch('/users/me', requireAuth, requireCsrf, validate('profileUpdate'), async (req, res, next) => {
  try {
    const updated = await updateUserProfile(req.user.id, req.body);
    res.json({ user: updated });
  } catch (err) {
    next(err);
  }
});

// ── DELETE ACCOUNT ──
app.delete('/users/me', requireAuth, requireCsrf, async (req, res, next) => {
  try {
    const user = await getUserById(req.user.id);
    await deleteUserAccount(req.user.id, user?.stripe_customer_id);
    clearAuthCookies(res);
    logEvent(EVENTS.USER_DELETED, req.user.id, { requestId: req.requestId });
    res.json({ message: 'Account deleted.' });
  } catch (err) {
    next(err);
  }
});

// ── BOOKING: CREATE ──
app.post('/bookings', requireAuth, requireCsrf, validate('bookingCreate'), async (req, res, next) => {
  try {
    const { experienceId, date, timeSlot, guestCount, addons, specialRequests, paymentMethodId } = req.body;
    const { getPool } = require('./security/database');

    // Server-side amount calculation — never trust client
    const totals = await calculateBookingTotal(getPool(), experienceId, guestCount, addons);

    const bookingCode = generateBookingCode();
    const booking     = await createBooking({
      userId: req.user.id,
      experienceId, date, timeSlot, guestCount,
      addonIds: addons, specialRequests, bookingCode,
    });

    // Charge
    const user = await getUserById(req.user.id);
    const charge = await chargeBooking({
      stripeCustomerId : user.stripe_customer_id,
      paymentMethodId,
      amountCents      : totals.totalCents,
      bookingId        : booking.id,
      description      : `WTM Booking ${bookingCode}`,
    });

    await confirmBooking(booking.id, charge.paymentIntentId, totals.totalCents);
    await trackPaymentResult(redis, true, req.user.id, { bookingId: booking.id });

    logEvent(EVENTS.BOOKING_CONFIRMED, req.user.id, { bookingId: booking.id, bookingCode });

    res.status(201).json({
      booking: {
        id          : booking.id,
        bookingCode,
        status      : 'confirmed',
        amountCents : totals.totalCents,
      },
    });
  } catch (err) {
    await trackPaymentResult(redis, false, req.user?.id, { error: err.message });
    next(err);
  }
});

// ── BOOKING: LIST ──
app.get('/bookings', requireAuth, async (req, res, next) => {
  try {
    const bookings = await getUserBookings(req.user.id);
    res.json({ bookings });
  } catch (err) {
    next(err);
  }
});

// ── REVIEW: CREATE ──
app.post('/reviews', requireAuth, requireCsrf, validate('reviewCreate'), async (req, res, next) => {
  try {
    const { bookingId, rating, body } = req.body;
    // Look up experienceId from booking (security: don't trust client)
    const { getPool } = require('./security/database');
    const bResult = await getPool().query(
      `SELECT experience_id FROM bookings WHERE id = $1 AND user_id = $2 LIMIT 1`,
      [bookingId, req.user.id]
    );
    if (!bResult.rows.length) {
      return res.status(403).json({ error: 'Booking not found.' });
    }
    const review = await createReview({
      userId: req.user.id,
      bookingId,
      experienceId: bResult.rows[0].experience_id,
      rating,
      body,
    });
    res.status(201).json({ review });
  } catch (err) {
    next(err);
  }
});

// ── MFA SETUP ──
app.post('/auth/mfa/setup', requireAuth, requireCsrf, async (req, res, next) => {
  try {
    const user   = await getUserById(req.user.id);
    const { base32, otpauth_url } = generateMFASecret(user.email);
    await storeMfaSecret(req.user.id, base32);
    res.json({ otpauth_url }); // Client uses this to generate QR code
  } catch (err) {
    next(err);
  }
});

app.post('/auth/mfa/verify', requireAuth, requireCsrf, async (req, res, next) => {
  try {
    const { token } = req.body;
    const user      = await getUserById(req.user.id);

    // Re-fetch to get secret (getUserById doesn't return it by default)
    const { getPool } = require('./security/database');
    const r = await getPool().query(
      `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, [req.user.id]
    );
    const { decrypt } = require('./security/encryption');
    const secret = decrypt(r.rows[0].mfa_secret_encrypted);

    if (!verifyMFAToken(secret, token)) {
      logEvent(EVENTS.MFA_FAILURE, req.user.id, { step: 'verify' }, 'warn');
      return res.status(400).json({ error: 'Invalid code.' });
    }

    await enableMfa(req.user.id);
    logEvent(EVENTS.MFA_ENABLED, req.user.id, { requestId: req.requestId });
    res.json({ message: 'Two-factor authentication enabled.' });
  } catch (err) {
    next(err);
  }
});

// ── PAYMENT METHOD: SETUP ──
app.post('/payment-methods/setup', requireAuth, requireCsrf, async (req, res, next) => {
  try {
    const user         = await getUserById(req.user.id);
    const clientSecret = await createSetupIntent(user.stripe_customer_id);
    res.json({ clientSecret }); // Client uses with Stripe.js — no card data here
  } catch (err) {
    next(err);
  }
});

// ── ADMIN: PROTECTED ──
app.get('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    logEvent(EVENTS.ADMIN_ACTION, req.user.id, { action: 'list_users', requestId: req.requestId });
    const { getPool } = require('./security/database');
    const result = await getPool().query(
      `SELECT id, name, city, role, active, created_at FROM users ORDER BY created_at DESC LIMIT 100`
    );
    res.json({ users: result.rows });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────────
// ERROR + 404 HANDLERS — must be last
// ─────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ─────────────────────────────────────────────
// GRACEFUL SHUTDOWN
// ─────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);
const server = app.listen(PORT, () => {
  console.log(JSON.stringify({ level: 'info', event: 'server_start', port: PORT, env: process.env.NODE_ENV }));
});

function shutdown(signal) {
  console.log(JSON.stringify({ level: 'info', event: 'shutdown', signal }));
  server.close(async () => {
    await redis.quit();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000); // force exit after 10s
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

module.exports = app;
