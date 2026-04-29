/**
 * WTM — Server Entry Point
 * Wires all security middleware together in the correct order.
 * This is the reference implementation — adapt for your framework.
 */

'use strict';

require('dotenv').config();

const express   = require('express');
const cookieParser = require('cookie-parser');
const { createClient } = require('redis');

const {
  corsMiddleware,
  securityHeaders,
  requestId,
  validate,
  errorHandler,
} = require('./security/api');

const { requireAuth, requireAdmin, buildAuthLimiter, setAuthCookies, clearAuthCookies, rotateTokens } = require('./security/auth');
const { logEvent, auditLog, EVENTS, checkSuspiciousLogin, trackPaymentResult } = require('./security/monitoring');
const { verifyWebhookSignature, handleWebhookEvent, chargeBooking, calculateBookingTotal, createSetupIntent, savePaymentMethod } = require('./security/payments');
const { hashPassword, verifyPassword, issueTokens, isAccountLocked, recordLoginFailure, clearLoginFailures, generateMFASecret, verifyMFAToken } = require('./security/auth');
const { getUserByEmailHmac, getUserById, createUser, createBooking, confirmBooking, getUserBookings, createReview, deleteUserAccount } = require('./security/database');
const { hmacField, generateToken, generateBookingCode, hashResetToken } = require('./security/encryption');

const app = express();

// ─────────────────────────────────────────────
// REDIS CLIENT
// ─────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL });
redis.connect().catch(err => { console.error('Redis connection failed:', err); process.exit(1); });

// ─────────────────────────────────────────────
// MIDDLEWARE ORDER — THIS ORDER MATTERS
// ─────────────────────────────────────────────
app.set('trust proxy', 1);               // trust first proxy (load balancer)
app.use(requestId);                      // attach request ID first
app.use(securityHeaders);                // security headers before anything else
app.use(corsMiddleware);                 // CORS
app.use(cookieParser());                 // parse httpOnly cookies
app.use(auditLog);                       // log all requests

// NOTE: Stripe webhook route must use raw body — register BEFORE express.json()
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = verifyWebhookSignature(req.body, sig);
  } catch (err) {
    logEvent('webhook_signature_failure', null, { error: err.message });
    return res.status(400).json({ error: 'Webhook signature verification failed.' });
  }

  await handleWebhookEvent(event, {
    onSuccess: async (pi) => {
      await confirmBooking(pi.metadata.booking_id, pi.id);
      await trackPaymentResult(redis, true);
      logEvent(EVENTS.PAYMENT_SUCCESS, pi.metadata.user_id, { amount: pi.amount, bookingId: pi.metadata.booking_id });
    },
    onFailure: async (pi) => {
      await trackPaymentResult(redis, false);
      logEvent(EVENTS.PAYMENT_FAILURE, pi.metadata.user_id, { bookingId: pi.metadata.booking_id });
    },
    onDispute: async (charge) => {
      logEvent('payment_dispute', null, { chargeId: charge.id, amount: charge.amount });
    },
    onRefund: async (charge) => {
      logEvent(EVENTS.REFUND_ISSUED, null, { chargeId: charge.id });
    },
  });

  res.json({ received: true });
});

app.use(express.json({ limit: '50kb' })); // parse JSON — limit body size

// ─────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────
const authLimiter = buildAuthLimiter(redis);

app.post('/auth/register', authLimiter, validate('register'), async (req, res, next) => {
  try {
    const { name, email, password } = req.validated;
    const emailHmac    = hmacField(email);
    const existing     = await getUserByEmailHmac(emailHmac);
    if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });

    const passwordHash = await hashPassword(password);
    // Create Stripe customer first so we have the ID for DB insert
    const { createStripeCustomer } = require('./security/payments');
    const stripeCustomer = await createStripeCustomer(null, email, name); // userId added after insert

    const user   = await createUser({ name, email, emailHmac, passwordHash, stripeCustomerId: stripeCustomer.id, city: null });
    const tokens = issueTokens(user.id);
    setAuthCookies(res, tokens);

    logEvent(EVENTS.REGISTER, user.id, { ip: req.ip });
    res.status(201).json({ user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) { next(err); }
});

app.post('/auth/login', authLimiter, validate('login'), async (req, res, next) => {
  try {
    const { email, password, mfa_code } = req.validated;
    const emailHmac = hmacField(email);
    const user      = await getUserByEmailHmac(emailHmac);

    // Generic error — don't reveal whether email exists
    const AUTH_ERROR = { error: 'Invalid email or password.' };

    if (!user) {
      logEvent(EVENTS.LOGIN_FAILURE, null, { ip: req.ip });
      return res.status(401).json(AUTH_ERROR);
    }

    // Check lockout
    if (await isAccountLocked(redis, user.id)) {
      logEvent(EVENTS.LOGIN_BLOCKED, user.id, { ip: req.ip });
      return res.status(429).json({ error: 'Account temporarily locked. Please try again in 30 minutes.' });
    }

    // Verify password
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      const failures = await recordLoginFailure(redis, user.id);
      logEvent(EVENTS.LOGIN_FAILURE, user.id, { ip: req.ip, failures });
      return res.status(401).json(AUTH_ERROR);
    }

    // Verify MFA if enabled
    if (user.mfa_enabled) {
      if (!mfa_code) return res.status(200).json({ mfa_required: true });
      if (!verifyMFAToken(user.mfa_secret, mfa_code)) {
        logEvent(EVENTS.MFA_FAILURE, user.id, { ip: req.ip });
        return res.status(401).json({ error: 'Invalid MFA code.' });
      }
    }

    await clearLoginFailures(redis, user.id);
    const tokens = issueTokens(user.id);
    setAuthCookies(res, tokens);

    const { newDevice } = await checkSuspiciousLogin(redis, user.id, req);
    logEvent(EVENTS.LOGIN_SUCCESS, user.id, { ip: req.ip, newDevice });

    res.json({ user: { id: user.id, name: user.name, email: user.email, city: user.city } });
  } catch (err) { next(err); }
});

app.post('/auth/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token.' });
    await rotateTokens(redis, refreshToken, res);
    res.json({ ok: true });
  } catch (err) {
    clearAuthCookies(res);
    next(err);
  }
});

app.post('/auth/logout', requireAuth, (req, res) => {
  clearAuthCookies(res);
  logEvent(EVENTS.LOGOUT, req.user.sub, { ip: req.ip });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// BOOKING ROUTES
// ─────────────────────────────────────────────
app.post('/bookings', requireAuth, validate('booking'), async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const { experience_id, date, time_slot, guests, addons, special_req, payment_method_id } = req.validated;

    // Fetch experience price from DB — never trust client-supplied amount
    const expResult = await require('./security/database').pool.query(
      'SELECT base_price_cents FROM experiences WHERE id = $1 AND verified = true',
      [experience_id]
    );
    if (!expResult.rows.length) return res.status(404).json({ error: 'Experience not found.' });

    const { base_price_cents } = expResult.rows[0];
    // Addons: fetch prices from DB too
    const addonTotal = 0; // TODO: fetch from DB like experience price

    const amountCents  = calculateBookingTotal({ basePrice: base_price_cents / 100, guests, addonsTotal: addonTotal });
    const bookingCode  = generateBookingCode();

    const user    = await getUserById(userId);
    const booking = await createBooking({ userId, experienceId: experience_id, date, timeSlot: time_slot, guests, addons, specialReq: special_req, amountCents, bookingCode });

    // Charge via Stripe — amount calculated server-side
    const paymentIntent = await chargeBooking({
      stripeCustomerId:  user.stripe_customer_id,
      paymentMethodId:   payment_method_id,
      amountCents,
      bookingId:         booking.id,
      experienceId:      experience_id,
      userId,
    });

    await confirmBooking(booking.id, paymentIntent.id);
    logEvent(EVENTS.PAYMENT_SUCCESS, userId, { bookingId: booking.id, amount: amountCents });

    res.status(201).json({ booking: { id: booking.id, booking_code: booking.booking_code, status: 'confirmed' } });
  } catch (err) { next(err); }
});

app.get('/bookings', requireAuth, async (req, res, next) => {
  try {
    const bookings = await getUserBookings(req.user.sub);
    res.json({ bookings });
  } catch (err) { next(err); }
});

// ─────────────────────────────────────────────
// PAYMENT METHOD ROUTES
// ─────────────────────────────────────────────
app.post('/payment-methods/setup', requireAuth, async (req, res, next) => {
  try {
    const user   = await getUserById(req.user.sub);
    const intent = await createSetupIntent(user.stripe_customer_id);
    res.json({ client_secret: intent.client_secret });
  } catch (err) { next(err); }
});

app.post('/payment-methods', requireAuth, async (req, res, next) => {
  try {
    const { payment_method_id } = req.body;
    if (!payment_method_id) return res.status(400).json({ error: 'payment_method_id required.' });
    const user = await getUserById(req.user.sub);
    const pm   = await savePaymentMethod(user.stripe_customer_id, payment_method_id);
    logEvent(EVENTS.PAYMENT_METHOD_ADDED, req.user.sub);
    res.status(201).json({ payment_method: pm });
  } catch (err) { next(err); }
});

// ─────────────────────────────────────────────
// ACCOUNT DELETION (GDPR / CCPA)
// ─────────────────────────────────────────────
app.delete('/account', requireAuth, async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const user   = await getUserById(userId);

    // Delete Stripe customer (removes all payment methods)
    if (user.stripe_customer_id) {
      const { deleteStripeCustomer } = require('./security/payments');
      await deleteStripeCustomer(user.stripe_customer_id);
    }

    await deleteUserAccount(userId);
    clearAuthCookies(res);
    logEvent(EVENTS.ACCOUNT_DELETED, userId, { ip: req.ip });
    res.json({ ok: true, message: 'Your account and personal data have been deleted.' });
  } catch (err) { next(err); }
});

// ─────────────────────────────────────────────
// HEALTH CHECK (no auth required)
// ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }));

// ─────────────────────────────────────────────
// ERROR HANDLER — must be last
// ─────────────────────────────────────────────
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.info(`WTM API running on port ${PORT}`));

module.exports = app;
