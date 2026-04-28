/**
 * WTM — Payment Security (PCI-DSS Compliance)  v2.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • CRITICAL: Raw card data NEVER touches WTM servers (Stripe Elements only)
 *   • All amounts calculated server-side — never trust client
 *   • Stripe webhook signature verification (reject unverified events)
 *   • Idempotency keys on every charge (prevent double billing)
 *   • Stored payment methods via Stripe SetupIntent
 *   • BNPL (Affirm/Afterpay/Klarna) — available for bookings of $500 and above, no upper cap
 *   • No upper cap — available on any booking $500+
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT WTM STORES: Only Stripe customer IDs and payment method tokens.
 * WHAT WTM NEVER STORES: Card numbers, CVVs, expiry dates.
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const Stripe = require('stripe');

// ─────────────────────────────────────────────
// STRIPE INIT — fail fast if key missing
// ─────────────────────────────────────────────
const STRIPE_SECRET_KEY      = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET  = process.env.STRIPE_WEBHOOK_SECRET;

if (!STRIPE_SECRET_KEY) {
  console.error('[FATAL] STRIPE_SECRET_KEY must be set');
  process.exit(1);
}
if (!STRIPE_WEBHOOK_SECRET) {
  console.error('[FATAL] STRIPE_WEBHOOK_SECRET must be set');
  process.exit(1);
}

const stripe = Stripe(STRIPE_SECRET_KEY, {
  apiVersion   : '2024-04-10',
  timeout      : 10000,             // 10s timeout
  maxNetworkRetries: 3,             // auto-retry on network errors
  telemetry    : false,             // do not send usage telemetry to Stripe
});

// ─────────────────────────────────────────────
// PRICING CONSTANTS
// Server-side source of truth. Never use client values.
// ─────────────────────────────────────────────
const GUEST_FEE_CENTS        = 7500;   // $75.00 per additional guest above 2
const MIN_BNPL_CENTS         = 50000;  // $500.00 — minimum for BNPL (no upper cap)
// MAX_BNPL_CENTS removed — no upper cap on installments per v3 policy

// ─────────────────────────────────────────────
// SERVER-SIDE BOOKING TOTAL CALCULATION
//
// CRITICAL: Always recalculate on the server.
// Never use an amount provided by the client.
// ─────────────────────────────────────────────
async function calculateBookingTotal(db, experienceId, guestCount, addonIds = []) {
  // Fetch base price from DB (source of truth)
  const experience = await db.query(
    `SELECT base_price_cents, max_guests, is_luxury
     FROM experiences
     WHERE id = $1 AND experience_verified = true AND active = true`,
    [experienceId]
  );

  if (!experience.rows.length) {
    throw Object.assign(new Error('Experience not found or unavailable.'), { status: 404 });
  }

  const exp = experience.rows[0];

  if (guestCount < 1 || guestCount > exp.max_guests) {
    throw Object.assign(
      new Error(`Guest count must be between 1 and ${exp.max_guests}.`),
      { status: 400 }
    );
  }

  // Base + extra guests (above 2)
  const extraGuests    = Math.max(0, guestCount - 2);
  const guestFeeCents  = extraGuests * GUEST_FEE_CENTS;
  let   totalCents     = exp.base_price_cents + guestFeeCents;

  // Add-ons: fetch server-side prices
  let addonTotal = 0;
  if (addonIds.length > 0) {
    const addonResult = await db.query(
      `SELECT id, price_cents FROM addons
       WHERE id = ANY($1::uuid[]) AND experience_id = $2 AND active = true`,
      [addonIds, experienceId]
    );
    // Only count addons that belong to this experience
    const foundIds = new Set(addonResult.rows.map(a => a.id));
    for (const id of addonIds) {
      if (!foundIds.has(id)) {
        throw Object.assign(new Error(`Invalid add-on: ${id}`), { status: 400 });
      }
    }
    addonTotal = addonResult.rows.reduce((sum, a) => sum + a.price_cents, 0);
    totalCents += addonTotal;
  }

  // BNPL eligibility: back-end enforcement
  const bnplEligible =
    !exp.is_luxury &&
    totalCents >= MIN_BNPL_CENTS; // $500+ no upper cap — removed: 
    

  return {
    basePriceCents : exp.base_price_cents,
    guestFeeCents,
    addonTotalCents: addonTotal,
    totalCents,
    bnplEligible,
    isLuxury       : exp.is_luxury,
    extraGuests,
  };
}

// ─────────────────────────────────────────────
// CREATE STRIPE CUSTOMER
// ─────────────────────────────────────────────
async function createStripeCustomer(userId, email, name) {
  const customer = await stripe.customers.create({
    email,
    name,
    metadata: { wtm_user_id: userId },
  });
  return customer.id;
}

// ─────────────────────────────────────────────
// SETUP INTENT — for saving a payment method
// The client uses the clientSecret with Stripe.js.
// The raw card never hits WTM servers.
// ─────────────────────────────────────────────
async function createSetupIntent(stripeCustomerId) {
  const intent = await stripe.setupIntents.create({
    customer             : stripeCustomerId,
    payment_method_types : ['card'],
    usage                : 'off_session',
  });
  return intent.client_secret;
}

// ─────────────────────────────────────────────
// SAVE PAYMENT METHOD
// ─────────────────────────────────────────────
async function savePaymentMethod(stripeCustomerId, paymentMethodId) {
  await stripe.paymentMethods.attach(paymentMethodId, {
    customer: stripeCustomerId,
  });
  await stripe.customers.update(stripeCustomerId, {
    invoice_settings: { default_payment_method: paymentMethodId },
  });
  // Return safe metadata only — never expose raw card data
  const pm = await stripe.paymentMethods.retrieve(paymentMethodId);
  return {
    id    : pm.id,
    brand : pm.card?.brand,
    last4 : pm.card?.last4,
    expiry: pm.card?.exp_month && pm.card?.exp_year
      ? `${pm.card.exp_month}/${pm.card.exp_year}`
      : null,
  };
}

// ─────────────────────────────────────────────
// CHARGE BOOKING
// Always uses server-calculated amount.
// Idempotency key prevents double charges.
// ─────────────────────────────────────────────
async function chargeBooking({ stripeCustomerId, paymentMethodId, amountCents, bookingId, description }) {
  if (!Number.isInteger(amountCents) || amountCents < 100) {
    throw new Error('Invalid amount for charge');
  }

  const intent = await stripe.paymentIntents.create(
    {
      amount              : amountCents,
      currency            : 'usd',
      customer            : stripeCustomerId,
      payment_method      : paymentMethodId,
      confirm             : true,
      off_session         : true,
      description,
      metadata            : { wtm_booking_id: bookingId },
      capture_method      : 'automatic',
    },
    {
      // Idempotency key: same booking can only be charged once
      idempotencyKey: `charge-${bookingId}`,
    }
  );

  return {
    paymentIntentId : intent.id,
    status          : intent.status,
    amountCents     : intent.amount,
  };
}

// ─────────────────────────────────────────────
// REFUND
// ─────────────────────────────────────────────
async function refundPayment(paymentIntentId, bookingId) {
  const refund = await stripe.refunds.create(
    {
      payment_intent : paymentIntentId,
      reason         : 'requested_by_customer',
      metadata       : { wtm_booking_id: bookingId },
    },
    {
      idempotencyKey: `refund-${bookingId}`,
    }
  );
  return { refundId: refund.id, status: refund.status };
}

// ─────────────────────────────────────────────
// STRIPE WEBHOOK SIGNATURE VERIFICATION
//
// CRITICAL: Only process events that Stripe signed.
// Must use raw (un-parsed) request body.
// Register this route BEFORE express.json() middleware.
// ─────────────────────────────────────────────
function verifyWebhookSignature(rawBody, sigHeader) {
  if (!sigHeader) {
    throw Object.assign(new Error('Missing Stripe-Signature header'), { status: 400 });
  }
  // stripe.webhooks.constructEvent throws if signature is invalid
  return stripe.webhooks.constructEvent(rawBody, sigHeader, STRIPE_WEBHOOK_SECRET);
}

// ─────────────────────────────────────────────
// WEBHOOK EVENT HANDLERS
// ─────────────────────────────────────────────
async function handleWebhookEvent(event, db) {
  switch (event.type) {

    case 'payment_intent.succeeded': {
      const bookingId = event.data.object.metadata?.wtm_booking_id;
      if (bookingId) {
        await db.query(
          `UPDATE bookings SET status = 'confirmed', payment_status = 'paid',
           stripe_payment_intent_id = $2, updated_at = NOW()
           WHERE id = $1`,
          [bookingId, event.data.object.id]
        );
      }
      break;
    }

    case 'payment_intent.payment_failed': {
      const bookingId = event.data.object.metadata?.wtm_booking_id;
      if (bookingId) {
        await db.query(
          `UPDATE bookings SET status = 'payment_failed', payment_status = 'failed',
           updated_at = NOW() WHERE id = $1`,
          [bookingId]
        );
      }
      break;
    }

    case 'customer.subscription.deleted': {
      // WTM does not use subscriptions — log unexpected event
      console.warn(JSON.stringify({
        level  : 'warn',
        event  : 'unexpected_stripe_event',
        type   : event.type,
        id     : event.id,
      }));
      break;
    }

    default:
      // Ignore unrecognized events — do not throw
      break;
  }
}

// ─────────────────────────────────────────────
// DELETE STRIPE CUSTOMER (GDPR/CCPA)
// ─────────────────────────────────────────────
async function deleteStripeCustomer(stripeCustomerId) {
  if (!stripeCustomerId) return;
  try {
    await stripe.customers.del(stripeCustomerId);
  } catch (err) {
    if (err.code === 'resource_missing') return; // Already deleted
    throw err;
  }
}

module.exports = {
  calculateBookingTotal,
  createStripeCustomer,
  createSetupIntent,
  savePaymentMethod,
  chargeBooking,
  refundPayment,
  verifyWebhookSignature,
  handleWebhookEvent,
  deleteStripeCustomer,
};
