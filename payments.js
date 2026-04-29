/**
 * WTM — Payment Security (PCI-DSS)
 *
 * CRITICAL RULE: WTM never stores, processes, or transmits
 * raw card numbers, CVVs, or expiry dates. All payment data
 * is handled exclusively by Stripe. WTM stores only:
 *   - stripe_customer_id
 *   - stripe_payment_method_id (token reference)
 *   - last4, brand, exp_month, exp_year (display only — not sensitive)
 *
 * ENV REQUIRED:
 *   STRIPE_SECRET_KEY       — sk_live_...
 *   STRIPE_PUBLISHABLE_KEY  — pk_live_...
 *   STRIPE_WEBHOOK_SECRET   — whsec_...
 */

'use strict';

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY, {
  apiVersion:     '2024-04-10',
  maxNetworkRetries: 3,
  timeout:        10000, // 10 seconds
});

// ─────────────────────────────────────────────
// CUSTOMER MANAGEMENT
// Create a Stripe customer when user registers.
// Store stripe_customer_id in users table.
// ─────────────────────────────────────────────
async function createStripeCustomer(userId, email, name) {
  return await stripe.customers.create({
    email,
    name,
    metadata: { wtm_user_id: userId },
  });
}

async function deleteStripeCustomer(stripeCustomerId) {
  return await stripe.customers.del(stripeCustomerId);
}

// ─────────────────────────────────────────────
// SETUP INTENT
// Client uses this to collect card details in
// Stripe Elements — card data NEVER touches
// WTM servers. After confirmation, client sends
// the payment_method_id to WTM to save.
// ─────────────────────────────────────────────
async function createSetupIntent(stripeCustomerId) {
  return await stripe.setupIntents.create({
    customer:             stripeCustomerId,
    payment_method_types: ['card'],
    usage:                'off_session', // for future bookings
  });
}

async function savePaymentMethod(stripeCustomerId, paymentMethodId) {
  // Attach method to customer
  await stripe.paymentMethods.attach(paymentMethodId, {
    customer: stripeCustomerId,
  });

  // Set as default
  await stripe.customers.update(stripeCustomerId, {
    invoice_settings: { default_payment_method: paymentMethodId },
  });

  // Retrieve safe display fields only
  const pm = await stripe.paymentMethods.retrieve(paymentMethodId);
  return {
    stripe_payment_method_id: paymentMethodId,
    brand:     pm.card.brand,
    last4:     pm.card.last4,
    exp_month: pm.card.exp_month,
    exp_year:  pm.card.exp_year,
  };
}

async function removePaymentMethod(paymentMethodId) {
  return await stripe.paymentMethods.detach(paymentMethodId);
}

// ─────────────────────────────────────────────
// PAYMENT INTENT
// Charge a saved payment method for a booking.
// amountCents must be a positive integer (e.g. $195.00 = 19500)
// ─────────────────────────────────────────────
async function chargeBooking({ stripeCustomerId, paymentMethodId, amountCents, bookingId, experienceId, userId }) {
  if (!Number.isInteger(amountCents) || amountCents <= 0) {
    throw new Error('amountCents must be a positive integer.');
  }

  return await stripe.paymentIntents.create({
    amount:         amountCents,
    currency:       'usd',
    customer:       stripeCustomerId,
    payment_method: paymentMethodId,
    confirm:        true,
    off_session:    true,
    return_url:     'https://whatsthemove.app/booking/confirm',
    metadata: {
      booking_id:    bookingId,
      experience_id: experienceId,
      user_id:       userId,
    },
  });
}

// ─────────────────────────────────────────────
// REFUND
// ─────────────────────────────────────────────
async function issueRefund(paymentIntentId, amountCents = null) {
  const params = { payment_intent: paymentIntentId };
  if (amountCents != null) params.amount = amountCents; // partial refund
  return await stripe.refunds.create(params);
}

// ─────────────────────────────────────────────
// WEBHOOK VERIFICATION
// ALWAYS verify webhook signatures. Never trust
// a payload that hasn't been verified.
// Use express.raw() for this route — not json().
// ─────────────────────────────────────────────
function verifyWebhookSignature(rawBody, signature) {
  return stripe.webhooks.constructEvent(
    rawBody,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET
  );
}

// ─────────────────────────────────────────────
// WEBHOOK ROUTER
// Handles all Stripe events.
// ─────────────────────────────────────────────
async function handleWebhookEvent(event, { onSuccess, onFailure, onDispute, onRefund }) {
  switch (event.type) {
    case 'payment_intent.succeeded':
      await onSuccess(event.data.object);
      break;

    case 'payment_intent.payment_failed':
      await onFailure(event.data.object);
      break;

    case 'charge.dispute.created':
      await onDispute(event.data.object);
      break;

    case 'charge.refunded':
      await onRefund(event.data.object);
      break;

    // Log unhandled events but don't error — Stripe sends many event types
    default:
      console.info(`Stripe webhook: unhandled event type ${event.type}`);
  }
}

// ─────────────────────────────────────────────
// AMOUNT CALCULATION
// Calculate booking total server-side.
// NEVER trust the amount sent from the client.
// Always recalculate from DB prices.
// ─────────────────────────────────────────────
function calculateBookingTotal({ basePrice, guests, addonsTotal }) {
  const BASE_GUESTS     = 2;
  const EXTRA_GUEST_FEE = 75_00; // cents

  const guestFee = Math.max(0, guests - BASE_GUESTS) * EXTRA_GUEST_FEE;
  const total    = (basePrice * 100) + guestFee + (addonsTotal * 100);

  if (!Number.isInteger(total) || total <= 0) {
    throw new Error('Invalid booking total calculation.');
  }
  return total; // in cents
}

module.exports = {
  createStripeCustomer,
  deleteStripeCustomer,
  createSetupIntent,
  savePaymentMethod,
  removePaymentMethod,
  chargeBooking,
  issueRefund,
  verifyWebhookSignature,
  handleWebhookEvent,
  calculateBookingTotal,
};
