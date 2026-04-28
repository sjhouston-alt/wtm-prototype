/**
 * WTM — Database Security  v2.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • Parameterized queries ONLY — never string interpolation
 *   • PostgreSQL Row-Level Security (RLS) context injection
 *   • Connection pool with TLS
 *   • GDPR/CCPA right-to-deletion (hard delete + Stripe customer removal)
 *   • Soft delete for bookings (anonymize, preserve financial audit trail)
 *   • Input validation before every query
 *   • Minimum-privilege query helpers
 * ─────────────────────────────────────────────────────────────────────────────
 * RULE: This file MUST be the only place that touches the DB.
 *       All queries are parameterized. No exceptions.
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const { Pool }      = require('pg');
const crypto        = require('crypto');
const { hmacField, encrypt, decrypt } = require('./encryption');
const { deleteStripeCustomer }        = require('./payments');

// ─────────────────────────────────────────────
// CONNECTION POOL
// Uses TLS to DB, min/max pool sizes, statement timeout.
// ─────────────────────────────────────────────
let pool;

function getPool() {
  if (pool) return pool;

  if (!process.env.DATABASE_URL) {
    console.error('[FATAL] DATABASE_URL must be set');
    process.exit(1);
  }

  pool = new Pool({
    connectionString : process.env.DATABASE_URL,
    max              : 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    ssl: process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: true }     // verify DB cert in production
      : false,
    statement_timeout: 10000,            // kill queries running >10s
  });

  pool.on('error', (err) => {
    console.error(JSON.stringify({
      level  : 'error',
      event  : 'pg_pool_error',
      message: err.message,
    }));
  });

  return pool;
}

// ─────────────────────────────────────────────
// RLS CONTEXT HELPER
// Sets app.current_user_id on the PG session so
// Row-Level Security policies can enforce isolation.
// Call this at the start of every authenticated request.
// ─────────────────────────────────────────────
async function withRlsContext(client, userId) {
  // Parameterized — prevents injection via userId
  await client.query(
    `SELECT set_config('app.current_user_id', $1::text, true)`,
    [userId]
  );
}

// ─────────────────────────────────────────────
// TRANSACTION HELPER
// Ensures RLS context is set for every transaction.
// ─────────────────────────────────────────────
async function withTransaction(userId, fn) {
  const db = getPool();
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    if (userId) await withRlsContext(client, userId);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
// USER QUERIES
// ─────────────────────────────────────────────

// Lookup by HMAC — never query by plaintext email
async function getUserByEmailHmac(emailHmac) {
  const db = getPool();
  const result = await db.query(
    `SELECT id, email_encrypted, password_hash, mfa_secret_encrypted,
            mfa_enabled, role, active, stripe_customer_id
     FROM users
     WHERE email_hmac = $1 AND active = true
     LIMIT 1`,
    [emailHmac]
  );
  if (!result.rows.length) return null;
  const row = result.rows[0];
  return {
    ...row,
    email: row.email_encrypted ? decrypt(row.email_encrypted) : null,
    mfa_secret: row.mfa_secret_encrypted ? decrypt(row.mfa_secret_encrypted) : null,
  };
}

async function getUserById(userId) {
  const db = getPool();
  const result = await db.query(
    `SELECT id, email_encrypted, name, city, preferences, avatar_url,
            mfa_enabled, role, active, stripe_customer_id, created_at
     FROM users
     WHERE id = $1 AND active = true
     LIMIT 1`,
    [userId]
  );
  if (!result.rows.length) return null;
  const row = result.rows[0];
  return {
    ...row,
    email: row.email_encrypted ? decrypt(row.email_encrypted) : null,
  };
}

async function createUser({ email, passwordHash, name, city }) {
  return withTransaction(null, async (client) => {
    // Check for existing user (by HMAC, not plaintext)
    const emailHmac    = hmacField(email);
    const emailEnc     = encrypt(email.toLowerCase().trim());

    const existing = await client.query(
      `SELECT id FROM users WHERE email_hmac = $1 LIMIT 1`,
      [emailHmac]
    );
    if (existing.rows.length) {
      throw Object.assign(new Error('An account with this email already exists.'), { status: 409 });
    }

    const result = await client.query(
      `INSERT INTO users (email_encrypted, email_hmac, password_hash, name, city, role, active)
       VALUES ($1, $2, $3, $4, $5, 'user', true)
       RETURNING id, name, city, created_at`,
      [emailEnc, emailHmac, passwordHash, name, city || null]
    );
    return result.rows[0];
  });
}

async function updateUserProfile(userId, { name, city, preferences }) {
  return withTransaction(userId, async (client) => {
    const result = await client.query(
      `UPDATE users SET
         name        = COALESCE($2, name),
         city        = COALESCE($3, city),
         preferences = COALESCE($4, preferences),
         updated_at  = NOW()
       WHERE id = $1 AND active = true
       RETURNING id, name, city, preferences`,
      [userId, name || null, city || null, preferences ? JSON.stringify(preferences) : null]
    );
    if (!result.rows.length) throw Object.assign(new Error('User not found.'), { status: 404 });
    return result.rows[0];
  });
}

// ─────────────────────────────────────────────
// PASSWORD RESET
// ─────────────────────────────────────────────
async function storeResetToken(userId, tokenHash, expiresAt) {
  const db = getPool();
  // Invalidate any existing tokens
  await db.query(
    `UPDATE password_resets SET used = true WHERE user_id = $1`,
    [userId]
  );
  await db.query(
    `INSERT INTO password_resets (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, tokenHash, expiresAt]
  );
}

async function consumeResetToken(tokenHash) {
  const db = getPool();
  const result = await db.query(
    `UPDATE password_resets
     SET used = true, used_at = NOW()
     WHERE token_hash = $1 AND used = false AND expires_at > NOW()
     RETURNING user_id`,
    [tokenHash]
  );
  return result.rows[0]?.user_id || null;
}

async function updatePasswordHash(userId, newHash) {
  const db = getPool();
  await db.query(
    `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`,
    [userId, newHash]
  );
}

// ─────────────────────────────────────────────
// BOOKING QUERIES
// ─────────────────────────────────────────────
async function createBooking({ userId, experienceId, date, timeSlot, guestCount, addonIds, specialRequests, bookingCode }) {
  return withTransaction(userId, async (client) => {
    const result = await client.query(
      `INSERT INTO bookings
         (user_id, experience_id, date, time_slot, guest_count, addon_ids,
          special_requests, booking_code, status, payment_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 'pending')
       RETURNING id, booking_code, status, created_at`,
      [
        userId,
        experienceId,
        date,
        timeSlot,
        guestCount,
        JSON.stringify(addonIds || []),
        specialRequests || null,
        bookingCode,
      ]
    );
    return result.rows[0];
  });
}

async function confirmBooking(bookingId, paymentIntentId, amountCents) {
  const db = getPool();
  const result = await db.query(
    `UPDATE bookings
     SET status = 'confirmed', payment_status = 'paid',
         stripe_payment_intent_id = $2, amount_charged_cents = $3,
         confirmed_at = NOW(), updated_at = NOW()
     WHERE id = $1
     RETURNING id, status`,
    [bookingId, paymentIntentId, amountCents]
  );
  return result.rows[0];
}

async function getUserBookings(userId) {
  return withTransaction(userId, async (client) => {
    const result = await client.query(
      `SELECT b.id, b.booking_code, b.date, b.time_slot, b.guest_count,
              b.status, b.payment_status, b.amount_charged_cents,
              b.created_at, b.confirmed_at,
              e.title, e.cover_image_url, e.location_name
       FROM bookings b
       JOIN experiences e ON e.id = b.experience_id
       WHERE b.user_id = $1
       ORDER BY b.date DESC`,
      [userId]
    );
    return result.rows;
  });
}

// ─────────────────────────────────────────────
// REVIEW QUERIES
// ─────────────────────────────────────────────
async function createReview({ userId, bookingId, experienceId, rating, body }) {
  return withTransaction(userId, async (client) => {
    // Verify user owns this booking
    const booking = await client.query(
      `SELECT id FROM bookings
       WHERE id = $1 AND user_id = $2 AND status = 'confirmed'
       LIMIT 1`,
      [bookingId, userId]
    );
    if (!booking.rows.length) {
      throw Object.assign(
        new Error('You can only review experiences you have completed.'),
        { status: 403 }
      );
    }

    // One review per booking
    const existing = await client.query(
      `SELECT id FROM reviews WHERE booking_id = $1 LIMIT 1`,
      [bookingId]
    );
    if (existing.rows.length) {
      throw Object.assign(new Error('You have already reviewed this booking.'), { status: 409 });
    }

    const result = await client.query(
      `INSERT INTO reviews (user_id, booking_id, experience_id, rating, body)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, rating, created_at`,
      [userId, bookingId, experienceId, rating, body]
    );

    // Update experience average rating
    await client.query(
      `UPDATE experiences
       SET avg_rating = (
         SELECT ROUND(AVG(rating)::numeric, 1) FROM reviews WHERE experience_id = $1
       ), review_count = (
         SELECT COUNT(*) FROM reviews WHERE experience_id = $1
       ), updated_at = NOW()
       WHERE id = $1`,
      [experienceId]
    );

    return result.rows[0];
  });
}

// ─────────────────────────────────────────────
// GDPR / CCPA RIGHT-TO-DELETION
// Hard-deletes user PII; anonymizes booking records
// to preserve financial audit trail.
// ─────────────────────────────────────────────
async function deleteUserAccount(userId, stripeCustomerId) {
  return withTransaction(userId, async (client) => {
    // 1. Anonymize bookings (keep financial record, remove PII)
    await client.query(
      `UPDATE bookings
       SET user_id = NULL, special_requests = '[deleted]', updated_at = NOW()
       WHERE user_id = $1`,
      [userId]
    );

    // 2. Delete reviews (user's own content)
    await client.query(
      `DELETE FROM reviews WHERE user_id = $1`,
      [userId]
    );

    // 3. Delete wishlist
    await client.query(
      `DELETE FROM wishlist WHERE user_id = $1`,
      [userId]
    );

    // 4. Delete saved payment methods from DB
    await client.query(
      `DELETE FROM payment_methods WHERE user_id = $1`,
      [userId]
    );

    // 5. Delete password resets
    await client.query(
      `DELETE FROM password_resets WHERE user_id = $1`,
      [userId]
    );

    // 6. Hard-delete user record
    await client.query(
      `DELETE FROM users WHERE id = $1`,
      [userId]
    );
  });

  // 7. Delete Stripe customer (outside transaction — can't roll back Stripe calls)
  if (stripeCustomerId) {
    await deleteStripeCustomer(stripeCustomerId);
  }
}

// ─────────────────────────────────────────────
// MFA SECRET STORAGE
// ─────────────────────────────────────────────
async function storeMfaSecret(userId, secretBase32) {
  const db = getPool();
  await db.query(
    `UPDATE users
     SET mfa_secret_encrypted = $2, mfa_enabled = false, updated_at = NOW()
     WHERE id = $1`,
    [userId, encrypt(secretBase32)]
  );
}

async function enableMfa(userId) {
  const db = getPool();
  await db.query(
    `UPDATE users SET mfa_enabled = true, updated_at = NOW() WHERE id = $1`,
    [userId]
  );
}

// ─────────────────────────────────────────────
// STRIPE CUSTOMER ID STORAGE
// ─────────────────────────────────────────────
async function saveStripeCustomerId(userId, stripeCustomerId) {
  const db = getPool();
  await db.query(
    `UPDATE users SET stripe_customer_id = $2, updated_at = NOW() WHERE id = $1`,
    [userId, stripeCustomerId]
  );
}

module.exports = {
  getPool,
  withTransaction,
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
};
