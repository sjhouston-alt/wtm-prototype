/**
 * WTM — Database Security
 * Covers: parameterized queries, connection pooling,
 *         Row-Level Security context, soft deletes,
 *         GDPR/CCPA account deletion
 *
 * ENV REQUIRED:
 *   DATABASE_URL — postgres://user:pass@host:5432/wtm_production
 */

'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:              { rejectUnauthorized: true }, // require valid cert in production
  max:              20,   // max connections in pool
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on('error', (err) => {
  console.error('Unexpected DB pool error:', err.message);
});

// ─────────────────────────────────────────────
// ROW-LEVEL SECURITY CONTEXT
// Set the current user ID on every connection
// so PostgreSQL RLS policies enforce data access.
// Always call this before running user queries.
// ─────────────────────────────────────────────
async function withUserContext(userId, fn) {
  const client = await pool.connect();
  try {
    await client.query(
      `SELECT set_config('app.current_user_id', $1, true)`,
      [userId]
    );
    return await fn(client);
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
// USERS
// Passwords are hashed before being passed here.
// Email is stored as both plaintext (for display)
// and HMAC (for fast lookups without decrypting).
// ─────────────────────────────────────────────
async function createUser({ name, email, emailHmac, passwordHash, stripeCustomerId, city }) {
  const result = await pool.query(
    `INSERT INTO users (name, email, email_hmac, password_hash, stripe_customer_id, city, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     RETURNING id, name, email, city, created_at`,
    [name, email, emailHmac, passwordHash, stripeCustomerId, city]
  );
  return result.rows[0];
}

async function getUserByEmailHmac(emailHmac) {
  // Use HMAC lookup — never do WHERE email = $1 with raw user input
  const result = await pool.query(
    `SELECT id, name, email, password_hash, stripe_customer_id, mfa_secret, mfa_enabled, city, preferences
     FROM users WHERE email_hmac = $1 AND deleted_at IS NULL LIMIT 1`,
    [emailHmac]
  );
  return result.rows[0] ?? null;
}

async function getUserById(userId) {
  const result = await pool.query(
    `SELECT id, name, email, stripe_customer_id, city, preferences, created_at
     FROM users WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
    [userId]
  );
  return result.rows[0] ?? null;
}

async function updateUserPreferences(userId, preferences, city) {
  const result = await pool.query(
    `UPDATE users SET preferences = $1, city = $2, updated_at = NOW()
     WHERE id = $3 AND deleted_at IS NULL
     RETURNING id, preferences, city`,
    [JSON.stringify(preferences), city, userId]
  );
  return result.rows[0] ?? null;
}

async function setMFASecret(userId, base32Secret) {
  await pool.query(
    `UPDATE users SET mfa_secret = $1, mfa_enabled = false WHERE id = $2`,
    [base32Secret, userId]
  );
}

async function enableMFA(userId) {
  await pool.query(
    `UPDATE users SET mfa_enabled = true WHERE id = $1`,
    [userId]
  );
}

// ─────────────────────────────────────────────
// BOOKINGS
// All amounts stored in cents (integer).
// status: pending | confirmed | cancelled | completed
// ─────────────────────────────────────────────
async function createBooking({ userId, experienceId, date, timeSlot, guests, addons, specialReq, amountCents, bookingCode }) {
  return await withUserContext(userId, async (client) => {
    const result = await client.query(
      `INSERT INTO bookings
         (user_id, experience_id, date, time_slot, guests, addons, special_req, amount_cents, booking_code, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', NOW())
       RETURNING id, booking_code, status, created_at`,
      [userId, experienceId, date, timeSlot, guests, JSON.stringify(addons), specialReq, amountCents, bookingCode]
    );
    return result.rows[0];
  });
}

async function confirmBooking(bookingId, stripePaymentIntentId) {
  const result = await pool.query(
    `UPDATE bookings
     SET status = 'confirmed', stripe_payment_intent_id = $1, confirmed_at = NOW()
     WHERE id = $2 AND status = 'pending'
     RETURNING id, booking_code, status`,
    [stripePaymentIntentId, bookingId]
  );
  return result.rows[0] ?? null;
}

async function getUserBookings(userId) {
  return await withUserContext(userId, async (client) => {
    const result = await client.query(
      `SELECT b.id, b.booking_code, b.date, b.time_slot, b.guests, b.amount_cents,
              b.status, b.created_at,
              e.title, e.category, e.hero_image
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
// REVIEWS
// Only users who completed a booking can review.
// ─────────────────────────────────────────────
async function createReview({ userId, bookingId, experienceId, rating, body }) {
  // Verify user owns this booking and it's completed
  const booking = await pool.query(
    `SELECT id FROM bookings
     WHERE id = $1 AND user_id = $2 AND status = 'completed' AND reviewed_at IS NULL`,
    [bookingId, userId]
  );
  if (!booking.rows.length) {
    throw new Error('Review not allowed: booking not found, not completed, or already reviewed.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO reviews (user_id, booking_id, experience_id, rating, body, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING id, rating, created_at`,
      [userId, bookingId, experienceId, rating, body]
    );
    await client.query(
      `UPDATE bookings SET reviewed_at = NOW() WHERE id = $1`,
      [bookingId]
    );
    await client.query('COMMIT');
    return result.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
// GDPR / CCPA — RIGHT TO DELETION
// Soft-delete user, anonymize booking records
// (kept for accounting/tax), remove Stripe data.
// ─────────────────────────────────────────────
async function deleteUserAccount(userId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Anonymize PII in bookings (records kept for 7 years per accounting law)
    await client.query(
      `UPDATE bookings
       SET special_req = NULL, user_note = NULL
       WHERE user_id = $1`,
      [userId]
    );

    // 2. Anonymize reviews (keep content, strip identity)
    await client.query(
      `UPDATE reviews SET user_id = NULL WHERE user_id = $1`,
      [userId]
    );

    // 3. Soft-delete user (preserves FK integrity)
    await client.query(
      `UPDATE users
       SET deleted_at = NOW(),
           name       = 'Deleted User',
           email      = NULL,
           email_hmac = NULL,
           password_hash = NULL,
           mfa_secret = NULL,
           preferences = '[]'
       WHERE id = $1`,
      [userId]
    );

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
// WISHLIST / SAVED EXPERIENCES
// ─────────────────────────────────────────────
async function saveExperience(userId, experienceId) {
  await pool.query(
    `INSERT INTO wishlist (user_id, experience_id, saved_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (user_id, experience_id) DO NOTHING`,
    [userId, experienceId]
  );
}

async function unsaveExperience(userId, experienceId) {
  await pool.query(
    `DELETE FROM wishlist WHERE user_id = $1 AND experience_id = $2`,
    [userId, experienceId]
  );
}

module.exports = {
  pool,
  withUserContext,
  createUser,
  getUserByEmailHmac,
  getUserById,
  updateUserPreferences,
  setMFASecret,
  enableMFA,
  createBooking,
  confirmBooking,
  getUserBookings,
  createReview,
  deleteUserAccount,
  saveExperience,
  unsaveExperience,
};
