/**
 * WTM — PII Data Minimization & Purge Policy  v1.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • PII inventory — what we collect, why, for how long
 *   • Automated purge schedules (GDPR/CCPA compliance)
 *   • Data access audit trail
 *   • Right-to-deletion flow
 *   • PII field encryption in transit and at rest
 *   • Pseudonymization of analytics data
 * ─────────────────────────────────────────────────────────────────────────────
 * PRINCIPLE: Collect the minimum data needed. Purge on schedule. Never log PII.
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const crypto = require('crypto');
const { logEvent, EVENTS } = require('./monitoring');

// ─────────────────────────────────────────────
// PII INVENTORY
// Documents every PII field, why we need it, and retention period.
// ─────────────────────────────────────────────
const PII_INVENTORY = {
  // users table
  email: {
    purpose   : 'Account login, booking confirmations, transactional emails',
    retention : 'Until account deletion + 30 days',
    encrypted : true,   // stored as HMAC + encrypted value
    canDelete : true,
  },
  name: {
    purpose   : 'Host introductions, booking confirmations',
    retention : 'Until account deletion',
    encrypted : false,
    canDelete : true,
  },
  city: {
    purpose   : 'Experience recommendations, location filtering',
    retention : 'Until account deletion',
    encrypted : false,
    canDelete : true,
  },
  stripe_customer_id: {
    purpose   : 'Payment processing via Stripe (we never store card data)',
    retention : 'Until account deletion + 7 years (financial records)',
    encrypted : false,  // not PII per se, but treated sensitively
    canDelete : false,  // must retain for financial audit trail
  },
  mfa_secret: {
    purpose   : 'Two-factor authentication',
    retention : 'Until MFA disabled or account deletion',
    encrypted : true,
    canDelete : true,
  },

  // bookings table
  special_requests: {
    purpose   : 'Communicate dietary/accessibility needs to hosts',
    retention : '90 days after experience date',
    encrypted : true,
    canDelete : true,
    autoPurge : { days: 90, field: 'experience_date' },
  },
  guest_count: {
    purpose   : 'Booking logistics and pricing',
    retention : '7 years (financial records)',
    encrypted : false,
    canDelete : false,
  },

  // reviews table
  review_body: {
    purpose   : 'Public review on experience listing',
    retention : 'Until user deletion request or experience removal',
    encrypted : false,  // public content
    canDelete : true,
  },

  // logs (NEVER stored)
  passwords      : { stored: false, note: 'Never logged, never stored in plaintext' },
  payment_details: { stored: false, note: 'Handled entirely by Stripe, never touches our servers' },
  card_numbers   : { stored: false, note: 'PCI DSS — never stored, never transmitted to our API' },
  auth_tokens    : { stored: false, note: 'Never logged — only in httpOnly cookies' },
};

// ─────────────────────────────────────────────
// PURGE SCHEDULE
// Run these as cron jobs. Recommended: daily at 3 AM UTC.
// ─────────────────────────────────────────────
const PURGE_SCHEDULE = [

  {
    name       : 'purge_special_requests',
    description: 'Remove special_requests from bookings older than 90 days',
    sql        : `
      UPDATE bookings
      SET    special_requests = NULL
      WHERE  special_requests IS NOT NULL
        AND  experience_date < NOW() - INTERVAL '90 days'
    `,
    schedule   : '0 3 * * *',  // daily 3 AM UTC
  },

  {
    name       : 'purge_inactive_accounts',
    description: 'Anonymize accounts with no activity in 3 years',
    sql        : `
      UPDATE users
      SET    email_hmac      = NULL,
             email_encrypted = NULL,
             name            = 'Deleted User',
             city            = NULL,
             mfa_secret      = NULL,
             active          = false,
             deleted_at      = NOW()
      WHERE  active    = true
        AND  last_seen < NOW() - INTERVAL '3 years'
        AND  deleted_at IS NULL
    `,
    schedule   : '0 3 * * 0',  // weekly, Sunday 3 AM UTC
  },

  {
    name       : 'purge_reset_tokens',
    description: 'Delete expired password reset tokens',
    sql        : `
      DELETE FROM password_reset_tokens
      WHERE  expires_at < NOW()
    `,
    schedule   : '0 */6 * * *',  // every 6 hours
  },

  {
    name       : 'purge_old_audit_logs',
    description: 'Remove audit log entries older than 2 years',
    sql        : `
      DELETE FROM audit_log
      WHERE  created_at < NOW() - INTERVAL '2 years'
        AND  event_type NOT IN ('payment_success', 'refund_issued', 'booking_created')
    `,
    // Retain financial events indefinitely for audit trail
    schedule   : '0 4 1 * *',   // monthly, 1st at 4 AM UTC
  },

];

// ─────────────────────────────────────────────
// RIGHT TO DELETION HANDLER
// Implements GDPR/CCPA right to erasure.
// Deletes PII but preserves anonymized financial records.
// ─────────────────────────────────────────────
async function executeRightToDeletion(pool, userId, requestedBy) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Anonymize user record (keep ID for FK integrity)
    await client.query(
      `UPDATE users SET
         email_hmac       = NULL,
         email_encrypted  = NULL,
         name             = 'Deleted User',
         city             = NULL,
         mfa_secret       = NULL,
         stripe_customer_id = NULL,
         prefs            = '[]',
         active           = false,
         deleted_at       = NOW()
       WHERE id = $1`,
      [userId]
    );

    // 2. Remove reviews (user's public content)
    await client.query(`DELETE FROM reviews WHERE user_id = $1`, [userId]);

    // 3. Anonymize bookings (keep for financial audit, remove PII)
    await client.query(
      `UPDATE bookings SET special_requests = NULL WHERE user_id = $1`,
      [userId]
    );

    // 4. Delete favorites and saved items
    await client.query(`DELETE FROM user_favorites WHERE user_id = $1`, [userId]);
    await client.query(`DELETE FROM user_plans WHERE user_id = $1`, [userId]);

    // 5. Revoke all sessions (Redis)
    // Caller must also call redis.del(`sessions:${userId}`)

    // 6. Log the deletion for audit trail
    await client.query(
      `INSERT INTO audit_log (user_id, event_type, metadata, created_at)
       VALUES ($1, 'user_deleted', $2, NOW())`,
      [userId, JSON.stringify({ requested_by: requestedBy, method: 'right_to_deletion' })]
    );

    await client.query('COMMIT');

    logEvent(EVENTS.USER_DELETED, userId, {
      method      : 'right_to_deletion',
      requested_by: requestedBy,
    });

    return { success: true };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────
// LOG SANITIZATION HELPER
// Strip PII fields before any logging call.
// ─────────────────────────────────────────────
const PII_LOG_FIELDS = new Set([
  'password', 'password_hash', 'newPassword', 'confirmPassword',
  'token', 'accessToken', 'refreshToken', 'csrfToken', 'mfaToken',
  'mfa_secret', 'resetToken',
  'cardNumber', 'cvv', 'card_number', 'cvc',
  'email', 'phone', 'ssn', 'dob', 'date_of_birth',
  'stripe_customer_id', 'paymentMethodId',
  'special_requests', 'dietary_restrictions',
  'ip', 'x-forwarded-for',
]);

function sanitizeForLogging(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 5) return obj;
  const out = {};
  for (const [key, val] of Object.entries(obj)) {
    if (PII_LOG_FIELDS.has(key.toLowerCase())) {
      out[key] = '[REDACTED]';
    } else if (typeof val === 'object' && val !== null) {
      out[key] = sanitizeForLogging(val, depth + 1);
    } else {
      out[key] = val;
    }
  }
  return out;
}

// ─────────────────────────────────────────────
// PSEUDONYMIZE FOR ANALYTICS
// Returns a consistent but non-reversible ID for analytics.
// Use this instead of user.id in any analytics events.
// ─────────────────────────────────────────────
function pseudonymizeId(userId) {
  return crypto
    .createHmac('sha256', process.env.ANALYTICS_SALT || 'wtm-analytics-salt-change-in-prod')
    .update(String(userId))
    .digest('hex')
    .substring(0, 16);
}

module.exports = {
  PII_INVENTORY,
  PURGE_SCHEDULE,
  executeRightToDeletion,
  sanitizeForLogging,
  pseudonymizeId,
};
