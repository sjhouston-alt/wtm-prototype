/**
 * WTM — Security Monitoring & Logging
 * Covers: security event logging, suspicious activity detection,
 *         automated alerts, audit trail
 *
 * RULE: Never log passwords, full card numbers, CVVs,
 *       raw tokens, or SSNs. Log the action, not the secret.
 */

'use strict';

const winston = require('winston');
const crypto  = require('crypto');

// ─────────────────────────────────────────────
// SECURITY LOGGER
// JSON format for SIEM ingestion.
// Ship to Datadog / Splunk / CloudWatch in prod.
// ─────────────────────────────────────────────
const securityLogger = winston.createLogger({
  level:  'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/security.log',   level: 'info'  }),
    new winston.transports.File({ filename: 'logs/security-error.log', level: 'error' }),
    ...(process.env.NODE_ENV !== 'production'
      ? [new winston.transports.Console({ format: winston.format.simple() })]
      : []),
  ],
});

// ─────────────────────────────────────────────
// SECURITY EVENT TYPES
// ─────────────────────────────────────────────
const EVENTS = {
  LOGIN_SUCCESS:          'login_success',
  LOGIN_FAILURE:          'login_failure',
  LOGIN_BLOCKED:          'login_blocked',
  LOGOUT:                 'logout',
  REGISTER:               'register',
  PASSWORD_CHANGE:        'password_change',
  PASSWORD_RESET_REQUEST: 'password_reset_request',
  PASSWORD_RESET_USED:    'password_reset_used',
  MFA_ENABLED:            'mfa_enabled',
  MFA_DISABLED:           'mfa_disabled',
  MFA_FAILURE:            'mfa_failure',
  ACCOUNT_DELETED:        'account_deleted',
  PAYMENT_SUCCESS:        'payment_success',
  PAYMENT_FAILURE:        'payment_failure',
  PAYMENT_METHOD_ADDED:   'payment_method_added',
  PAYMENT_METHOD_REMOVED: 'payment_method_removed',
  REFUND_ISSUED:          'refund_issued',
  SUSPICIOUS_ACTIVITY:    'suspicious_activity',
  ADMIN_ACTION:           'admin_action',
  TOKEN_REFRESHED:        'token_refreshed',
  NEW_DEVICE_LOGIN:       'new_device_login',
  DATA_EXPORT_REQUEST:    'data_export_request',
  DATA_DELETION_REQUEST:  'data_deletion_request',
};

// ─────────────────────────────────────────────
// LOG SECURITY EVENT
// ─────────────────────────────────────────────
function logEvent(type, userId, meta = {}) {
  // Scrub any accidentally included sensitive fields
  const FORBIDDEN_KEYS = ['password', 'token', 'secret', 'cvv', 'card_number', 'ssn'];
  const safeMeta = Object.fromEntries(
    Object.entries(meta).filter(([k]) => !FORBIDDEN_KEYS.some(f => k.toLowerCase().includes(f)))
  );

  securityLogger.info({
    event:     type,
    userId:    userId ?? 'anonymous',
    timestamp: new Date().toISOString(),
    ...safeMeta,
  });
}

// ─────────────────────────────────────────────
// REQUEST LOGGER MIDDLEWARE
// Logs all API requests for audit trail.
// Excludes health check endpoints.
// ─────────────────────────────────────────────
function auditLog(req, res, next) {
  const SKIP = ['/health', '/favicon.ico'];
  if (SKIP.includes(req.path)) return next();

  const start = Date.now();
  res.on('finish', () => {
    securityLogger.info({
      event:      'api_request',
      method:     req.method,
      path:       req.path,
      status:     res.statusCode,
      duration_ms: Date.now() - start,
      ip:         req.ip,
      requestId:  req.id,
      userId:     req.user?.sub ?? 'anonymous',
      userAgent:  req.headers['user-agent']?.substring(0, 120) ?? '',
    });
  });
  next();
}

// ─────────────────────────────────────────────
// DEVICE FINGERPRINT
// Lightweight hash of User-Agent + Accept headers.
// Used to detect logins from new devices.
// Not a replacement for proper device tracking.
// ─────────────────────────────────────────────
function deviceFingerprint(req) {
  const raw = [
    req.headers['user-agent'] ?? '',
    req.headers['accept-language'] ?? '',
    req.headers['accept-encoding'] ?? '',
  ].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
}

// ─────────────────────────────────────────────
// SUSPICIOUS ACTIVITY DETECTION
// Call after login success to check for anomalies.
// ─────────────────────────────────────────────
async function checkSuspiciousLogin(redisClient, userId, req) {
  const fingerprint    = deviceFingerprint(req);
  const knownKey       = `known_devices:${userId}`;
  const knownDevices   = await redisClient.sMembers(knownKey);
  const isNewDevice    = !knownDevices.includes(fingerprint);

  if (isNewDevice) {
    // Register this device
    await redisClient.sAdd(knownKey, fingerprint);
    await redisClient.expire(knownKey, 365 * 24 * 60 * 60); // 1 year

    logEvent(EVENTS.NEW_DEVICE_LOGIN, userId, {
      fingerprint,
      ip:        req.ip,
      userAgent: req.headers['user-agent']?.substring(0, 80),
    });

    return { newDevice: true, fingerprint };
  }

  return { newDevice: false, fingerprint };
}

// ─────────────────────────────────────────────
// ALERT THRESHOLDS
// These checks run on a cron job (every 5 min).
// In production, alerts route to PagerDuty / Slack.
// ─────────────────────────────────────────────
async function runAlertChecks(redisClient, pool) {
  const alerts = [];

  // 1. High payment failure rate in last 5 minutes
  const recentFailures = await redisClient.get('payment_failures:5m') ?? '0';
  const recentSuccess  = await redisClient.get('payment_success:5m')  ?? '0';
  const total          = parseInt(recentFailures) + parseInt(recentSuccess);
  if (total > 10) {
    const failureRate = parseInt(recentFailures) / total;
    if (failureRate > 0.05) {
      alerts.push({ level: 'critical', type: 'high_payment_failure_rate', rate: failureRate });
    }
  }

  // 2. Accounts locked in last hour
  const lockedAccounts = await redisClient.keys('lockout:*');
  if (lockedAccounts.length > 20) {
    alerts.push({ level: 'warning', type: 'mass_lockout', count: lockedAccounts.length });
  }

  // Log all alerts
  alerts.forEach(alert => {
    securityLogger.error({ event: 'automated_alert', ...alert, timestamp: new Date().toISOString() });
    // TODO: route to PagerDuty / Slack webhook in production
  });

  return alerts;
}

// ─────────────────────────────────────────────
// TRACK PAYMENT METRICS (for alert checks)
// Call after each payment attempt.
// ─────────────────────────────────────────────
async function trackPaymentResult(redisClient, success) {
  const key = success ? 'payment_success:5m' : 'payment_failures:5m';
  await redisClient.incr(key);
  await redisClient.expire(key, 5 * 60); // reset every 5 minutes
}

module.exports = {
  EVENTS,
  logEvent,
  auditLog,
  deviceFingerprint,
  checkSuspiciousLogin,
  runAlertChecks,
  trackPaymentResult,
};
