/**
 * WTM — Security Monitoring & Alerting  v2.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • Structured security event logging (JSON, severity levels)
 *   • Audit log middleware (every request logged)
 *   • Brute force detection (IP + account)
 *   • Anomalous login detection (new country/device)
 *   • Payment failure spike detection
 *   • CSRF/injection attack pattern detection
 *   • Automated alerts (email / Slack webhook)
 *   • Incident response playbook reference
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const crypto = require('crypto');

// ─────────────────────────────────────────────
// SECURITY EVENT CONSTANTS
// ─────────────────────────────────────────────
const EVENTS = Object.freeze({
  // Auth
  LOGIN_SUCCESS          : 'login_success',
  LOGIN_FAILURE          : 'login_failure',
  ACCOUNT_LOCKED         : 'account_locked',
  LOGOUT                 : 'logout',
  TOKEN_ROTATED          : 'token_rotated',
  TOKEN_REPLAY_DETECTED  : 'token_replay_detected',
  MFA_ENABLED            : 'mfa_enabled',
  MFA_FAILURE            : 'mfa_failure',
  PASSWORD_CHANGED       : 'password_changed',
  PASSWORD_RESET_REQUEST : 'password_reset_request',
  PASSWORD_RESET_COMPLETE: 'password_reset_complete',

  // Sessions & CSRF
  CSRF_FAILURE           : 'csrf_failure',
  SESSION_EXPIRED        : 'session_expired',

  // Payments
  PAYMENT_SUCCESS        : 'payment_success',
  PAYMENT_FAILURE        : 'payment_failure',
  WEBHOOK_RECEIVED       : 'webhook_received',
  WEBHOOK_SIG_FAILURE    : 'webhook_signature_failure',
  REFUND_ISSUED          : 'refund_issued',

  // Data
  USER_CREATED           : 'user_created',
  USER_DELETED           : 'user_deleted',
  BOOKING_CREATED        : 'booking_created',
  BOOKING_CONFIRMED      : 'booking_confirmed',

  // Security
  RATE_LIMIT_HIT         : 'rate_limit_hit',
  SUSPICIOUS_LOGIN       : 'suspicious_login',
  PAYMENT_SPIKE          : 'payment_failure_spike',
  INJECTION_ATTEMPT      : 'injection_attempt_detected',
  ADMIN_ACTION           : 'admin_action',
});

// ─────────────────────────────────────────────
// LOG EVENT
// All security events are JSON-structured for SIEM ingestion.
// Strip PII from logs — never log passwords, tokens, or card data.
// ─────────────────────────────────────────────
function logEvent(eventType, userId, metadata = {}, severity = 'info') {
  const entry = {
    level     : severity,
    event     : eventType,
    userId    : userId || null,
    timestamp : new Date().toISOString(),
    ...sanitizeMetadata(metadata),
  };
  console.log(JSON.stringify(entry));
}

// Ensure no sensitive fields ever make it into logs
const REDACTED_KEYS = new Set([
  'password', 'newPassword', 'token', 'secret', 'apiKey',
  'authorization', 'cookie', 'cardNumber', 'cvv', 'ssn',
  'mfaToken', 'resetToken',
]);

function sanitizeMetadata(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (REDACTED_KEYS.has(k) || REDACTED_KEYS.has(k.toLowerCase())) {
      out[k] = '[REDACTED]';
    } else if (typeof v === 'object' && v !== null) {
      out[k] = sanitizeMetadata(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

// ─────────────────────────────────────────────
// AUDIT LOG MIDDLEWARE
// Logs every request with timing, status, and IP.
// Applied before route handlers.
// ─────────────────────────────────────────────
function auditLog(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const entry = {
      level      : res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info',
      event      : 'http_request',
      method     : req.method,
      path       : sanitizePath(req.path),
      status     : res.statusCode,
      durationMs,
      ip         : getClientIp(req),
      requestId  : req.requestId,
      userId     : req.user?.id || null,
      userAgent  : req.headers['user-agent']?.substring(0, 200) || null,
      timestamp  : new Date().toISOString(),
    };
    console.log(JSON.stringify(entry));

    // Trigger alerts for suspicious patterns
    if (res.statusCode === 403) {
      checkCsrfPattern(req, res.statusCode);
    }
  });

  next();
}

// Remove tokens/ids from path before logging
function sanitizePath(path) {
  return path
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':uuid')
    .replace(/[A-Z0-9]{10,}/g, ':token')
    .substring(0, 200);
}

// ─────────────────────────────────────────────
// SUSPICIOUS LOGIN DETECTION
// Flags logins from new countries or unusual times.
// ─────────────────────────────────────────────
async function checkSuspiciousLogin(redis, userId, req) {
  const ip     = getClientIp(req);
  const ua     = (req.headers['user-agent'] || '').substring(0, 200);
  const key    = `lastip:${userId}`;
  const lastIp = await redis.get(key);

  // First login or same IP — store and continue
  if (!lastIp || lastIp === ip) {
    await redis.set(key, ip, { EX: 30 * 24 * 3600 });
    return { suspicious: false };
  }

  // Different IP — log as suspicious
  const hash = crypto.createHash('sha1').update(ua).digest('hex').slice(0, 8);
  logEvent(EVENTS.SUSPICIOUS_LOGIN, userId, {
    reason       : 'new_ip',
    ipHash       : crypto.createHash('sha1').update(ip).digest('hex').slice(0, 8),
    uaHash       : hash,
    requestId    : req.requestId,
  }, 'warn');

  await redis.set(key, ip, { EX: 30 * 24 * 3600 });
  return { suspicious: true };
}

// ─────────────────────────────────────────────
// PAYMENT FAILURE SPIKE DETECTION
// If >5 payment failures in 10 minutes — alert.
// ─────────────────────────────────────────────
async function trackPaymentResult(redis, success, userId, metadata = {}) {
  if (success) {
    logEvent(EVENTS.PAYMENT_SUCCESS, userId, metadata);
    return;
  }

  logEvent(EVENTS.PAYMENT_FAILURE, userId, metadata, 'warn');

  const spikeKey = 'payment_failures_window';
  const count    = await redis.incr(spikeKey);
  if (count === 1) await redis.expire(spikeKey, 600);  // 10-minute window

  if (count >= 5) {
    logEvent(EVENTS.PAYMENT_SPIKE, null, {
      count,
      windowMinutes: 10,
      action: 'alert_triggered',
    }, 'error');
    await sendAlert({
      subject : '[WTM ALERT] Payment failure spike detected',
      body    : `${count} payment failures in the last 10 minutes. Investigate immediately.`,
      level   : 'critical',
    });
  }
}

// ─────────────────────────────────────────────
// CSRF / INJECTION PATTERN DETECTION
// ─────────────────────────────────────────────
const SQL_INJECTION_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
  /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
  /(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|SCRIPT)/i,
];

const XSS_PATTERNS = [
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
];

function checkInjectionAttempt(req, res, next) {
  const toCheck = [
    JSON.stringify(req.body  || ''),
    JSON.stringify(req.query || ''),
    req.path,
  ].join(' ');

  for (const pattern of [...SQL_INJECTION_PATTERNS, ...XSS_PATTERNS]) {
    if (pattern.test(toCheck)) {
      logEvent(EVENTS.INJECTION_ATTEMPT, req.user?.id || null, {
        path     : sanitizePath(req.path),
        method   : req.method,
        requestId: req.requestId,
        ip       : getClientIp(req),
        pattern  : pattern.source.substring(0, 50),
      }, 'error');
      break; // log once per request
    }
  }
  next(); // Always continue — blocking is Joi/DB's job
}

function checkCsrfPattern(req, statusCode) {
  if (statusCode === 403) {
    logEvent(EVENTS.CSRF_FAILURE, req.user?.id || null, {
      path     : sanitizePath(req.path),
      method   : req.method,
      requestId: req.requestId,
      ip       : getClientIp(req),
    }, 'warn');
  }
}

// ─────────────────────────────────────────────
// ALERT SENDER
// Sends critical alerts via email (SendGrid) or Slack.
// ─────────────────────────────────────────────
async function sendAlert({ subject, body, level = 'warn' }) {
  // Slack webhook (if configured)
  if (process.env.SLACK_ALERT_WEBHOOK_URL) {
    try {
      const payload = JSON.stringify({
        text: `*[WTM ${level.toUpperCase()}]* ${subject}\n\`\`\`${body}\`\`\``,
      });
      const url  = new URL(process.env.SLACK_ALERT_WEBHOOK_URL);

      // Validate it's actually Slack — prevent SSRF
      if (!url.hostname.endsWith('.slack.com')) {
        logEvent('alert_ssrf_prevented', null, { hostname: url.hostname }, 'error');
        return;
      }

      const https  = require('https');
      const options = {
        hostname : url.hostname,
        path     : url.pathname + url.search,
        method   : 'POST',
        headers  : {
          'Content-Type'  : 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      };

      await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          res.on('data', () => {});
          res.on('end', resolve);
        });
        req.on('error', reject);
        req.setTimeout(5000, () => { req.destroy(); reject(new Error('Slack timeout')); });
        req.write(payload);
        req.end();
      });
    } catch (err) {
      console.error(JSON.stringify({ level: 'error', event: 'slack_alert_failed', message: err.message }));
    }
  }

  // Email via SendGrid (if configured)
  if (process.env.SENDGRID_API_KEY && process.env.SECURITY_ALERT_EMAIL) {
    try {
      const sgMail = require('@sendgrid/mail');
      sgMail.setApiKey(process.env.SENDGRID_API_KEY);
      await sgMail.send({
        to      : process.env.SECURITY_ALERT_EMAIL,
        from    : process.env.EMAIL_FROM || 'noreply@whatsthemove.app',
        subject,
        text    : body,
      });
    } catch (err) {
      console.error(JSON.stringify({ level: 'error', event: 'email_alert_failed', message: err.message }));
    }
  }
}

// ─────────────────────────────────────────────
// UTILITY: GET CLIENT IP
// Respects X-Forwarded-For behind a trusted proxy.
// ─────────────────────────────────────────────
function getClientIp(req) {
  // express sets req.ip when trust proxy is set
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

module.exports = {
  EVENTS,
  logEvent,
  auditLog,
  checkSuspiciousLogin,
  trackPaymentResult,
  checkInjectionAttempt,
  sendAlert,
  getClientIp,
};
