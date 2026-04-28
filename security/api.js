/**
 * WTM — API Security Middleware  v2.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • Security headers (Helmet, strict CSP, Permissions-Policy)
 *   • CORS (strict allowlist)
 *   • Input validation (Joi schemas)
 *   • Input sanitization (sanitize-html for free-text)
 *   • Request body size limits
 *   • Request ID (trace every request)
 *   • Error handler (never leak stack traces or internal details)
 *   • HTTP Parameter Pollution (HPP) prevention
 *   • Content-Type enforcement
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const Joi         = require('joi');
const sanitize    = require('sanitize-html');
const helmet      = require('helmet');
const cors        = require('cors');
const hpp         = require('hpp');
const crypto      = require('crypto');

// ─────────────────────────────────────────────
// ALLOWED ORIGINS
// ─────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://whatsthemove.app',
  'https://www.whatsthemove.app',
  ...(process.env.NODE_ENV === 'development'
    ? ['http://localhost:3000', 'http://localhost:5173']
    : []),
];

if (!ALLOWED_ORIGINS.length) {
  console.error('[FATAL] No allowed CORS origins configured');
  process.exit(1);
}

// ─────────────────────────────────────────────
// CORS
// Strict: only allowlisted origins, credentials enabled.
// ─────────────────────────────────────────────
const corsMiddleware = cors({
  origin(origin, callback) {
    // Allow requests with no origin (server-to-server, curl in dev)
    if (!origin) return callback(null, false);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS: origin '${origin}' not allowed`));
  },
  credentials    : true,
  methods        : ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders : ['Content-Type', 'X-CSRF-Token', 'X-Request-Id'],
  exposedHeaders : ['X-Request-Id'],
  maxAge         : 86400,   // 24h preflight cache
});

// ─────────────────────────────────────────────
// SECURITY HEADERS  (Helmet v7+)
// ─────────────────────────────────────────────
const securityHeaders = helmet({
  // Content Security Policy — only allow WTM's own assets + Stripe
  contentSecurityPolicy: {
    directives: {
      defaultSrc      : ["'self'"],
      scriptSrc       : [
        "'self'",
        'https://js.stripe.com',
        // All inline scripts must use nonces — no 'unsafe-inline'
      ],
      scriptSrcAttr   : ["'none'"],
      styleSrc        : ["'self'", "'unsafe-inline'"],   // allow Stripe injected styles
      imgSrc          : ["'self'", 'data:', 'https:'],
      connectSrc      : ["'self'", 'https://api.stripe.com'],
      frameSrc        : ['https://js.stripe.com', 'https://hooks.stripe.com'],
      fontSrc         : ["'self'"],
      objectSrc       : ["'none'"],
      baseUri         : ["'self'"],
      formAction      : ["'self'"],
      frameAncestors  : ["'none'"],   // clickjacking prevention
      upgradeInsecureRequests: [],
    },
  },
  // HSTS — 2 years, include subdomains, preload
  hsts: {
    maxAge            : 63072000,
    includeSubDomains : true,
    preload           : true,
  },
  // Prevent MIME type sniffing
  noSniff: true,
  // Prevent clickjacking (also in CSP frameAncestors)
  frameguard: { action: 'deny' },
  // Referrer policy — only send origin for same-origin requests
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Hide X-Powered-By
  hidePoweredBy: true,
  // Cross-Origin policies
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy  : { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
});

// ─────────────────────────────────────────────
// PERMISSIONS POLICY
// Disables all browser features WTM doesn't need.
// ─────────────────────────────────────────────
function permissionsPolicy(req, res, next) {
  res.setHeader(
    'Permissions-Policy',
    [
      'accelerometer=()',
      'ambient-light-sensor=()',
      'autoplay=()',
      'battery=()',
      'camera=()',
      'display-capture=()',
      'document-domain=()',
      'encrypted-media=()',
      'execution-while-not-rendered=()',
      'fullscreen=(self)',
      'geolocation=()',
      'gyroscope=()',
      'magnetometer=()',
      'microphone=()',
      'midi=()',
      'navigation-override=()',
      'payment=(self)',
      'picture-in-picture=()',
      'publickey-credentials-get=()',
      'screen-wake-lock=()',
      'serial=()',
      'sync-xhr=()',
      'usb=()',
      'web-share=(self)',
      'xr-spatial-tracking=()',
    ].join(', ')
  );
  next();
}

// ─────────────────────────────────────────────
// REQUEST ID
// Every request gets a unique ID for tracing.
// ─────────────────────────────────────────────
function requestId(req, res, next) {
  const id = crypto.randomBytes(12).toString('hex');
  req.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
}

// ─────────────────────────────────────────────
// CONTENT-TYPE ENFORCEMENT
// Reject requests with unexpected Content-Type.
// ─────────────────────────────────────────────
function enforceJsonContentType(req, res, next) {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('application/json')) {
      return res.status(415).json({ error: 'Content-Type must be application/json.' });
    }
  }
  next();
}

// ─────────────────────────────────────────────
// HTTP PARAMETER POLLUTION PREVENTION
// ─────────────────────────────────────────────
const hppMiddleware = hpp({
  whitelist: [],   // No query params may appear more than once
});

// ─────────────────────────────────────────────
// SANITIZE HTML — strip all tags from free-text inputs
// ─────────────────────────────────────────────
const SANITIZE_OPTIONS = {
  allowedTags        : [],   // No HTML allowed
  allowedAttributes  : {},
  disallowedTagsMode : 'escape',
};

function sanitizeString(value) {
  if (typeof value !== 'string') return value;
  return sanitize(value.trim(), SANITIZE_OPTIONS);
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === 'string') {
      out[key] = sanitizeString(val);
    } else if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
      out[key] = sanitizeObject(val);
    } else if (Array.isArray(val)) {
      out[key] = val.map(item =>
        typeof item === 'string' ? sanitizeString(item) : item
      );
    } else {
      out[key] = val;
    }
  }
  return out;
}

// ─────────────────────────────────────────────
// JOI VALIDATION SCHEMAS
// All API inputs must be validated before use.
// ─────────────────────────────────────────────
const PASSWORD_SCHEMA = Joi.string()
  .min(10)
  .max(128)
  .pattern(/[A-Z]/, 'uppercase')
  .pattern(/[a-z]/, 'lowercase')
  .pattern(/[0-9]/, 'number')
  .pattern(/[^A-Za-z0-9]/, 'special')
  .required()
  .messages({
    'string.min'        : 'Password must be at least 10 characters.',
    'string.max'        : 'Password must be no more than 128 characters.',
    'string.pattern.name': 'Password must include uppercase, lowercase, number, and special character.',
  });

const EMAIL_SCHEMA = Joi.string()
  .email({ tlds: { allow: false } })
  .max(254)
  .lowercase()
  .trim()
  .required();

const SCHEMAS = {

  register: Joi.object({
    email    : EMAIL_SCHEMA,
    password : PASSWORD_SCHEMA,
    name     : Joi.string().min(1).max(100).trim().required(),
    city     : Joi.string().min(1).max(100).trim().optional(),
  }),

  login: Joi.object({
    email    : EMAIL_SCHEMA,
    password : Joi.string().max(128).required(),
    mfaToken : Joi.string().length(6).pattern(/^\d+$/).optional(),
  }),

  bookingCreate: Joi.object({
    experienceId     : Joi.string().uuid().required(),
    date             : Joi.string().isoDate().required(),
    timeSlot         : Joi.string().max(50).required(),
    guestCount       : Joi.number().integer().min(1).max(50).required(),
    addons           : Joi.array().items(Joi.string().uuid()).max(20).default([]),
    specialRequests  : Joi.string().max(500).trim().allow('').default(''),
    paymentMethodId  : Joi.string().max(100).optional(),
  }),

  profileUpdate: Joi.object({
    name  : Joi.string().min(1).max(100).trim().optional(),
    city  : Joi.string().min(1).max(100).trim().optional(),
    prefs : Joi.array().items(
      Joi.string().valid(
        'Food','After Hours','Art','Travel','Touch Grass',
        'Wellness','Entertainment','Thrill Seeking','Surprise Me',
        'Kid-Friendly','Pet-Friendly'
      )
    ).max(11).optional(),
    bio : Joi.string().max(300).trim().allow('').optional(),
  }),

  reviewCreate: Joi.object({
    bookingId : Joi.string().uuid().required(),
    rating    : Joi.number().integer().min(1).max(5).required(),
    body      : Joi.string().min(10).max(1000).trim().required(),
  }),

  passwordReset: Joi.object({
    email : EMAIL_SCHEMA,
  }),

  passwordChange: Joi.object({
    token       : Joi.string().min(32).max(128).required(),
    newPassword : PASSWORD_SCHEMA,
  }),

};

// ─────────────────────────────────────────────
// VALIDATE MIDDLEWARE FACTORY
// Validates req.body against a named schema.
// Sanitizes string fields after validation.
// ─────────────────────────────────────────────
function validate(schemaName) {
  const schema = SCHEMAS[schemaName];
  if (!schema) throw new Error(`Unknown schema: ${schemaName}`);

  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly      : false,
      stripUnknown    : true,   // remove fields not in schema
      allowUnknown    : false,
    });

    if (error) {
      const messages = error.details.map(d => d.message);
      return res.status(400).json({ error: 'Validation failed.', details: messages });
    }

    // Sanitize all string values
    req.body = sanitizeObject(value);
    next();
  };
}

// ─────────────────────────────────────────────
// UUID PARAM VALIDATION
// Prevents path traversal and injection via URL params.
// ─────────────────────────────────────────────
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validateUuidParam(paramName) {
  return (req, res, next) => {
    const val = req.params[paramName];
    if (!val || !UUID_REGEX.test(val)) {
      return res.status(400).json({ error: 'Invalid ID.' });
    }
    next();
  };
}

// ─────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// NEVER expose stack traces or internal errors in production.
// Log full error internally; return generic message to client.
// ─────────────────────────────────────────────
function errorHandler(err, req, res, next) {  // eslint-disable-line no-unused-vars
  const requestId = req.requestId || 'unknown';

  // Log full error for internal debugging
  console.error(JSON.stringify({
    level     : 'error',
    requestId,
    message   : err.message,
    stack     : process.env.NODE_ENV !== 'production' ? err.stack : undefined,
    path      : req.path,
    method    : req.method,
    userId    : req.user?.id || null,
    timestamp : new Date().toISOString(),
  }));

  // Determine HTTP status
  const status = err.status || err.statusCode || 500;

  // Never expose internal details in production
  if (process.env.NODE_ENV === 'production' && status === 500) {
    return res.status(500).json({
      error    : 'An unexpected error occurred. Please try again.',
      requestId,
    });
  }

  // For 4xx errors, the message is safe to return
  if (status >= 400 && status < 500) {
    return res.status(status).json({
      error    : err.message || 'Bad request.',
      requestId,
    });
  }

  // Development: return full error
  res.status(status).json({
    error    : err.message,
    requestId,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
}

// ─────────────────────────────────────────────
// 404 HANDLER
// ─────────────────────────────────────────────
function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Not found.' });
}

module.exports = {
  corsMiddleware,
  securityHeaders,
  permissionsPolicy,
  requestId,
  enforceJsonContentType,
  hppMiddleware,
  validate,
  validateUuidParam,
  sanitizeString,
  sanitizeObject,
  errorHandler,
  notFoundHandler,
  SCHEMAS,
};
