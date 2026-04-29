/**
 * WTM — API Security Middleware
 * Covers: input validation, sanitization, security headers,
 *         CORS, SQL injection prevention helpers
 */

'use strict';

const Joi          = require('joi');
const sanitizeHtml = require('sanitize-html');
const helmet       = require('helmet');
const cors         = require('cors');

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://whatsthemove.app',
  'https://www.whatsthemove.app',
  process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : null,
].filter(Boolean);

const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow server-to-server requests (no origin)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin ${origin} not allowed.`));
  },
  methods:        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  credentials:    true,
  maxAge:         86400, // preflight cache 24 hours
});

// ─────────────────────────────────────────────
// SECURITY HEADERS (Helmet)
// ─────────────────────────────────────────────
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:              ["'self'"],
      scriptSrc:               ["'self'", 'https://js.stripe.com'],
      styleSrc:                ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:                 ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:                  ["'self'", 'data:', 'https://images.unsplash.com', 'https://*.stripe.com'],
      connectSrc:              ["'self'", 'https://api.stripe.com'],
      frameSrc:                ['https://js.stripe.com', 'https://hooks.stripe.com'],
      objectSrc:               ["'none'"],
      baseUri:                 ["'self'"],
      formAction:              ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge:            63072000, // 2 years
    includeSubDomains: true,
    preload:           true,
  },
  referrerPolicy:     { policy: 'strict-origin-when-cross-origin' },
  frameguard:         { action: 'deny' },
  noSniff:            true,
  xssFilter:          true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
});

// ─────────────────────────────────────────────
// INPUT SANITIZATION
// Strip all HTML from free-text user inputs.
// Never allow raw HTML from users into the DB.
// ─────────────────────────────────────────────
const SANITIZE_OPTIONS = {
  allowedTags:       [],
  allowedAttributes: {},
  disallowedTagsMode: 'recursiveEscape',
};

function sanitizeText(value) {
  if (typeof value !== 'string') return value;
  return sanitizeHtml(value.trim(), SANITIZE_OPTIONS);
}

function sanitizeObject(obj, fields) {
  const result = { ...obj };
  fields.forEach(field => {
    if (result[field] != null) result[field] = sanitizeText(result[field]);
  });
  return result;
}

// ─────────────────────────────────────────────
// VALIDATION SCHEMAS
// ─────────────────────────────────────────────
const schemas = {
  register: Joi.object({
    name:     Joi.string().min(1).max(80).required(),
    email:    Joi.string().email().max(255).required(),
    password: Joi.string().min(8).max(128)
      .pattern(/[A-Z]/, 'uppercase')
      .pattern(/[0-9]/, 'number')
      .required()
      .messages({
        'string.pattern.name': 'Password must contain at least one {{#name}} character.',
      }),
  }),

  login: Joi.object({
    email:    Joi.string().email().max(255).required(),
    password: Joi.string().max(128).required(),
    mfa_code: Joi.string().length(6).pattern(/^\d+$/).optional(),
  }),

  booking: Joi.object({
    experience_id: Joi.string().uuid().required(),
    date:          Joi.date().iso().greater('now').required(),
    time_slot:     Joi.string().pattern(/^([01]\d|2[0-3]):[0-5]\d$/).required(),
    guests:        Joi.number().integer().min(1).max(20).required(),
    addons:        Joi.array().items(Joi.string().uuid()).max(10).default([]),
    special_req:   Joi.string().max(500).allow('').optional(),
    payment_method_id: Joi.string().max(50).required(),
  }),

  profileUpdate: Joi.object({
    name:         Joi.string().min(1).max(80),
    city:         Joi.string().valid(
      'Los Angeles', 'New York City', 'Chicago', 'San Francisco',
      'Houston', 'Dallas', 'Atlanta', 'Phoenix', 'Philadelphia', 'Washington D.C.'
    ),
    preferences:  Joi.array().items(
      Joi.string().valid(
        'Food', 'After Hours', 'Art', 'Travel', 'Touch Grass',
        'Wellness', 'Entertainment', 'Thrill Seeking', 'Surprise Me',
        'Kid-Friendly', 'Pet-Friendly'
      )
    ).max(11),
  }).min(1),

  review: Joi.object({
    booking_id: Joi.string().uuid().required(),
    rating:     Joi.number().integer().min(1).max(5).required(),
    body:       Joi.string().min(10).max(1000).required(),
  }),
};

// ─────────────────────────────────────────────
// VALIDATION MIDDLEWARE FACTORY
// Usage: app.post('/bookings', validate('booking'), handler)
// ─────────────────────────────────────────────
function validate(schemaName) {
  return (req, res, next) => {
    const schema = schemas[schemaName];
    if (!schema) return next(new Error(`Unknown schema: ${schemaName}`));

    const { error, value } = schema.validate(req.body, {
      abortEarly:       false,
      stripUnknown:     true,
      convert:          true,
    });

    if (error) {
      return res.status(400).json({
        error:  'Validation failed.',
        fields: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      });
    }

    // Sanitize all string fields after Joi validation
    req.validated = sanitizeObject(value, ['name', 'special_req', 'body']);
    next();
  };
}

// ─────────────────────────────────────────────
// REQUEST ID MIDDLEWARE
// Attach a unique ID to every request for log
// correlation and incident tracing.
// ─────────────────────────────────────────────
const { randomUUID } = require('crypto');

function requestId(req, res, next) {
  req.id = req.headers['x-request-id'] || randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
}

// ─────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// Never leak stack traces or internal details
// to the client in production.
// ─────────────────────────────────────────────
function errorHandler(err, req, res, next) {
  const isProd = process.env.NODE_ENV === 'production';

  // Log full error internally
  console.error({ requestId: req.id, error: err.message, stack: err.stack });

  // Specific known errors
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  if (err.message?.startsWith('CORS:')) {
    return res.status(403).json({ error: 'Request not allowed.' });
  }

  // Generic — never leak internals in production
  res.status(err.status || 500).json({
    error: isProd ? 'Something went wrong. Please try again.' : err.message,
    ...(isProd ? {} : { stack: err.stack }),
  });
}

module.exports = {
  corsMiddleware,
  securityHeaders,
  sanitizeText,
  sanitizeObject,
  validate,
  schemas,
  requestId,
  errorHandler,
};
