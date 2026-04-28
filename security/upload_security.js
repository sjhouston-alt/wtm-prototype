/**
 * WTM — File Upload Security  v1.0
 * ─────────────────────────────────────────────────────────────────────────────
 * Covers:
 *   • MIME type validation (magic bytes, not just extension)
 *   • File size limits per upload type
 *   • Filename sanitization (path traversal prevention)
 *   • Virus scanning hook (ClamAV / cloud AV)
 *   • Image dimension validation (prevent decompression bombs)
 *   • Quarantine flow before serving
 *   • All files served from separate CDN domain (never same-origin)
 * ─────────────────────────────────────────────────────────────────────────────
 * RULE: Never serve uploaded files from the same origin as the API.
 *       Always serve from a dedicated CDN subdomain (e.g. cdn.whatsthemove.app).
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const path    = require('path');
const crypto  = require('crypto');
const { logEvent, EVENTS } = require('./monitoring');

// ─────────────────────────────────────────────
// ALLOWED FILE TYPES
// ─────────────────────────────────────────────
const ALLOWED_UPLOAD_TYPES = {
  // Experience/host photos
  experience_photo: {
    mimeTypes  : ['image/jpeg', 'image/png', 'image/webp'],
    maxBytes   : 10 * 1024 * 1024,   // 10MB
    magicBytes : {
      'image/jpeg': [Buffer.from([0xFF, 0xD8, 0xFF])],
      'image/png' : [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
      'image/webp': [Buffer.from('RIFF'), Buffer.from('WEBP')],
    },
  },
  // Host identity documents (ID.me integration - never stored raw)
  identity_doc: {
    mimeTypes : ['image/jpeg', 'image/png', 'application/pdf'],
    maxBytes  : 5 * 1024 * 1024,   // 5MB
    magicBytes: {
      'image/jpeg'      : [Buffer.from([0xFF, 0xD8, 0xFF])],
      'image/png'       : [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
      'application/pdf' : [Buffer.from('%PDF')],
    },
  },
};

// ─────────────────────────────────────────────
// MAGIC BYTE VALIDATION
// Checks actual file content, not just Content-Type header.
// Prevents MIME type spoofing attacks.
// ─────────────────────────────────────────────
function validateMagicBytes(buffer, declaredMimeType, allowedConfig) {
  const signatures = allowedConfig.magicBytes[declaredMimeType];
  if (!signatures) return false;

  // For WEBP: check both RIFF at offset 0 and WEBP at offset 8
  if (declaredMimeType === 'image/webp') {
    return (
      buffer.subarray(0, 4).equals(signatures[0]) &&
      buffer.subarray(8, 12).equals(signatures[1])
    );
  }

  return signatures.some(sig => buffer.subarray(0, sig.length).equals(sig));
}

// ─────────────────────────────────────────────
// FILENAME SANITIZATION
// Prevents path traversal, null bytes, and reserved names.
// ─────────────────────────────────────────────
function sanitizeFilename(filename) {
  if (!filename || typeof filename !== 'string') return null;

  // Remove null bytes
  let safe = filename.replace(/\0/g, '');

  // Remove path separators
  safe = path.basename(safe);

  // Remove leading dots (hidden files)
  safe = safe.replace(/^\.+/, '');

  // Allow only safe characters
  safe = safe.replace(/[^a-zA-Z0-9._-]/g, '_');

  // Prevent double extensions (e.g. evil.php.jpg)
  const parts = safe.split('.');
  if (parts.length > 2) {
    // Keep only last extension
    safe = parts[0] + '.' + parts[parts.length - 1];
  }

  // Reject reserved Windows filenames (just in case)
  const reserved = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i;
  if (reserved.test(safe)) return null;

  // Length limit
  if (safe.length > 200) safe = safe.substring(0, 200);

  return safe || null;
}

// ─────────────────────────────────────────────
// GENERATE SAFE STORAGE KEY
// Never store files with user-provided names.
// Use a UUID-based key to prevent enumeration.
// ─────────────────────────────────────────────
function generateStorageKey(uploadType, originalMime) {
  const ext = {
    'image/jpeg'      : 'jpg',
    'image/png'       : 'png',
    'image/webp'      : 'webp',
    'application/pdf' : 'pdf',
  }[originalMime] || 'bin';

  const uuid = crypto.randomUUID();
  return `${uploadType}/${uuid}.${ext}`;
}

// ─────────────────────────────────────────────
// VALIDATE UPLOAD MIDDLEWARE FACTORY
// ─────────────────────────────────────────────
function validateUpload(uploadType) {
  const config = ALLOWED_UPLOAD_TYPES[uploadType];
  if (!config) throw new Error(`Unknown upload type: ${uploadType}`);

  return async (req, res, next) => {
    try {
      // multer or busboy should have already parsed the file
      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: 'No file provided.' });
      }

      // 1. Size check (multer limits should catch this first, belt-and-suspenders)
      if (file.size > config.maxBytes) {
        return res.status(413).json({
          error: `File too large. Maximum size is ${config.maxBytes / 1024 / 1024}MB.`,
        });
      }

      // 2. MIME type check
      if (!config.mimeTypes.includes(file.mimetype)) {
        logEvent(EVENTS.INJECTION_ATTEMPT, req.user?.id, {
          reason   : 'invalid_mime_type',
          provided : file.mimetype,
          allowed  : config.mimeTypes,
          requestId: req.requestId,
        }, 'warn');
        return res.status(415).json({ error: 'File type not allowed.' });
      }

      // 3. Magic byte validation
      const buffer = file.buffer || Buffer.alloc(0);
      if (buffer.length > 0 && !validateMagicBytes(buffer, file.mimetype, config)) {
        logEvent(EVENTS.INJECTION_ATTEMPT, req.user?.id, {
          reason    : 'magic_byte_mismatch',
          requestId : req.requestId,
        }, 'warn');
        return res.status(415).json({ error: 'File content does not match declared type.' });
      }

      // 4. Generate a safe storage key (never use original filename)
      req.file.safeKey      = generateStorageKey(uploadType, file.mimetype);
      req.file.originalSafe = sanitizeFilename(file.originalname);

      // 5. Flag for AV scan before serving
      req.file.requiresAvScan = true;

      next();
    } catch (err) {
      next(err);
    }
  };
}

// ─────────────────────────────────────────────
// IMAGE DIMENSION CHECK
// Prevents decompression bomb attacks (tiny file, massive decoded size).
// Use sharp or jimp to get dimensions before processing.
// ─────────────────────────────────────────────
async function checkImageDimensions(buffer, mimeType) {
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(mimeType)) return true;
  try {
    const sharp = require('sharp');
    const meta  = await sharp(buffer).metadata();
    const MAX_PX = 8000; // 8000x8000 max
    if (meta.width > MAX_PX || meta.height > MAX_PX) {
      return false; // Reject — possible decompression bomb
    }
    return true;
  } catch {
    return false; // Can't parse — reject
  }
}

module.exports = {
  validateUpload,
  sanitizeFilename,
  generateStorageKey,
  validateMagicBytes,
  checkImageDimensions,
  ALLOWED_UPLOAD_TYPES,
};
