-- ═══════════════════════════════════════════════════════════
-- WTM — Production Database Schema
-- PostgreSQL 15+
-- Run as superuser during initial setup only.
-- ═══════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────
-- EXTENSIONS
-- ─────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- query monitoring

-- ─────────────────────────────────────────────
-- APP USER (least privilege)
-- ─────────────────────────────────────────────
CREATE USER wtm_app WITH PASSWORD '*** set via secrets manager ***';
GRANT CONNECT ON DATABASE wtm_production TO wtm_app;
GRANT USAGE ON SCHEMA public TO wtm_app;

-- ─────────────────────────────────────────────
-- TABLES
-- ─────────────────────────────────────────────
CREATE TABLE users (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name                TEXT        NOT NULL,
  email               TEXT        UNIQUE,            -- nullable after deletion
  email_hmac          TEXT        UNIQUE,            -- HMAC for fast lookup, nullable after deletion
  password_hash       TEXT,                          -- nullable (SSO users have no password)
  stripe_customer_id  TEXT        UNIQUE,
  mfa_secret          TEXT,                          -- encrypted at app layer
  mfa_enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
  city                TEXT,
  preferences         JSONB       NOT NULL DEFAULT '[]',
  role                TEXT        NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ,
  deleted_at          TIMESTAMPTZ                    -- soft delete
);

CREATE TABLE experiences (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  title               TEXT        NOT NULL,
  category            TEXT        NOT NULL,
  description         TEXT        NOT NULL,
  host_name           TEXT        NOT NULL,
  host_bio            TEXT,
  host_avatar_url     TEXT,
  hero_image_url      TEXT,
  base_price_cents    INTEGER     NOT NULL CHECK (base_price_cents > 0),
  duration_minutes    INTEGER,
  max_guests          INTEGER     NOT NULL DEFAULT 8,
  city                TEXT        NOT NULL,
  verified            BOOLEAN     NOT NULL DEFAULT FALSE,
  verified_type       TEXT,                          -- 'chef', 'captain', 'guide', 'host', 'venue'
  active              BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ
);

CREATE TABLE addons (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  experience_id       UUID        REFERENCES experiences(id) ON DELETE CASCADE,
  name                TEXT        NOT NULL,
  description         TEXT,
  price_cents         INTEGER     NOT NULL CHECK (price_cents > 0),
  active              BOOLEAN     NOT NULL DEFAULT TRUE
);

CREATE TABLE bookings (
  id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  booking_code                TEXT        NOT NULL UNIQUE,
  user_id                     UUID        REFERENCES users(id),
  experience_id               UUID        NOT NULL REFERENCES experiences(id),
  date                        DATE        NOT NULL,
  time_slot                   TIME        NOT NULL,
  guests                      INTEGER     NOT NULL CHECK (guests > 0),
  addons                      JSONB       NOT NULL DEFAULT '[]',
  special_req                 TEXT,
  amount_cents                INTEGER     NOT NULL CHECK (amount_cents > 0),
  stripe_payment_intent_id    TEXT        UNIQUE,
  status                      TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','confirmed','cancelled','completed','refunded')),
  reviewed_at                 TIMESTAMPTZ,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confirmed_at                TIMESTAMPTZ,
  cancelled_at                TIMESTAMPTZ
);

CREATE TABLE payment_methods (
  id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stripe_payment_method_id    TEXT        NOT NULL UNIQUE,
  brand                       TEXT        NOT NULL,
  last4                       TEXT        NOT NULL,
  exp_month                   INTEGER     NOT NULL,
  exp_year                    INTEGER     NOT NULL,
  is_default                  BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE reviews (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
  booking_id      UUID        NOT NULL UNIQUE REFERENCES bookings(id),
  experience_id   UUID        NOT NULL REFERENCES experiences(id),
  rating          INTEGER     NOT NULL CHECK (rating BETWEEN 1 AND 5),
  body            TEXT        NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE wishlist (
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  experience_id   UUID        NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
  saved_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, experience_id)
);

CREATE TABLE password_resets (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash      TEXT        NOT NULL UNIQUE, -- SHA-256 of raw token
  expires_at      TIMESTAMPTZ NOT NULL,
  used_at         TIMESTAMPTZ
);

-- ─────────────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────────────
CREATE INDEX idx_users_email_hmac        ON users(email_hmac) WHERE deleted_at IS NULL;
CREATE INDEX idx_bookings_user_id        ON bookings(user_id);
CREATE INDEX idx_bookings_experience_id  ON bookings(experience_id);
CREATE INDEX idx_bookings_date           ON bookings(date);
CREATE INDEX idx_experiences_city_cat    ON experiences(city, category) WHERE active = TRUE AND verified = TRUE;
CREATE INDEX idx_reviews_experience_id   ON reviews(experience_id);
CREATE INDEX idx_wishlist_user_id        ON wishlist(user_id);

-- ─────────────────────────────────────────────
-- ROW-LEVEL SECURITY
-- Users can only access their own data.
-- Even if the app layer has a bug, the DB
-- enforces isolation at the row level.
-- ─────────────────────────────────────────────
ALTER TABLE bookings        ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE wishlist        ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews         ENABLE ROW LEVEL SECURITY;

-- Bookings: users see only their own
CREATE POLICY user_own_bookings ON bookings
  FOR ALL
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

-- Payment methods: users see only their own
CREATE POLICY user_own_payments ON payment_methods
  FOR ALL
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

-- Wishlist: users see only their own
CREATE POLICY user_own_wishlist ON wishlist
  FOR ALL
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

-- Reviews: users can only update/delete their own; all can read
CREATE POLICY user_own_reviews_write ON reviews
  FOR ALL
  USING (user_id = current_setting('app.current_user_id', true)::uuid);

CREATE POLICY reviews_public_read ON reviews
  FOR SELECT
  USING (true);

-- ─────────────────────────────────────────────
-- GRANT PERMISSIONS TO APP USER
-- Read + write on tables (no DROP, no TRUNCATE)
-- ─────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE ON
  users, experiences, addons, bookings, payment_methods,
  reviews, wishlist, password_resets
TO wtm_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO wtm_app;

-- Explicitly deny destructive operations
REVOKE DELETE ON users        FROM wtm_app; -- soft-delete only
REVOKE DELETE ON bookings     FROM wtm_app; -- status change only
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM wtm_app;
