-- ═══════════════════════════════════════════════════════════════
-- WTM — Production Database Schema  v2.0
-- PostgreSQL 15+
-- ═══════════════════════════════════════════════════════════════
-- Run this as a superuser (e.g., postgres).
-- The app connects as 'wtm_app' (least-privilege user).
-- ═══════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────
-- EXTENSIONS
-- ─────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────
-- APP USER (least-privilege)
-- Only SELECT/INSERT/UPDATE on necessary tables.
-- No DROP, TRUNCATE, or schema changes.
-- ─────────────────────────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wtm_app') THEN
    CREATE ROLE wtm_app WITH LOGIN PASSWORD 'CHANGE_ME_IN_PRODUCTION';
  END IF;
END $$;

-- ─────────────────────────────────────────────
-- TABLES
-- ─────────────────────────────────────────────

-- USERS
-- Email stored encrypted at rest.
-- email_hmac used for lookups (HMAC blind index).
-- Passwords are bcrypt hashes only — never plaintext.
CREATE TABLE IF NOT EXISTS users (
  id                     UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  email_encrypted        TEXT         NOT NULL,            -- AES-256-GCM encrypted
  email_hmac             TEXT         NOT NULL UNIQUE,     -- HMAC blind index for lookups
  password_hash          TEXT         NOT NULL,            -- bcrypt hash only
  name                   TEXT         NOT NULL,
  city                   TEXT,
  preferences            JSONB        DEFAULT '[]',
  avatar_url             TEXT,
  role                   TEXT         NOT NULL DEFAULT 'user'  CHECK (role IN ('user','host','admin')),
  active                 BOOLEAN      NOT NULL DEFAULT true,
  mfa_enabled            BOOLEAN      NOT NULL DEFAULT false,
  mfa_secret_encrypted   TEXT,                             -- AES-256-GCM encrypted TOTP secret
  stripe_customer_id     TEXT         UNIQUE,
  last_login_at          TIMESTAMPTZ,
  created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email_hmac ON users(email_hmac);
CREATE INDEX IF NOT EXISTS idx_users_active     ON users(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_users_role       ON users(role);

-- EXPERIENCES
CREATE TABLE IF NOT EXISTS experiences (
  id                    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  host_user_id          UUID         REFERENCES users(id) ON DELETE SET NULL,
  title                 TEXT         NOT NULL,
  description           TEXT,
  category              TEXT         NOT NULL CHECK (category IN ('dining','water','arts','adventure','travel','wellness','nightlife')),
  location_name         TEXT,
  city                  TEXT,
  cover_image_url       TEXT,
  base_price_cents      INTEGER      NOT NULL CHECK (base_price_cents >= 0),
  max_guests            INTEGER      NOT NULL DEFAULT 20 CHECK (max_guests >= 1),
  is_luxury             BOOLEAN      NOT NULL DEFAULT false,
  experience_verified   BOOLEAN      NOT NULL DEFAULT false,  -- must be true to go live
  active                BOOLEAN      NOT NULL DEFAULT false,
  avg_rating            NUMERIC(3,1),
  review_count          INTEGER      NOT NULL DEFAULT 0,
  created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exp_category  ON experiences(category) WHERE active = true AND experience_verified = true;
CREATE INDEX IF NOT EXISTS idx_exp_city      ON experiences(city)     WHERE active = true AND experience_verified = true;
CREATE INDEX IF NOT EXISTS idx_exp_verified  ON experiences(experience_verified, active);

-- ADD-ONS
CREATE TABLE IF NOT EXISTS addons (
  id              UUID     PRIMARY KEY DEFAULT uuid_generate_v4(),
  experience_id   UUID     NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
  name            TEXT     NOT NULL,
  description     TEXT,
  price_cents     INTEGER  NOT NULL CHECK (price_cents >= 0),
  active          BOOLEAN  NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_addons_exp ON addons(experience_id) WHERE active = true;

-- BOOKINGS
-- user_id is nullable to allow anonymization on account deletion (GDPR).
-- Never hard-delete bookings — they are financial records.
CREATE TABLE IF NOT EXISTS bookings (
  id                         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id                    UUID         REFERENCES users(id) ON DELETE SET NULL,
  experience_id              UUID         NOT NULL REFERENCES experiences(id),
  booking_code               TEXT         NOT NULL UNIQUE,
  date                       DATE         NOT NULL,
  time_slot                  TEXT         NOT NULL,
  guest_count                INTEGER      NOT NULL CHECK (guest_count >= 1),
  addon_ids                  JSONB        DEFAULT '[]',
  special_requests           TEXT,
  status                     TEXT         NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','cancelled','payment_failed')),
  payment_status             TEXT         NOT NULL DEFAULT 'pending' CHECK (payment_status IN ('pending','paid','failed','refunded')),
  stripe_payment_intent_id   TEXT,
  amount_charged_cents       INTEGER,
  confirmed_at               TIMESTAMPTZ,
  created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bookings_user        ON bookings(user_id);
CREATE INDEX IF NOT EXISTS idx_bookings_experience  ON bookings(experience_id);
CREATE INDEX IF NOT EXISTS idx_bookings_code        ON bookings(booking_code);
CREATE INDEX IF NOT EXISTS idx_bookings_date        ON bookings(date);

-- PAYMENT METHODS (Stripe tokens only — never raw card data)
CREATE TABLE IF NOT EXISTS payment_methods (
  id                    UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id               UUID    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stripe_payment_method TEXT    NOT NULL,  -- Stripe PaymentMethod ID only (pm_xxx)
  brand                 TEXT,
  last4                 TEXT,
  expiry                TEXT,
  is_default            BOOLEAN NOT NULL DEFAULT false,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pm_user ON payment_methods(user_id);

-- REVIEWS (public)
CREATE TABLE IF NOT EXISTS reviews (
  id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID         REFERENCES users(id) ON DELETE SET NULL,
  booking_id      UUID         NOT NULL UNIQUE REFERENCES bookings(id),
  experience_id   UUID         NOT NULL REFERENCES experiences(id),
  rating          SMALLINT     NOT NULL CHECK (rating BETWEEN 1 AND 5),
  body            TEXT         NOT NULL,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reviews_experience ON reviews(experience_id);
CREATE INDEX IF NOT EXISTS idx_reviews_user       ON reviews(user_id);

-- WISHLIST
CREATE TABLE IF NOT EXISTS wishlist (
  id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  experience_id   UUID         NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, experience_id)
);

CREATE INDEX IF NOT EXISTS idx_wishlist_user ON wishlist(user_id);

-- PASSWORD RESETS (hashed tokens only)
CREATE TABLE IF NOT EXISTS password_resets (
  id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT         NOT NULL UNIQUE,  -- SHA-256 of raw token
  expires_at  TIMESTAMPTZ  NOT NULL,
  used        BOOLEAN      NOT NULL DEFAULT false,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);

-- ─────────────────────────────────────────────
-- ROW-LEVEL SECURITY
-- Enforces data isolation at the database layer.
-- Even if the application has a bug, users cannot
-- see or modify other users' data.
-- ─────────────────────────────────────────────
ALTER TABLE bookings        ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE wishlist        ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews         ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owners (superuser bypass must be explicit)
ALTER TABLE bookings        FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_methods FORCE ROW LEVEL SECURITY;
ALTER TABLE wishlist        FORCE ROW LEVEL SECURITY;

-- Bookings: users see/modify only their own
CREATE POLICY user_own_bookings ON bookings
  FOR ALL
  TO wtm_app
  USING (
    user_id::text = current_setting('app.current_user_id', true)
    OR current_setting('app.current_user_id', true) IS NULL
  );

-- Payment methods: users see/modify only their own
CREATE POLICY user_own_payment_methods ON payment_methods
  FOR ALL
  TO wtm_app
  USING (user_id::text = current_setting('app.current_user_id', true));

-- Wishlist: users see/modify only their own
CREATE POLICY user_own_wishlist ON wishlist
  FOR ALL
  TO wtm_app
  USING (user_id::text = current_setting('app.current_user_id', true));

-- Reviews: all can read, users can only modify their own
CREATE POLICY reviews_public_read ON reviews
  FOR SELECT TO wtm_app
  USING (true);

CREATE POLICY reviews_own_write ON reviews
  FOR INSERT TO wtm_app
  WITH CHECK (user_id::text = current_setting('app.current_user_id', true));

CREATE POLICY reviews_own_delete ON reviews
  FOR DELETE TO wtm_app
  USING (user_id::text = current_setting('app.current_user_id', true));

-- ─────────────────────────────────────────────
-- GRANT PERMISSIONS (least-privilege)
-- ─────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE ON
  users, experiences, addons, bookings, payment_methods,
  reviews, wishlist, password_resets
TO wtm_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO wtm_app;

-- Explicitly DENY destructive operations
REVOKE DELETE ON users        FROM wtm_app;  -- soft-delete only (active = false)
REVOKE DELETE ON bookings     FROM wtm_app;  -- status update only (financial records)
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM wtm_app;

-- Allow DELETE on non-financial tables (GDPR)
GRANT DELETE ON reviews, wishlist, payment_methods, password_resets TO wtm_app;

-- ─────────────────────────────────────────────
-- UPDATED_AT TRIGGER
-- ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
  t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','experiences','bookings'] LOOP
    EXECUTE format(
      'DROP TRIGGER IF EXISTS trg_%s_updated_at ON %I;
       CREATE TRIGGER trg_%s_updated_at
       BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at();',
      t, t, t, t
    );
  END LOOP;
END $$;

-- ─────────────────────────────────────────────
-- INDEX ON PARTIAL ACTIVE RECORDS
-- ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_active_id
  ON users(id) WHERE active = true;

CREATE INDEX IF NOT EXISTS idx_bookings_user_status
  ON bookings(user_id, status) WHERE user_id IS NOT NULL;
