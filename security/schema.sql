-- ═══════════════════════════════════════════════════════════════
-- WTM — Production Database Schema  v2.1
-- PostgreSQL 15+
-- Security fixes in v2.1:
--   • Hardcoded DB password removed — provisioned via secrets manager
--   • RLS NULL bypass removed — policies now fail closed
--   • Category enum corrected to match app (dining/offshore/arts/adventure/wellness/outside/kids)
--   • Missing indexes added (booking status, payment status, date+status, city+category, reviews, wishlist, reset expiry)
-- ═══════════════════════════════════════════════════════════════
-- Run this as a superuser (e.g., postgres).
-- The app connects as 'wtm_app' (least-privilege user).
-- wtm_app password is provisioned via secrets manager at deploy time.
-- NEVER hardcode credentials in this file.
-- ═══════════════════════════════════════════════════════════════


-- ─────────────────────────────────────────────
-- EXTENSIONS
-- ─────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ─────────────────────────────────────────────
-- APP USER (least-privilege)
-- Password is NOT set here. It is provisioned by your
-- infrastructure tool (Terraform / Pulumi / AWS Secrets Manager)
-- before this schema runs. If the role already exists, this is a no-op.
-- Only SELECT/INSERT/UPDATE on necessary tables.
-- No DROP, TRUNCATE, or schema changes.
-- ─────────────────────────────────────────────
DO $$
BEGIN
IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wtm_app') THEN
-- Role created without LOGIN or PASSWORD here.
-- Grant LOGIN + set password via your secrets provisioner:
--   ALTER ROLE wtm_app WITH LOGIN PASSWORD '<from_secrets_manager>';
CREATE ROLE wtm_app;
    RAISE NOTICE 'Role wtm_app created. Set password via secrets manager before connecting.';
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
-- FIX v2.1: category enum updated to match app categories.
-- Old values (water, travel, nightlife) caused booking 500s on valid app categories.
CREATE TABLE IF NOT EXISTS experiences (
  id                    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  host_user_id          UUID         REFERENCES users(id) ON DELETE SET NULL,
  title                 TEXT         NOT NULL,
description           TEXT,
  category              TEXT         NOT NULL CHECK (category IN ('dining','offshore','arts','adventure','wellness','outside','kids')),
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
-- FIX v2.1: compound city+category index for Explore feed queries
CREATE INDEX IF NOT EXISTS idx_exp_city_category
ON experiences(city, category) WHERE active = true AND experience_verified = true;


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
-- FIX v2.1: status indexes for admin dashboard and payment reconciliation queries
CREATE INDEX IF NOT EXISTS idx_bookings_status
ON bookings(status) WHERE status IN ('pending','confirmed');
CREATE INDEX IF NOT EXISTS idx_bookings_payment_status
ON bookings(payment_status) WHERE payment_status = 'pending';
-- Compound date+status for upcoming bookings feed
CREATE INDEX IF NOT EXISTS idx_bookings_date_status
ON bookings(date, status) WHERE status = 'confirmed';
-- Compound user+status for My Plans queries
CREATE INDEX IF NOT EXISTS idx_bookings_user_status
ON bookings(user_id, status) WHERE user_id IS NOT NULL;


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
-- FIX v2.1: compound index for experience detail page (reviews sorted by date)
CREATE INDEX IF NOT EXISTS idx_reviews_exp_created
ON reviews(experience_id, created_at DESC);


-- WISHLIST
CREATE TABLE IF NOT EXISTS wishlist (
  id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  experience_id   UUID         NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
UNIQUE(user_id, experience_id)
);


CREATE INDEX IF NOT EXISTS idx_wishlist_user ON wishlist(user_id);
-- FIX v2.1: compound index for heart icon state check on every card render
CREATE INDEX IF NOT EXISTS idx_wishlist_user_exp
ON wishlist(user_id, experience_id);


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
-- FIX v2.1: expiry index for cleanup jobs and token validation
CREATE INDEX IF NOT EXISTS idx_password_resets_expires
ON password_resets(expires_at) WHERE used = false;


-- ─────────────────────────────────────────────
-- ROW-LEVEL SECURITY
-- Enforces data isolation at the database layer.
-- Even if the application has a bug, users cannot
-- see or modify other users' data.
--
-- FIX v2.1: NULL bypass removed from all policies.
-- Policies now fail CLOSED. If app.current_user_id is not set,
-- the query returns zero rows instead of all rows.
-- database.js withTransaction() always sets this before any query.
-- ─────────────────────────────────────────────
ALTER TABLE bookings        ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE wishlist        ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews         ENABLE ROW LEVEL SECURITY;


-- Force RLS even for table owners (superuser bypass must be explicit)
ALTER TABLE bookings        FORCE ROW LEVEL SECURITY;
ALTER TABLE payment_methods FORCE ROW LEVEL SECURITY;
ALTER TABLE wishlist        FORCE ROW LEVEL SECURITY;


-- Bookings: users see/modify only their own.
-- FIX v2.1: removed "OR ... IS NULL" clause that allowed full table reads
-- when app.current_user_id was not set on the session.
DROP POLICY IF EXISTS user_own_bookings ON bookings;
CREATE POLICY user_own_bookings ON bookings
FOR ALL
TO wtm_app
USING (user_id::text = current_setting('app.current_user_id', true));


-- Payment methods: users see/modify only their own
DROP POLICY IF EXISTS user_own_payment_methods ON payment_methods;
CREATE POLICY user_own_payment_methods ON payment_methods
FOR ALL
TO wtm_app
USING (user_id::text = current_setting('app.current_user_id', true));


-- Wishlist: users see/modify only their own
DROP POLICY IF EXISTS user_own_wishlist ON wishlist;
CREATE POLICY user_own_wishlist ON wishlist
FOR ALL
TO wtm_app
USING (user_id::text = current_setting('app.current_user_id', true));


-- Reviews: all can read, users can only modify their own
DROP POLICY IF EXISTS reviews_public_read ON reviews;
CREATE POLICY reviews_public_read ON reviews
FOR SELECT TO wtm_app
USING (true);


DROP POLICY IF EXISTS reviews_own_write ON reviews;
CREATE POLICY reviews_own_write ON reviews
FOR INSERT TO wtm_app
WITH CHECK (user_id::text = current_setting('app.current_user_id', true));


DROP POLICY IF EXISTS reviews_own_delete ON reviews;
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
-- PARTIAL INDEX ON ACTIVE RECORDS
-- ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_active_id
ON users(id) WHERE active = true;