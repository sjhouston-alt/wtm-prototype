-- ═══════════════════════════════════════════════════════════════════════════
-- WTM — Schema v3 Additions
-- Run after schema.sql v2 baseline
--
-- New in v3:
--   Tiers: rookie / regular / local (Amethyst / Emerald / Ruby)
--   Points: NEVER expire (expires_at removed from points_ledger)
--   Points credit 48-72h after experience completion
--   Cancellation policies per experience
--   Waivers: e-signed, cryptographically hashed, per guest
--   ID verification: ID.me levels 1-5 per experience requirement
--   Favorites: user_favorites table
--   Redemption caps: per-member + global quarterly limits
--   Seasonal redemption catalog: core (always) + rotating (monthly)
--   Payment methods: encrypted Stripe tokens only (PCI-DSS SAQ-A)
--   Anti-exploit: velocity monitoring, referral fraud prevention
--   Weighted QE: free=0.25, standard=1.0, premium=1.5, exclusive=2.0
--   Free-experience QE capped at 25% of annual total
-- ═══════════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────────
-- HOSTS
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hosts (
  id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id              UUID         NOT NULL REFERENCES users(id),
  business_name        TEXT         NOT NULL,
  display_name         TEXT         NOT NULL,
  bio                  TEXT,
  avatar_url           TEXT,
  city                 TEXT         NOT NULL,
  role                 TEXT         NOT NULL CHECK (role IN ('chef','captain','guide','host','curator','instructor')),

  -- Verification (gating listings)
  experience_verified  BOOLEAN      NOT NULL DEFAULT false,
  verified_at          TIMESTAMPTZ,

  -- Small business flags
  small_business       BOOLEAN      NOT NULL DEFAULT true,
  bipoc_owned          BOOLEAN      NOT NULL DEFAULT false,
  women_owned          BOOLEAN      NOT NULL DEFAULT false,
  veteran_owned        BOOLEAN      NOT NULL DEFAULT false,

  -- 1.5× points promotion for guests in first 90 days
  promotion_started_at TIMESTAMPTZ,
  in_promotion_period  BOOLEAN      GENERATED ALWAYS AS (
    promotion_started_at IS NOT NULL
    AND promotion_started_at > (NOW() - INTERVAL '90 days')
  ) STORED,

  -- Stripe Connect
  stripe_account_id    TEXT,
  subscription_tier    TEXT         DEFAULT 'free' CHECK (subscription_tier IN ('free','pro','premier')),

  active               BOOLEAN      NOT NULL DEFAULT true,
  created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS hosts_city_idx       ON hosts(city) WHERE active = true;
CREATE INDEX IF NOT EXISTS hosts_promo_idx      ON hosts(in_promotion_period) WHERE in_promotion_period = true;

-- ─────────────────────────────────────────────────────────────────────────
-- EXPERIENCES
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS experiences (
  id                      UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  slug                    TEXT         NOT NULL UNIQUE,
  host_id                 UUID         NOT NULL REFERENCES hosts(id),
  title                   TEXT         NOT NULL,
  category                TEXT         NOT NULL CHECK (category IN ('dining','offshore','arts','adventure','wellness','outside','kid-friendly')),
  city                    TEXT         NOT NULL,

  -- Pricing (transparent — no hidden fees ever)
  price_base_cents        INTEGER      NOT NULL CHECK (price_base_cents >= 0),
  price_per_guest_cents   INTEGER      NOT NULL DEFAULT 0,
  is_free                 BOOLEAN      GENERATED ALWAYS AS (price_base_cents = 0) STORED,

  -- Installments available for $500+ bookings only
  installments_eligible   BOOLEAN      GENERATED ALWAYS AS (price_base_cents >= 50000) STORED,

  -- Capacity
  duration_min            INTEGER      NOT NULL CHECK (duration_min > 0),
  min_guests              INTEGER      NOT NULL DEFAULT 1,
  max_guests              INTEGER      NOT NULL DEFAULT 10,

  -- Content
  description             TEXT         NOT NULL,
  image_url               TEXT         NOT NULL,
  gallery_urls            JSONB        NOT NULL DEFAULT '[]',
  tags                    JSONB        NOT NULL DEFAULT '[]',
  vibes                   JSONB        NOT NULL DEFAULT '[]',
  age_restriction         INTEGER,

  -- Boolean access flags
  pet_friendly            BOOLEAN      NOT NULL DEFAULT false,
  kid_friendly            BOOLEAN      NOT NULL DEFAULT false,

  -- Exclusive access (requires regular or local tier)
  exclusive               BOOLEAN      NOT NULL DEFAULT false,
  required_member_tier    TEXT         CHECK (required_member_tier IN ('regular','local')),

  -- Tier preview (lower tier can see this as teaser)
  preview_for_tier        TEXT         CHECK (preview_for_tier IN ('rookie','regular')),

  -- Points
  points_mult             NUMERIC(3,1) NOT NULL DEFAULT 1.0 CHECK (points_mult >= 1.0 AND points_mult <= 5.0),

  -- Cancellation policy key (references CANCELLATION_POLICIES constant)
  cancellation_policy     TEXT         NOT NULL DEFAULT 'flexible'
    CHECK (cancellation_policy IN ('free','flexible','standard','moderate','firm','strict','non_refundable')),

  -- Verification requirements (ID.me levels)
  verification_level      TEXT         NOT NULL DEFAULT 'none'
    CHECK (verification_level IN ('none','age_21','identity','driver','medical')),

  -- Waiver
  waiver_required         BOOLEAN      NOT NULL DEFAULT false,
  waiver_template_id      TEXT,
  waiver_type             TEXT,

  -- Status
  status                  TEXT         NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft','pending_review','live','paused','archived')),
  published_at            TIMESTAMPTZ,

  -- Cached aggregates (recomputed nightly)
  rating_avg              NUMERIC(3,2) DEFAULT 0,
  rating_count            INTEGER      DEFAULT 0,
  booking_count           INTEGER      DEFAULT 0,

  created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS exp_category_city_idx ON experiences(category, city) WHERE status='live';
CREATE INDEX IF NOT EXISTS exp_exclusive_idx     ON experiences(exclusive)      WHERE status='live' AND exclusive=true;
CREATE INDEX IF NOT EXISTS exp_free_idx          ON experiences(is_free)        WHERE status='live' AND is_free=true;
CREATE INDEX IF NOT EXISTS exp_pet_idx           ON experiences(pet_friendly)   WHERE status='live' AND pet_friendly=true;
CREATE INDEX IF NOT EXISTS exp_kid_idx           ON experiences(kid_friendly)   WHERE status='live' AND kid_friendly=true;
CREATE INDEX IF NOT EXISTS exp_waiver_idx        ON experiences(waiver_required) WHERE waiver_required=true;
CREATE INDEX IF NOT EXISTS exp_verification_idx  ON experiences(verification_level) WHERE verification_level<>'none';
CREATE INDEX IF NOT EXISTS exp_preview_idx       ON experiences(preview_for_tier) WHERE preview_for_tier IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- MEMBER PROFILES (Amethyst / Emerald / Ruby)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS member_profiles (
  user_id                    UUID         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

  -- Current tier
  tier                       TEXT         NOT NULL DEFAULT 'rookie'
    CHECK (tier IN ('rookie','regular','local')),
  tier_gem                   TEXT         GENERATED ALWAYS AS (
    CASE tier
      WHEN 'rookie'  THEN 'Amethyst'
      WHEN 'regular' THEN 'Emerald'
      WHEN 'local'   THEN 'Ruby'
    END
  ) STORED,

  -- Points — NEVER expire (expires_at not used)
  points_balance             INTEGER      NOT NULL DEFAULT 0 CHECK (points_balance >= 0),
  points_lifetime            INTEGER      NOT NULL DEFAULT 0,

  -- Annual QE (resets Dec 31)
  qualifying_experiences     NUMERIC(6,2) NOT NULL DEFAULT 0,  -- supports fractional QE
  status_year                INTEGER      NOT NULL DEFAULT EXTRACT(YEAR FROM NOW()),

  -- Tier achievement timestamps
  rookie_achieved_at         TIMESTAMPTZ  DEFAULT NOW(),
  regular_achieved_at        TIMESTAMPTZ,
  local_achieved_at          TIMESTAMPTZ,

  -- Feature flags (set by tier trigger)
  ai_concierge_enabled       BOOLEAN      NOT NULL DEFAULT false,
  human_concierge_enabled    BOOLEAN      NOT NULL DEFAULT false,
  members_only_unlocked      BOOLEAN      NOT NULL DEFAULT false,

  -- Stats (user-facing — spend is tracked separately, never shown)
  total_bookings             INTEGER      NOT NULL DEFAULT 0,
  total_experiences          INTEGER      NOT NULL DEFAULT 0,
  categories_explored        JSONB        NOT NULL DEFAULT '[]',
  member_since               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

  -- Birthday bonus
  birthday_month             INTEGER      CHECK (birthday_month BETWEEN 1 AND 12),
  birthday_day               INTEGER      CHECK (birthday_day BETWEEN 1 AND 31),

  -- Anti-fraud velocity
  points_earned_30d          INTEGER      NOT NULL DEFAULT 0,
  last_velocity_reset        DATE         DEFAULT CURRENT_DATE,

  updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Backend-only spend tracking (never surfaces in user-facing UI)
CREATE TABLE IF NOT EXISTS member_spend (
  user_id        UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  year           INTEGER      NOT NULL,
  month          INTEGER      NOT NULL CHECK (month BETWEEN 1 AND 12),
  amount_cents   INTEGER      NOT NULL DEFAULT 0,
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, year, month)
);

-- ─────────────────────────────────────────────────────────────────────────
-- POINTS LEDGER (no expiry)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS points_ledger (
  id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id             UUID         NOT NULL REFERENCES users(id),
  delta               INTEGER      NOT NULL,
  reason              TEXT         NOT NULL CHECK (reason IN (
    'booking', 'exclusive_bonus', 'small_biz_bonus', 'referral', 'review',
    'birthday_bonus', 'tier_upgrade_bonus', 'redemption', 'manual_adjustment',
    'clawback_refund', 'clawback_cancellation'
  )),
  related_booking_id  UUID,
  related_user_id     UUID,
  description         TEXT,
  multiplier          NUMERIC(3,1),
  -- Points credit 48-72h after experience completion
  available_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),  -- when points become spendable
  -- NOTE: NO expires_at column — points never expire per business rule
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS pts_user_idx      ON points_ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS pts_available_idx ON points_ledger(available_at) WHERE available_at > NOW();

-- ─────────────────────────────────────────────────────────────────────────
-- QE LEDGER (weighted qualifying experiences)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qe_ledger (
  id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id             UUID         NOT NULL REFERENCES users(id),
  booking_id          UUID,
  experience_id       UUID         REFERENCES experiences(id),
  price_cents         INTEGER      NOT NULL DEFAULT 0,
  qe_weight           NUMERIC(4,2) NOT NULL,
  is_free             BOOLEAN      NOT NULL DEFAULT false,
  status_year         INTEGER      NOT NULL,
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS qe_user_year_idx ON qe_ledger(user_id, status_year);

-- ─────────────────────────────────────────────────────────────────────────
-- FAVORITES
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_favorites (
  user_id        UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  experience_id  UUID         NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, experience_id)
);

CREATE INDEX IF NOT EXISTS fav_user_idx ON user_favorites(user_id, created_at DESC);

-- ─────────────────────────────────────────────────────────────────────────
-- CANCELLATION POLICIES (enforced at booking time)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cancellation_requests (
  id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  booking_id          UUID         NOT NULL REFERENCES bookings(id),
  user_id             UUID         NOT NULL REFERENCES users(id),
  requested_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  policy_at_request   TEXT         NOT NULL,  -- snapshot of policy at request time
  hours_before        NUMERIC      NOT NULL,  -- hours before experience start
  within_window       BOOLEAN      NOT NULL,  -- true = eligible for full refund
  refund_pct          INTEGER      NOT NULL CHECK (refund_pct BETWEEN 0 AND 100),
  refund_amount_cents INTEGER,
  refund_issued_at    TIMESTAMPTZ,
  status              TEXT         NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','processed','denied','no_show'))
);

-- ─────────────────────────────────────────────────────────────────────────
-- WAIVERS (e-signed per booking guest)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS waivers (
  id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  booking_id          UUID         NOT NULL REFERENCES bookings(id),
  signer_user_id      UUID         REFERENCES users(id),
  signer_name         TEXT         NOT NULL,
  signer_dob          DATE,
  is_minor            BOOLEAN      NOT NULL DEFAULT false,
  guardian_user_id    UUID         REFERENCES users(id),  -- required if is_minor=true

  waiver_template_id  TEXT         NOT NULL,
  waiver_type         TEXT         NOT NULL,

  -- Cryptographic proof of signing
  signature_hash      TEXT         NOT NULL,  -- SHA-256 of signed content
  signed_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  signer_ip           INET,
  signer_device_fp    TEXT,         -- device fingerprint

  -- DocuSign / HelloSign reference
  vendor              TEXT         NOT NULL DEFAULT 'hellosign',
  vendor_envelope_id  TEXT,
  vendor_signed_at    TIMESTAMPTZ,
  pdf_url_encrypted   TEXT,         -- AES-256-GCM encrypted S3 URL

  -- Annual re-sign tracking
  expires_at          TIMESTAMPTZ,  -- 1 year for annual re-sign requirement
  superseded_by       UUID         REFERENCES waivers(id)
);

CREATE INDEX IF NOT EXISTS waivers_booking_idx ON waivers(booking_id);
CREATE INDEX IF NOT EXISTS waivers_user_idx    ON waivers(signer_user_id);
CREATE INDEX IF NOT EXISTS waivers_expires_idx ON waivers(expires_at) WHERE expires_at IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- ID VERIFICATIONS (ID.me as primary vendor)
-- Images purged 24h after verification; only result + hash retained
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS id_verifications (
  id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id             UUID         NOT NULL REFERENCES users(id),

  -- Verification level (1-5)
  level               TEXT         NOT NULL CHECK (level IN ('age_21','identity','driver','medical','member_tier')),
  result              TEXT         NOT NULL CHECK (result IN ('pending','passed','failed','review','expired')),

  -- ID.me (primary) / Persona / Veriff reference
  vendor              TEXT         NOT NULL DEFAULT 'id.me',
  vendor_inquiry_id   TEXT,         -- external reference only (no raw data stored here)
  vendor_verified_at  TIMESTAMPTZ,

  -- What was verified (result only — no raw PII)
  age_verified        BOOLEAN,
  min_age_met         INTEGER,
  license_valid       BOOLEAN,
  license_state       CHAR(2),
  mvr_clear           BOOLEAN,      -- no DUI in 5yr, no suspension in 2yr, <3 violations
  medical_cleared     BOOLEAN,

  -- Privacy: raw ID images purged 24h after verification
  images_purged_at    TIMESTAMPTZ,
  -- Biometric: stored as one-way hash only
  face_geometry_hash  TEXT,
  voice_print_hash    TEXT,

  -- Re-verification triggers
  verified_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  expires_at          TIMESTAMPTZ  GENERATED ALWAYS AS (verified_at + INTERVAL '12 months') STORED,
  revalidation_reason TEXT,

  -- BIPA / CCPA / GDPR consent
  biometric_consent_at TIMESTAMPTZ,
  deletion_requested_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS id_ver_user_idx    ON id_verifications(user_id, verified_at DESC);
CREATE INDEX IF NOT EXISTS id_ver_expires_idx ON id_verifications(expires_at) WHERE result='passed';
CREATE INDEX IF NOT EXISTS id_ver_purge_idx   ON id_verifications(images_purged_at) WHERE images_purged_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- PAYMENT METHODS (encrypted Stripe tokens — PCI-DSS SAQ-A)
-- We NEVER store raw card numbers, CVVs, or expiration dates.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payment_methods (
  id                    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id               UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Stripe payment method token — encrypted with AES-256-GCM before storage
  -- Raw card data stays in Stripe's vault, never on our servers
  stripe_pm_token_enc   TEXT         NOT NULL,  -- encrypted Stripe pm_xxxxx token
  stripe_customer_enc   TEXT         NOT NULL,  -- encrypted Stripe customer ID

  -- Display-only metadata (safe to store)
  brand                 TEXT,         -- 'visa', 'mastercard', 'amex', etc.
  last4                 CHAR(4),
  exp_month             INTEGER,
  exp_year              INTEGER,
  wallet_type           TEXT         CHECK (wallet_type IN ('apple_pay','google_pay','card',NULL)),

  is_default            BOOLEAN      NOT NULL DEFAULT false,
  created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS pm_user_idx ON payment_methods(user_id) WHERE TRUE;

ALTER TABLE payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_methods FORCE  ROW LEVEL SECURITY;
CREATE POLICY pm_isolate ON payment_methods FOR ALL TO wtm_app
  USING (user_id = current_setting('app.current_user_id')::UUID);

-- ─────────────────────────────────────────────────────────────────────────
-- REDEMPTION CATALOG (core year-round + rotating seasonal)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS redemption_catalog (
  id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  title                TEXT         NOT NULL,
  description          TEXT,
  image_url            TEXT,
  points_cost          INTEGER      NOT NULL CHECK (points_cost > 0),
  value_cents          INTEGER,
  reward_type          TEXT         NOT NULL CHECK (reward_type IN ('credit','discount','free_experience','add_on','perk')),
  required_tier        TEXT         NOT NULL DEFAULT 'rookie' CHECK (required_tier IN ('rookie','regular','local')),
  related_experience_id UUID        REFERENCES experiences(id),

  -- Availability
  available_year_round BOOLEAN      NOT NULL DEFAULT false,
  season               TEXT         CHECK (season IN ('winter','spring','summer','fall')),
  active_month_start   INTEGER      CHECK (active_month_start BETWEEN 1 AND 12),
  active_month_end     INTEGER      CHECK (active_month_end BETWEEN 1 AND 12),

  -- HARD CAPS — every redemption must have limits
  cap_per_member_month      INTEGER,
  cap_per_member_year       INTEGER  NOT NULL DEFAULT 2,
  cap_per_member_quarter    INTEGER,
  cap_global_quarter        INTEGER  NOT NULL DEFAULT 100,

  -- Safety check: no single high-cost experience redeemable as free
  -- (enforced by application + CHECK below)
  is_full_freebie           BOOLEAN  NOT NULL DEFAULT false,
  max_freebie_value_cents   INTEGER  GENERATED ALWAYS AS (
    CASE WHEN is_full_freebie THEN value_cents ELSE NULL END
  ) STORED,

  -- A full-freebie redemption can only exist if value is under $100 retail
  CONSTRAINT freebie_value_limit CHECK (
    NOT is_full_freebie OR value_cents IS NULL OR value_cents <= 10000
  ),

  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active      BOOLEAN     NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS redcat_tier_idx    ON redemption_catalog(required_tier) WHERE active=true;
CREATE INDEX IF NOT EXISTS redcat_season_idx  ON redemption_catalog(season) WHERE active=true AND available_year_round=false;
CREATE INDEX IF NOT EXISTS redcat_yearround_idx ON redemption_catalog(available_year_round) WHERE available_year_round=true;

-- ─────────────────────────────────────────────────────────────────────────
-- REDEMPTIONS (history + cap enforcement)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS redemptions (
  id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id              UUID         NOT NULL REFERENCES users(id),
  catalog_id           UUID         NOT NULL REFERENCES redemption_catalog(id),
  booking_id           UUID         REFERENCES bookings(id),
  points_deducted      INTEGER      NOT NULL CHECK (points_deducted > 0),
  value_applied_cents  INTEGER,
  status               TEXT         NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','applied','expired','reversed')),
  created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS redemptions_user_idx ON redemptions(user_id, created_at DESC);

-- Materialized view for fast cap checking
CREATE MATERIALIZED VIEW IF NOT EXISTS redemption_caps_check AS
  SELECT
    r.user_id,
    r.catalog_id,
    COUNT(*) FILTER (WHERE r.created_at >= date_trunc('month', NOW()))    AS count_this_month,
    COUNT(*) FILTER (WHERE r.created_at >= date_trunc('quarter', NOW()))  AS count_this_quarter,
    COUNT(*) FILTER (WHERE r.created_at >= date_trunc('year', NOW()))     AS count_this_year,
    COUNT(*) FILTER (WHERE r.catalog_id = r.catalog_id
      AND r.created_at > NOW() - INTERVAL '90 days')                      AS count_last_90d
  FROM redemptions r
  WHERE r.status NOT IN ('expired','reversed')
  GROUP BY r.user_id, r.catalog_id
WITH NO DATA;

CREATE UNIQUE INDEX ON redemption_caps_check(user_id, catalog_id);

-- ─────────────────────────────────────────────────────────────────────────
-- ANTI-FRAUD: VELOCITY MONITORING
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fraud_signals (
  id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id           UUID         NOT NULL REFERENCES users(id),
  signal_type       TEXT         NOT NULL CHECK (signal_type IN (
    'points_velocity', 'redemption_spike', 'referral_abuse',
    'booking_pattern', 'account_age', 'device_mismatch', 'ip_anomaly'
  )),
  severity          TEXT         NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  description       TEXT,
  auto_action       TEXT         CHECK (auto_action IN ('none','flag','pause_redemptions','suspend')),
  resolved          BOOLEAN      NOT NULL DEFAULT false,
  detected_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  resolved_at       TIMESTAMPTZ
);

-- ─────────────────────────────────────────────────────────────────────────
-- AI CONCIERGE REQUESTS (Regular and Local tiers)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_concierge_requests (
  id                 UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id            UUID         NOT NULL REFERENCES users(id),
  tier_at_request    TEXT         NOT NULL CHECK (tier_at_request IN ('regular','local')),
  request_text       TEXT         NOT NULL,
  ai_response        TEXT,
  suggested_exp_ids  JSONB        DEFAULT '[]',
  confirmed_booking_id UUID       REFERENCES bookings(id),
  human_escalated    BOOLEAN      NOT NULL DEFAULT false,
  escalated_at       TIMESTAMPTZ,
  escalation_resolved_at TIMESTAMPTZ,
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────────────
-- MESSAGES (Signal Protocol E2E encrypted)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
  id                UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  thread_id         UUID         NOT NULL,
  sender_user_id    UUID         REFERENCES users(id),
  recipient_user_id UUID         REFERENCES users(id),
  ciphertext        BYTEA        NOT NULL,
  ephemeral_key     BYTEA        NOT NULL,
  message_index     INTEGER      NOT NULL,
  prev_chain_length INTEGER,
  sent_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  read_at           TIMESTAMPTZ,
  related_booking_id UUID        REFERENCES bookings(id)
);

CREATE INDEX IF NOT EXISTS msg_thread_idx ON messages(thread_id, sent_at);

-- ─────────────────────────────────────────────────────────────────────────
-- DEVICE KEYS (Signal Protocol prekeys)
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_keys (
  id                      UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id                 UUID    NOT NULL REFERENCES users(id),
  device_id               TEXT    NOT NULL,
  identity_key_pub        BYTEA   NOT NULL,
  signed_prekey_pub       BYTEA   NOT NULL,
  signed_prekey_signature BYTEA   NOT NULL,
  one_time_prekeys        JSONB   NOT NULL DEFAULT '[]',
  registered_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, device_id)
);

-- ─────────────────────────────────────────────────────────────────────────
-- AUDIT LOG
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  actor_user_id    UUID         REFERENCES users(id),
  actor_ip         INET,
  action           TEXT         NOT NULL,
  resource_type    TEXT,
  resource_id      UUID,
  metadata         JSONB,
  result           TEXT         NOT NULL CHECK (result IN ('success','failure','blocked')),
  occurred_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_actor_idx  ON audit_log(actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_action_idx ON audit_log(action, occurred_at DESC);

-- ─────────────────────────────────────────────────────────────────────────
-- REVIEWS
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reviews (
  id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID         REFERENCES users(id),
  experience_id   UUID         NOT NULL REFERENCES experiences(id),
  booking_id      UUID         NOT NULL REFERENCES bookings(id) UNIQUE,
  rating          INTEGER      NOT NULL CHECK (rating BETWEEN 1 AND 5),
  body            TEXT,
  photos          JSONB        NOT NULL DEFAULT '[]',
  helpful_count   INTEGER      NOT NULL DEFAULT 0,
  host_response   TEXT,
  host_responded_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reviews_exp_idx ON reviews(experience_id);

-- ─────────────────────────────────────────────────────────────────────────
-- ROW-LEVEL SECURITY
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE member_profiles      ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_profiles      FORCE  ROW LEVEL SECURITY;
CREATE POLICY mp_isolate ON member_profiles FOR ALL TO wtm_app
  USING (user_id = current_setting('app.current_user_id')::UUID);

ALTER TABLE qe_ledger            ENABLE ROW LEVEL SECURITY;
ALTER TABLE qe_ledger            FORCE  ROW LEVEL SECURITY;
CREATE POLICY qe_isolate ON qe_ledger FOR SELECT TO wtm_app
  USING (user_id = current_setting('app.current_user_id')::UUID);

ALTER TABLE points_ledger        ENABLE ROW LEVEL SECURITY;
ALTER TABLE points_ledger        FORCE  ROW LEVEL SECURITY;
CREATE POLICY pts_isolate ON points_ledger FOR SELECT TO wtm_app
  USING (user_id = current_setting('app.current_user_id')::UUID);

ALTER TABLE user_favorites       ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_favorites       FORCE  ROW LEVEL SECURITY;
CREATE POLICY fav_isolate ON user_favorites FOR ALL TO wtm_app
  USING (user_id = current_setting('app.current_user_id')::UUID);

ALTER TABLE waivers              ENABLE ROW LEVEL SECURITY;
ALTER TABLE waivers              FORCE  ROW LEVEL SECURITY;
CREATE POLICY waiver_isolate ON waivers FOR SELECT TO wtm_app
  USING (signer_user_id = current_setting('app.current_user_id')::UUID);

ALTER TABLE id_verifications     ENABLE ROW LEVEL SECURITY;
ALTER TABLE id_verifications     FORCE  ROW LEVEL SECURITY;
CREATE POLICY idv_isolate ON id_verifications FOR SELECT TO wtm_app
  USING (user_id = current_setting('app.current_user_id')::UUID);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE  ROW LEVEL SECURITY;
CREATE POLICY msg_visibility ON messages FOR SELECT TO wtm_app
  USING (
    sender_user_id    = current_setting('app.current_user_id')::UUID OR
    recipient_user_id = current_setting('app.current_user_id')::UUID
  );

-- ─────────────────────────────────────────────────────────────────────────
-- TIER PROMOTION TRIGGER
-- Rookie (0-6 QE) → Regular (7-17 QE) → Local (18+ QE)
-- ─────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_member_tier()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.qualifying_experiences >= 18 THEN
    NEW.tier := 'local';
    IF OLD.tier <> 'local' THEN
      NEW.local_achieved_at   := NOW();
    END IF;
    NEW.ai_concierge_enabled      := true;
    NEW.human_concierge_enabled   := true;
    NEW.members_only_unlocked     := true;
  ELSIF NEW.qualifying_experiences >= 7 THEN
    NEW.tier := 'regular';
    IF OLD.tier NOT IN ('regular','local') THEN
      NEW.regular_achieved_at := NOW();
    END IF;
    NEW.ai_concierge_enabled      := true;
    NEW.human_concierge_enabled   := false;
    NEW.members_only_unlocked     := true;
  ELSE
    NEW.tier := 'rookie';
    NEW.ai_concierge_enabled      := false;
    NEW.human_concierge_enabled   := false;
    NEW.members_only_unlocked     := false;
  END IF;
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER member_tier_update
  BEFORE UPDATE OF qualifying_experiences ON member_profiles
  FOR EACH ROW EXECUTE FUNCTION update_member_tier();

-- ─────────────────────────────────────────────────────────────────────────
-- WEIGHTED QE CALCULATION
-- Free experiences capped at 25% of annual total
-- ─────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION calculate_weighted_qe(p_user_id UUID, p_year INTEGER)
RETURNS NUMERIC AS $$
DECLARE
  free_qe  NUMERIC := 0;
  paid_qe  NUMERIC := 0;
  total    NUMERIC;
  free_cap NUMERIC;
BEGIN
  SELECT COALESCE(SUM(qe_weight),0) INTO free_qe
  FROM qe_ledger
  WHERE user_id=p_user_id AND status_year=p_year AND is_free=true;

  SELECT COALESCE(SUM(qe_weight),0) INTO paid_qe
  FROM qe_ledger
  WHERE user_id=p_user_id AND status_year=p_year AND is_free=false;

  total    := free_qe + paid_qe;
  free_cap := total * 0.25;
  IF free_qe > free_cap THEN free_qe := free_cap; END IF;

  RETURN ROUND((paid_qe + free_qe)::NUMERIC, 2);
END;
$$ LANGUAGE plpgsql STABLE;

-- ─────────────────────────────────────────────────────────────────────────
-- ANNUAL STATUS RESET (pg_cron — Dec 31 23:55 UTC)
-- Points NEVER expire — only QE resets
-- ─────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION annual_tier_reset() RETURNS void AS $$
BEGIN
  UPDATE member_profiles SET
    qualifying_experiences = 0,
    status_year            = EXTRACT(YEAR FROM NOW()) + 1,
    -- NOTE: points_balance NOT reset — points never expire
    updated_at             = NOW();
END;
$$ LANGUAGE plpgsql;

-- ─────────────────────────────────────────────────────────────────────────
-- POINTS VELOCITY MONITOR (run hourly via pg_cron)
-- Flags accounts earning >50K points in 30 days for manual review
-- ─────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION check_points_velocity() RETURNS void AS $$
DECLARE rec RECORD;
BEGIN
  FOR rec IN
    SELECT user_id, SUM(delta) AS earned
    FROM points_ledger
    WHERE delta > 0 AND created_at > NOW() - INTERVAL '30 days'
    GROUP BY user_id
    HAVING SUM(delta) > 50000
  LOOP
    -- Only insert if not already flagged in last 7 days
    INSERT INTO fraud_signals (user_id, signal_type, severity, description, auto_action)
    SELECT rec.user_id, 'points_velocity', 'high',
      'Earned ' || rec.earned || ' points in 30 days', 'flag'
    WHERE NOT EXISTS (
      SELECT 1 FROM fraud_signals
      WHERE user_id=rec.user_id
        AND signal_type='points_velocity'
        AND detected_at > NOW() - INTERVAL '7 days'
    );
  END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ─────────────────────────────────────────────────────────────────────────
-- GRANT LEAST-PRIVILEGE
-- ─────────────────────────────────────────────────────────────────────────
GRANT EXECUTE ON FUNCTION calculate_weighted_qe(UUID, INTEGER) TO wtm_app;
GRANT EXECUTE ON FUNCTION annual_tier_reset()                   TO wtm_app;
GRANT EXECUTE ON FUNCTION check_points_velocity()               TO wtm_app;
