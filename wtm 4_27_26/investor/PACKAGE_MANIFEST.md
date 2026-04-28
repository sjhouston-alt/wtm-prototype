# WTM Investor Package — Complete File Manifest
**Version 4.0** · April 2026

This folder contains every file needed to demonstrate WTM's full vision to a prospective investor: product prototype, business model, technical architecture, security posture, and database design.

---

## Cross-Platform Support

WTM ships natively to both iOS and Android on the latest OS versions and current-generation devices.

| Platform | OS versions | Devices | Browser fallback |
|---|---|---|---|
| iOS | 17, 18 | iPhone 15 line, iPhone 16 line | Safari 17+ |
| Android | 14 (API 34), 15 (API 35) | Galaxy S24/S25 lines, Pixel 8/9 lines | Chrome 120+ |

Production stack: **React Native** with platform-specific code, distributed through App Store and Google Play. Apple Pay and Google Pay are both first-class payment options. Push notifications via APNs (iOS) and FCM (Android). Biometric auth via Face ID, Touch ID, and Android BiometricPrompt. Identity verification via **ID.me** (the same vendor used by the IRS, VA, and 30+ state governments).

HTML prototypes render correctly at all four target viewports: 393×852 (iPhone 15 Pro), 430×932 (15 Pro Max), 384×854 (Pixel 8 Pro), and 412×915 (Galaxy S24 Ultra). Safe-area insets handle the iOS Dynamic Island and Android gesture bar.

---

## How to Use This Package

### For the investor meeting
1. **Lead with the deck:** Open `WTM_Investor_Deck.pptx` in Keynote or PowerPoint
2. **Live demo:** Open `wtm_home_v2.html` in a browser, then `wtm_rewards.html` for the loyalty program
3. **Share `SECURITY_MANUAL.md`** if technical due diligence comes up during the meeting

### For follow-up due diligence
- `schema_v3_additions.sql` shows the production-ready data model
- `WTM_DATABASE_ARCHITECTURE.md` covers hosting, scaling, backup, and disaster recovery
- `messaging_signal_protocol.js` demonstrates Signal-grade E2E encryption
- `SECURITY_MANUAL.md` is a 19-section technical reference covering every security layer

### For scaling the team after investment
- `CLAUDE_DESIGN_PROMPT.md` — paste into Claude to regenerate any screen on-brand and on-spec instantly

---

## File Index

### Investor materials

| File | Description |
|---|---|
| `WTM_Investor_Deck.pptx` | 17-slide pitch deck |
| `WTM_Business_Plan.md` | Comprehensive business plan — market analysis, go-to-market, revenue model, unit economics, ops plan, financial projections, appendices |
| `PACKAGE_MANIFEST.md` | This file |
| `CLAUDE_DESIGN_PROMPT.md` | Design system + all locked rules in a pasteable prompt |

### App prototype

| File | Description |
|---|---|
| `wtm_experiences_db.js` | Master experience database v3 — 74 experiences, 7 categories, Amethyst/Emerald/Ruby tiers, cancellation policies, verification levels, waiver flags, favorites helpers, seasonal redemption catalog |
| `wtm_home_v2.html` | Home screen v3 — reordered (vibes first → featured → categories → free → local → members only → collections → surprise me), Emerald tier points pill, favorites hearts, price font fix (DM Sans tabular-nums), tier preview badges |
| `wtm_rewards.html` | Rewards screen v3 — Amethyst/Emerald/Ruby tier ladder, monthly/quarterly/yearly stats tabs, 6 redemptions (3 core + 3 seasonal), no spend tile, points never expire note, AI Concierge card, QE explainer |

### Backend security files

| File | Description |
|---|---|
| `auth.js` | Login, registration, MFA TOTP, JWT httpOnly cookies, CSRF, rate limiting, account lockout, re-verification triggers |
| `encryption.js` | AES-256-GCM field encryption, HMAC blind index, card token encryption |
| `payments.js` | Stripe PCI-DSS SAQ-A, server-side amount calculation, encrypted card tokens, Apple Pay + Google Pay, installments at $500+ (updated from $200) |
| `api.js` | Helmet CSP, CORS allowlist, Joi validation, sanitize-html, HPP, error handler |
| `database.js` | Parameterized queries, RLS context, GDPR deletion, soft delete |
| `monitoring.js` | Structured logging, brute force detection, points velocity monitoring, redemption spike alerts |
| `server.js` | Express entry point, middleware order, all routes wired |
| `schema.sql` | PostgreSQL v2 baseline schema with RLS and triggers |
| `schema_v3_additions.sql` | All new v3 tables with full detail (see description above) |
| `messaging_signal_protocol.js` | Signal Protocol E2E: X3DH, Double Ratchet, Sealed Sender |

### Architecture and security docs

| File | Description |
|---|---|
| `WTM_DATABASE_ARCHITECTURE.md` | Production schema, hosting stack, capacity planning, RLS, backup, sharding, migration, disaster recovery |
| `SECURITY_MANUAL.md` | 19-section security manual including ID.me verification, waivers, cancellations, card storage, loyalty anti-fraud, mobile security |

---

## Stats Summary

### Product
- **74 experiences** across **7 categories** in **10 launch cities**
- **12 exclusive** (Members Only) experiences — reserved for Regular and Local members
- **5 free** experiences — unlimited bookings, count toward QE at 0.25 each
- **20 pet-friendly** experiences (pets welcome to attend with owner, across all categories)
- **29 kid-friendly** experiences (kids welcome with adults, plus 7 dedicated Kids experiences)
- **22 experiences require waivers** (jet ski, scuba, paragliding, supercar, axe throwing, etc.)
- **17 experiences require ID verification** (ID.me — age 21+, identity, driver, medical)
- Blended average experience price: **~$165** (down from $250 — more sub-$100 options)

### Membership
- **3 tiers:** Rookie (Amethyst) → Regular (Emerald) → Local (Ruby)
- Tiers named after gemstones, not metals — emotionally resonant, aspirational
- Members-only experiences unlock at **Regular** tier (not the top tier)
- **Weighted QE** prevents free-event gaming (25% free-event cap)
- **Points never expire** — drives long-term engagement and emotional investment
- **AI Concierge** available at Regular tier; human escalation at Local tier

### Technology
- **Dual-platform:** iOS 17+ and Android 14+ targets in React Native
- **Signal Protocol** E2E messaging — X3DH + Double Ratchet + Sealed Sender
- **ID.me** identity verification — the same platform used by IRS, VA, and 30+ state governments
- **In-app e-signatures** for waivers — cryptographic hash + timestamp + device fingerprint
- **AES-256-GCM** field-level encryption for PII and card tokens
- **PostgreSQL RLS FORCE** on every sensitive table
- **PCI-DSS SAQ-A scope** — we never see, transmit, or store raw card numbers
- **Hardware-backed keys** via iOS Secure Enclave and Android Keystore
- AWS RDS Multi-AZ — RPO 5 minutes, RTO 15 minutes

### Business
- **15% take rate** vs 30% on legacy platforms — empowers small business hosts
- **5 revenue streams:** commission, host subscriptions, gift cards, sponsored placements, brand partnerships
- **Installment payments** (Affirm/Afterpay/Klarna) for bookings $500 and above
- **No subscription fee** for consumers. No ads. No hidden fees. Ever.
- **Anti-exploit redemption system:** universal caps, velocity monitoring, no high-cost freebies
- **3 paths to Local status:** 18 standard bookings, 12 premium, or 9 exclusive

---

## Next Steps After the Meeting

1. **Code review session** — share GitHub repo access
2. **Live product walkthrough** — 30-min demo of the prototype in a browser
3. **Database deep-dive** — walk through `WTM_DATABASE_ARCHITECTURE.md` with engineering lead
4. **Financial model** — cap table + 5-year P&L (separate dataroom file)
5. **Term sheet review** — target close in 8 weeks

---

*"Less planning. More living." — four words that describe the entire pitch.*
