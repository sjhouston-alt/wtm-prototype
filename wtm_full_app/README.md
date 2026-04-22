# What's the Move

**Premium experience-booking app prototype.** Targeting millennials and Gen Z who want to discover and book memorable experiences without the friction of hidden fees, unclear pricing, or clunky booking flows.

**Live prototype:** [View the full walkthrough →](./index.html)

---

## About

What's the Move simplifies the discovery and booking of premium experiences across seven categories: Dining, Water, Arts & Music, Adventure, Travel, Wellness, and Nightlife.

The core promise: **the price you see is the price you pay.** No taxes, no service fees, no hidden charges. Every experience is verified before going live.

Launch cities: Los Angeles, New York, Chicago, San Francisco, Houston, Dallas, Atlanta, Phoenix, Philadelphia, Washington DC, and Portland. Available across the continental US with manual city entry for users outside launch markets.

---

## The Prototype

This is a fully interactive mobile prototype built as self-contained HTML. Every screen is tappable, every transition is wired, and the full user journey works end to end. No build step, no dependencies, no framework — just open and run.

### How To Navigate

1. **Open `index.html`** to enter the prototype at the Splash screen
2. **Tap through** like a real user, or use the **dev nav** at the bottom of the viewport to jump to any screen
3. The frame is sized to a real mobile viewport (390px) so it feels like the actual app

---

## Screens

### 🎬 Entry Flow
Splash → 3 onboarding screens → Account Creation (Apple, Google, or Email) → Profile Setup (avatar, city, preference tags) → Ready

### 🏠 Home
Rotating gradient greeting (7 rotating lines), Surprise Me hero card, What's The Vibe pill scroller, Featured Tonight horizontal card scroll, Browse By Category grid

### 🔍 Explore
Search, category filter row, vibe pill filters (multi-select including Date Night, Celebration, Group, Solo, First Date, Anniversary, Kid-Friendly, Pet-Friendly), list / map toggle with functional view switching, 6 result cards with full metadata, map pins color-coded by category

### 📄 Experience Detail
Full-bleed hero image, Verified Experience chip, editorial title block, category and vibe badges, detailed host bio with stats, 5-course editorial course tiles, What's Included checklist, availability calendar with active and muted dates, guest stepper, public reviews with star ratings, floating price CTA bar with Add To Plans + Book Now

### 💳 Booking Flow
3 steps plus confirmation:
- **Step 1:** Date selection (calendar) and time slot picker with Available/Booked/Selected states
- **Step 2:** Guest counter, add-ons with live running total, special requests textarea with real placeholder copy
- **Step 3:** Review summary with conditional line items (additional guests, add-ons) that only appear when relevant, payment method radio selector (Card, Apple Pay, Google Pay, PayPal), optional installments block (Affirm, Afterpay, Klarna) that appears only when total is between $200 and $1,500
- **Confirmation:** Shareable branded card with watermark, Add To Calendar (Apple + Google), share destinations (Text, Instagram, Snapchat, X, Copy Link)

### 📋 My Plans
Two modes:
- **All Bookings** — status tabs (Upcoming, Confirmed, Past) with booking cards, live star-rating card for past experiences, Write Review action that posts publicly to the listing
- **Named Plans** — user-organized multi-stop itineraries (e.g., "Vegas Bachelorette," "Anniversary Weekend") with full timeline view showing day, time, category, location, guest count, and per-stop status (Confirmed, Pending Confirmation)

### 👤 Profile
Profile hero with avatar and city chip, 3-stat strip (Experiences, Saved, Avg Rating), 4 sub-tabs:
- **History** — past experiences with verified chips
- **Saved** — wishlist grid
- **Vibes** — preference tag editor
- **Settings** — Account (Edit Profile, City, Payment Methods, Email & Password), Notifications (Push, Email, SMS with toggles), Preferences (Vibes, Accessibility, Language), Support & Legal (Help, Terms, Privacy, About), Sign Out

### 🎁 Surprise Me
Vibe multi-selector, budget slider ($50–$500+), when picker (Tonight, Tomorrow, Weekend, This Week), Surprise Me CTA, AI-style reveal card with 6 rotating picks, percentage match badge, Try Again shuffle or Book It primary CTA

---

## File Structure

```
/
├── index.html                     → Master flow (entry point)
├── wtm_entry_flow_onboarding.html → Standalone entry flow
├── wtm_home.html                  → Standalone home
├── wtm_explore.html               → Standalone explore
├── wtm_detail.html                → Standalone experience detail
├── wtm_booking_flow.html          → Standalone booking (3 steps + confirmation)
├── wtm_my_plans.html              → Standalone my plans
├── wtm_profile.html               → Standalone profile
└── wtm_surprise_me.html           → Standalone surprise me
```

Each standalone file renders independently and contains only its own screens, so they can be shared or handed off individually (e.g., for design review of just the booking flow).

---

## Design System

### Color Palette

| Token | Value | Usage |
|---|---|---|
| Base | `#080810` | App background (near-black) |
| Ambient Glow (Purple) | `rgba(139, 92, 246, 0.35)` | Top-left ambient light |
| Ambient Glow (Pink) | `rgba(236, 72, 153, 0.28)` | Top-right ambient light |
| Ambient Glow (Teal) | `rgba(45, 212, 191, 0.22)` | Bottom-center ambient light |
| Brand Gradient | `linear-gradient(90deg, #c084fc, #f472b6, #fb923c)` | Text accents, watermarks |
| CTA Gradient | `linear-gradient(135deg, #8b5cf6, #ec4899)` | Primary buttons, active states |

### Category Accent Colors

| Category | Accent |
|---|---|
| Dining | Purple (`#c084fc`) |
| Water | Teal (`#2dd4bf`) |
| Arts & Music | Pink (`#f472b6`) |
| Adventure | Amber (`#fb923c`) |
| Travel | Blue (`#3b82f6`) |
| Wellness | Green (`#4ade80`) |
| Nightlife | Indigo (`#818cf8`) |

### Typography

Bold, editorial. System font stack with Inter / SF Pro Display fallbacks. Negative letter-spacing on display sizes for a premium, intentional feel.

---

## Product Rules (Non-Negotiable)

These rules apply to every screen and every future build.

### Pricing Transparency
- All-inclusive pricing. No taxes, no service fees, no hidden charges.
- The price displayed to the user is exactly what they pay.
- Guest fee formula: `total = base + max(0, guests − 2) × 75 + addonTotal`. Base covers up to 2 guests.
- Additional-guest line item appears in the booking summary **only when guest count exceeds 2**.
- Installments (Affirm, Afterpay, Klarna) appear **only when total is between $200 and $1,500**, and are excluded from select luxury experiences via a back-end flag.

### Verification
Every experience displays a green **Verified** chip with the correct noun for its type:
- Verified Chef, Verified Captain, Verified Guide, Verified Host, Verified Venue, Verified Experience

Verification is gated by the back-end `experience_verified` flag. Unverified experiences do not go live.

### Writing Rules
- **No em dashes** anywhere. Use commas or restructure.
- **No "household"** anywhere.
- **No pricing structure, fee, tax, or back-end logic** language in UI copy.
- **No subscription language** anywhere.
- **Title Case** on every button, CTA, and section header.

### Tags
- **Kid-Friendly** and **Pet-Friendly** are tags only. They never become sections, toggles, or dedicated filters.
- Preference tags available in onboarding and profile: Food, After Hours, Art, Travel, Touch Grass, Wellness, Entertainment, Thrill Seeking, Surprise Me, Kid-Friendly, Pet-Friendly. All are optional with no minimum or maximum selection.

### Bottom Navigation
Four tabs, persistent on every post-onboarding screen:
- **Home** — landing feed
- **Explore** — search and discovery
- **My Plans** — bookings and named plans
- **Profile** — account, preferences, settings (no separate Settings tab)

---

## What's Working Live In The Prototype

- Rotating home greeting (7 lines randomize per visit)
- Search, filter pills, vibe pills (multi-select)
- List ↔ Map toggle on Explore
- Calendar date picker + time slot picker with state management
- Guest stepper with live running total updates
- Add-on toggles that update total and Step 3 summary in real time
- Conditional line items (additional guests, add-ons) that only render when relevant
- Payment method radio selector
- Installments block that appears and recalculates based on total
- My Plans mode switching (All Bookings ↔ Named Plans)
- Status tabs (Upcoming, Confirmed, Past) with counts
- Interactive 5-star rating on past bookings
- Profile sub-tab switching (History, Saved, Vibes, Settings)
- Settings toggles (Push, Email, SMS)
- Surprise Me flow with 6 rotating reveal picks, budget slider, when picker, and shuffle function

---

## For Developers & Designers

This prototype is the **product spec made tangible**. Every interaction, copy choice, color, and edge case was deliberate.

When building the production app, use this prototype as the source of truth for:
- Screen layouts and information hierarchy
- Component behavior (counters, toggles, conditional logic)
- Copy voice and exact language
- Color system and design tokens
- Edge cases (e.g., when installments appear, when guest fee line items show)

Changes to rules should be agreed on explicitly, not inferred from the prototype.

---

## Status

**Build complete.** All 17 screens across 8 pieces, stitched end to end, with every locked product decision applied consistently.

Next steps moving from prototype to production:
- Category pages (one per category, deep dive)
- Additional experience types beyond the Private Chef prototype
- Continued expansion of the component library as new surfaces are added
- Messaging / chat between guests and hosts
- Host onboarding flow
- Admin / verification tooling

---

Built with care. Ready to move.
