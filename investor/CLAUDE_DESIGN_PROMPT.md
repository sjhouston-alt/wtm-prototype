# Claude Design Prompt — What's the Move (WTM)
**Version 4.0** · April 2026

> Paste the prompt block below into any Claude conversation to regenerate or extend the WTM prototype. Every locked product decision is embedded so any output stays on-brand, on-spec, and exploit-resistant.

---

## Cross-Platform Requirements (locked)

WTM ships to both iOS and Android on the latest OS versions and current-generation devices.

**iOS targets:** iOS 17, 18 — iPhone 15 line, iPhone 16 line — Safari 17+
**Android targets:** Android 14 (API 34), Android 15 (API 35) — Galaxy S24/S25, Pixel 8/9 — Chrome 120+

**Test viewports:** 393×852 (iPhone 15 Pro), 430×932 (15 Pro Max), 384×854 (Pixel 8 Pro), 412×915 (Galaxy S24 Ultra)

**Required CSS (every screen):**
- `<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, maximum-scale=1.0, user-scalable=no">`
- `padding-top: env(safe-area-inset-top)` on top bar (clears iOS Dynamic Island)
- `padding-bottom: env(safe-area-inset-bottom)` on bottom nav (clears Android gesture bar)
- Touch targets minimum 44×44pt (iOS) / 48×48dp (Android)
- `-webkit-tap-highlight-color: transparent` on all clickable elements
- `overscroll-behavior: contain` on scroll containers
- System font fallback: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- All animations use `transform` + `opacity` only (GPU-accelerated)
- `prefers-color-scheme` respected on first load, then localStorage takes over

**Production stack:** React Native, iOS 17+ / Android 14+, App Store + Google Play, Stripe Elements + Apple Pay + Google Pay, APNs + FCM, Face ID + Touch ID + Android BiometricPrompt.

---

## The Prompt

```
You are building What's the Move (WTM), a premium experience-booking app for
millennials and Gen Z. Output a single self-contained HTML file with all CSS
in <style> and all JS in <script>. No build step. No external JS files except
wtm_experiences_db.js (load via <script src="wtm_experiences_db.js"></script>
and use window.WTM.*).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CROSS-PLATFORM (apply to every screen)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
iOS 17/18: iPhone 15/16 lines. Android 14/15: Galaxy S24/S25, Pixel 8/9.
Test at: 393×852, 430×932, 384×854, 412×915.
viewport: width=device-width, initial-scale=1.0, viewport-fit=cover, maximum-scale=1.0
Safe-area insets: top bar and bottom nav must use env(safe-area-inset-*).
Touch targets: minimum 44×44pt (iOS) / 48×48dp (Android).
-webkit-tap-highlight-color: transparent on all clickables.
overscroll-behavior: contain on scroll containers.
Animations: transform + opacity only (GPU-accelerated).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CATEGORIES (7 — Pets is NOT a category)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1. Dining        #a855f7 (purple)
 2. Offshore      #14b8a6 (teal)
 3. Arts & Music  #ec4899 (pink)
 4. Adventure     #f59e0b (amber)
 5. Wellness      #22c55e (green)
 6. Outside       #6366f1 (indigo)
 7. Kid-Friendly   #f59e0b (amber) — experiences DESIGNED for children

pet_friendly = FLAG on individual experiences (pets welcome to attend WITH owner).
kid_friendly = FLAG on individual experiences (kids welcome WITH adults).
NEVER: Travel, Nightlife, Water, Pets as a category.
NEVER: pet_friendly to mean "experience is for/about pets."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MEMBERSHIP TIERS — Amethyst / Emerald / Ruby
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rookie  (Amethyst) 0-6 QE   — #a855f7 — grad: linear-gradient(135deg,#c084fc,#a855f7,#7e22ce)
Regular (Emerald)  7-17 QE  — #10b981 — grad: linear-gradient(135deg,#34d399,#10b981,#047857)
Local   (Ruby)     18+ QE   — #e11d48 — grad: linear-gradient(135deg,#fb7185,#e11d48,#9f1239)

Members-only experiences: "Reserved for Regulars and Locals" (exact copy).
Exclusive banner section: show lower on home (after Featured, Categories, Free, Local Spotlight).
Tier preview: Rookie sees 3 locked Regular experiences, Regular sees 3 locked Local experiences.
NEVER use: Bronze, Silver, Gold, Platinum — those are deprecated.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRICING RULES (non-negotiable)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
total = base + max(0, guests-2) × per_guest_fee + addons + 0 (no fees ever)
Show "From $[base]" on cards (DM Sans, font-variant-numeric: tabular-nums, 700 weight).
Guest fee line item only appears in booking summary when guests > 2.
Installments (Affirm/Afterpay/Klarna): $500+ total only.
Free experiences show amber FREE badge. Unlimited free bookings allowed.
NEVER surface how much a user has spent in any user-facing UI.
Average experience price ~$165 (not $250 — catalog has many sub-$100 options).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POINTS AND REWARDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Points NEVER expire — never mention expiration in user-facing copy.
Points credit 48-72 hours after experience completion (not at booking).
Show: points earned, QE progress, categories explored, experiences completed.
NEVER show: dollars spent, money paid — track backend-only.
QE weights: free=0.25 (capped at 25% annual), standard=1.0, premium=1.5, exclusive=2.0.
Rewards UI shows 6 items max: 3 core (always) + 3 rotating seasonal.
No single premium/exclusive experience redeemable as free (discount only).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HOME SCREEN ORDER (required)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Top bar (greeting + points pill + theme toggle + notif + avatar)
2. Vibe pills (first interactive element)
3. Featured Tonight carousel
4. Browse by Category grid (7 categories + All tile)
5. Free This Week carousel
6. Local Business Spotlight carousel
7. Members Only banner (Reserved for Regulars and Locals)
8. Curated Collections list
9. Surprise Me card (last — for the undecided)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERIFIED CHIP (exact)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span class="chip chip-v">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
  Verified
</span>
CSS: background:rgba(34,197,94,.16); border:1px solid rgba(34,197,94,.3); color:#4ade80;
NEVER: "Verified Chef", "Verified Captain", "Verified Host" — just Verified.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXCLUSIVE CHIP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
background:rgba(168,85,247,.18); border:1px solid rgba(168,85,247,.4); color:#a855f7;
Label: "Members Only"
Section heading copy: "Reserved for Regulars and Locals"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FAVORITES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Heart icon on every experience card (top right). Tap toggles favorite.
Persist to localStorage as JSON array under key 'wtm-favorites'.
Filled ruby red (#e11d48) when active. Animated fill on activation.
WTM.toggleFavorite(id), WTM.isFavorited(id), WTM.getFavoriteExperiences() helpers available.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXPERIENCE PRICE FONT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Price on cards: DM Sans, font-variant-numeric: tabular-nums, 700 weight, 13px.
(NOT Space Grotesk for prices — use DM Sans with tabular-nums for perfect price alignment.)
Free badge: amber #f59e0b, DM Sans, font-weight:800.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DESIGN SYSTEM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Dark (default): --base:#080810 --surface:#0f0f1a --text:#fff --text2:rgba(255,255,255,.65)
Light (toggle): --base:#FAF8F5 --surface:#F2EFE9 --text:#111018
Brand gradient: linear-gradient(90deg,#c084fc,#f472b6,#fb923c)
CTA gradient:   linear-gradient(135deg,#8b5cf6,#ec4899)
Ambient orbs: purple top-left, pink top-right, teal bottom-center (both themes, light at 0.05 opacity)
Typography: Space Grotesk 700 (display/titles/CTAs) + DM Sans 400-600 (body) + system fallback
Theme toggle: moon/sun icon in top bar, persists via localStorage('wtm-theme'),
              respects prefers-color-scheme on first load.
Bottom nav: Home, Explore, My Plans, Profile — active item uses brand gradient on text.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WRITING RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title Case on ALL buttons, CTAs, section headers.
NO em dashes — use commas or restructure.
NO "household".
NO mention of fees, taxes, back-end logic, or pricing structure.
NO subscription language for users.
NO mention of how much a user has spent.
Points pill: "[balance] · [Tier name]" — e.g., "3,820 · Regular"
Greeting rotation (7, random per login):
  "Less Planning. More Living." / "Good Things Are Happening Right Now." /
  "Your Next Favorite Memory Starts Here." / "Unforgettable Moments, Made Simple." /
  "Every Moment, Thoughtfully Curated." / "The Moments That Matter, Made Easy." /
  "More Memories, Seamless Planning."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ALWAYS INCLUDE ON EVERY SCREEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Dark + light theme (CSS vars + localStorage)
2. Real Unsplash images matching the ACTIVITY (not generic)
3. Verified chip on every experience card
4. Exclusive (Members Only) chip on exclusive experiences
5. Free (amber) badge on free experiences
6. Pet OK / Kid OK chips where applicable
7. Heart/favorite button on every experience card
8. Bottom nav with active screen highlighted
9. Theme toggle in top bar
10. Ambient orbs in background
11. Space Grotesk for display, DM Sans for body + tabular-nums for prices
12. Title Case on all CTAs and headers
13. No em dashes
14. Safe-area insets on top bar and bottom nav
15. viewport-fit=cover meta tag
16. Touch targets minimum 44pt / 48dp
17. overscroll-behavior:contain on scroll containers
18. -webkit-tap-highlight-color:transparent on interactive elements

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOW BUILD: [DESCRIBE THE SCREEN OR FEATURE YOU WANT]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## What to avoid

- Generic AI aesthetics (Inter font, purple-on-white gradients, predictable card layouts)
- Syne (deprecated — replaced by Space Grotesk)
- Em dashes anywhere in copy
- Mentioning spend, fees, taxes, or pricing structure in UI
- Pets as a category
- Bronze, Silver, Gold, Platinum tier names
- Members Only as the first thing the user sees on home
- Surprise Me as the first thing the user sees on home
- Hardcoding experience data — always load from wtm_experiences_db.js

---

## Example prompts

> Build the WTM Explore screen. Search bar at top. Category filter chips. Vibe pill row. Results grid (2 columns). Each card shows image, Verified chip, title, category, rating, price (DM Sans tabular-nums). Heart/favorite button. Filter sheet slides up from bottom with sort, price range, and category multi-select. Show tier preview badges on locked exclusive experiences.

> Build the WTM Experience Detail screen. Full-bleed hero image with back button and favorite heart. Verified chip + title + host name + rating. Price bar at bottom (From $X + Book Now CTA). Scrollable: description, what's included checklist, host bio, editorial photo tiles, availability calendar, guest counter, cancellation policy notice. If experience requires age verification or waiver, show a notice chip below the title.

> Build the WTM Booking Flow Step 2 (Guests + Add-ons). Guest counter. Add-on cards (each with image, title, description, price). Special requests text field. Running total at bottom (DM Sans tabular-nums). If total ≥ $500, show installment option. If experience is non-refundable, show a clear notice. If experience requires a waiver, show "You will sign a waiver at the next step."
