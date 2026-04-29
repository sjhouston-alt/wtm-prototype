# WTM Prototype — Claude Chrome Command Reference
# Comprehensive commands for ongoing development, QA, and maintenance.
# Placeholders are ALL_CAPS — swap in the real value each time.

---

## SECTION 1 — LIVE SITE VERIFICATION (Console / JS)
Run directly in the browser DevTools console on the live app.
URL: https://sjhouston-alt.github.io/wtm-prototype/app/wtm_app.html

### 1A. Health Check (app globals)

```js
console.log("=== WTM Health Check ===");
console.log("EXPERIENCES_DB count:", typeof EXPERIENCES_DB !== "undefined" ? EXPERIENCES_DB.length : "NOT LOADED");
console.log("ADDONS_DB count:",      typeof ADDONS_DB      !== "undefined" ? ADDONS_DB.length      : "NOT LOADED");
console.log("COLLECTIONS count:",    typeof COLLECTIONS    !== "undefined" ? COLLECTIONS.length    : "NOT LOADED");
console.log("currentUser:",  typeof currentUser  !== "undefined" ? JSON.stringify(currentUser)  : "NOT SET");
console.log("currentScreen:", typeof currentScreen !== "undefined" ? currentScreen : "NOT SET");
console.log("========================");
```

### 1B. Category Card Counts

```js
(function() {
  if (typeof EXPERIENCES_DB === "undefined") { console.error("EXPERIENCES_DB not loaded"); return; }
  const counts = {};
  EXPERIENCES_DB.forEach(e => { counts[e.category] = (counts[e.category] || 0) + 1; });
  console.log("=== Experiences By Category ===");
  Object.entries(counts).sort((a,b) => b[1]-a[1]).forEach(([cat, n]) => console.log(cat + ":", n));
  console.log("TOTAL:", EXPERIENCES_DB.length);
})();
```

### 1C. Pet-Friendly Flag Check

```js
(function() {
  if (typeof EXPERIENCES_DB === "undefined") { console.error("EXPERIENCES_DB not loaded"); return; }
  const pf = EXPERIENCES_DB.filter(e => e.tags && e.tags.includes("Pet-Friendly"));
  console.log("=== Pet-Friendly Experiences ===");
  console.log("Count:", pf.length);
  pf.forEach(e => console.log(e.id, "|", e.title));
})();
```

### 1D. Members-Only / Free / Verified Counts

```js
(function() {
  if (typeof EXPERIENCES_DB === "undefined") { console.error("EXPERIENCES_DB not loaded"); return; }
  const membersOnly = EXPERIENCES_DB.filter(e => e.members_only).length;
  const free        = EXPERIENCES_DB.filter(e => e.price === 0 || e.price === "0" || e.price === "Free").length;
  const verified    = EXPERIENCES_DB.filter(e => e.experience_verified).length;
  const unverified  = EXPERIENCES_DB.filter(e => !e.experience_verified).length;
  console.log("=== Status Counts ===");
  console.log("Members-Only:", membersOnly);
  console.log("Free (price=0):", free);
  console.log("Verified:", verified);
  console.log("Unverified (should be 0):", unverified);
})();
```

---

## SECTION 2 — SYNTAX ERROR DIAGNOSIS & FIX (GitHub API / shell)

### 2A. Find Next Syntax Error
Replace FILE_PATH with e.g. `app/wtm_experiences_db.js`

```sh
curl -s "https://raw.githubusercontent.com/sjhouston-alt/wtm-prototype/main/FILE_PATH" | node --check
```

### 2B. View Raw File Around a Line Number
Replace FILE_PATH and LINE_NUMBER.

```sh
curl -s "https://raw.githubusercontent.com/sjhouston-alt/wtm-prototype/main/FILE_PATH" | \
  awk "NR>=(LINE_NUMBER-20) && NR<=(LINE_NUMBER+20) {printf \"%d\t%s\n\", NR, \$0}"
```

### 2C. Targeted Line Edit With Commit (Python — GitHub Contents API)
**Step 1** — get current file SHA:

```sh
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/repos/sjhouston-alt/wtm-prototype/contents/FILE_PATH" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['sha'])"
```

**Step 2** — patch and commit. Replace OLD_TEXT, NEW_TEXT, FILE_PATH, FILE_SHA, COMMIT_MSG, GITHUB_TOKEN:

```python
import base64, json, urllib.request

TOKEN    = "GITHUB_TOKEN"
REPO     = "sjhouston-alt/wtm-prototype"
PATH     = "FILE_PATH"
SHA      = "FILE_SHA"
MSG      = "COMMIT_MSG"
OLD_TEXT = r"""OLD_TEXT"""
NEW_TEXT = r"""NEW_TEXT"""

raw_url  = f"https://raw.githubusercontent.com/{REPO}/main/{PATH}"
req      = urllib.request.Request(raw_url, headers={"Authorization": f"token {TOKEN}"})
original = urllib.request.urlopen(req).read().decode()

if OLD_TEXT not in original:
    print("ERROR: OLD_TEXT not found — check your text carefully")
    exit(1)

patched  = original.replace(OLD_TEXT, NEW_TEXT, 1)
encoded  = base64.b64encode(patched.encode()).decode()
payload  = json.dumps({"message": MSG, "content": encoded, "sha": SHA}).encode()
api_url  = f"https://api.github.com/repos/{REPO}/contents/{PATH}"
put_req  = urllib.request.Request(api_url, data=payload, method="PUT",
             headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"})
resp     = urllib.request.urlopen(put_req).read()
print("SUCCESS — commit:", json.loads(resp)["commit"]["sha"])
```

### 2D. Remove Misplaced EXP Entries From ADDONS_DB or COLLECTIONS
Replace FILE_PATH, FILE_SHA, COMMIT_MSG, GITHUB_TOKEN:

```python
import base64, json, re, urllib.request

TOKEN = "GITHUB_TOKEN"
REPO  = "sjhouston-alt/wtm-prototype"
PATH  = "FILE_PATH"
SHA   = "FILE_SHA"
MSG   = "COMMIT_MSG"

raw_url  = f"https://raw.githubusercontent.com/{REPO}/main/{PATH}"
req      = urllib.request.Request(raw_url, headers={"Authorization": f"token {TOKEN}"})
original = urllib.request.urlopen(req).read().decode()

# Remove any JS object block whose id starts with EXP followed by digits
cleaned = re.sub(
    r'\{[^{}]*?id:\s*["\'\']EXP\d+["\'\'][^{}]*?\},?\s*',
    '', original, flags=re.DOTALL
)

if cleaned == original:
    print("No EXP entries found — file unchanged")
    exit(0)

removed = len(re.findall(r'id:\s*["\'\']EXP\d+', original))
print(f"Removed {removed} EXP entry/entries")

encoded = base64.b64encode(cleaned.encode()).decode()
payload = json.dumps({"message": MSG, "content": encoded, "sha": SHA}).encode()
api_url = f"https://api.github.com/repos/{REPO}/contents/{PATH}"
put_req = urllib.request.Request(api_url, data=payload, method="PUT",
            headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"})
resp    = urllib.request.urlopen(put_req).read()
print("SUCCESS — commit:", json.loads(resp)["commit"]["sha"])
```

---

## SECTION 3 — FILE COMMITS (Python — GitHub Contents API)

### 3A. Add a Brand-New File
Replace FILE_PATH, FILE_CONTENT, COMMIT_MSG, GITHUB_TOKEN:

```python
import base64, json, urllib.request

TOKEN   = "GITHUB_TOKEN"
REPO    = "sjhouston-alt/wtm-prototype"
PATH    = "FILE_PATH"      # e.g. "app/wtm_new_screen.html"
MSG     = "COMMIT_MSG"
CONTENT = """FILE_CONTENT"""

encoded = base64.b64encode(CONTENT.encode()).decode()
payload = json.dumps({"message": MSG, "content": encoded}).encode()
api_url = f"https://api.github.com/repos/{REPO}/contents/{PATH}"
req     = urllib.request.Request(api_url, data=payload, method="PUT",
            headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"})
resp    = urllib.request.urlopen(req).read()
print("SUCCESS — commit:", json.loads(resp)["commit"]["sha"])
```

### 3B. Replace Entire File
Get SHA first (see 2C Step 1). Then replace FILE_PATH, FILE_SHA, NEW_CONTENT, COMMIT_MSG, GITHUB_TOKEN:

```python
import base64, json, urllib.request

TOKEN       = "GITHUB_TOKEN"
REPO        = "sjhouston-alt/wtm-prototype"
PATH        = "FILE_PATH"
SHA         = "FILE_SHA"
MSG         = "COMMIT_MSG"
NEW_CONTENT = """NEW_CONTENT"""

encoded = base64.b64encode(NEW_CONTENT.encode()).decode()
payload = json.dumps({"message": MSG, "content": encoded, "sha": SHA}).encode()
api_url = f"https://api.github.com/repos/{REPO}/contents/{PATH}"
req     = urllib.request.Request(api_url, data=payload, method="PUT",
            headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"})
resp    = urllib.request.urlopen(req).read()
print("SUCCESS — commit:", json.loads(resp)["commit"]["sha"])
```

### 3C. Append to End of File
Get SHA first (see 2C Step 1). Then replace FILE_PATH, FILE_SHA, APPEND_TEXT, COMMIT_MSG, GITHUB_TOKEN:

```python
import base64, json, urllib.request

TOKEN       = "GITHUB_TOKEN"
REPO        = "sjhouston-alt/wtm-prototype"
PATH        = "FILE_PATH"
SHA         = "FILE_SHA"
MSG         = "COMMIT_MSG"
APPEND_TEXT = """APPEND_TEXT"""

raw_url  = f"https://raw.githubusercontent.com/{REPO}/main/{PATH}"
req      = urllib.request.Request(raw_url, headers={"Authorization": f"token {TOKEN}"})
original = urllib.request.urlopen(req).read().decode()

combined = original.rstrip("\n") + "\n" + APPEND_TEXT + "\n"
encoded  = base64.b64encode(combined.encode()).decode()
payload  = json.dumps({"message": MSG, "content": encoded, "sha": SHA}).encode()
api_url  = f"https://api.github.com/repos/{REPO}/contents/{PATH}"
put_req  = urllib.request.Request(api_url, data=payload, method="PUT",
             headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"})
resp     = urllib.request.urlopen(put_req).read()
print("SUCCESS — commit:", json.loads(resp)["commit"]["sha"])
```

---

## SECTION 4 — GITHUB PAGES & REPO VERIFICATION

### 4A. Confirm Deployment Status

```sh
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/repos/sjhouston-alt/wtm-prototype/pages" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('Status:', d.get('status')); print('URL:', d.get('html_url')); print('Build:', d.get('build_type'))"
```

### 4B. Check File Tree

```sh
# Root
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/repos/sjhouston-alt/wtm-prototype/git/trees/main?recursive=0" | \
  python3 -c "import sys,json; [print(f['path']) for f in json.load(sys.stdin)['tree']]"

# /app folder
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/repos/sjhouston-alt/wtm-prototype/contents/app" | \
  python3 -c "import sys,json; [print(f['name']) for f in json.load(sys.stdin)]"

# /security folder
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/repos/sjhouston-alt/wtm-prototype/contents/security" | \
  python3 -c "import sys,json; [print(f['name']) for f in json.load(sys.stdin)]"
```

### 4C. Get Latest 3 Commits

```sh
curl -s -H "Authorization: token GITHUB_TOKEN" \
  "https://api.github.com/repos/sjhouston-alt/wtm-prototype/commits?per_page=3" | \
  python3 -c "
import sys, json
for c in json.load(sys.stdin):
    print(c['sha'][:7], c['commit']['author']['date'][:10], '|', c['commit']['message'].split(chr(10))[0])
"
```

---

## SECTION 5 — APP UI INTERACTION (Console — Live Site)
Run in console on https://sjhouston-alt.github.io/wtm-prototype/app/wtm_app.html

### 5A. Full Explore Walkthrough — Tap Each Category

```js
(function() {
  const categories = ["Dining","Water","Arts & Music","Adventure","Travel","Wellness","Nightlife"];
  let i = 0;
  function next() {
    if (i >= categories.length) { console.log("All categories tapped."); return; }
    const cat = categories[i++];
    console.log("Tapping category:", cat);
    const pills = Array.from(document.querySelectorAll(".category-pill, .filter-pill, [data-category]"));
    const pill  = pills.find(el => el.textContent.trim() === cat || el.dataset.category === cat);
    if (pill) { pill.click(); setTimeout(next, 600); }
    else { console.warn("Pill not found for:", cat); setTimeout(next, 300); }
  }
  next();
})();
```

### 5B. Booking Flow Smoke Test

```js
(function() {
  const checks = [
    { label: "Calendar",       sel: ".calendar-grid, [data-screen='booking'] .cal, #booking-calendar" },
    { label: "Time slots",     sel: ".time-slot, .slot-pill, [data-slot]" },
    { label: "Guest stepper",  sel: ".guest-stepper, .stepper-row, [data-guest-count]" },
    { label: "Running total",  sel: ".running-total, .price-total, #booking-total" },
    { label: "Book Now CTA",   sel: ".book-now-btn, .cta-book, [data-action='book']" },
    { label: "Add-on toggles", sel: ".addon-toggle, .addon-row input[type='checkbox']" }
  ];
  console.log("=== Booking Flow Smoke Test ===");
  checks.forEach(c => {
    const found = document.querySelector(c.sel);
    console.log((found ? "PASS" : "FAIL"), c.label, found ? "" : "(NOT FOUND)");
  });
})();
```

### 5C. Surprise Me Test

```js
(function() {
  const checks = [
    { label: "Vibe selector",   sel: ".vibe-selector, .vibe-pill, [data-vibe]" },
    { label: "Budget slider",   sel: "input[type='range'], .budget-slider" },
    { label: "When picker",     sel: ".when-picker, .when-pill, [data-when]" },
    { label: "Surprise Me CTA", sel: ".surprise-me-btn, [data-action='surprise'], .cta-surprise" },
    { label: "Reveal card",     sel: ".reveal-card, .surprise-result, .result-card" },
    { label: "Try Again btn",   sel: ".try-again-btn, [data-action='shuffle'], .btn-shuffle" }
  ];
  console.log("=== Surprise Me Smoke Test ===");
  checks.forEach(c => {
    const found = document.querySelector(c.sel);
    console.log((found ? "PASS" : "FAIL"), c.label, found ? "" : "(NOT FOUND)");
  });
  const cta = document.querySelector(".surprise-me-btn, [data-action='surprise'], .cta-surprise");
  if (cta) { cta.click(); console.log("Surprise Me CTA clicked."); }
  else { console.warn("Navigate to Surprise Me screen first."); }
})();
```

---

## SECTION 6 — EXPERIENCE DATA QA (Console — Live Site)

### 6A. Find Experiences Missing Required Fields

```js
(function() {
  if (typeof EXPERIENCES_DB === "undefined") { console.error("EXPERIENCES_DB not loaded"); return; }
  const REQUIRED = ["id","title","category","price","experience_verified","tags","description","host","location"];
  const issues = [];
  EXPERIENCES_DB.forEach(e => {
    const missing = REQUIRED.filter(f => e[f] === undefined || e[f] === null || e[f] === "");
    if (missing.length) issues.push({ id: e.id, title: e.title, missing });
  });
  console.log("=== Missing Required Fields ===");
  if (issues.length === 0) {
    console.log("All good — no missing fields.");
  } else {
    issues.forEach(i => console.warn(i.id, "|", i.title, "| missing:", i.missing.join(", ")));
    console.log("Total issues:", issues.length);
  }
})();
```

### 6B. Find Duplicate IDs

```js
(function() {
  if (typeof EXPERIENCES_DB === "undefined") { console.error("EXPERIENCES_DB not loaded"); return; }
  const seen = {}, dupes = [];
  EXPERIENCES_DB.forEach(e => {
    if (seen[e.id]) dupes.push(e.id);
    seen[e.id] = true;
  });
  console.log("=== Duplicate IDs ===");
  if (dupes.length === 0) { console.log("No duplicates found."); }
  else { console.error("DUPLICATES:", dupes.join(", ")); }
})();
```

### 6C. Inspect Any Single Experience by ID
Replace TARGET_ID with e.g. `"EXP001"`:

```js
(function() {
  const TARGET_ID = "TARGET_ID";
  if (typeof EXPERIENCES_DB === "undefined") { console.error("EXPERIENCES_DB not loaded"); return; }
  const exp = EXPERIENCES_DB.find(e => e.id === TARGET_ID);
  if (!exp) { console.error("Experience not found:", TARGET_ID); return; }
  console.log("=== Experience:", TARGET_ID, "===");
  Object.entries(exp).forEach(([k, v]) => console.log(k + ":", JSON.stringify(v)));
})();
```
