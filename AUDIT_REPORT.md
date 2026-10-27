# LawCypenLab v24 — Full Audit & Enhancement Report

**Scope:** Flask-based web security training lab (~8,680-line `app.py`, 149
templates, 348 routes). Everything below was verified against a live,
running instance — real HTTP requests, real browser screenshots, real
exploit payloads — not code review alone. All intentional vulnerabilities
(the point of the lab) were left untouched; everything listed here is an
unintentional bug or a genuine gap between what the backend does and what
the UI shows.

---

## 1. Startup & crash bugs

| # | Issue | Root cause | Fix |
|---|---|---|---|
| 1 | **App wouldn't start at all** | Two functions both named/routed `api_v0_crew` → `/api/v0/crew`. Flask refuses a duplicate endpoint name and raised `AssertionError` on boot. | Removed the stale duplicate; kept the complete Wave-27 implementation. |
| 2 | **`/go` open-redirect route silently dead** | Two different functions (`open_redirect`, `open_redirect_relay`) were both bound to the exact same path. Flask allows this (names differ) but only ever dispatches to whichever registered first — the second was permanently unreachable, even though the SSRF-chain lab's own docs point students at it. | Merged into one function; confirmed the SSRF-chain demo (`/station/ssrf-chain`) depends on exactly this endpoint. |
| 3 | `/setup/create-admin` crashed on reuse | Blank/duplicate username hit `sqlite3.IntegrityError` (UNIQUE constraint) with no try/except — not the CVE-2023-22515 behavior being taught (unauthenticated reachability), just a missing guard. | Wrapped in try/except, flashes an error instead of a 500. |
| 4 | `/api/teamcity/setup` crashed if no admin existed | `admin["id"]` on a `None` row → `TypeError`. Reachable in practice since the app's own admin panel lets you delete/demote the last admin. | Added `None` check, returns clean 404 JSON. |
| 5 | `/sshd/auth` (XZ backdoor demo) had the identical bug | Same unguarded `fetchone()` → subscript pattern as #4. | Same fix applied. |
| 6 | **7 endpoints crashed on non-numeric query params** | `int(request.args.get(...))` with no exception handling on `/api/export/messages`, `/ground-relay/session-check`, `/api/transfer/folder`, `/stream/rapid-reset`, `/api/audit-log`, `/h2/rapid-reset` (×2 params). `?limit=abc` → unhandled `ValueError` → 500. | Added a shared `_safe_int(value, default)` helper; the "no upper bound" vulnerability each route demonstrates is unchanged, it just no longer dies on garbage input. |

**How found:** fuzzed every one of the 348 routes with empty/garbage
payloads (GET and POST/PATCH/DELETE/PUT), then reproduced each crash in
isolation before and after the fix.

---

## 2. Backend/frontend wiring bugs

| # | Page | Problem | Fix |
|---|---|---|---|
| 7 | **Station Log Viewer** (`/logs`) | Template was entirely about a *different* vulnerability (CWE-117 log injection — had an explanatory hint box but **no input field at all**), while the real backend implements path traversal/LFI via `?file=`. The template also referenced an undefined `logs` variable instead of the `entries`/`fname`/`content` the route actually passed, so the 3 seeded log entries never displayed. | Rewrote the template to match the real backend: accurate CWE-22 framing, a working file-read form, and a real index table with working "Read" links. Verified the full exploit (`?file=../.env`) dumps real secrets end-to-end. |
| 8 | **Cloud SSRF/IMDS demo** (`/cloud/ssrf-demo`) | No dedicated template existed — it silently borrowed `star_charts.html` (a *different*, unrelated SSRF module's template). Visiting it showed "STAR CHARTS — EXTERNAL FEED FETCHER" with the wrong CWE, wrong narrative, zero mention of AWS IMDS. | Built a proper dedicated template (`cloud/ssrf-demo.html`, modeled on the sibling `k8s-ssrf.html`) with the real IMDS-specific content the backend already implements. Confirmed Star Charts itself renders unaffected. |
| 9 | **Satellite Contact Search** (`/satellite/contacts`) mislabeled its own query | Page header correctly says "XPath Injection" and the backend genuinely builds `./contact[callsign='...']` — but the static description box showed `(&(callsign=INPUT)(active=true))`, which is **LDAP filter syntax**, copy-pasted from the real LDAP Injection page (`/station/directory`). | Corrected the description to the real XPath predicate syntax. |
| 10 | **Dashboard** showing fake empty states | `/dashboard` always rendered "No tickets yet" / "No crew data" — the route never passed `recent_tickets` or `crew` to the template at all. The template also referenced `t.title`, a column that doesn't exist (`tickets.subject` is the real name). | Wired up the real queries; fixed the column-name typo; color-coded the status badge (open vs. closed). |
| 11 | **Mobile navigation completely unreachable** | CSS and JS both had full, working support for a hamburger menu (`#menu-toggle` click handler, slide-in sidebar, media queries) — but the `<button>` itself was never added to `base.html`. On any screen ≤560px, the sidebar was permanently hidden with no way to open it. | Added the button, a dimmed backdrop overlay, and extended the JS for `aria-expanded`, Escape-to-close, click-outside-to-close, and auto-close on navigation. Caught and fixed a second bug in my own first pass: the click-outside handler checked `e.target !== toggle`, but clicks land on the button's inner `<span>` bars, so open/close fired on the same click. |
| 12 | **7 broken sidebar nav-highlight mappings** | Routes passed an `active=` value that didn't match what the corresponding sidebar link checked for — found by diffing every `active=='x'` in `base.html` against every `active=` set in `app.py` (two passes needed: the codebase inconsistently mixes single/double quotes for the kwarg). Visiting these pages highlighted the *wrong* nearby link, or nothing at all. | Fixed: Docking Webhook (was highlighting Docking Requests), Spring4Shell/Log4Shell Analog (highlighted nothing), Email Change/ATO (highlighted Profile Settings), GraphQL v5 (highlighted API Portal), CTF Scoreboard (highlighted Challenge Board), Shellshock Analog (highlighted nothing — route passed no `active` at all). |
| 13 | **17 tables with zero CSS styling** across 16 templates | Bare `<table>` tags with no class, while every other table in the app uses `class="data-table"`. Measured computed `padding: 0px` on one (vs. `10px 13px` on a styled one) — confirmed genuinely unstyled, not just visually sparse. | Fixed all 17 occurrences in `admin/posts.html`, `admin/comments.html`, `admin/media.html`, `admin/crew_report.html`, `admin/plugins.html`, `admin/settings.html`, `admin/users.html`, `crew_directory.html`, `search.html`, `commander_dashboard.html`, `upload.html`, `directory_lookup.html`, `cargo.html`, `iot_devices.html`, `promotion_request.html` (×2), `support.html`. |
| 14 | Support-ticket table label collision | Status badge "OPEN" sat directly next to an action button also labeled "OPEN" (meaning "open this ticket to view it") — confusing whenever a ticket's actual status was open. | Renamed the action button to "View". |

---

## 3. Accessibility

- Added a themed `:focus-visible` ring (cyan, matching the design system)
  across buttons, links, and nav items that previously fell back to the
  browser's mismatched default outline.
- Confirmed inputs/textareas already had a proper custom focus treatment
  (border-color + box-shadow) — not a gap.

---

## 4. Robustness hardening (beyond the crash fixes above)

- Audited all 12 `open()` call sites in `app.py` for unguarded file I/O:
  11 were already safely wrapped in try/except or guarded by
  `os.path.exists`/`os.makedirs`; the one true gap (`keys/default.key`)
  reads a fixed file shipped in the repo, not user input, so it's not a
  real risk.
- Confirmed zero division-by-zero patterns, zero unguarded
  `request.files[...]` direct-dict access, zero unguarded
  `get_json(silent=True)` subscript patterns.
- Smoke-tested the two standalone raw-socket services
  (`modbus_sim.py`, `ground_antenna_sim.py`) with garbage input — both
  already had solid exception handling throughout; no changes needed.

---

## 5. Seed data (`seed.py`)

- Added 2 new crew members (`m.reyes`, security officer;
  `a.singh`, trainee) — total 8 seeded users, all cross-referenced
  through messages, notifications, audit log, and crew notes.
- Populated `ticket_replies` (previously always empty despite the table
  existing and the UI supporting it) with a real reply thread.
- Added more cargo items, a second docking request, a third CMS post,
  more notifications/audit entries.
- Verified referential integrity after every change: 13+ foreign-key
  style checks (every `*_id` column against its parent table),
  zero orphaned rows.
- Confirmed `satellite_contacts`'s seeded rows deliberately mirror a
  hardcoded in-memory XML blob used by the XPath-injection demo (XPath
  needs XML, not SQL rows) — intentional duplication, not a gap.

---

## 6. Documentation

- Added a **Maintenance log** section to `README.md` (plain-language
  changelog of every fix above).
- Corrected stale route-count/line-count stats.
- Updated the seeded-accounts tables in both `README.md` and
  `STUDENT_GUIDE.md` for the 2 new users.

---

## 7. Visual audit coverage

Every one of the app's ~110 HTML pages (everything except pure-JSON API
endpoints with no template) was opened in a real headless browser and
visually reviewed, including:

- Full desktop screenshots of every CVE-analog, VRT-lab, CTF, and core
  CRUD page.
- Mobile-width (375px) screenshots verifying the nav-drawer fix.
- Targeted interaction tests: clicking through the mobile menu
  open/close/Escape/backdrop/auto-close-on-nav-click states; exercising
  the fixed path-traversal exploit end-to-end (`../env` → real secrets
  dumped); confirming the SSRF-chain demo's documented attack
  (`/go?url=...`) matches the fixed `/go` route's live behavior.
- Two apparent "faded/blank page" screenshots were investigated and
  traced to headless-Chromium fade-in-transition timing, confirmed via
  computed-style checks (`opacity: 1`, correct colors) — not real bugs.

---

## 8. Verification methodology

Every fix in this report was confirmed with this cycle, every time:

1. **Reproduce the bug first** (crash, wrong render, wrong highlight,
   wrong exploit target) against the *unpatched* code.
2. Apply the fix.
3. **Re-run the exact same reproduction** and confirm it's resolved.
4. Full regression sweep: all 348 routes (268 GET, 184
   POST/PATCH/DELETE/PUT — 452 total requests) hit both anonymously and
   authenticated as `admin`, checking for any 5xx response.
5. Fresh `python3 seed.py` + fresh boot before shipping, so the
   delivered zip's database reflects none of the test-session side
   effects (e.g. the intentional `/zerologon` vuln blanking the admin
   password when fuzzed with empty POST data — expected lab behavior,
   not a bug, but reseeded regardless so the shipped state is clean).

**Final state:** syntax-clean, 0/452 requests return a 5xx error,
login/register/logout flow confirmed working, all intentional
vulnerabilities confirmed still fully functional and unmodified.
