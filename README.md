# LawCypenLab :: AEGIS STATION

An intentionally vulnerable, space-station-themed web application for
security training, CTF-style practice, and demo material — built with
Flask + SQLite and a custom "orbital ops" HUD interface.

> ⚠️ **FOR AUTHORIZED SECURITY TRAINING / TESTING USE ONLY.**
> This application is deliberately insecure — hardcoded secrets, a
> backdoor admin login, SQL injection, remote code execution via the
> plugin uploader, and more, all placed on purpose. Run it **only** on
> an isolated VM, container, or lab network you control. Never deploy
> it to a shared host, a cloud instance with a public IP, or any
> network you don't fully own. Never reuse any of its code patterns
> (raw SQL string interpolation, `pickle.loads` on user input, `debug=True`
> in production, etc.) in real software.

## Maintenance log

This copy has been through a syntax/logic audit and a round of
hardening and data enrichment, independent of the intentional
vulnerabilities (those are untouched — see the vuln tables below).
Everything here was verified by booting the app, crawling every
route, and re-seeding from scratch.

**Fixed — app wouldn't start or would crash on normal use:**
- Two functions were both named/routed `api_v0_crew` →
  `/api/v0/crew`; Flask refuses to register a duplicate endpoint name
  and the app failed to start at all. The stale duplicate was removed.
- Two different functions (`open_redirect`, `open_redirect_relay`)
  were both bound to the exact same `/go` path. Flask allows this
  (the names differ) but only ever dispatches to whichever was
  registered first, so the second was permanently dead code — even
  though the SSRF-chain lab's own docs point students at it. Merged
  into one.
- `/setup/create-admin` — a blank or repeated username crashed the
  app with an unhandled `sqlite3.IntegrityError` (UNIQUE constraint).
  Not the CVE-2023-22515 behavior the route demonstrates (reachability
  with no auth) — just a missing try/except. Now flashes an error
  instead.
- `/api/teamcity/setup` and `/sshd/auth` (XZ backdoor analog) both
  assumed an admin account always exists; if the last admin is ever
  deleted or demoted — which the app's own admin panel allows — the
  lookup returns `None` and indexing it crashed with `TypeError`. Both
  now return a clean error response instead.
- Seven query-param-driven `int(...)` conversions
  (`/api/export/messages?limit=`, `/ground-relay/session-check`,
  `/api/transfer/folder`, `/stream/rapid-reset`, `/api/audit-log`,
  `/h2/rapid-reset`) crashed with a 500 on any non-numeric value.
  Replaced with a shared `_safe_int()` helper that falls back to the
  existing default instead of raising — the unbounded-input behavior
  each route is meant to demonstrate is unchanged, it just no longer
  dies on `?limit=abc`.

All of the above were confirmed broken first (reproduced the exact
crash), then fixed, then re-confirmed clean with the same request.

**Checked and found to be working as designed (not bugs):** ~20
pyflakes warnings (unused variables/imports) were reviewed individually
— every one is either an intentionally-unused value that *is* the
vulnerability being taught (e.g. a decoded JWT payload nothing ever
checks) or a harmless leftover import. `satellite_contacts` in
`schema.sql` looks unused from `app.py` alone but is intentionally
mirrored into a static in-memory XML blob for the XPath-injection demo
(XPath needs XML, not SQL rows) — the seeded rows and the XML match
1:1.

## Setup

### Option A — Docker (recommended, isolated by default)

```bash
docker compose up --build
```

Browse to `http://127.0.0.1:5000`. The compose file binds only to
`127.0.0.1` on purpose — see the comments in `docker-compose.yml`
before changing that.

### Option B — local Python

```bash
cd lawcypenlab
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
python3 seed.py      # creates instance/aegis.db with sample crew/data
python3 app.py         # serves on http://127.0.0.1:5000
```

Re-run `python3 seed.py` any time to reset the database to a clean
starting state (it drops and recreates all tables).

## Seeded accounts

| Username | Password    | Role    |
|----------|-------------|---------|
| admin    | aegis2024   | admin   |
| r.solis  | password1   | officer |
| k.mbeki  | starfall99  | crew    |
| t.okafor | letmein     | crew    |
| j.vance  | orbit2023   | crew    |
| m.reyes  | security1   | officer |
| a.singh  | trainee2024 | crew    |
| guest    | guest       | crew    |

The admin console lives at `/admin/login` — it's a separate,
independently-weak login from the crew login at `/login`.

`seed.py` also populates sample messages, a multi-reply support
ticket thread (`/support/1`), two docking requests, three CMS posts,
and cross-referencing notifications/audit-log/crew-notes entries for
every seeded account, so every page has real content to look at on
first run rather than empty states.

## Layout

```
app.py              Flask app — all routes live here, in order:
                     auth → crew/dashboard → station systems →
                     comms/tickets/upload/settings → JSON API →
                     CMS (public "Ops Board" + /admin console)
schema.sql           SQLite schema
seed.py               Resets and seeds the database
templates/            Crew-facing pages (dark HUD theme)
templates/admin/       Admin console pages
static/css/style.css  Full stylesheet (design tokens at the top)
var_logs/              Sample log files (used by the log viewer)
plugins_store/         Where uploaded CMS plugins land
uploads/                Where crew file uploads land
.env                    Sample "leaked" secrets file (traversal target)
```

Every vulnerable code path is marked inline in `app.py` with a
`# --- VULN: ... ---` comment explaining the bug and why it's there —
useful if you're adapting, extending, or walking students through the
source directly, without needing a separate answer key.

## Satellite / ICS-SCADA / IoT module

A second wave of routes leans into OT-flavored bugs:

- `/uplink` — **no auth at all** (missing `@login_required`); its
  "checksum expression" field runs through raw `eval()` on user input.
- `/scada` — PLC-style register read/write with no role separation
  and no bounds checking — any crew role can push the reactor core
  temperature register out of safe range.
- `/iot/devices` + `/iot/devices/<id>/firmware` — device fleet with
  plaintext default credentials, plus a firmware "validator" upload
  that auto-executes the moment it lands (no manual run step, unlike
  the CMS plugin loader).
- `/api/telemetry` — live station + SCADA telemetry, no
  authentication, and a misconfigured CORS response
  (`Access-Control-Allow-Origin: *` + `Allow-Credentials: true`
  together).
- `/debug/bundle` — any logged-in crew member can download a zip of
  the entire application directory, `.env` and live SQLite DB
  included.
- `/field-terminal/login?sid=...` — accepts and pins a caller-supplied
  session id (session fixation).
- `/ground-station/tle` — "orbital elements" upload parsed with
  `yaml.load(..., Loader=yaml.UnsafeLoader)` — insecure deserialization,
  a YAML-flavored sibling of the pickle bug in Backup/Restore.
- `/api/iot/ota/<device_id>` — unauthenticated firmware-over-the-air
  push endpoint; no signature check on the uploaded image.
- `/kiosk/login` — a second login form with distinct "no such crew
  ID" vs. "wrong passphrase" errors (user enumeration).
- `/api/docking/<id>` — same BOLA pattern as `/api/crew/<id>`, applied
  to docking requests.
- `/reports/generate` — Server-Side Template Injection: the crew's
  "report template" is rendered with `render_template_string()`
  directly, so `{{ config.SECRET_KEY }}` or a `__class__.__mro__`
  gadget chain runs server-side, not just the intended `{{ user }}`
  placeholder.
- `/ground-control/*` — a second, separately-authenticated persona
  (linked from the bottom of the main login page). A single hardcoded
  station key (`GC-STATIC-KEY-0001`) grants full access — same key
  for every operator, never rotated, accepted both via a login form
  *and* silently via an `X-Station-Key` header with no session at
  all. From there, `/ground-control/command` issues destructive
  satellite directives with no confirmation step, no two-person rule,
  and no audit trail.
- `/crew` — a client-side, **DOM-based** XSS: a `?welcome=` query
  param is written into `innerHTML` entirely in JavaScript, so it's
  invisible to any server-side output-encoding review (e.g.
  `/crew?welcome=<img src=x onerror=alert(document.cookie)>`).
- `/login` — a rate limiter exists (5 failed attempts / 60s), but it
  keys off a client-supplied `X-Forwarded-For` header with no reverse
  proxy actually setting it, so any client resets their own lockout
  by sending a new made-up value on every request.
- `/tools/callsign-validate` — a **ReDoS**: the validation regex has a
  nested quantifier (`([A-Za-z0-9]+)+`) that backtracks exponentially
  on non-matching input. Confirmed: a 29-char payload took ~11s to
  evaluate, 30 chars took ~45s — each extra character roughly
  quadruples the time. Test cautiously; don't push payloads much
  longer than ~30 characters unless you want the worker thread to
  hang for a very long time.

## Raw-socket ICS simulator (separate from the web app)

`modbus_sim.py` is a standalone, plaintext, **unauthenticated** TCP
service on port 5502 speaking a small Modbus-flavored register
protocol — useful for practicing raw network-protocol interaction
against an ICS-style target rather than only HTTP. Run it alongside
(or instead of) the web app:

```bash
python3 modbus_sim.py
# then, in another terminal:
nc 127.0.0.1 5502
> HELP
> LIST
> READ reactor_core_temp_c
> WRITE reactor_core_temp_c 9999
> DUMP
```

No auth, no encryption, no bounds checking on writes, no audit log —
see the docstring at the top of the file for the full vuln summary.
It is not wired into `docker-compose.yml`; run it directly with
Python if you want it available.

## Wave 6 — extended threat surface

- `/go?url=...` — **open redirect**, no allow-list on the target.
- `/admin/media/import-archive` — **zip slip**: archive entry names
  are joined onto the upload directory with no path containment
  check. Confirmed: an entry named `../../zipslip_proof.txt` wrote a
  file two directories above `uploads/`, outside the project entirely.
- `/cargo/claim/<id>` — a **race condition / TOCTOU (lost update)**.
  Twenty concurrent claims against a restricted item with quantity 12
  all returned `"claimed": true`, but the database only reflects a
  single decrement (each request read the same stale quantity and
  overwrote the others' writes) — 19 of 20 "confirmed" claims were
  never actually recorded.
- `/directory/lookup` — an **LDAP-style filter injection**: the search
  filter is built as a raw Python boolean expression from user input
  and evaluated with `eval()`. A crafted crew ID bypasses the intended
  exact-match-only filter and dumps every directory record, including
  ones with `ROOT` clearance that the filter is meant to exclude.
- `/api/graphql` — **GraphQL-style introspection** left enabled with
  no auth, handing back the full internal schema (field and mutation
  names never exposed in the UI, including `password_hash` and
  `api_token`).
- `/clickjack-demo` + `clickjack_poc.html` (project root) — the app
  never sets `X-Frame-Options` or `frame-ancestors` anywhere. The
  standalone PoC file frames the live Airlock page under a decoy
  button; open it directly in a browser (not through Flask) while
  logged into the app in another tab.
- `/relay/check-cert` — **improper certificate validation** (CWE-295):
  `requests.get(..., verify=False)`. Confirmed against a local
  self-signed HTTPS server: plain `requests.get()` correctly rejects
  the cert, but this endpoint connects anyway.
- `/api/profile` (PATCH) — a **second, JSON-based mass-assignment**
  surface distinct from the form-based one: the request body is
  merged straight into the user's row, column names included. Chained
  end-to-end: `guest`/`guest` → `PATCH /api/profile` with
  `{"is_admin": 1, "role": "admin"}` → `guest` can then log into
  `/admin/login` and reach the full CMS console, secrets and all.

## Interface

The whole app shares one visual system (`static/css/style.css` +
`static/js/app.js`), so this applies everywhere at once:

- An ambient animated starfield behind every page (`<canvas id="starfield">`,
  respects `prefers-reduced-motion` — draws a single static frame instead
  of animating if the user has that set).
- A `⌘K` / `Ctrl+K` **command palette** that indexes whatever nav links
  are present on the current page — type to filter, arrow keys + Enter
  to jump. Click the "⌘K quick nav" chip in the top bar, or just press
  the shortcut.
- A thin progress bar across the top on every navigation/form submit.
- Panels fade/lift in on load, glow on hover, and buttons get a subtle
  lift + glow on hover/focus; everything above respects
  `prefers-reduced-motion`.

## Wave 7 — CSV injection, blind SSRF, API excessive exposure

- `/cargo/<id>/note` + `/cargo/export.csv` — any crew member can set a
  cargo item's description to anything, and the CSV export writes it
  out with no leading-character neutralization. Confirmed: a
  description starting with `=cmd|'/c calc'!A1` lands in the exported
  CSV verbatim — a spreadsheet app treats it as a live formula the
  moment someone opens the file (**CSV/Formula Injection**).
- `/docking/webhook` — any crew member can register a callback URL
  that the **server itself** POSTs to whenever *any* docking request
  changes status (not just their own). Confirmed against a local
  listener: registering `http://127.0.0.1:9999/callback` and then
  approving a docking request produced a real outbound POST from the
  Flask process carrying the status-change payload — a **blind/stored
  SSRF** with no response ever shown back to the registrant.
- `/api/users/<id>/full` — any valid crew JWT returns the **entire
  raw user row**, including `password_hash` and `api_token`, fields
  the UI never surfaces (**Excessive Data Exposure**, API3:2019).
- `/api/admin/users` — meant to be admin-only, but only checks that
  the bearer token is *valid*, never that the role is admin. Confirmed:
  an ordinary crew login token pulls the full user table, hashes and
  tokens included (**Broken Function Level Authorization**, API5:2019).
- `/api/export/messages?limit=` — no upper bound on the client-supplied
  limit. Confirmed against a 202-row table: `limit=5` returns 5,
  `limit=999999` returns all 202 in one response
  (**Unrestricted Resource Consumption**, API4:2019).

## Wave 8 — parameter pollution, reflected file download, referer auth, workflow escalation

- `/tools/hpp-demo` — **HTTP Parameter Pollution**: the form submits
  `role` twice. `request.form.get()` (used for the "visible" check)
  silently returns only the first value, while the actual grant uses
  the last value via `getlist()`. Confirmed: submitting
  `role=crew&role=admin` shows `check_passed: true` (checked value
  `"crew"`) but `value_actually_granted: "admin"`.
- `/api/export/profile?filename=&callback=` — **Reflected File
  Download**: both the download filename and a JSONP-style callback
  wrapper are taken from the query string with no validation.
  Confirmed: `filename=profile.bat&callback=@echo off && echo PWNED`
  produces a downloadable file named `profile.bat` whose content
  starts with `@echo off && echo PWNED(...)` — something that looks
  like the user's own profile export but is attacker-authored content.
- `/internal/ops-summary` — trusts the `Referer` header instead of a
  session to decide whether a request "came from inside the station"
  (CWE-293). Confirmed: no `Referer` → 403; a trivially spoofed
  `Referer: http://<same-host>/anything` → 200 with internal stats.
- `/promotions/request` + `/promotions/<id>/approve` — a **workflow-
  logic privilege escalation**: nothing stops the same account from
  submitting a promotion request and then approving it themselves.
  Confirmed end-to-end: `guest` (role `crew`) requested `admin`,
  approved their own request, and the database now shows `guest` as
  `admin`.

## Wave 9 — Station Commander: a fourth privilege tier

A longer escalation ladder now exists: **crew → officer → admin →
commander**, and the top tier is reachable through a fundamentally
different (and simpler) flaw than anything below it.

- `/commander/succession` — the entire "emergency succession
  protocol" is one self-attestation checkbox with no verification
  against rank, seniority, or any record. Ticking it sets a bare,
  **unsigned** cookie (`acting_commander=1`) — no JWT, no session, no
  cryptography of any kind.
- `/commander/dashboard` + `/commander/override` — confirmed reachable
  by a client that supplies `Cookie: acting_commander=1` with **no
  login at all** (`commander_required` never checks for a session,
  unlike `login_required` elsewhere). From there, a "Wipe Audit Log"
  directive clears the in-memory commander action log entirely.
- The tier is also a case study in **integration gaps**: `/admin/`
  and `/ground-control/` predate Commander and were never updated to
  recognize it, so commander access doesn't carry over to either —
  confirmed by testing `/admin/` with a valid commander cookie and
  getting redirected to the ordinary admin login. A privilege tier
  bolted on after the fact, without updating the access-control
  checks that came before it, is a very real bug class on its own.

## Wave 10 — GPS spoofing, improper signature verification, replay attack

- `/nav/gps-sync` — **GPS/telemetry spoofing acceptance**: no
  plausibility or kinematic check on any field. Confirmed: submitting
  `lat=89.999&lon=179.999&alt_km=99999&velocity_kms=500000` in one
  request "teleports" the station instantly to a physically
  impossible position and velocity, accepted exactly like a real
  gradual orbital update.
- `/iot/devices/<id>/firmware-signed` — **improper signature
  verification** (CWE-347): looks like real signed-firmware
  validation (there's a signature field, there's a "Verify" step),
  but the check only confirms the field is non-empty. Confirmed:
  the literal string `totally-not-a-real-signature-x` is accepted
  as a valid signature with no cryptographic check against the
  firmware bytes at all.
- `ground_antenna_sim.py` — a **second, independent raw-socket
  service** (UDP, port 5503) speaking a small ground-antenna control
  protocol, demonstrating a **replay attack** distinct from anything
  else in the lab: no nonce, timestamp, or sequence number on any
  command. Confirmed: capturing one legitimate `SLEW` command and
  resending the *exact same bytes* twice more was accepted and
  actioned identically all three times — the server has no way to
  tell a replay from an original. Run it alongside `modbus_sim.py` for
  two independent OT-protocol targets with two different flaw
  classes (no auth at all, vs. a static shared key with no replay
  protection).

## Wave 11 — second-order SQL injection, JWT "kid" header injection

- `/admin/crew-report` — a **second-order SQL injection**. Crew bios
  are stored perfectly safely via a parameterized query in
  `/profile/settings` — nothing happens at save time no matter what
  you put in the bio. This later admin-only report, added separately,
  pulls those stored bios back out and concatenates them into a fresh
  query with an f-string. Confirmed end-to-end: `guest` set their bio
  to `x' UNION SELECT id,username,password_hash,role FROM users WHERE
  username='admin' --`, nothing happened on save — then the *next
  time an admin generated the report*, it returned the admin
  account's raw `password_hash` in the results. The trigger and the
  payload are in two completely different requests, by two different
  users, at two different points in time.
- `/api/token-v2` + `/api/crew-v2/<id>` — **JWT "kid" header
  injection**. Legitimate tokens are signed using the key file named
  in their own `kid` header (`default.key`), but the verification
  side never restricts `kid` to that one file — it's joined onto the
  keys directory with no path sanitization. Confirmed, chained
  through the ordinary file upload feature: uploaded a file
  containing `forged-secret-xyz` via `/upload`, then self-signed a
  token with `kid: "../uploads/notes.txt"` using that same string as
  the HMAC key. The server read the uploaded file's own content back
  out as the "trusted" verification key, validated the forged
  signature, and returned the full admin profile (including
  `clearance_notes`) for a token nobody with the real secret ever
  issued.

## Wave 12 — config injection, integer underflow, cache deception, account-linking CSRF

- `/preferences/update` — **configuration injection via unrestricted
  deep merge**. Meant only to let a crew member set their own display
  theme/motion prefs, but it recursively merges the *entire*
  client-supplied JSON body into one shared, global config object with
  no key allow-list. Confirmed: an ordinary crew member's "preference
  update" containing `{"security": {"debug_mode": true,
  "signature_enforcement": false}}` flipped both flags station-wide,
  immediately visible to any client (even unauthenticated) via
  `/system/config-status`.
- `/cargo/claim-custom/<id>` — a **business-logic integer underflow**.
  The claim amount is subtracted from stock with no check that it's
  positive. Confirmed: submitting `amount=-500` against a restricted
  narcotics item with stock 12 raised it to 512 — the exact inverse of
  "claiming reduces stock," letting a crew member manufacture
  unlimited restricted cargo.
- `/profile/settings/report<ext>` (e.g. `.css`, `.pdf`) — **web cache
  deception**. A static-looking extension is meant to make a reverse
  proxy treat this as a cacheable asset; the in-app cache lookup here
  happens *before* any auth check, keyed only on the bare path.
  Confirmed: after the victim (`guest`) visited their own
  `/profile/settings/report.css` once, a completely logged-out second
  client requesting that exact path got the victim's private settings
  (email, bio) served back verbatim, cache hit and all.
- `/federation/connect` + `/federation/callback` — **OAuth-style
  account-linking CSRF**: no `state` parameter or any other anti-CSRF
  token ties the callback to the session that started the flow.
  Confirmed: a crafted link
  (`/federation/callback?external_id=attacker-controlled-mc-id-666`)
  opened by an already-logged-in victim silently linked the
  attacker's external identity to the victim's account — no
  confirmation step, no state check, nothing to stop it.

## Wave 12 — config injection, integer underflow, cache deception, account-linking CSRF

- `/preferences/update` + `/system/config-status` — **configuration
  injection via unrestricted deep merge**. The endpoint is meant only
  to set a crew member's own display prefs, but it recursively merges
  the *entire* client JSON body into one shared, global config object
  with no key allow-list. Confirmed: a `guest` request that also
  included `{"security": {"debug_mode": true, "signature_enforcement":
  false}}` flipped those station-wide flags immediately, visible to
  everyone via the unauthenticated `/system/config-status` read-back.
- `/cargo/claim-custom/<id>` — a **business-logic integer underflow**.
  `amount` is subtracted from stock with no sign or bound check.
  Confirmed: submitting `amount=-500` against a restricted item
  raised its quantity from 12 to **512** instead of depleting it.
- `/profile/settings/report<ext>` — **web cache deception**. A
  static-looking suffix (`.css`) is treated as cacheable, and the
  cache is keyed only by path — checked *before* any auth check — with
  no per-user variation. Confirmed: after a logged-in victim
  (`k.mbeki`) visited their own `/profile/settings/report.css`, a
  second request to that exact path with **no session at all**
  received the victim's cached email and bio straight back.
- `/federation/connect` + `/federation/callback` — **OAuth-style
  account-linking CSRF**: no `state` parameter or any other token ties
  the callback to the session that started it. Confirmed end-to-end:
  an attacker started the link flow with their own external ID,
  captured the resulting callback URL, and got a different logged-in
  victim to load it — the victim's account ended up linked to the
  attacker's chosen external identity with no confirmation step.

## Wave 13 — lying-in-wait XSS, bay double-booking, token reuse, entity-expansion DoS

- `/admin/crew-bios-digest` — a **second-order, "lying in wait" stored
  XSS**, technically distinct from the second-order SQLi in
  `/admin/crew-report` even though the narrative shape is similar. A
  crew member's bio (set through the safe, parameterized
  `/profile/settings`) renders escaped everywhere else in the app —
  their own profile page included — but this one digest page renders
  it with `|safe`. Confirmed end-to-end: a `<script>` bio payload sat
  inert in the database, showed as literal escaped text on the
  crew member's own profile, and only fired as live, executing script
  when an admin opened this specific page — in the admin's own
  authenticated session.
- `/docking/<id>/assign-bay` — **double-booking**: approving a
  request into a bay never checks whether that bay already holds
  another approved request. Confirmed: two separate vessels were both
  approved into "Bay 2" simultaneously, with the second assignment's
  own response showing the first vessel still sitting there.
- `/reset-password/<token>` — **token reuse** (CWE-294): the token
  lookup never filters on the `used` flag it dutifully sets after a
  successful reset. Confirmed: the exact same token reset the same
  account's password twice, and the second (supposedly-already-used)
  reset's new password logged in successfully.
- `/telemetry/import` — the existing XXE endpoint also supports a
  **billion-laughs-style entity expansion DoS**, a different
  exploitation of the same `resolve_entities=True` parser than the
  file-read technique documented earlier. Confirmed at a deliberately
  tiny, safe scale: 3 nested levels of 10x entity repetition turned a
  ~200-byte payload into 6,020 characters of output — a few more
  nesting levels from the same tiny input would produce gigabytes.

## Wave 14 — unauthenticated real-time stream, missing re-auth, session non-invalidation

- `/stream/telemetry` — a Server-Sent Events endpoint (a different
  transport than every other route in this lab) that broadcasts live
  station telemetry — including current SCADA register values — with
  **no authentication at all**. Confirmed: a plain `curl` with no
  cookies received the full live stream. Real-time/streaming
  endpoints are easy to miss in a review that only walks conventional
  request/response routes.
- `/profile/change-password` — **missing re-authentication for a
  sensitive action**: the form has no "current password" field at
  all, so anyone riding along on a valid session (a stolen cookie, an
  XSS payload from elsewhere in this lab) can permanently take over
  the account. Confirmed end-to-end with two separate logged-in
  sessions for the same account ("device A" and "device B"): device A
  changed the password with no proof of the old one, the old password
  stopped working immediately — and **device B's already-established
  session kept working perfectly afterward** (CWE-613, Insufficient
  Session Expiration). Since sessions here are stateless signed
  cookies with no server-side store, there is nothing to revoke even
  in principle — every other logged-in device stays logged in,
  indefinitely, completely unaffected by the account's password
  changing underneath it.

## Wave 15 — client-side-only authorization, ORDER BY injection, unaudited impersonation

- `/station/self-destruct` — **client-side-only authorization**, one of
  the most common real-world access control bugs precisely because the
  UI looks correctly locked down. The "Initiate Sequence" button is
  genuinely `disabled` in the rendered HTML for any non-commander role
  — confirmed present in the markup for a `crew`-role account — but
  the route performs *no* server-side role check at all. A direct
  POST (devtools, curl, anything) triggers it regardless.
- `/crew/sorted?sort=` — **SQL injection via `ORDER BY`**, a
  technically distinct injection point from every WHERE-clause SQLi
  elsewhere in this lab (most drivers, sqlite3 included, can't
  parameterize column names or raw ORDER BY expressions, which is
  exactly why real codebases reach for string formatting here and why
  this bug class persists in practice). Confirmed the injection point
  with a deliberately broken payload (raw SQL syntax error reflected
  back), then confirmed genuine **boolean-based blind extraction**: a
  `CASE WHEN (subquery)='f' THEN u.id ELSE u.username END` sort
  expression produced a different row order for a correct first-character
  guess of the admin's password hash than for an incorrect one — no
  UNION needed, exploitable one character at a time.
- `/admin/users/<id>/impersonate` — **unaudited admin impersonation**:
  one click logs the admin into any account with no confirmation, no
  audit log entry, no time limit, no visible notice to the
  impersonated user, and no restriction on which accounts (including
  other admins) can be targeted. Confirmed: an admin session became a
  fully authenticated `r.solis` session instantly, with nothing
  recorded anywhere.

## CVE Analog Lab (`/cve-lab`)

Flask/Python reproductions of real, publicly-disclosed CVE vulnerability
patterns. These are not literal copies of the original product code —
each reproduces the same underlying bug *class* inside this app,
framed and labelled honestly as an analog, not a direct exploit of
the named product. A dedicated hub page at `/cve-lab` explains each one
and lets you run them with one click. The API-only endpoints (`/tools/*`,
`/api/*`, `/vpn/*`, etc.) can also be reached directly from the hub page
via JavaScript fetch calls in the browser.

| CVE | Pattern reproduced | Route |
|---|---|---|
| CVE-2021-44228 (Log4Shell) | Expression injection via `${eval:...}` / `${lookup:...}` in a log formatter | `/tools/log-console` |
| CVE-2022-22965 (Spring4Shell) | Unrestricted dotted-path data binding walks Python's live object graph | `/tools/settings-binder` |
| CVE-2017-5638 (Struts S2-045) | Non-MIME Content-Type header evaluated as Python expression, pre-auth | `/tools/upload-classify` |
| CVE-2021-41773 (Apache HTT Server) | Traversal check fires on literal `..` but decodes the path afterwards (blocked by Werkzeug's own normalization in this server — the code is vulnerable; a non-normalising client/proxy exercises it) | `/media2/view?path=` |
| CVE-2023-34362 (MOVEit Transfer) | Unauthenticated folder-listing API builds raw SQL from a query param | `/api/transfer/folder?folder=` |
| CVE-2023-4966 (Citrix Bleed) | Over-read of a shared buffer leaks the previous request's session token | `/ground-relay/session-check?expected_len=N` |
| CVE-2023-22515 (Confluence) | First-run admin-creation setup endpoint reachable on a live, already-configured deployment | `/setup/create-admin` |
| CVE-2024-3400 (PAN-OS GlobalProtect) | Session ID used unsanitised in both a file path and a shell command | `/vpn/session-init` |
| CVE-2023-38831 (WinRAR) | Extension check inspects first dot-segment; OS honours the final one | `/upload/firmware-package` |
| CVE-2021-26855 (ProxyLogon chain) | SSRF + arbitrary file write chained together | `/proxy/fetch-and-store` |
| CVE-2022-1388 (F5 BIG-IP) | Presence (not validity) of an internal routing header bypasses all auth | `/api/icontrol/system-info` |
| CVE-2023-23752 (Joomla!) | `?list=all` parameter bypasses access check on a public API endpoint | `/api/public/station-list` |

**Batch 3 (2022-2024):**

| CVE | Pattern | Route |
|---|---|---|
| CVE-2023-35078 (Ivanti MobileIron) | API path prefix excluded from auth filter entirely | `/api/cve-batch3/ivanti-bypass` |
| CVE-2023-2868 (Barracuda ESG) | Filename in file-write + shell command, pre-auth | `/cgi-bin/submit.cgi` |
| CVE-2023-35036 (MOVEit Transfer) | `user_id` alone issues a full session token | `/human.aspx` |
| CVE-2023-3519 (Citrix ADC) | OpenID discovery endpoint evals `redirect_uri` as code | `/citrix/oauth/idp/.well-known/openid-configuration` |
| CVE-2024-28255 (OpenMetadata) | Metadata query filter expression eval'd directly | `/api/openmetadata/query` |
| CVE-2024-1709 (ScreenConnect) | Setup wizard creates admin with zero verification | `/api/screenconnect/setup` |
| CVE-2023-42793 (TeamCity) | Unauthenticated REST endpoint creates admin tokens | `/api/teamcity/setup` |
| CVE-2021-21985 (VMware vRealize) | Analytics collector makes server-side requests to any URL | `/api/vrealize/analytics` |
| CVE-2024-23897 (Jenkins) | `@filename` in workspace path reads arbitrary files | `/jenkins/workspace/@<path>` |
| CVE-2022-36804 (Bitbucket) | Branch name injected into shell command | `/api/bitbucket/mirror/repo` |

**Batch 4 (Supply chain, auth bypass, protocol):**

| CVE | Pattern | Route |
|---|---|---|
| CVE-2024-3094 (XZ Utils backdoor) | Magic bytes in pubkey field bypass SSH auth | `/sshd/auth` |
| SAML Wrapping (SolarWinds Orion analog) | Outer signature validated, Assertion content never verified | `/saml/consume` |
| CVE-2023-46604 (Apache ActiveMQ) | Pre-auth pickle deserialization on message broker | `/activemq/message` |
| CVE-2023-20198 (Cisco IOS XE) | Single unauthenticated GET creates privilege-15 admin | `/webui/logoutconfirm.html` |
| CVE-2022-40684 (Fortinet FortiOS) | Unauthenticated API config endpoint, path traversal | `/api/fortios/config` |
| CVE-2023-26360 (Adobe ColdFusion) | Pre-auth YAML unsafe deserialization on AMF endpoint | `/cfide/main/ide.cfm` |
| CVE-2023-43770 (Roundcube) | Webmail renders message bodies with `\|safe` — persistent XSS | `/mail/rcube/` |
| CVE-2018-7600 (Drupalgeddon 2) | `#post_render_callback` form key eval'd as code | `/drupal/user/register` |
| CVE-2020-1472 (ZeroLogon) | All-zero challenge response accepted, resets admin password | `/api/netlogon/auth` |
| CVE-2021-22005 (VMware ESXi) | Unauthenticated hypervisor API with hidden `?exec=` parameter | `/api/esxi/vm-list` |

## Notes for extending it

- The `/admin` plugin loader (`admin_plugin_run`) dynamically imports
  and executes whatever `.py` file was uploaded — that's the
  intentional RCE path. Keep this contained to an isolated lab.
- `debug=True` is on by default (leaves the interactive Werkzeug
  debugger reachable on unhandled exceptions) — the auto-*reloader* is
  deliberately turned off, though, since it would otherwise restart
  the dev server every time a file lands in `uploads/` or
  `plugins_store/`.
- All "weak" values (password hashing, JWT secret, admin override
  code, session secret) are defined near the top of `app.py` if you
  want to swap them for a different lab scenario.

## Wave 24 — New Vulnerability Classes

| Route | Vuln | Priority | CWE |
|-------|------|----------|-----|
| `/api/v8/token` · `/api/v8/jwks` · `/api/v8/crew` | **JWT jku Header Injection** — server fetches signing key from attacker-supplied URL; also secondary SSRF on the jku GET | P1 | CWE-347 |
| `/latest/meta-data/<path>` · `/cloud/ssrf-demo` | **AWS IMDS SSRF** — fake EC2 metadata endpoint with IAM credentials, user-data secrets; practice full SSRF→credential-theft chain | P1 | OWASP A10 |
| `/api/sync/state` | **Python marshal RCE** — `marshal.loads()` + `exec()` on attacker-crafted code objects; same danger as pickle, far less recognised | P1 | CWE-502 |
| `/tools/xml-dos` | **Billion Laughs DoS** — internal entity expansion only (no network), `huge_tree=True` removes lxml's 256 MB cap; distinct from XXE file-read | P2 | CWE-776 |
| `/api/v2/sensitive-data` | **CORS null Origin** — reflects `Origin: null` + `Allow-Credentials: true`; exploitable from sandboxed iframes and `data:` URIs | P2 | CWE-346 |
| `/api/v5/graphql/alias-batch` | **GraphQL Alias Batching** — N credential checks in 1 HTTP request; per-request rate limiter sees 1 call | P2 | OWASP API4 |
| `/kiosk/login-v2` | **Lockout Case Bypass** — lockout key is raw string, SQLite COLLATE NOCASE matches; `Admin`/`ADMIN`/`aDmIn` each get 3 fresh guesses | P2 | CWE-307 |
| `/reset-link-click` | **Reset Token in Referer** — token in URL leaks to analytics/CDN/proxy server logs | P2 | CWE-598 |
| `/satellite/contacts` | **XPath Injection** — `' or '1'='1` dumps all contacts including ROOT-clearance `api_secret` values | P2 | CWE-643 |
| `/tools/headers-audit` | **Missing Security Headers** — grades CSP, X-Frame-Options, XCTO, HSTS, Referrer-Policy, Permissions-Policy, Cache-Control, COOP with Flask fix snippet | P3 | CWE-693 |
| `/tools/subdomain-takeover` | **Dangling CNAME / Subdomain Takeover** — 4 simulated CNAMEs (Azure, Heroku, GitHub, Fastly), 2 claimable, cookie scope and CSP bypass impact | P3 | CWE-350 |

### Wave 24 totals
- **Routes:** +19 (302 total)
- **New vuln classes:** 11
- **app.py:** ~6,568 lines

## Wave 25 — New Vulnerability Classes

| Route | Vuln | Priority | CWE |
|-------|------|----------|-----|
| `/station/file-read` | **file:// SSRF via urllib** — urllib.urlopen() accepts file://, ftp:// unlike requests; reads /etc/passwd, .env, app.py | P1 | CWE-918 |
| `/ops/gopher-relay` | **Gopher SSRF → Redis Injection** — gopher:// sends raw bytes to TCP; KEYS/GET/SET against fake Redis store; extends to SMTP, FastCGI | P1 | CWE-918 |
| `/api/v9/token` + `/api/v9/x5u-cert` + `/api/v9/crew` | **JWT x5u Header Injection** — RSA/X.509 cert variant of jku (Wave 24); fetches attacker cert, verifies against attacker public key | P1 | CWE-347 |
| `/station/directory` | **LDAP Injection** — raw uid in filter `(&(uid=<INPUT>)(active=true))`; `*` dumps all entries with clearance+secrets | P2 | CWE-90 |
| `/aegis-repo/.git/<path>` | **Full .git Directory Dump** — HEAD, config (deploy token), objects, packed-refs; git-dumper reconstructs full source history | P2 | CWE-538 |
| `/ops/log-poison` | **Log Poisoning → LFI Chain** — User-Agent injected into access log; log rendered via Jinja2 → SSTI → RCE chain | P1 | CWE-116+22 |
| `/account/reset-v2` | **Insecure Randomness** — `random.randint()` seeded with `time.time()`; ±60s seed window = 120 tries to crack; predict button demos crack | P2 | CWE-338 |
| `/api/v5/graphql/hidden` | **Hidden GraphQL Mutations via Introspection** — nukeAllCrewLogs, exportCrewHashes, grantCommanderRole discoverable but undocumented; no auth check | P2 | OWASP API8 |
| `/telemetry/data-feed` | **Content-Type Confusion → XML/XXE** — JSON endpoint silently processes XML when Content-Type switched; XXE via resolve_entities=True | P2 | CWE-436+611 |
| `/mission/ops` | **Workflow State Machine Bypass** — DRAFT→ACTIVE in one PATCH, skipping SUBMITTED+APPROVED; frontend-only enforcement | P2 | CWE-841 |
| `/profile/svg-process` | **SVG XXE via Server-Side Processing** — SVG parsed by lxml to extract title metadata; XXE in `<title>&xxe;</title>` reads local files | P1 | CWE-611 |
| `/auth/2fa-v2/verify` | **2FA TOCTOU Race Condition** — check-then-act gap with 50ms sleep; two concurrent requests with same OTP both authenticate | P1 | CWE-362 |

### Wave 25 totals
- **Routes:** +17 (323 total)
- **New vuln classes:** 12
- **app.py:** ~7,744 lines

## Wave 27 — API / Storage / K8s / Auth

| Route | Vuln | Priority | CWE |
|-------|------|----------|-----|
| `/api/v0/crew` | **API Version Bypass** — v0 unauthenticated; v1 added auth but v0 never removed | P1 | CWE-306 |
| `/cloud/k8s-ssrf` + `/k8s-api/*` | **Kubernetes SSRF** — SSRF to fake K8s API; reads secrets, configmaps, service accounts | P1 | CWE-918 |
| `/api/v10/crew` | **JWT Claim Confusion** — server uses `email` claim for identity, not `sub`; register with victim's email | P2 | CWE-287 |
| `/api/admin/purge` | **HTTP Verb Tampering** — GET enforces admin role; DELETE bypasses the check entirely | P2 | CWE-650 |
| `/redirect/unicode` | **Unicode Homograph Redirect** — lookalike chars (ɑ vs a) pass domain substring allow-list | P2 | CWE-601 |
| `/store/storage-xss` | **Browser Storage XSS Chain** — JWT in sessionStorage; any XSS on origin exfiltrates it | P2 | CWE-79+922 |

## 🚩 CTF Flag System

15 challenges across 7 categories (Injection, JWT, Deserialization, SSRF, AccessControl, XXE, AI/LLM, SSO).

| Route | Purpose |
|-------|---------|
| `/ctf` | Challenge board — lists all flags, categories, point values, hints |
| `/ctf/submit` | POST endpoint to submit flags (`AEGIS{...}` format) |
| `/ctf/scoreboard` | Live scoreboard sorted by points |

Point values: 100–400 pts per flag. Submit via the challenge board UI or:
```bash
curl -X POST http://localhost:5000/ctf/submit \
  -b "session=<your-session>" \
  -d "flag=AEGIS{sqli_or_1eq1_bypass}"
```

### Wave 27 + CTF totals
- **Routes:** 348 (two accidental duplicate registrations removed —
  see Maintenance log above; no vuln routes were removed, just the
  dead/crashing duplicates)
- **Templates:** 149
- **CTF flags:** 15 (100–400 pts each)
- **app.py:** ~8,680 lines
