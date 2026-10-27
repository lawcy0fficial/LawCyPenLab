"""
LawCypenLab :: AEGIS STATION — database seeder.

Run once (or any time you want a clean slate):
    python seed.py

Creates instance/aegis.db from schema.sql and inserts intentionally
weak / vulnerable sample data (weak hashing, predictable tokens,
guessable admin credentials, etc). This is a training target —
do not reuse these patterns in real software.
"""
import hashlib
import os
import secrets
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "aegis.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def md5(s: str) -> str:
    # Intentionally weak, unsalted hashing — a vulnerability by design.
    return hashlib.md5(s.encode()).hexdigest()


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())

    cur = conn.cursor()

    # --- users -----------------------------------------------------
    users = [
        # username, password, email, role, is_admin
        ("admin", "aegis2024", "admin@aegis-station.ops", "admin", 1),
        ("r.solis", "password1", "r.solis@aegis-station.ops", "officer", 0),
        ("k.mbeki", "starfall99", "k.mbeki@aegis-station.ops", "crew", 0),
        ("t.okafor", "letmein", "t.okafor@aegis-station.ops", "crew", 0),
        ("j.vance", "orbit2023", "j.vance@aegis-station.ops", "crew", 0),
        ("m.reyes", "security1", "m.reyes@aegis-station.ops", "officer", 0),
        ("a.singh", "trainee2024", "a.singh@aegis-station.ops", "crew", 0),
        ("guest", "guest", "guest@aegis-station.ops", "crew", 0),
    ]
    user_ids = {}
    for username, pw, email, role, is_admin in users:
        token = secrets.token_hex(4)  # short, brute-forceable API token (weak on purpose)
        cur.execute(
            "INSERT INTO users (username, password_hash, email, role, is_admin, api_token) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, md5(pw), email, role, is_admin, token),
        )
        user_ids[username] = cur.lastrowid

    # --- crew profiles ----------------------------------------------
    profiles = [
        ("admin", "Station Director", "Director", "System administrator account for AEGIS Station.",
         "ROOT ACCESS — override code kept in /admin/settings backup export."),
        ("r.solis", "Officer R. Solis", "Flight Officer", "Runs docking ops and cargo scheduling.",
         "Clearance: BLUE. Psych eval on file: nominal."),
        ("k.mbeki", "Dr. K. Mbeki", "Chief Medical Officer", "Keeps the crew alive. Mostly.",
         "Clearance: BLUE. Allergy notes: none recorded."),
        ("t.okafor", "T. Okafor", "Systems Engineer", "Life support and hull maintenance.",
         "Clearance: GREEN. Reprimand 2024-02: unauthorized airlock cycle."),
        ("j.vance", "J. Vance", "Navigator", "Plots long-range trajectories.",
         "Clearance: GREEN. Flagged for extended EVA hours."),
        ("m.reyes", "Officer M. Reyes", "Security Officer", "Station access control and incident response.",
         "Clearance: BLUE. Holds the physical override keycard backup."),
        ("a.singh", "A. Singh", "Trainee", "Rotating trainee, currently shadowing Systems Engineering.",
         "Clearance: GREEN. 14 days into 90-day probationary period."),
        ("guest", "Guest Account", "Visitor", "Temporary visitor access.",
         "Clearance: NONE."),
    ]
    for username, name, rank, bio, notes in profiles:
        cur.execute(
            "INSERT INTO crew_profiles (user_id, display_name, rank, bio, clearance_notes, avatar_path) "
            "VALUES (?, ?, ?, ?, ?, NULL)",
            (user_ids[username], name, rank, bio, notes),
        )

    # --- messages -----------------------------------------------------
    cur.execute(
        "INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)",
        (user_ids["r.solis"], user_ids["k.mbeki"], "Docking bay 3 clear for 0600. Confirm med bay staffing."),
    )
    cur.execute(
        "INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)",
        (user_ids["t.okafor"], user_ids["admin"], "Life support diagnostics scheduled for tonight."),
    )
    cur.execute(
        "INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)",
        (user_ids["m.reyes"], user_ids["admin"], "Keycard log shows 3 failed badge attempts at Bay C overnight."),
    )
    cur.execute(
        "INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)",
        (user_ids["t.okafor"], user_ids["a.singh"], "Shadow me on the life-support rounds at 0800, bring your badge."),
    )

    # --- tickets --------------------------------------------------------
    cur.execute(
        "INSERT INTO tickets (user_id, subject, body, status) VALUES (?, ?, ?, 'open')",
        (user_ids["j.vance"], "Navigation console lag",
         "Console 4 is lagging badly during trajectory recalculation."),
    )
    cur.execute(
        "INSERT INTO tickets (user_id, subject, body, status) VALUES (?, ?, ?, 'closed')",
        (user_ids["k.mbeki"], "Med bay fridge temperature",
         "Fridge 2 ran two degrees warm overnight, logged for review."),
    )
    cur.execute(
        "INSERT INTO tickets (user_id, subject, body, status) VALUES (?, ?, ?, 'open')",
        (user_ids["a.singh"], "Badge not provisioned for Bay C",
         "My badge reads 'access denied' at Bay C. Training rotation starts tomorrow."),
    )

    # --- ticket replies ---------------------------------------------------
    # Ticket ids line up with insertion order above: 1 = nav console lag,
    # 2 = med bay fridge, 3 = badge provisioning. ticket_detail.html renders
    # reply bodies with |safe, so these also double as a stored-XSS target.
    ticket_replies = [
        (1, user_ids["t.okafor"], "Looked at console 4, reseated the GPU riser. Let me know if it lags again."),
        (1, user_ids["j.vance"], "Ran fine for a full shift after that, thanks."),
        (2, user_ids["k.mbeki"], "Compressor swapped, logged under maintenance ticket M-0442. Closing this out."),
    ]
    cur.executemany(
        "INSERT INTO ticket_replies (ticket_id, author_id, body) VALUES (?, ?, ?)",
        ticket_replies,
    )

    # --- cargo -----------------------------------------------------------
    cargo_items = [
        ("CGO-1001", "Hydroponics nutrient packs", 240, "Bay A", 0),
        ("CGO-1002", "Spare O2 scrubber cartridges", 60, "Bay A", 0),
        ("CGO-1003", "EVA suit patch kits", 30, "Bay B", 0),
        ("CGO-1004", "Experimental propulsion isotope sample", 2, "Bay C", 1),
        ("CGO-1005", "Medical narcotics reserve", 12, "Bay C", 1),
        ("CGO-1006", "Ration packs", 900, "Bay B", 0),
        ("CGO-1007", "Replacement badge reader units", 10, "Bay A", 0),
        ("CGO-1008", "Sidearm, security locker (training rotation)", 1, "Bay C", 1),
    ]
    cur.executemany(
        "INSERT INTO cargo (manifest_code, description, quantity, bay, restricted) VALUES (?, ?, ?, ?, ?)",
        cargo_items,
    )

    # --- docking requests --------------------------------------------------
    cur.execute(
        "INSERT INTO docking_requests (requester_id, vessel_name, bay, status) VALUES (?, ?, ?, 'pending')",
        (user_ids["j.vance"], "MV Halcyon Drift", "Bay 2"),
    )
    cur.execute(
        "INSERT INTO docking_requests (requester_id, vessel_name, bay, status) VALUES (?, ?, ?, 'approved')",
        (user_ids["r.solis"], "SS Meridian Courier", "Bay 3"),
    )

    # --- CMS posts / comments ------------------------------------------
    cur.execute(
        "INSERT INTO posts (title, content, author_id, published) VALUES (?, ?, ?, 1)",
        (
            "Welcome to AEGIS Station Ops",
            "<p>This board carries station-wide announcements. Chief Engineer notes go out every Monday.</p>",
            user_ids["admin"],
        ),
    )
    cur.execute(
        "INSERT INTO posts (title, content, author_id, published) VALUES (?, ?, ?, 1)",
        (
            "Docking Schedule — Week 14",
            "<p>Bay 2 and Bay 3 are reserved for incoming supply runs. See the docking board for live status.</p>",
            user_ids["r.solis"],
        ),
    )
    cur.execute(
        "INSERT INTO posts (title, content, author_id, published) VALUES (?, ?, ?, 1)",
        (
            "New Trainee Rotation Starting",
            "<p>Welcome A. Singh, joining us for a 90-day rotation shadowing Systems Engineering. "
            "Please badge them through Bay C if you see an access issue — provisioning ticket is open.</p>",
            user_ids["m.reyes"],
        ),
    )
    cur.execute(
        "INSERT INTO comments (post_id, author_name, body, approved) VALUES (1, ?, ?, 1)",
        ("t.okafor", "Good to know, thanks for the update."),
    )
    cur.execute(
        "INSERT INTO comments (post_id, author_name, body, approved) VALUES (3, ?, ?, 1)",
        ("k.mbeki", "Welcome aboard, A. Singh!"),
    )

    # --- station logs (files referenced live on disk under /var_logs) ----
    cur.executemany(
        "INSERT INTO station_logs (filename, summary) VALUES (?, ?)",
        [
            ("2024-05-01.log", "Routine systems check, all nominal."),
            ("2024-05-02.log", "Minor pressure fluctuation, Bay C, resolved."),
            ("2024-05-03.log", "Airlock cycle count reset after maintenance."),
        ],
    )

    # --- plugins (CMS) ---------------------------------------------------
    cur.execute(
        "INSERT INTO plugins (name, filename, enabled, uploaded_by) VALUES (?, ?, 1, ?)",
        ("Station Weather Widget", "weather_widget.py", user_ids["admin"]),
    )


    # --- notifications ---
    notifications = [
        (user_ids["admin"], "SECURITY ALERT", "Unrecognised login from 45.33.32.156"),
        (user_ids["r.solis"], "Docking Approved", "MV Halcyon Drift cleared for Bay 2 at 06:00 UTC"),
        (user_ids["k.mbeki"], "Med Bay Alert", "Crew member vitals out of range — review required"),
        (user_ids["j.vance"], "Navigation Warning", "Debris field at bearing 042, avoidance burn queued"),
        (user_ids["admin"], "Admin Override Used", "OMEGA-7734 applied to /admin/ at 04:22 UTC"),
        (user_ids["m.reyes"], "Badge Access Failure", "3 failed badge attempts at Bay C — review requested"),
        (user_ids["a.singh"], "Welcome", "Trainee rotation provisioned. Badge access pending Bay C ticket."),
        (user_ids["guest"], "Welcome", "Temporary visitor access provisioned. Expires 72h."),
    ]
    for uid, title, body in notifications:
        cur.execute("INSERT INTO notifications (user_id, title, body) VALUES (?,?,?)", (uid, title, body))

    # --- audit log ---
    audit_entries = [
        (user_ids["admin"], "admin", "LOGIN", "dashboard", "10.0.0.1"),
        (user_ids["r.solis"], "r.solis", "DOCKING_APPROVE", "request_id=1", "10.0.0.12"),
        (user_ids["admin"], "admin", "ADMIN_SETTINGS_VIEW", "/admin/settings", "10.0.0.1"),
        (user_ids["k.mbeki"], "k.mbeki", "FILE_UPLOAD", "meddata_q1.csv", "10.0.0.8"),
        (user_ids["m.reyes"], "m.reyes", "BADGE_ACCESS_DENIED", "bay=C user=a.singh", "10.0.0.15"),
        (user_ids["r.solis"], "r.solis", "DOCKING_APPROVE", "request_id=2", "10.0.0.12"),
    ]
    for actor_id, actor_name, action, target, ip in audit_entries:
        cur.execute("INSERT INTO audit_log (actor_id, actor_username, action, target, ip_address) VALUES (?,?,?,?,?)",
                    (actor_id, actor_name, action, target, ip))

    # --- API keys ---
    for username, uid in user_ids.items():
        key = os.urandom(4).hex()
        cur.execute("INSERT INTO api_keys (user_id, key_hash, label, scopes) VALUES (?,?,?,?)",
                    (uid, key, f"{username}-default", "read,write"))

    # --- crew notes (IDOR-accessible) ---
    notes = [
        (user_ids["admin"], user_ids["r.solis"], "OFFICER clearance confirmed after psych eval.", "OFFICER"),
        (user_ids["admin"], user_ids["k.mbeki"], "Medical override authority. Can access narcotics bay.", "ALPHA"),
        (user_ids["admin"], user_ids["j.vance"], "Navigation error incident 2024-02-14 under review.", "OFFICER"),
        (user_ids["r.solis"], user_ids["t.okafor"], "Unauthorised airlock cycle — reprimand filed.", "CREW"),
        (user_ids["m.reyes"], user_ids["a.singh"], "Probationary trainee, badge access not yet fully provisioned.", "CREW"),
    ]
    for author, subject, note, cls in notes:
        cur.execute("INSERT INTO crew_notes (author_id, subject_id, note, classification) VALUES (?,?,?,?)",
                    (author, subject, note, cls))


    # --- Wave 24: satellite contacts (XPath injection target) ---
    sat_contacts = [
        ('AEGIS-GS1',   'ROOT',  'GS1-SECRET-NX7734',  'Primary ground station — override authority'),
        ('RELAY-ALPHA', 'BLUE',  'RELAY-SECRET-A2B3',  'Comms relay, Pacific basin'),
        ('RELAY-BRAVO', 'GREEN', 'RELAY-SECRET-C4D5',  'Backup relay, Atlantic basin'),
    ]
    for cs, cl, sec, notes in sat_contacts:
        cur.execute(
            "INSERT INTO satellite_contacts (callsign, clearance, api_secret, notes) VALUES (?,?,?,?)",
            (cs, cl, sec, notes)
        )

    conn.commit()
    conn.close()
    print(f"Seeded database at {DB_PATH}")


if __name__ == "__main__":
    main()
