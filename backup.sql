-- AEGIS STATION :: Database backup
-- Generated: 2024-03-15 02:00 UTC (automated nightly)

CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, email TEXT, role TEXT, is_admin INTEGER, api_token TEXT);
INSERT INTO users VALUES(1,'admin','21232f297a57a5a743894a0e4a801fc3','admin@aegis-station.ops','admin',1,'tk_a1b2c3d4e5f6');
INSERT INTO users VALUES(2,'r.solis','5f4dcc3b5aa765d61d8327deb882cf99','r.solis@aegis-station.ops','officer',0,'tk_b2c3d4e5f6a1');
INSERT INTO users VALUES(3,'k.mbeki','5f4dcc3b5aa765d61d8327deb882cf99','k.mbeki@aegis-station.ops','crew',0,'tk_c3d4e5f6a1b2');
-- password hashes are MD5: admin=admin, others=password
