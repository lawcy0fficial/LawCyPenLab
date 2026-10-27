"""
LawCypenLab :: AEGIS STATION — ICS/PLC raw-socket simulator.

A tiny, deliberately unauthenticated TCP service that speaks a
plaintext, Modbus-flavored register protocol — separate from the web
app, for practicing raw network-protocol interaction against an ICS
target rather than only HTTP.

FOR AUTHORIZED SECURITY TRAINING USE ONLY. Bind to 127.0.0.1 unless
you're deliberately running it on an isolated lab network.

Run:
    python3 modbus_sim.py
Then, e.g.:
    nc 127.0.0.1 5502
    > HELP
    > READ reactor_core_temp_c
    > WRITE reactor_core_temp_c 9999
    > DUMP

Protocol (line-based, plaintext, no auth, no framing/CRC at all):
    HELP                       list commands
    LIST                       list register names
    READ <register>            read one register
    WRITE <register> <value>   write one register — no bounds check,
                                no write-permission check, no session,
                                no source-IP allow-list
    DUMP                       dump every register
    QUIT                       close connection

--- VULN SUMMARY (this file) ---
- No authentication of any kind on the socket — anyone who can reach
  the port can read and write every register.
- No transport encryption (plaintext TCP), no message integrity check
  (no CRC/checksum), unlike even minimal real Modbus deployments.
- WRITE performs no bounds/range validation and no read-only vs.
  read-write register distinction — any client can push any register
  to any value, including out-of-range "reactor" values.
- No rate limiting / connection throttling — trivially scriptable for
  a flood or brute-parameter sweep.
- No logging of who changed what — no audit trail at all.
"""
import socketserver
import threading

HOST = "127.0.0.1"   # change deliberately if you need LAN reachability in an isolated lab
PORT = 5502

REGISTERS = {
    "reactor_core_temp_c": 340,
    "coolant_flow_lpm": 1180,
    "power_output_mw": 42,
    "control_rod_position_pct": 88,
    "airlock_bay1_state": 1,   # 1 = sealed, 0 = open
    "airlock_bay2_state": 1,
    "airlock_bay3_state": 1,
    "solar_truss_angle_deg": 23,
}

lock = threading.Lock()


class ICSHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"AEGIS-ICS-SIM v1 :: no authentication required\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                break
            parts = line.decode(errors="replace").strip().split()
            if not parts:
                continue
            cmd = parts[0].upper()

            if cmd == "HELP":
                self.wfile.write(
                    b"HELP | LIST | READ <reg> | WRITE <reg> <val> | DUMP | QUIT\r\n"
                )
            elif cmd == "LIST":
                self.wfile.write((", ".join(REGISTERS.keys()) + "\r\n").encode())
            elif cmd == "READ" and len(parts) == 2:
                reg = parts[1]
                with lock:
                    val = REGISTERS.get(reg)
                self.wfile.write((f"{reg}={val}\r\n" if val is not None else "ERR unknown register\r\n").encode())
            elif cmd == "WRITE" and len(parts) == 3:
                reg, raw_val = parts[1], parts[2]
                if reg not in REGISTERS:
                    self.wfile.write(b"ERR unknown register\r\n")
                    continue
                try:
                    val = int(raw_val)
                except ValueError:
                    self.wfile.write(b"ERR value must be integer\r\n")
                    continue
                # no bounds check, no permission check, no auth — by design
                with lock:
                    REGISTERS[reg] = val
                self.wfile.write((f"OK {reg}={val}\r\n").encode())
            elif cmd == "DUMP":
                with lock:
                    body = "\r\n".join(f"{k}={v}" for k, v in REGISTERS.items())
                self.wfile.write((body + "\r\n").encode())
            elif cmd == "QUIT":
                self.wfile.write(b"BYE\r\n")
                break
            else:
                self.wfile.write(b"ERR unknown command (try HELP)\r\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadingTCPServer((HOST, PORT), ICSHandler)
    print(f"AEGIS-ICS-SIM listening on {HOST}:{PORT} (unauthenticated, plaintext) — Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
