"""
LawCypenLab :: AEGIS STATION — ground antenna array control protocol
simulator (UDP), distinct from modbus_sim.py's TCP register protocol.

FOR AUTHORIZED SECURITY TRAINING USE ONLY. Bind to 127.0.0.1 unless
you're deliberately running it on an isolated lab network.

This one demonstrates a REPLAY ATTACK: every command is a single,
static UDP datagram with no nonce, no timestamp, no sequence number,
and no session/handshake of any kind. Capture one legitimate command
off the wire and you can resend the exact same bytes, at any point in
the future, and the antenna array will execute it again — the server
has no way to tell a replay from an original.

Run:
    python3 ground_antenna_sim.py
Then, e.g. (from another terminal):
    echo -n "AUTH:GA-FIELD-KEY-2024|CMD:SLEW|AZ:180|EL:45" | \
        python3 -c "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(sys.stdin.buffer.read(), ('127.0.0.1', 5503)); print(s.recv(1024).decode())"

Protocol (single UDP datagram, pipe-delimited, plaintext):
    AUTH:<shared-key>|CMD:<SLEW|PARK|CALIBRATE|RESET>|AZ:<deg>|EL:<deg>

--- VULN SUMMARY (this file) ---
- Static shared key (GA-FIELD-KEY-2024), identical for every field
  technician and every antenna in the array, transmitted in cleartext
  in every single packet — trivially sniffable on any shared network
  segment.
- NO REPLAY PROTECTION: no nonce, no timestamp, no monotonic counter,
  no per-command uniqueness check at all. The exact same datagram,
  captured once, can be resent unmodified at any later time and will
  be honored identically every time (confirm this yourself: send the
  same bytes twice in a row and watch both get accepted and logged).
- No source-IP allow-list, no rate limiting, no encryption (plaintext
  UDP) — trivially spoofable and floodable.
- No acknowledgement/sequence handshake, so there is also no way for
  the real sender to detect that their command was captured and
  replayed by someone else.
"""
import socketserver

HOST = "127.0.0.1"  # change deliberately if you need LAN reachability in an isolated lab
PORT = 5503

SHARED_KEY = "GA-FIELD-KEY-2024"  # same key for every technician, every antenna — never rotated

STATE = {"az": 0.0, "el": 0.0, "parked": True}
ACCEPTED_LOG = []  # every accepted command, including exact replays — nothing here is deduplicated


def parse(datagram):
    fields = {}
    for part in datagram.split("|"):
        if ":" in part:
            k, v = part.split(":", 1)
            fields[k.strip().upper()] = v.strip()
    return fields


class AntennaHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            text = data.decode(errors="replace")
        except Exception:
            return
        fields = parse(text)

        if fields.get("AUTH") != SHARED_KEY:
            sock.sendto(b"ERR auth", self.client_address)
            return

        cmd = fields.get("CMD", "").upper()
        # --- VULN: this datagram is accepted and actioned with no check
        # that it hasn't been seen before — see ACCEPTED_LOG below; a
        # captured-and-replayed packet is indistinguishable from a fresh
        # one at every step of this handler. ---
        if cmd == "SLEW":
            try:
                STATE["az"] = float(fields.get("AZ", STATE["az"]))
                STATE["el"] = float(fields.get("EL", STATE["el"]))
                STATE["parked"] = False
                reply = f"OK SLEW az={STATE['az']} el={STATE['el']}"
            except ValueError:
                reply = "ERR bad AZ/EL"
        elif cmd == "PARK":
            STATE["parked"] = True
            reply = "OK PARK"
        elif cmd == "CALIBRATE":
            reply = "OK CALIBRATE"
        elif cmd == "RESET":
            STATE["az"], STATE["el"], STATE["parked"] = 0.0, 0.0, True
            reply = "OK RESET"
        else:
            reply = "ERR unknown CMD"

        ACCEPTED_LOG.append(text)
        print(f"[{len(ACCEPTED_LOG)}] accepted (no replay check): {text!r} -> {reply}")
        sock.sendto(reply.encode(), self.client_address)


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadingUDPServer((HOST, PORT), AntennaHandler)
    print(f"AEGIS-GROUND-ANTENNA-SIM listening on udp {HOST}:{PORT} — Ctrl+C to stop")
    print("Try sending the exact same datagram twice — both will be accepted identically.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
