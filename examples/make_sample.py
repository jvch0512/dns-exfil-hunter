"""Regenerates examples/queries.csv deterministically: tunneling, a DGA, a CDN and normal browsing."""
import base64, random

rng = random.Random(11)
rows, t = [], 1760000000.0
for i in range(120):  # iodine-style tunnel over TXT
    t += rng.uniform(0.2, 1.5)
    payload = base64.b32encode(bytes(rng.getrandbits(8) for _ in range(30))).decode().lower().rstrip("=")
    rows.append((t, "10.2.1.40", f"{payload[:50]}.t.evil-tunnel.net", "TXT", "NOERROR"))
for i in range(60):  # DGA: random names, NXDOMAIN
    t += rng.uniform(1, 5)
    name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(14, 20)))
    rows.append((t, "10.2.3.8", f"{name}.xyz", "A", "NXDOMAIN"))
for i in range(80):  # CDN with long hashed names (benign, allowlist candidate)
    t += rng.uniform(1, 9)
    h = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    rows.append((t, "10.2.5.2", f"{h}.cdn-assets.example", "A", "NOERROR"))
for i in range(300):  # normal browsing
    t += rng.uniform(0.5, 6)
    rows.append((t, f"10.2.9.{rng.randint(10, 20)}", rng.choice(["www.example.org", "mail.example.org", "api.example.org", "static.example.org", "login.example.org"]), "A", "NOERROR"))
rows.sort()
with open("examples/queries.csv", "w") as f:
    f.write("ts,client,qname,qtype,rcode\n" + "\n".join(f"{r[0]:.2f},{r[1]},{r[2]},{r[3]},{r[4]}" for r in rows) + "\n")
