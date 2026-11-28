# Testing & attack simulation lab

Safe test commands to run from another machine (or WSL / VM / local
terminal) to simulate attacks and verify engine responses. Replace
`<SERVER_IP>` with the IP of the machine running the engine.

## 1. Web exploits (SQL injection & path traversal)

Sends malicious HTTP queries detected by the nginx access log parser:

```bash
# SQL injection attempt:
curl -m 5 "http://<SERVER_IP>/?id=1%27%20OR%201=1--"

# Directory traversal attempt:
curl -m 5 --path-as-is "http://<SERVER_IP>/../../../../etc/passwd"
```

## 2. SSH brute-force protection

Triggers the stateful sliding-window rule (5 failed attempts within 60
seconds):

```bash
# Automated brute-force simulation using Hydra:
hydra -l testuser -p wrongpass <SERVER_IP> ssh

# Or manually attempt 5 failed logins:
ssh wronguser@<SERVER_IP>
```

## 3. Network port scanning

Scans ports to trigger kernel-level port sweep detection:

```bash
# Fast SYN scan across ports 1-30:
nmap -Pn -sS -p 1-30 <SERVER_IP>
```

## 4. Multi-stage attack correlation (the "killshot")

Tests the `SCAN_THEN_BRUTE` sequence correlation engine:

1. First, run a port scan: `nmap -Pn -sS -p 1-25 <SERVER_IP>`
2. Within 5 minutes, attempt an SSH login failure: `ssh fakeuser@<SERVER_IP>`
3. The engine correlates both signals into an escalated, high-severity ban.

## 5. Volumetric SYN flood (DDoS mitigation)

Demonstrates line-rate kernel packet dropping:

```bash
# High-speed TCP SYN flood:
sudo hping3 -S -p 80 --flood <SERVER_IP>

# Multi-process parallel flood (higher PPS across multiple CPU cores):
for i in {1..8}; do sudo hping3 -S -p 80 --flood <SERVER_IP> & done

# Random IP spoofed botnet flood (tests 1,000,000 IP hash map capacity):
sudo hping3 -S -p 80 --flood --rand-source <SERVER_IP>
```

## 6. High-speed benchmark (1–2 million drops/sec)

Physical Wi-Fi radio channels are capped around 30k–80k frames/sec due to
802.11 airtime and ACK overhead. To demonstrate XDP's full
1,000,000–2,000,000+ packets/sec capability, use the in-memory virtual
lab instead:

1. **Start the virtual lab interface:**
   ```bash
   ./tools/setup_veth_lab.sh start
   ```
2. **Start enforcement, Local API, and the engine on the virtual
   interface** (three terminals, in this order — see the main README's
   [startup sequence](../README.md#running-the-stack)):
   ```bash
   sudo ./bouncer-xdp veth-bench
   LOCAL_API_TOKEN=your-secret ./local-api engine.db 8088
   sudo ./engine veth-bench --enforce
   ```
   Type `block 198.51.100.2` in the engine console, then `list` — wait for
   it to show `[enforced]` (bouncer-xdp's next poll, ≤2s) before starting
   the flood below, or the first couple seconds of packets will pass
   through before enforcement catches up.
3. **Launch the multi-thread batch generator (another terminal):**
   ```bash
   sudo ./tools/bench_flood 198.51.100.1 198.51.100.2 4 veth-gen 80
   ```
   Watch the live showcase dashboard at `http://127.0.0.1:5000/?showcase=1`
   display 1.5M–2.0M+ drops/sec.
4. **Clean up when finished:**
   ```bash
   sudo ./bouncer-xdp cleanup veth-bench
   ./tools/setup_veth_lab.sh stop
   ```

---

See also: [Detection internals](detection.md) for what each test is
exercising under the hood, and [`THREAT_MODEL.md`](../THREAT_MODEL.md) for
the attacker-capability assumptions these tests are built against.
