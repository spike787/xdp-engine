# Threat Model

## Assets
- **The Host System**: CPU, memory, and kernel stability.
- **Protected Applications**: The web servers and SSH daemons running on the host.
- **Engine Data**: The SQLite database containing historical offense data, alerts, and metrics.
- **The BPF Maps**: The direct interface between user space and kernel space packet dropping.

## Attacker Capabilities
We assume the attacker can:
- Send arbitrary volumes of network traffic to the host from any IP address.
- Forge (spoof) source IP addresses.
- Craft malicious payloads (e.g., XSS, SQLi) in HTTP requests.
- Attempt to bruteforce exposed services.
- Influence log file contents by causing target applications to log attacker-controlled strings.

## Trust Boundaries
1. **Log Files (`/var/log/secure or /var/log/nginx/access.log`)**: Untrusted. Attackers control usernames and User-Agent strings. The engine parses this data securely without passing it to a shell.
2. **The Control Socket (`/run/xdp_engine.sock`)**: Trusted but secured. Boundary strictly enforced via UNIX permissions (`0600`) and `SO_PEERCRED` checks ensuring only `root` can send commands.
3. **The Web Dashboard**: Read-only boundary. The dashboard runs locally and pulls state directly from a read-only connection to SQLite. Attacker data is safely rendered as raw text, neutering XSS payloads.
4. **Pinned BPF Maps**: Kernel boundary. Since the bouncer-xdp separation (see `docs/adr/0002-bouncer-xdp-separation.md`), `bouncer-xdp` is the *only* process that writes to `blocked_ips` to dictate packet blocking - it is the sole root-privileged component that loads/attaches the BPF program and owns pinning. `engine` and future tools open the same maps read-mostly via `bpf_obj_get()` against the pinned paths under `/sys/fs/bpf/xdp_engine/` rather than writing to them directly.
5. **The Local API (`local_api.cpp`)**: Network-facing boundary. A bearer-token-protected HTTP service bouncers poll for decisions (`GET /decisions`) and analysts use for evidence export (`GET /export`). The token comparison is constant-time to avoid leaking its length or content via timing. It opens the same SQLite database the engine writes to, read-only in practice (it issues no writes of its own), in WAL mode so concurrent access is safe.

## Built-In Mitigations
- **Validated IPs**: All user input, socket commands, and log file parses are strictly validated as legitimate IPv4 addresses before processing.
- **Allowlist Wins**: Built-in protection prevents blocking crucial infrastructure (e.g., `127.0.0.1` or admin IPs passed via `--allow`).
- **Rate Cap & Cooldown**: Syn-flood limits protect kernel and user space from being overwhelmed.
- **TTL & Expiry**: Blocks expire at the decision layer, not in the kernel. `engine` records each block/unblock as a timestamped decision in SQLite; Local API's `/decisions` only ever lists decisions that are still active (`expires_at_unix = 0` for permanent, or still in the future); `bouncer-xdp` re-derives the kernel map's contents from that list on every poll (default every 2s), so a block that has expired or been manually unblocked gets released from the kernel map on the next poll without needing any in-kernel expiry tracking.
- **Enforcement Persistence, Fail-Static Behavior**: `bouncer-xdp` pins both the XDP link and all BPF maps to `/sys/fs/bpf/xdp_engine/`, so enforcement survives `bouncer-xdp` itself crashing or restarting - on restart it resumes against the existing attachment instead of re-attaching, and (since the bouncer-xdp resume-reconciliation fix) correctly reconciles the kernel map against Local API's current decisions on its first poll back. If Local API becomes unreachable, `bouncer-xdp` deliberately leaves the current kernel state untouched ("fail static, not fail open") rather than either detaching (which would let all blocked traffic back in) or blocking everyone. This is a deliberate change from an earlier design where the engine detaching XDP on exit was the safety net - detaching is now a conscious, explicit action (`bouncer-xdp cleanup <iface>`), not an automatic consequence of any process stopping.
- **Root-only Socket**: Hardened UNIX socket prevents local privilege escalation.
- **Read-Only Dashboard**: The presentation layer cannot alter the system state or database.

## Known Limitations
- **IPv4 Only**: The BPF program currently only parses and blocks IPv4 traffic. IPv6 is not supported.
- **Spoofed-Source SYN Floods**: The engine drops packets based on source IP. A highly distributed spoofed-source SYN flood could bypass threshold limits or erroneously block spoofed victims (though SYN cookies usually mitigate the latter).
- **No Encrypted-Payload Inspection**: The engine cannot inspect TLS/HTTPS payloads directly in kernel space; it relies on application logs for layer 7 insights.
- **Log Rotation**: Handled without a restart - `LogTailer` polls the watched file's inode/device and size on each pass and reopens from the start on rotation (inode change) or truncation (size shrinks below the last read offset). See `log_tailer.h` and `LogTailerTest.RotationAndTruncation`.
- **Single Host**: The state is entirely local. It cannot synchronize blocks across a cluster of machines.
