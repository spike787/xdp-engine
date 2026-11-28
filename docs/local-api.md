# Local API

`local-api` is the shared control plane described in [`ROADMAP.md`](../ROADMAP.md)
and [ADR-0001](adr/0001-architecture.md). It reads the same `engine.db`
SQLite file `engine` writes to and exposes it over HTTP, so that bouncers,
dashboards, and external tooling all have one place to read decisions and
telemetry from, instead of touching the database directly.

```bash
make local-api
LOCAL_API_TOKEN=your-secret ./local-api engine.db 8088
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness check, no auth required |
| `GET /decisions` | Active block decisions, as served to bouncers |
| `GET /export?type=alerts\|events&format=csv\|json&since=&until=` | Evidence export, filterable by ISO-8601 timestamp range |
| `GET /metrics` | Prometheus exposition format — see below |

Every request other than `/healthz` requires `Authorization: Bearer <token>`
matching `LOCAL_API_TOKEN`. If that variable is unset, the API logs a
warning and runs unauthenticated — fine for local testing, not for anything
reachable beyond localhost.

```bash
curl -H "Authorization: Bearer your-secret" \
  "http://127.0.0.1:8088/export?type=alerts&format=csv" -o alerts.csv
```

## Prometheus metrics

`GET /metrics` reports the same numbers the live showcase dashboard
already reads from the shared SQLite DB (see
[ADR-0005](adr/0005-prometheus-metrics.md)), in Prometheus's text
exposition format:

```bash
curl -H "Authorization: Bearer your-secret" http://127.0.0.1:8088/metrics
```

```
xdp_engine_alerts_total 42
xdp_engine_events_total 318
xdp_engine_decisions_active 2
xdp_engine_packets_dropped_total 1204
xdp_engine_packets_passed_total 88213
xdp_engine_packets_by_protocol_total{protocol="tcp"} 70211
xdp_engine_packets_by_protocol_total{protocol="udp"} 15902
xdp_engine_packets_by_protocol_total{protocol="icmp"} 1800
xdp_engine_packets_by_protocol_total{protocol="other"} 300
xdp_engine_syn_rate_limit 200
xdp_engine_mode{mode="enforce"} 1
xdp_engine_mode{mode="detect"} 0
xdp_engine_last_metrics_timestamp_seconds 1795847268
```

The packet-counter metrics (everything from `xdp_engine_packets_dropped_total`
onward) are **omitted entirely** — not reported as zero — until `engine` has
run at least once against this database; `xdp_engine_alerts_total`,
`xdp_engine_events_total`, and `xdp_engine_decisions_active` are always
present, since a real zero is a meaningful answer for those. Sample
`prometheus.yml` scrape config:

```yaml
scrape_configs:
  - job_name: xdp-engine
    static_configs:
      - targets: ["127.0.0.1:8088"]
    authorization:
      credentials: your-secret
```

---

See also: [Enforcement (bouncers)](enforcement.md) for who consumes
`/decisions`, and the [main README](../README.md) for how `local-api` fits
into the overall startup sequence.
