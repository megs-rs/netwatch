# NetWatch

Network traffic analyzer CLI for passive local network monitoring. Targets IoT device auditing (cameras, etc.).

## Status

MVP (Fase 2 done). **Python 3.11+ + Click + Scapy + SQLite** (chose Python over spec's Go recommendation). Tests deferred. Spec: `especificacao-cli-netwatch.md`. v0.1 pushed to `https://github.com/megs-rs/netwatch` (public, branch `main`).

## Commands

```bash
pip install -e .            # install deps (click, scapy)
netwatch                    # CLI entry (click group in netwatch/cli.py)
netwatch analyze offline capture.pcap --db ./netwatch.db
netwatch devices list --db <path>   # also: flows list, summary, export
```

Working: `analyze offline`, `devices list/rename/tag`, `flows list`, `summary`, `export`.
Stubs: `capture start/stop/status`.
Out of scope: `alerts check`, `watch`, enrichment flags, `--capture-payload`.

## Git / GitHub

```bash
git add -A && git commit -m "..."   # concise, lowercase, scope prefix
git push origin main
```

- Remote `origin` → `https://github.com/megs-rs/netwatch.git`.
- **`gh` CLI is broken** (stale keyring token, PAT lacks `read:org`). Use `curl` with `GITHUB_TOKEN` from `../.env` instead.
- Commit style: `netwatch v0.1: ...` + bullet body in Portuguese. Match repo history.

## Architecture

```
netwatch/
├── cli.py              # Click entry, all commands
├── output.py           # format_output(): table/json/csv
├── capture/engine.py   # Scapy wrappers: read_packets(), iter_packets()
├── analyzer/
│   ├── flow.py         # 5-tuple flow aggregation, bidirectional
│   ├── protocol.py     # L4 header + L7 (port table + DPI: TLS, HTTP, SSH)
│   └── device.py       # MAC extraction, hostname from DNS
├── enrichment/oui.py   # OUIDatabase: MAC→vendor lookup
└── storage/
    ├── db.py           # SQLite Database class (WAL mode) + CRUD
    └── models.py       # dataclasses: Device, Flow, DNSLog; enums: L4Protocol, Direction
```

## Non-obvious details

- **Flow aggregation is bidirectional per local device.** `build_flows()` discovers all private IPs in the pcap, then merges request+reply into one flow keyed by `(local_ip, remote_ip, local_port, remote_port, l4)`. `bytes_sent`/`bytes_received` split upload vs download. Never key on directional src/dst.
- `collect_devices()` only records MACs whose **source IP is private** — otherwise the gateway collects all external IPs from reply packets (real bug, already fixed).
- **TLS SNI extraction** (`_extract_sni_from_raw`): walks record header (5B) + handshake header (4B) + client version (2B) + random (32B) + session_id, then ciphers, compression, extensions. Must skip the 32-byte random before `session_id_len`.
- `devices list --sort bytes_total|flow_count` uses a LEFT JOIN with flows table.
- Storage: dataclass models ↔ SQLite via `Database` in `storage/db.py`. Per-row `commit()`. WAL + foreign_keys ON. Device IPs in `device_ips` table.
- Datetimes stored as ISO strings; lexicographic comparison works.
- `--format json|csv|table` is global; `format_output()` in `output.py` dispatches.
- Default DB: `~/.netwatch/netwatch.db`; auto-creates parent dirs and schema.
- Live capture needs root/CAP_NET_RAW; offline pcap processing does not.
- `analyze offline` auto-finds `data/oui.txt` for OUI lookup if present.

## Conventions

- Docstrings and section markers (`# --- capture ---`) are used in code; no inline explanatory comments.
- No tests yet. `ruff` is a dev dependency but has no config section — just `ruff check` if needed.
- No CI workflows configured.
