# NetWatch

Network traffic analyzer CLI for passive local network monitoring. Targets IoT device auditing (cameras, etc.).

## Status

Python implementation in progress, MVP (Fase 2 done). Decision: **Python + Click + Scapy + SQLite** (chose Python over spec's Go recommendation). Tests deferred. The spec is `especificacao-cli-netwatch.md`.

## Commands

```bash
pip install -e .            # install deps (click, scapy)
netwatch                    # CLI entry (click group in netwatch/cli.py)
netwatch analyze offline capture.pcap --db ./netwatch.db  # offline pcap analysis
netwatch devices list --db <path>   # also: config, flows list, summary, export
```

Working: `analyze offline`, `devices list/rename/tag`, `flows list`, `summary`, `export`.
Stubs: `capture start/stop/status`.
Out of scope: `alerts check`, `watch`, enrichment (`--resolve-dns/asn`), `--capture-payload`.

## Architecture

```
netwatch/
├── cli.py              # Click entry, all commands
├── output.py           # table/json/csv formatting helpers (format_output)
├── capture/
│   └── engine.py       # Scapy wrappers: read_packets(), iter_packets()
├── analyzer/
│   ├── flow.py         # 5-tuple flow aggregation, direction classification
│   ├── protocol.py     # L4 (header) + L7 (port table + DPI: TLS, HTTP, SSH)
│   └── device.py       # MAC extraction, hostname from DNS
├── enrichment/
│   └── oui.py          # OUIDatabase class for MAC→vendor lookup
└── storage/
    ├── db.py           # SQLite Database class (WAL mode) + CRUD
    └── models.py       # dataclasses: Device, Flow, DNSLog (L4Protocol, Direction enums)
```

## Non-obvious details

- `analyze offline` reads pcap via Scapy's `rdpcap()`, builds flows via 5-tuple aggregation, classifies L4 from header + L7 via port table + DPI (detects TLS handshake 0x16 0x03, HTTP GET/POST, SSH banner), extracts TLS SNI. Stores flows + devices in SQLite.
- **Flow aggregation is bidirectional per local device.** `build_flows()` first discovers all local (private) IPs in the pcap, then for each packet associates the flow with whichever endpoint is private. Request and reply packets are merged into a single flow keyed by `(local_ip, remote_ip, local_port, remote_port, l4)`, so `bytes_sent`/`bytes_received` correctly split upload vs download. Never key on directional src/dst or you lose the received side.
- `collect_devices()` only records MACs whose source IP is private — otherwise the gateway ends up collecting all external IPs from reply packets (a real bug that was fixed).
- **TLS SNI extraction** (`_extract_sni_from_raw`): offset walks record header (5B) + handshake header (4B) + client version (2B) + random (32B) + session_id, then ciphers, compression, and extensions; must skip the 32-byte random before reading session_id_len. Verified against real ClientHellos.
- `devices list --sort bytes_total|flow_count` uses a LEFT JOIN with flows table for accurate per-device aggregates.
- Storage layer uses **dataclass** models ↔ SQLite via `Database` in `netwatch/storage/db.py`. Writes are per-row `commit()`.
- Datetimes stored as ISO strings; comparisons use ISO strings (lexicographic order works).
- `--format json|csv|table` is a global CLI convention; `format_output()` in `output.py` dispatches.
- Duration parsing helper `_parse_duration()` (`24h`, `7d`, `30d`) in `cli.py`; reuse it.
- `_human_bytes()` format helper in `cli.py`.
- Default DB `~/.netwatch/netwatch.db`; `Database` auto-creates parent dirs and schema.
- SQLite uses WAL mode + foreign_keys ON; device IP history kept in `device_ips` table.
- Live capture needs root/CAP_NET_RAW; offline pcap processing has no privilege requirement.
- OUI lookup: `OUIDatabase("data/oui.txt")` loads prefix→vendor map. `analyze offline` auto-finds `data/oui.txt` if present.
- Privacy/spec guards (`--i-have-authorization`, `--anonymize`, `--capture-payload` warning) not yet implemented.

## Conventions

- No comments in code (project convention).
- No tests yet.
