"""CLI entry point for NetWatch."""

from __future__ import annotations

import signal
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import click

from netwatch import __version__
from netwatch.storage.db import Database

DEFAULT_DB = "~/.netwatch/netwatch.db"


def _get_db(db_path: str) -> Database:
    return Database(Path(db_path).expanduser())


@click.group()
@click.version_option(version=__version__, prog_name="netwatch")
def main() -> None:
    """NetWatch - Network traffic analyzer CLI for passive local monitoring.

    Captures and analyzes network traffic to identify devices, protocols, and
    data volume. Focus: IoT device auditing (cameras, smart home, etc.)."""
    pass


# --- capture ---

@main.group()
def capture() -> None:
    """Start, stop, or check the status of a live packet capture."""


@capture.command("start")
@click.option("-i", "--interface", required=True, help="Network interface to capture from (e.g. eth0, wlp0s20f3)")
@click.option("--mode", default="live", type=click.Choice(["live", "mirror", "gateway"]),
              help="Capture mode: live (direct interface), mirror (SPAN port), or gateway (router)")
@click.option("--duration", default="continuous",
              help="How long to capture: 30, 30s, 5m, 1h, or continuous (default)")
@click.option("--filter", "bpf_filter", default="",
              help="BPF filter to restrict capture (tcpdump syntax, e.g. 'port 443')")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def capture_start(interface: str, mode: str, duration: str, bpf_filter: str, db: str) -> None:
    """Start live packet capture on an interface and ingest into the database.

    Requires root or CAP_NET_RAW. Packets are processed in batches and flows
    are aggregated bidirectionally per local device. Use --duration to limit
    capture time, or Ctrl+C to stop a continuous capture."""
    from netwatch.analyzer.device import collect_devices
    from netwatch.analyzer.flow import build_flows
    from netwatch.capture.engine import can_capture, interface_exists, sniff_packets
    from netwatch.capture.state import clear_state, write_state
    from netwatch.enrichment.oui import OUIDatabase

    if not interface_exists(interface):
        click.echo(f"Interface {interface} not found", err=True)
        sys.exit(1)
    if not can_capture():
        click.echo("Live capture requires root / CAP_NET_RAW.", err=True)
        click.echo("Run with sudo or grant the capability:", err=True)
        click.echo("  sudo setcap cap_net_raw+ep $(which netwatch)", err=True)
        sys.exit(1)

    default_oui = Path(__file__).parent.parent / "data" / "oui.txt"
    oui_db = OUIDatabase(str(default_oui)) if default_oui.exists() else None

    database = _get_db(db)
    state_path = write_state(interface)

    stop_flag = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_flag.set())
    signal.signal(signal.SIGINT, lambda *_: stop_flag.set())

    seconds = _parse_capture_duration(duration)
    started = time.monotonic()
    total_packets = 0
    total_flows = 0
    total_devices = 0
    click.echo(f"Capturing on {interface} (mode={mode}) ...", err=True)
    if seconds is None:
        click.echo("  press Ctrl+C to stop", err=True)

    try:
        while True:
            if stop_flag.is_set():
                break
            remaining = None
            if seconds is not None:
                elapsed = time.monotonic() - started
                if elapsed >= seconds:
                    break
                remaining = min(10, seconds - elapsed)

            packets = sniff_packets(interface, timeout=remaining or 10, bpf_filter=bpf_filter)
            if not packets:
                if seconds is None and not stop_flag.is_set():
                    continue
                break

            flows = build_flows(packets)
            devices = collect_devices(packets, oui_db=oui_db)
            for flow in flows:
                database.insert_flow(flow)
            for device in devices:
                database.upsert_device(device)
            total_packets += len(packets)
            total_flows += len(flows)
            total_devices += len(devices)
            click.echo(f"  +{len(packets)} packets, {len(flows)} flows, {len(devices)} devices", err=True)
            if seconds is not None and time.monotonic() - started >= seconds:
                break
    finally:
        clear_state(state_path)

    click.echo(f"Done: {total_packets} packets, {total_flows} flows, {total_devices} devices -> {db}")


@capture.command("stop")
def capture_stop() -> None:
    """Stop a running capture started with 'capture start'."""
    from netwatch.capture.state import clear_state, read_state, stop_capture

    state = read_state()
    if not state:
        click.echo("No capture running.")
        return
    if stop_capture():
        click.echo(f"Stopping capture on {state.get('interface', '?')} (pid {state.get('pid')}).")
    else:
        click.echo("Capture process not running; clearing state.", err=True)
    clear_state()


@capture.command("status")
def capture_status() -> None:
    """Show status of a running capture (interface, PID, uptime)."""
    from datetime import datetime as _dt

    from netwatch.capture.state import process_alive, read_state

    state = read_state()
    if not state:
        click.echo("No capture running.")
        return
    pid = state.get("pid")
    interface = state.get("interface", "?")
    started_at = state.get("started_at")
    alive = process_alive(pid) if pid else False
    uptime = ""
    if alive and started_at:
        try:
            diff = _dt.utcnow() - _dt.fromisoformat(started_at)
            uptime = f"{int(diff.total_seconds())}s"
        except ValueError:
            pass
    status = "running" if alive else "stopped"
    click.echo(f"Status: {status}")
    click.echo(f"Interface: {interface}")
    click.echo(f"PID: {pid}")
    if uptime:
        click.echo(f"Uptime: {uptime}")
    if not alive:
        click.echo("  (stale state; run 'capture stop' to clear)")


# --- analyze ---

@main.group()
def analyze() -> None:
    """Analyze network data from capture files."""


@analyze.command("offline")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
@click.option("--oui-file", default=None, help="Path to OUI vendor database (auto-detected from data/oui.txt)")
def analyze_offline(pcap_file: str, db: str, oui_file: str | None) -> None:
    """Analyze an existing .pcap/.pcapng capture file.

    Reads all packets, builds bidirectional flows per local device, classifies
    protocols (L4 + DPI), extracts TLS SNI, and stores results in SQLite.
    Automatically uses data/oui.txt for MAC vendor lookup if present."""
    from netwatch.analyzer.device import collect_devices
    from netwatch.analyzer.flow import build_flows
    from netwatch.capture.engine import read_packets
    from netwatch.enrichment.oui import OUIDatabase

    if oui_file is None:
        default_oui = Path(__file__).parent.parent / "data" / "oui.txt"
        if default_oui.exists():
            oui_file = str(default_oui)

    oui_db = OUIDatabase(oui_file) if oui_file else None

    click.echo(f"Reading {pcap_file} ...", err=True)
    packets = read_packets(pcap_file)
    click.echo(f"  {len(packets)} packets", err=True)

    flows = build_flows(packets)
    devices = collect_devices(packets, oui_db=oui_db)

    database = _get_db(db)
    for flow in flows:
        database.insert_flow(flow)
    for device in devices:
        database.upsert_device(device)

    click.echo(f"Inserted {len(flows)} flows, {len(devices)} devices into {db}")


# --- devices ---

@main.group()
def devices() -> None:
    """List, rename, and tag discovered network devices."""


@devices.command("list")
@click.option("--tag", default=None, help="Show only devices with this tag (e.g. camera, iot)")
@click.option("--since", default=None, help="Show only devices active since this period (24h, 7d, 30d)")
@click.option("--sort", default="last_seen", type=click.Choice(["bytes_total", "last_seen", "flow_count"]),
              help="Sort devices by: last_seen, bytes_total, or flow_count")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]),
              help="Output format (default: table)")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def devices_list(tag: str | None, since: str | None, sort: str, fmt: str, db: str) -> None:
    """List discovered devices with vendor, IP, alias, tags, and traffic stats."""
    from netwatch.output import format_output

    database = _get_db(db)
    since_dt = _parse_duration(since) if since else None
    devs = database.list_devices(tag=tag, since=since_dt, sort=sort)

    headers = ["MAC", "VENDOR", "IP", "ALIAS", "TAGS", "FLOWS", "BYTES TOTAL", "LAST SEEN"]
    rows = []
    for d in devs:
        rows.append([
            d.mac_address,
            d.vendor,
            ", ".join(d.ip_addresses) if d.ip_addresses else "-",
            d.alias or "-",
            ", ".join(d.tags) if d.tags else "-",
            str(getattr(d, "_flow_count", 0)),
            _human_bytes(getattr(d, "_bytes_total", 0)),
            d.last_seen.strftime("%Y-%m-%d %H:%M"),
        ])
    format_output(fmt, headers, rows)


@devices.command("rename")
@click.argument("mac")
@click.argument("alias")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def devices_rename(mac: str, alias: str, db: str) -> None:
    """Rename a device by setting a human-readable alias.

    MAC can be full (aa:bb:cc:dd:ee:ff) or partial prefix. Alias replaces
    any existing name for that device."""
    database = _get_db(db)
    if database.update_device_alias(mac, alias):
        click.echo(f"Device {mac} renamed to {alias}")
    else:
        click.echo(f"Device {mac} not found", err=True)
        sys.exit(1)


@devices.command("tag")
@click.argument("mac")
@click.argument("tag")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def devices_tag(mac: str, tag: str, db: str) -> None:
    """Tag a device with a category (e.g. camera, iot, trusted).

    Tags can be used for filtering in 'devices list --tag' and for rules."""
    database = _get_db(db)
    if database.add_device_tag(mac, tag):
        click.echo(f"Tag '{tag}' added to device {mac}")
    else:
        click.echo(f"Device {mac} not found", err=True)
        sys.exit(1)


# --- flows ---

@main.group()
def flows() -> None:
    """List and filter network flows (device-to-device connections)."""


@flows.command("list")
@click.option("--device", default=None, help="Filter by device MAC address or alias")
@click.option("--protocol", default=None, help="Filter by L4 or L7 protocol (tcp, udp, tls, http, dns)")
@click.option("--external-only", is_flag=True, help="Show only traffic to/from external IPs")
@click.option("--internal-only", is_flag=True, help="Show only traffic between local devices")
@click.option("--since", default=None, help="Show only flows active since this period (24h, 7d)")
@click.option("--min-bytes", default=None, type=int, help="Show only flows with at least N bytes")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]),
              help="Output format (default: table)")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def flows_list(
    device: str | None,
    protocol: str | None,
    external_only: bool,
    internal_only: bool,
    since: str | None,
    min_bytes: int | None,
    fmt: str,
    db: str,
) -> None:
    """List network flows with protocol, SNI, and traffic volume.

    Flows are bidirectional per local device. Use --external-only to focus
    on IoT devices talking to the internet, or --internal-only for local
    traffic (e.g. camera to NVR)."""
    from netwatch.output import format_output

    database = _get_db(db)
    since_dt = _parse_duration(since) if since else None
    flow_list = database.list_flows(
        device=device,
        protocol=protocol,
        external_only=external_only,
        internal_only=internal_only,
        since=since_dt,
        min_bytes=min_bytes,
    )

    headers = ["DEVICE", "DST_IP", "PORT", "PROTO", "SNI", "BYTES UP", "BYTES DOWN", "COUNTRY"]
    rows = []
    for f in flow_list:
        rows.append([
            f.src_mac or "-",
            f.dst_ip,
            str(f.dst_port) if f.dst_port else "-",
            f.l7_protocol or f.l4_protocol.value,
            f.sni or "-",
            _human_bytes(f.bytes_sent),
            _human_bytes(f.bytes_received),
            f.dst_country or "-",
        ])
    format_output(fmt, headers, rows)


# --- summary ---

@main.command("summary")
@click.option("--since", default=None, help="Show only activity from this period (24h, 7d, 30d)")
@click.option("--group-by", default="device", help="Group results by: device")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]),
              help="Output format (default: table)")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def summary(since: str | None, group_by: str, fmt: str, db: str) -> None:
    """Show aggregated traffic summary by device, destination, and country."""
    from netwatch.output import format_output

    database = _get_db(db)
    since_dt = _parse_duration(since) if since else None
    stats = database.get_flow_summary(since=since_dt)

    headers = ["DEVICE", "DST_IP", "COUNTRY", "SENT", "RECEIVED", "FLOWS"]
    rows = []
    for s in stats:
        rows.append([
            s["src_mac"] or "-",
            s["dst_ip"],
            s["dst_country"] or "-",
            _human_bytes(s["total_sent"]),
            _human_bytes(s["total_received"]),
            str(s["flow_count"]),
        ])
    format_output(fmt, headers, rows)


# --- export ---

@main.command("export")
@click.option("--format", "fmt", default="csv", type=click.Choice(["json", "csv"]),
              help="Export format: csv or json (default: csv)")
@click.option("--output", "-o", default=None, help="Output file path (stdout if omitted)")
@click.option("--since", default=None, help="Export only flows from this period (24h, 7d, 30d)")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path [default: ~/.netwatch/netwatch.db]")
def export(fmt: str, output: str | None, since: str | None, db: str) -> None:
    """Export all flows for external analysis (spreadsheets, scripts, etc.)."""
    from netwatch.output import format_output

    database = _get_db(db)
    since_dt = _parse_duration(since) if since else None
    flow_list = database.list_flows(since=since_dt)

    headers = ["FLOW_ID", "SRC_IP", "DST_IP", "SRC_MAC", "DST_MAC", "SRC_PORT", "DST_PORT",
               "L4_PROTO", "L7_PROTO", "SNI", "BYTES_SENT", "BYTES_RECEIVED",
               "PACKETS_SENT", "PACKETS_RECEIVED", "STARTED_AT", "LAST_ACTIVITY", "DIRECTION"]
    rows = []
    for f in flow_list:
        rows.append([
            f.flow_id, f.src_ip, f.dst_ip, f.src_mac, f.dst_mac,
            str(f.src_port), str(f.dst_port), f.l4_protocol.value,
            f.l7_protocol or "", f.sni or "",
            str(f.bytes_sent), str(f.bytes_received),
            str(f.packets_sent), str(f.packets_received),
            f.started_at.isoformat(), f.last_activity_at.isoformat(),
            f.direction.value,
        ])

    file = open(output, "w") if output else None
    try:
        format_output(fmt, headers, rows, file=file)
    finally:
        if file:
            file.close()
            click.echo(f"Exported to {output}")


# --- config ---

@main.command("config")
@click.option("--db", default=DEFAULT_DB, help="Database path to check [default: ~/.netwatch/netwatch.db]")
def config(db: str) -> None:
    """Show database configuration and basic stats."""
    db_path = Path(db).expanduser()
    click.echo(f"Database: {db_path}")
    if db_path.exists():
        database = _get_db(db)
        stats = database.get_stats()
        click.echo(f"  Devices: {stats['devices']}")
        click.echo(f"  Flows: {stats['flows']}")
        click.echo(f"  Total bytes: {_human_bytes(stats['total_bytes'])}")
    else:
        click.echo("  (database not yet created)")


# --- update-oui ---

@main.command("update-oui")
@click.option("--url", default=None,
              help="URL of the OUI database (default: nmap-mac-prefixes from GitHub)")
@click.option("--output", default=None,
              help="Output file path (default: data/oui.txt relative to project root)")
def update_oui(url: str | None, output: str | None) -> None:
    """Download the MAC vendor (OUI) database for device identification.

    After downloading, 'capture start' and 'analyze offline' will automatically
    resolve MAC addresses to vendor names (e.g. Hikvision, Intelbras, TP-Link).
    The file is saved to data/oui.txt by default."""
    from netwatch.enrichment.fetch import DEFAULT_OUI_URL, DEFAULT_OUI_PATH, download_oui

    out = Path(output).expanduser() if output else DEFAULT_OUI_PATH
    src = url or DEFAULT_OUI_URL

    click.echo(f"Baixando OUI de {src} ...", err=True)
    try:
        db = download_oui(url=src, output=out)
    except Exception as exc:
        click.echo(f"Erro ao baixar OUI: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Salvo {db.count()} prefixos OUI em {out}")


# --- helpers ---

def _parse_capture_duration(s: str) -> int | None:
    """Parse a capture duration like '10', '30s', '5m', '1h' into seconds. None = continuous."""
    s = s.strip().lower()
    if s == "continuous":
        return None
    if s.endswith("s"):
        return max(1, int(s[:-1]))
    if s.endswith("m"):
        return max(1, int(s[:-1]) * 60)
    if s.endswith("h"):
        return max(1, int(s[:-1]) * 3600)
    try:
        return max(1, int(s))
    except ValueError:
        click.echo(f"Invalid duration: {s}", err=True)
        sys.exit(1)


def _parse_duration(s: str) -> datetime:
    """Parse a duration string like '24h', '7d', '30d' into a datetime."""
    s = s.strip().lower()
    now = datetime.utcnow()
    if s.endswith("d"):
        return now - timedelta(days=int(s[:-1]))
    if s.endswith("h"):
        return now - timedelta(hours=int(s[:-1]))
    if s.endswith("m"):
        return now - timedelta(minutes=int(s[:-1]))
    return now - timedelta(days=int(s))


def _human_bytes(n: int) -> str:
    """Format bytes into human readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


if __name__ == "__main__":
    main()
