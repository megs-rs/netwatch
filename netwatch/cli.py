"""CLI entry point for NetWatch."""

from __future__ import annotations

import sys
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
    """NetWatch - Network traffic analyzer CLI."""


# --- capture ---

@main.group()
def capture() -> None:
    """Capture network traffic."""


@capture.command("start")
@click.option("-i", "--interface", required=True, help="Network interface to capture")
@click.option("--mode", default="live", type=click.Choice(["live", "mirror", "gateway"]))
@click.option("--duration", default="continuous", help="Capture duration (1h, 24h, continuous)")
@click.option("--filter", "bpf_filter", default="", help="BPF filter (tcpdump syntax)")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def capture_start(interface: str, mode: str, duration: str, bpf_filter: str, db: str) -> None:
    """Start live packet capture."""
    click.echo(f"Capture not yet implemented (interface={interface}, mode={mode})")


@capture.command("stop")
def capture_stop() -> None:
    """Stop a running capture."""
    click.echo("Capture stop not yet implemented.")


@capture.command("status")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def capture_status(db: str) -> None:
    """Show capture status."""
    click.echo("Capture status not yet implemented.")


# --- analyze ---

@main.group()
def analyze() -> None:
    """Analyze network data."""


@analyze.command("offline")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
@click.option("--oui-file", default=None, help="Path to IEEE OUI database file")
def analyze_offline(pcap_file: str, db: str, oui_file: str | None) -> None:
    """Analyze an existing .pcap/.pcapng file."""
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
    """Manage discovered devices."""


@devices.command("list")
@click.option("--tag", default=None, help="Filter by tag")
@click.option("--since", default=None, help="Filter by activity since (e.g. 24h, 7d)")
@click.option("--sort", default="last_seen", type=click.Choice(["bytes_total", "last_seen", "flow_count"]))
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def devices_list(tag: str | None, since: str | None, sort: str, fmt: str, db: str) -> None:
    """List discovered devices."""
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
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def devices_rename(mac: str, alias: str, db: str) -> None:
    """Rename a device (set alias)."""
    database = _get_db(db)
    if database.update_device_alias(mac, alias):
        click.echo(f"Device {mac} renamed to {alias}")
    else:
        click.echo(f"Device {mac} not found", err=True)
        sys.exit(1)


@devices.command("tag")
@click.argument("mac")
@click.argument("tag")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def devices_tag(mac: str, tag: str, db: str) -> None:
    """Tag a device."""
    database = _get_db(db)
    if database.add_device_tag(mac, tag):
        click.echo(f"Tag '{tag}' added to device {mac}")
    else:
        click.echo(f"Device {mac} not found", err=True)
        sys.exit(1)


# --- flows ---

@main.group()
def flows() -> None:
    """Manage network flows."""


@flows.command("list")
@click.option("--device", default=None, help="Filter by device MAC or alias")
@click.option("--protocol", default=None, help="Filter by L4/L7 protocol")
@click.option("--external-only", is_flag=True, help="Show only external traffic")
@click.option("--internal-only", is_flag=True, help="Show only internal traffic")
@click.option("--since", default=None, help="Filter since (e.g. 24h, 7d)")
@click.option("--min-bytes", default=None, type=int, help="Filter flows above minimum bytes")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
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
    """List network flows."""
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
@click.option("--since", default=None, help="Period (e.g. 7d, 30d)")
@click.option("--group-by", default="device", help="Group by field")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv"]))
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def summary(since: str | None, group_by: str, fmt: str, db: str) -> None:
    """Show traffic summary."""
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
@click.option("--format", "fmt", default="csv", type=click.Choice(["json", "csv"]))
@click.option("--output", "-o", default=None, help="Output file (stdout if omitted)")
@click.option("--since", default=None, help="Export data since period (e.g. 30d)")
@click.option("--db", default=DEFAULT_DB, help="SQLite database path")
def export(fmt: str, output: str | None, since: str | None, db: str) -> None:
    """Export data for external analysis."""
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
@click.option("--db", default=DEFAULT_DB, help="Show/set default database path")
def config(db: str) -> None:
    """Show configuration."""
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


# --- helpers ---

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
