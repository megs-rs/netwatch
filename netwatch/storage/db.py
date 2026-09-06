"""SQLite storage layer for NetWatch."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from netwatch.storage.models import Device, Direction, Flow, L4Protocol

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac_address TEXT PRIMARY KEY,
    vendor TEXT DEFAULT '',
    hostname TEXT,
    alias TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip_addresses TEXT DEFAULT '[]',
    tags TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS device_ips (
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (mac_address, ip_address),
    FOREIGN KEY (mac_address) REFERENCES devices(mac_address)
);

CREATE TABLE IF NOT EXISTS flows (
    flow_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_mac TEXT DEFAULT '',
    dst_mac TEXT DEFAULT '',
    src_port INTEGER DEFAULT 0,
    dst_port INTEGER DEFAULT 0,
    l4_protocol TEXT NOT NULL,
    l7_protocol TEXT,
    sni TEXT,
    dst_asn TEXT,
    dst_country TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    packets_sent INTEGER DEFAULT 0,
    packets_received INTEGER DEFAULT 0,
    started_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'internal-internal'
);

CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac TEXT NOT NULL,
    query_name TEXT NOT NULL,
    resolved_ips TEXT DEFAULT '[]',
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_src_mac ON flows(src_mac);
CREATE INDEX IF NOT EXISTS idx_flows_dst_mac ON flows(dst_mac);
CREATE INDEX IF NOT EXISTS idx_flows_started_at ON flows(started_at);
CREATE INDEX IF NOT EXISTS idx_flows_l7_protocol ON flows(l7_protocol);
CREATE INDEX IF NOT EXISTS idx_device_ips_mac ON device_ips(mac_address);
CREATE INDEX IF NOT EXISTS idx_dns_logs_mac ON dns_logs(device_mac);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # --- Devices ---

    def upsert_device(self, device: Device) -> None:
        self.conn.execute(
            """INSERT INTO devices (mac_address, vendor, hostname, alias, first_seen, last_seen, ip_addresses, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(mac_address) DO UPDATE SET
                   vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END,
                   hostname = COALESCE(excluded.hostname, devices.hostname),
                   alias = COALESCE(excluded.alias, devices.alias),
                   last_seen = excluded.last_seen,
                   ip_addresses = excluded.ip_addresses,
                   tags = excluded.tags
            """,
            (
                device.mac_address,
                device.vendor,
                device.hostname,
                device.alias,
                device.first_seen.isoformat(),
                device.last_seen.isoformat(),
                json.dumps(device.ip_addresses),
                json.dumps(device.tags),
            ),
        )
        for ip in device.ip_addresses:
            self.conn.execute(
                """INSERT INTO device_ips (mac_address, ip_address, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(mac_address, ip_address) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (device.mac_address, ip, device.first_seen.isoformat(), device.last_seen.isoformat()),
            )
        self.conn.commit()

    def get_device(self, mac: str) -> Device | None:
        row = self.conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,)).fetchone()
        if not row:
            return None
        return self._row_to_device(row)

    def list_devices(
        self,
        tag: str | None = None,
        since: datetime | None = None,
        sort: str = "last_seen",
    ) -> list[Device]:
        query = "SELECT d.*, " \
                "COALESCE(f.bytes_total, 0) AS bytes_total, " \
                "COALESCE(f.flow_count, 0) AS flow_count " \
                "FROM devices d " \
                "LEFT JOIN ( " \
                "  SELECT src_mac AS mac, " \
                "         SUM(bytes_sent + bytes_received) AS bytes_total, " \
                "         COUNT(*) AS flow_count " \
                "  FROM flows GROUP BY src_mac " \
                ") f ON d.mac_address = f.mac WHERE 1=1"
        params: list = []
        if tag:
            query += " AND d.tags LIKE ?"
            params.append(f"%{tag}%")
        if since:
            query += " AND d.last_seen >= ?"
            params.append(since.isoformat())
        sort_col = {"bytes_total": "bytes_total", "flow_count": "flow_count", "last_seen": "last_seen"}.get(sort, "last_seen")
        query += f" ORDER BY {sort_col} DESC"
        rows = self.conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            dev = self._row_to_device(r)
            dev._bytes_total = r["bytes_total"]
            dev._flow_count = r["flow_count"]
            results.append(dev)
        return results

    def update_device_alias(self, mac: str, alias: str) -> bool:
        cur = self.conn.execute("UPDATE devices SET alias = ? WHERE mac_address = ?", (alias, mac))
        self.conn.commit()
        return cur.rowcount > 0

    def update_device_tags(self, mac: str, tags: list[str]) -> bool:
        cur = self.conn.execute(
            "UPDATE devices SET tags = ? WHERE mac_address = ?",
            (json.dumps(tags), mac),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def add_device_tag(self, mac: str, tag: str) -> bool:
        device = self.get_device(mac)
        if not device:
            return False
        if tag not in device.tags:
            device.tags.append(tag)
            return self.update_device_tags(mac, device.tags)
        return True

    def _row_to_device(self, row: sqlite3.Row) -> Device:
        return Device(
            mac_address=row["mac_address"],
            vendor=row["vendor"] or "",
            hostname=row["hostname"],
            alias=row["alias"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            ip_addresses=json.loads(row["ip_addresses"] or "[]"),
            tags=json.loads(row["tags"] or "[]"),
        )

    # --- Flows ---

    def insert_flow(self, flow: Flow) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO flows
               (flow_id, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port,
                l4_protocol, l7_protocol, sni, dst_asn, dst_country,
                bytes_sent, bytes_received, packets_sent, packets_received,
                started_at, last_activity_at, direction)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                flow.flow_id,
                flow.src_ip,
                flow.dst_ip,
                flow.src_mac,
                flow.dst_mac,
                flow.src_port,
                flow.dst_port,
                flow.l4_protocol.value,
                flow.l7_protocol,
                flow.sni,
                flow.dst_asn,
                flow.dst_country,
                flow.bytes_sent,
                flow.bytes_received,
                flow.packets_sent,
                flow.packets_received,
                flow.started_at.isoformat(),
                flow.last_activity_at.isoformat(),
                flow.direction.value,
            ),
        )
        self.conn.commit()

    def list_flows(
        self,
        device: str | None = None,
        protocol: str | None = None,
        external_only: bool = False,
        internal_only: bool = False,
        since: datetime | None = None,
        until: datetime | None = None,
        min_bytes: int | None = None,
    ) -> list[Flow]:
        query = "SELECT * FROM flows WHERE 1=1"
        params: list = []
        if device:
            query += " AND (src_mac = ? OR dst_mac = ?)"
            params.extend([device, device])
        if protocol:
            query += " AND (l4_protocol = ? OR l7_protocol = ?)"
            params.extend([protocol, protocol])
        if external_only:
            query += " AND direction = 'internal-external'"
        if internal_only:
            query += " AND direction = 'internal-internal'"
        if since:
            query += " AND started_at >= ?"
            params.append(since.isoformat())
        if until:
            query += " AND started_at <= ?"
            params.append(until.isoformat())
        if min_bytes:
            query += " AND (bytes_sent + bytes_received) >= ?"
            params.append(min_bytes)
        query += " ORDER BY last_activity_at DESC"
        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_flow(r) for r in rows]

    def get_flow_summary(self, since: datetime | None = None) -> list[dict]:
        query = """
            SELECT src_mac, dst_ip, dst_country,
                   SUM(bytes_sent) as total_sent,
                   SUM(bytes_received) as total_received,
                   COUNT(*) as flow_count
            FROM flows
            WHERE 1=1
        """
        params: list = []
        if since:
            query += " AND started_at >= ?"
            params.append(since.isoformat())
        query += " GROUP BY src_mac, dst_ip ORDER BY (total_sent + total_received) DESC"
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _row_to_flow(self, row: sqlite3.Row) -> Flow:
        return Flow(
            flow_id=row["flow_id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_mac=row["src_mac"],
            dst_mac=row["dst_mac"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            l4_protocol=L4Protocol(row["l4_protocol"]),
            l7_protocol=row["l7_protocol"],
            sni=row["sni"],
            dst_asn=row["dst_asn"],
            dst_country=row["dst_country"],
            bytes_sent=row["bytes_sent"],
            bytes_received=row["bytes_received"],
            packets_sent=row["packets_sent"],
            packets_received=row["packets_received"],
            started_at=datetime.fromisoformat(row["started_at"]),
            last_activity_at=datetime.fromisoformat(row["last_activity_at"]),
            direction=Direction(row["direction"]),
        )

    # --- Stats ---

    def get_stats(self) -> dict:
        device_count = self.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        flow_count = self.conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        total_bytes = self.conn.execute(
            "SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) FROM flows"
        ).fetchone()[0]
        return {
            "devices": device_count,
            "flows": flow_count,
            "total_bytes": total_bytes,
        }
