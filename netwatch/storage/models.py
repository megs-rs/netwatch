"""Data models for NetWatch."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class L4Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class Direction(str, Enum):
    INTERNAL_INTERNAL = "internal-internal"
    INTERNAL_EXTERNAL = "internal-external"


@dataclass
class Device:
    mac_address: str
    vendor: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    hostname: str | None = None
    alias: str | None = None
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tags: list[str] = field(default_factory=list)


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_mac: str = ""
    dst_mac: str = ""
    src_port: int = 0
    dst_port: int = 0
    l4_protocol: L4Protocol = L4Protocol.OTHER
    l7_protocol: str | None = None
    sni: str | None = None
    dst_asn: str | None = None
    dst_country: str | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    last_activity_at: datetime = field(default_factory=datetime.utcnow)
    direction: Direction = Direction.INTERNAL_INTERNAL
    flow_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class DNSLog:
    device_mac: str
    query_name: str
    resolved_ips: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
