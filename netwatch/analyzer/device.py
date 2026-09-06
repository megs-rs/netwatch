"""Device identification from packets."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from netwatch.enrichment.oui import OUIDatabase
from netwatch.storage.models import Device

def collect_devices(packets: Iterable[Packet], oui_db: OUIDatabase | None = None) -> list[Device]:
    devices: dict[str, Device] = {}

    for pkt in packets:
        eth = pkt.getlayer(Ether)
        if eth is None or not eth.src:
            continue
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt.getlayer(IP)
        if not _is_private(ip_layer.src):
            continue

        mac = eth.src.lower()
        ip = ip_layer.src
        ts = _packet_time(pkt)

        device = devices.get(mac)
        if device is None:
            vendor = oui_db.lookup(mac) if oui_db else ""
            device = Device(
                mac_address=mac,
                vendor=vendor,
                first_seen=ts,
                last_seen=ts,
            )
            devices[mac] = device
        else:
            device.first_seen = min(device.first_seen, ts)
            device.last_seen = max(device.last_seen, ts)

        if device.hostname is None:
            device.hostname = extract_hostname(pkt)

        if ip not in device.ip_addresses:
            device.ip_addresses.append(ip)

    return list(devices.values())


def _is_private(ip: str) -> bool:
    try:
        octets = [int(o) for o in ip.split(".")]
    except ValueError:
        return False
    if len(octets) != 4:
        return False
    a = octets[0]
    if a == 10:
        return True
    if a == 172 and 16 <= octets[1] <= 31:
        return True
    if a == 192 and octets[1] == 168:
        return True
    if a == 127:
        return True
    return False


def extract_hostname(pkt: Packet) -> str | None:
    return _try_dns_hostname(pkt)


def _try_dns_hostname(pkt: Packet) -> str | None:
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import UDP

        if not pkt.haslayer(UDP):
            return None
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.haslayer(DNSQR):
            return pkt.getlayer(DNSQR).qname.decode("utf-8", errors="ignore").rstrip(".")
    except Exception:
        return None
    return None


def _packet_time(pkt: Packet) -> datetime:
    if hasattr(pkt, "time"):
        return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).replace(tzinfo=None)
    return datetime.utcnow()
