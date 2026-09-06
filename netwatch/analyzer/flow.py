"""Flow aggregation and packet analysis."""

from __future__ import annotations

from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from netwatch.analyzer.protocol import extract_sni, get_l4, get_l7
from netwatch.storage.models import Direction, Flow

SESSION_TIMEOUT_SECONDS = 300


def build_flows(packets: list[Packet]) -> list[Flow]:
    local_ips = _discover_local_ips(packets)
    sessions: dict[tuple, Flow] = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt.getlayer(IP)
        eth = pkt.getlayer(Ether)
        ts = _packet_time(pkt)

        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        src_mac = eth.src if eth else ""
        dst_mac = eth.dst if eth else ""
        src_port = dst_port = 0

        if pkt.haslayer(TCP):
            src_port = pkt.getlayer(TCP).sport
            dst_port = pkt.getlayer(TCP).dport
        elif pkt.haslayer(UDP):
            src_port = pkt.getlayer(UDP).sport
            dst_port = pkt.getlayer(UDP).dport

        if ip_src in local_ips:
            local_ip, remote_ip = ip_src, ip_dst
            local_mac, remote_mac = src_mac, dst_mac
            local_port, remote_port = src_port, dst_port
            outgoing = True
        elif ip_dst in local_ips:
            local_ip, remote_ip = ip_dst, ip_src
            local_mac, remote_mac = dst_mac, src_mac
            local_port, remote_port = dst_port, src_port
            outgoing = False
        else:
            continue

        l4 = get_l4(pkt)
        direction = _classify_direction(local_ip, remote_ip)

        key = (local_ip, remote_ip, local_port, remote_port, l4.value)

        flow = sessions.get(key)
        if flow is None:
            flow = Flow(
                src_ip=local_ip,
                dst_ip=remote_ip,
                src_mac=local_mac,
                dst_mac=remote_mac,
                src_port=local_port,
                dst_port=remote_port,
                l4_protocol=l4,
                started_at=ts,
                last_activity_at=ts,
                direction=direction,
            )
            sessions[key] = flow

        bytes_len = len(pkt)
        if outgoing:
            flow.bytes_sent += bytes_len
            flow.packets_sent += 1
        else:
            flow.bytes_received += bytes_len
            flow.packets_received += 1

        flow.last_activity_at = max(flow.last_activity_at, ts)

        if flow.l7_protocol is None:
            flow.l7_protocol = get_l7(pkt)
        if flow.sni is None:
            flow.sni = extract_sni(pkt) or flow.sni

    return list(sessions.values())


def _discover_local_ips(packets: list[Packet]) -> set[str]:
    local_ips: set[str] = set()
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip_layer = pkt.getlayer(IP)
        eth = pkt.getlayer(Ether)
        if eth is None:
            continue
        if _is_private(ip_layer.src) and not eth.src.startswith(("ff", "01:00:5e")):
            local_ips.add(ip_layer.src)
    return local_ips


def _classify_direction(src_ip: str, dst_ip: str) -> Direction:
    if _is_private(src_ip) and _is_private(dst_ip):
        return Direction.INTERNAL_INTERNAL
    return Direction.INTERNAL_EXTERNAL


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


def _packet_time(pkt: Packet) -> datetime:
    if hasattr(pkt, "time"):
        return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).replace(tzinfo=None)
    return datetime.utcnow()
