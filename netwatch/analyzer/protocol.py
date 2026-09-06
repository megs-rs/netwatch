"""Protocol classification for NetWatch."""

from __future__ import annotations

from scapy.layers.inet import ICMP, TCP, UDP
from scapy.packet import Packet

from netwatch.storage.models import L4Protocol

KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    443: "tls",
    514: "syslog",
    554: "rtsp",
    1900: "ssdp",
    1883: "mqtt",
    3389: "rdp",
    5353: "mdns",
    8000: "http-alt",
    8080: "http-alt",
    8554: "rtsp",
}


def get_l4(pkt: Packet) -> L4Protocol:
    if pkt.haslayer(TCP):
        return L4Protocol.TCP
    if pkt.haslayer(UDP):
        return L4Protocol.UDP
    if pkt.haslayer(ICMP):
        return L4Protocol.ICMP
    return L4Protocol.OTHER


def get_l7(pkt: Packet) -> str | None:
    tcp = pkt.getlayer(TCP)
    udp = pkt.getlayer(UDP)
    if tcp is not None:
        proto = classify_tcp(pkt, tcp)
        if proto:
            return proto
    if udp is not None:
        proto = classify_udp(pkt, udp)
        if proto:
            return proto
    return None


def classify_tcp(pkt: Packet, tcp: TCP) -> str | None:
    dport = tcp.dport
    if dport in KNOWN_PORTS:
        return KNOWN_PORTS[dport]
    if tcp.payload:
        raw = bytes(tcp.payload)
        if detect_tls(raw):
            return "tls"
        if raw.startswith(b"SSH-"):
            return "ssh"
        if raw.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP/")):
            return "http"
    return None


def classify_udp(pkt: Packet, udp: UDP) -> str | None:
    dport = udp.dport
    if dport in KNOWN_PORTS:
        return KNOWN_PORTS[dport]
    return None


def detect_tls(raw: bytes) -> bool:
    if len(raw) < 5:
        return False
    content_type = raw[0]
    version_major = raw[1]
    return content_type == 0x16 and version_major == 0x03


def extract_sni(pkt: Packet) -> str | None:
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt.getlayer(TCP)
    if not tcp.payload:
        return None
    raw = bytes(tcp.payload)
    return _extract_sni_from_raw(raw)


def _extract_sni_from_raw(raw: bytes) -> str | None:
    if len(raw) < 5:
        return None
    if raw[0] != 0x16 or raw[1] != 0x03:
        return None
    try:
        offset = 5
        handshake_type = raw[offset]
        if handshake_type != 0x01:
            return None
        offset += 4
        offset += 2
        offset += 32
        session_id_len = raw[offset]
        offset += 1 + session_id_len
        cipher_len = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2 + cipher_len
        comp_len = raw[offset]
        offset += 1 + comp_len
        if offset + 2 > len(raw):
            return None
        ext_total = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        end = offset + ext_total
        while offset + 4 <= end and offset < len(raw):
            ext_type = int.from_bytes(raw[offset : offset + 2], "big")
            ext_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            offset += 4
            if ext_type == 0x0000:
                sni_data = raw[offset : offset + ext_len]
                if len(sni_data) < 5:
                    return None
                name_len = int.from_bytes(sni_data[3:5], "big")
                name = sni_data[5 : 5 + name_len]
                return name.decode("utf-8", errors="ignore") or None
            offset += ext_len
    except (ValueError, IndexError, OverflowError):
        return None
    return None
