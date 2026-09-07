"""Packet capture wrapper around Scapy."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sniff
from scapy.utils import PcapReader, rdpcap


def read_packets(path: str | Path) -> list[Packet]:
    return rdpcap(str(path))


def iter_packets(path: str | Path) -> Iterator[Packet]:
    with PcapReader(str(path)) as reader:
        yield from reader


def sniff_packets(interface: str, timeout: int, bpf_filter: str = "") -> list[Packet]:
    """Capture packets live from an interface for ``timeout`` seconds."""
    return sniff(iface=interface, timeout=timeout, filter=bpf_filter or None, store=True)


def interface_exists(interface: str) -> bool:
    """Return True if the given interface is present on the system."""
    from scapy.arch import get_if_list
    return interface in get_if_list()


def can_capture() -> bool:
    """Return True if a raw socket can be opened (CAP_NET_RAW/root required)."""
    import socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
        return True
    except PermissionError:
        return False
