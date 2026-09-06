"""Packet capture wrapper around Scapy."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapReader, rdpcap


def read_packets(path: str | Path) -> list[Packet]:
    return rdpcap(str(path))


def iter_packets(path: str | Path) -> Iterator[Packet]:
    with PcapReader(str(path)) as reader:
        yield from reader
