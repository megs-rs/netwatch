"""Download and validate the OUI vendor database."""

from __future__ import annotations

from pathlib import Path
from urllib.request import urlopen

from netwatch.enrichment.oui import OUIDatabase

DEFAULT_OUI_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes"

DEFAULT_OUI_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "oui.txt"


def download_oui(url: str = DEFAULT_OUI_URL, output: Path = DEFAULT_OUI_PATH) -> OUIDatabase:
    """Download an OUI database to ``output`` and return a loaded OUIDatabase."""
    with urlopen(url, timeout=30) as resp:
        data = resp.read()

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(".tmp")
    tmp.write_bytes(data)
    output.write_bytes(data)

    db = OUIDatabase(output)
    if not db.is_loaded():
        tmp.unlink(missing_ok=True)
        raise ValueError(f"Nenhum prefixo OUI parseado no conteúdo baixado de {url}")
    tmp.unlink(missing_ok=True)
    return db
