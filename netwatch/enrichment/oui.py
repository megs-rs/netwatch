"""Local OUI (IEEE) lookup for vendor identification."""

from __future__ import annotations

from pathlib import Path


class OUIDatabase:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._oui: dict[str, str] = {}
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        with open(self.path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                prefix, vendor = parts
                prefix = prefix.replace(":", "").replace("-", "").lower()
                if len(prefix) not in (6, 7, 9):
                    continue
                self._oui[prefix] = vendor

    def lookup(self, mac: str) -> str:
        normalized = mac.replace(":", "").replace("-", "").lower()
        for size in (9, 7, 6):
            prefix = normalized[:size]
            vendor = self._oui.get(prefix)
            if vendor is not None:
                return vendor
        return ""

    def count(self) -> int:
        return len(self._oui)

    def is_loaded(self) -> bool:
        return bool(self._oui)
