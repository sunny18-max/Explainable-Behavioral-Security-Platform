from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .config import MonitorConfig


class HoneypotManager:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.honeypot_dir = self.config.honeypot_path
        self.honeypot_dir.mkdir(parents=True, exist_ok=True)
        self._fingerprints: dict[str, tuple[int, int]] = {}

    def ensure_decoys(self) -> list[Path]:
        paths: list[Path] = []
        for file_name in self.config.honeypot_file_names:
            path = self.honeypot_dir / file_name
            if not path.exists():
                path.write_text(
                    "Decoy document for behavioral security monitoring.\n"
                    "This file contains no real credentials or secrets.\n",
                    encoding="utf-8",
                )
            paths.append(path)
        self._prime_fingerprints(paths)
        return paths

    def check_hits(self, started_at: datetime, ended_at: datetime) -> list[str]:
        hits: list[str] = []
        for path in self.ensure_decoys():
            try:
                stat_result = path.stat()
            except OSError:
                continue
            touch_ns = max(stat_result.st_mtime_ns, stat_result.st_ctime_ns)
            fingerprint = (touch_ns, int(stat_result.st_size))
            key = str(path)
            previous = self._fingerprints.get(key)
            self._fingerprints[key] = fingerprint
            if previous is None or previous == fingerprint:
                continue
            touched_at = datetime.fromtimestamp(touch_ns / 1_000_000_000)
            if started_at <= touched_at <= ended_at:
                hits.append(f"Honeypot file touched: {path.name}")
        return hits

    def summary(self) -> dict[str, object]:
        paths = self.ensure_decoys()
        return {
            "directory": str(self.honeypot_dir),
            "decoy_count": len(paths),
            "files": [path.name for path in paths],
        }

    def _prime_fingerprints(self, paths: list[Path]) -> None:
        for path in paths:
            key = str(path)
            if key in self._fingerprints:
                continue
            try:
                stat_result = path.stat()
            except OSError:
                continue
            touch_ns = max(stat_result.st_mtime_ns, stat_result.st_ctime_ns)
            self._fingerprints[key] = (touch_ns, int(stat_result.st_size))
