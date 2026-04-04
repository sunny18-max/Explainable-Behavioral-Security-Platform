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
        self._pending_hits: list[str] = []
        self._last_triggered_at: datetime | None = None

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

    def trigger_demo_hit(self, file_name: str | None = None) -> str:
        paths = self.ensure_decoys()
        target = next((path for path in paths if path.name == file_name), paths[0])
        stamp = datetime.now()
        with target.open("a", encoding="utf-8") as handle:
            handle.write(f"Simulated decoy interaction for dashboard demo at {stamp.isoformat()}\n")
        self._last_triggered_at = stamp
        hit_message = f"Honeypot file touched: {target.name}"
        self._pending_hits.append(hit_message)
        return hit_message

    def check_hits(self, started_at: datetime, ended_at: datetime) -> list[str]:
        hits: list[str] = []
        if self._pending_hits:
            hits.extend(self._pending_hits)
            self._pending_hits.clear()
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
        return list(dict.fromkeys(hits))

    def summary(self) -> dict[str, object]:
        paths = self.ensure_decoys()
        return {
            "directory": str(self.honeypot_dir),
            "decoy_count": len(paths),
            "files": [path.name for path in paths],
            "automation_ready": True,
            "last_triggered_at": (
                self._last_triggered_at.isoformat()
                if self._last_triggered_at is not None
                else None
            ),
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
