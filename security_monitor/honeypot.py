from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .config import MonitorConfig


class HoneypotManager:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.honeypot_dir = self.config.honeypot_path
        self.honeypot_dir.mkdir(parents=True, exist_ok=True)

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
        return paths

    def check_hits(self, started_at: datetime, ended_at: datetime) -> list[str]:
        hits: list[str] = []
        for path in self.ensure_decoys():
            try:
                stat_result = path.stat()
            except OSError:
                continue
            last_touch = max(
                stat_result.st_mtime,
                stat_result.st_ctime,
                getattr(stat_result, "st_atime", 0.0),
            )
            touched_at = datetime.fromtimestamp(last_touch)
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
