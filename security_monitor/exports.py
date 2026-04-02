from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from urllib import error, request

from .config import MonitorConfig


class ExportManager:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.export_dir = self.config.export_path
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.siem_dir = self.export_dir / "siem"
        self.siem_dir.mkdir(parents=True, exist_ok=True)

    def export_siem(
        self,
        payload: dict[str, object],
        webhook_url: str | None = None,
    ) -> dict[str, object]:
        event = self._siem_event(payload)
        file_path = self.siem_dir / self.config.siem_jsonl_file
        with file_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True) + "\n")

        result: dict[str, object] = {
            "ok": True,
            "file_path": str(file_path),
            "webhook_status": "skipped",
        }

        if webhook_url:
            try:
                response = self._post_webhook(webhook_url, event)
                result["webhook_status"] = response
            except Exception as exc:  # pragma: no cover - network/environment specific
                result["ok"] = False
                result["webhook_status"] = f"failed: {exc}"
                result["error"] = str(exc)

        return result

    def build_pdf(self, payload: dict[str, object]) -> bytes:
        current = payload.get("current") or {}
        runtime = payload.get("runtime") or {}
        stats = payload.get("stats") or {}
        alerts = payload.get("alerts") or []

        lines = [
            "CogniShield Behavioral Security Report",
            "",
            f"Generated: {payload.get('generated_at', datetime.now().isoformat())}",
            f"User: {payload.get('user_name', runtime.get('user_name', 'unknown'))}",
            f"Mode: {runtime.get('mode', 'unknown')}",
            f"Privacy mode: {runtime.get('privacy_mode', 'browser_aware')}",
            "",
            f"Summary: {current.get('summary', 'No active assessment')}",
            f"Severity: {current.get('severity', 'idle')}",
            f"Risk score: {current.get('risk_score', 0)}",
            f"Confidence: {current.get('confidence_score', 0)}",
            "",
            "Explanation:",
            str(current.get("explanation", "No explanation available.")),
            "",
            "Recommended actions:",
        ]

        recommended_actions = current.get("recommended_actions") or []
        if recommended_actions:
            lines.extend(f"- {action}" for action in recommended_actions)
        else:
            lines.append("- No action guidance available.")

        lines.extend(
            [
                "",
                "Watchlist and deception hits:",
            ]
        )
        watchlist_hits = current.get("watchlist_hits") or []
        honeypot_hits = current.get("honeypot_hits") or []
        combined_hits = [*watchlist_hits, *honeypot_hits]
        if combined_hits:
            lines.extend(f"- {item}" for item in combined_hits)
        else:
            lines.append("- No watchlist or honeypot hits.")

        lines.extend(
            [
                "",
                "Runtime metrics:",
                f"- Total samples: {stats.get('total_samples', 0)}",
                f"- Alerts: {stats.get('anomaly_count', 0)}",
                f"- Average risk: {stats.get('average_risk', 0)}",
                f"- Browser events: {stats.get('browser_event_count', 0)}",
                f"- Honeypot detections: {stats.get('honeypot_detection_count', 0)}",
                "",
                "Recent alerts:",
            ]
        )

        if alerts:
            for alert in alerts[:6]:
                lines.append(
                    f"- {alert.get('severity', 'unknown')} | {alert.get('risk_score', 0)} | {alert.get('summary', '')}"
                )
        else:
            lines.append("- No recent alerts.")

        return _build_pdf_bytes(lines)

    def _siem_event(self, payload: dict[str, object]) -> dict[str, object]:
        runtime = payload.get("runtime") or {}
        current = payload.get("current") or {}
        return {
            "generated_at": payload.get("generated_at", datetime.now().isoformat()),
            "platform": "CogniShield",
            "user_name": payload.get("user_name", runtime.get("user_name")),
            "mode": runtime.get("mode"),
            "privacy_mode": runtime.get("privacy_mode"),
            "risk_score": current.get("risk_score"),
            "severity": current.get("severity"),
            "summary": current.get("summary"),
            "explanation": current.get("explanation"),
            "recommended_actions": current.get("recommended_actions", []),
            "watchlist_hits": current.get("watchlist_hits", []),
            "honeypot_hits": current.get("honeypot_hits", []),
            "process_observations": current.get("process_observations", []),
            "search_queries": current.get("search_queries", []),
            "domains": current.get("domains", []),
            "risk_factors": current.get("risk_factors", []),
            "intent_matches": current.get("intent_matches", []),
        }

    def _post_webhook(self, webhook_url: str, event: dict[str, object]) -> str:
        body = json.dumps(event).encode("utf-8")
        req = request.Request(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.config.webhook_timeout_seconds) as response:
                return f"delivered:{response.status}"
        except error.HTTPError as exc:  # pragma: no cover - network/environment specific
            return f"http_error:{exc.code}"


def _build_pdf_bytes(lines: list[str]) -> bytes:
    wrapped_lines: list[str] = []
    for line in lines:
        segments = wrap(line, width=92) or [""]
        wrapped_lines.extend(segments)

    lines_per_page = 42
    pages = [
        wrapped_lines[index : index + lines_per_page]
        for index in range(0, len(wrapped_lines), lines_per_page)
    ] or [[]]

    objects: list[bytes] = []
    page_object_ids: list[int] = []
    current_object_id = 1

    catalog_id = current_object_id
    current_object_id += 1
    pages_id = current_object_id
    current_object_id += 1
    font_id = current_object_id
    current_object_id += 1

    content_ids: list[int] = []
    for _ in pages:
        content_ids.append(current_object_id)
        current_object_id += 1
        page_object_ids.append(current_object_id)
        current_object_id += 1

    objects.append(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1"))

    kids = " ".join(f"{page_id} 0 R" for page_id in page_object_ids)
    objects.append(
        f"<< /Type /Pages /Count {len(page_object_ids)} /Kids [{kids}] >>".encode("latin-1")
    )

    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for page_lines, content_id, page_id in zip(pages, content_ids, page_object_ids):
        stream = _content_stream(page_lines)
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream"
        )
        objects.append(
            (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("latin-1")
        )

    buffer = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(buffer))
        buffer.extend(f"{index} 0 obj\n".encode("latin-1"))
        buffer.extend(obj)
        buffer.extend(b"\nendobj\n")

    xref_offset = len(buffer)
    buffer.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    buffer.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    buffer.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("latin-1")
    )
    return bytes(buffer)


def _content_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 11 Tf", "50 760 Td", "14 TL"]
    for line in lines:
        commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("T*")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def _pdf_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )
