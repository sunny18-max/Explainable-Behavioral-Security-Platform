from __future__ import annotations

from datetime import datetime
from urllib.parse import parse_qs, urlparse

from .models import BrowserEvent


class BrowserCompanionParser:
    search_hosts = {
        "www.google.com": "q",
        "google.com": "q",
        "www.bing.com": "q",
        "bing.com": "q",
        "search.brave.com": "q",
        "duckduckgo.com": "q",
        "www.duckduckgo.com": "q",
        "search.yahoo.com": "p",
        "www.yahoo.com": "p",
        "www.youtube.com": "search_query",
    }

    def from_payload(self, payload: dict[str, object]) -> BrowserEvent:
        observed_at = self._parse_datetime(payload.get("observed_at"))
        browser_name = str(payload.get("browser_name") or "browser").strip().lower()
        tab_title = str(payload.get("tab_title") or payload.get("title") or "").strip()
        url = str(payload.get("url") or "").strip()
        parsed_url = urlparse(url) if url else None
        domain = self._normalize_domain(parsed_url.netloc if parsed_url else "")
        search_query = self._extract_search_query(parsed_url)
        if not tab_title:
            tab_title = domain or "active browser tab"

        return BrowserEvent(
            observed_at=observed_at,
            browser_name=browser_name,
            tab_title=tab_title,
            url=url,
            domain=domain,
            search_query=search_query,
            source=str(payload.get("source") or "extension"),
            tab_id=self._parse_optional_int(payload.get("tab_id")),
            window_id=self._parse_optional_int(payload.get("window_id")),
        )

    def _parse_datetime(self, raw_value: object) -> datetime:
        if isinstance(raw_value, str) and raw_value.strip():
            try:
                return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
            except ValueError:
                return datetime.now()
        return datetime.now()

    def _normalize_domain(self, raw_domain: str) -> str:
        return raw_domain.lower().removeprefix("www.").strip()

    def _extract_search_query(self, parsed_url: object) -> str | None:
        if parsed_url is None:
            return None
        host = self._normalize_domain(getattr(parsed_url, "netloc", ""))
        parameter_name = self.search_hosts.get(host)
        if parameter_name is None:
            return None

        query_string = getattr(parsed_url, "query", "")
        query_values = parse_qs(query_string).get(parameter_name, [])
        if not query_values:
            return None
        query = str(query_values[0]).strip()
        return query or None

    @staticmethod
    def _parse_optional_int(raw_value: object) -> int | None:
        if raw_value in (None, ""):
            return None
        try:
            return int(raw_value)
        except (TypeError, ValueError):
            return None
