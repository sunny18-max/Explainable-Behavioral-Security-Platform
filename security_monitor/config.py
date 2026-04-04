from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class MonitorConfig:
    app_name: str = "Explainable Security Monitor"
    database_path: Path = field(
        default_factory=lambda: Path("data") / "security_monitor.db"
    )
    frontend_dist_path: Path = field(
        default_factory=lambda: Path("frontend") / "dist"
    )
    export_path: Path = field(
        default_factory=lambda: Path("exports")
    )
    honeypot_path: Path = field(
        default_factory=lambda: Path("data") / "honeypots"
    )
    analysis_interval_seconds: int = 5
    active_window_poll_seconds: float = 1.0
    training_sample_target: int = 12
    profile_history_limit: int = 180
    chart_history_limit: int = 36
    alert_history_limit: int = 12
    default_privacy_mode: str = "browser_aware"
    raw_behavior_retention_days: int = 14
    raw_browser_retention_days: int = 7
    anomaly_threshold: float = 55.0
    medium_risk_threshold: float = 30.0
    supported_user: str = "primary_user"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    browser_companion_stale_seconds: int = 90
    feedback_history_limit: int = 24
    webhook_timeout_seconds: int = 4
    siem_jsonl_file: str = "siem_events.jsonl"
    suspicious_query_terms: tuple[str, ...] = (
        "credential dump",
        "credential dumping",
        "mimikatz",
        "token replay",
        "reverse shell",
        "uac bypass",
        "lsass dump",
        "keylogger",
        "powershell encodedcommand",
        "dump creds",
        "vpn download",
        "free vpn",
        "third-party app",
        "third party app",
        "unofficial installer",
        "apk download",
        "cracked software",
        "openvpn",
        "wireguard",
        "nordvpn",
        "protonvpn",
    )
    suspicious_process_watchlist: tuple[str, ...] = (
        "credential_dump.exe",
        "unknown_updater.exe",
        "remote_assist.exe",
        "procdump.exe",
        "mimikatz.exe",
    )
    suspicious_parent_watchlist: tuple[str, ...] = (
        "powershell.exe",
        "cmd.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
    )
    vpn_process_watchlist: tuple[str, ...] = (
        "openvpn.exe",
        "wireguard.exe",
        "nordvpn.exe",
        "protonvpn.exe",
        "tailscale.exe",
        "warp-svc.exe",
        "hamachi-2-ui.exe",
    )
    honeypot_file_names: tuple[str, ...] = (
        "Executive_Payroll_2026.txt",
        "Privileged_Access_Notes.txt",
        "VPN_Reset_Backup.txt",
    )
    admin_tool_domains: tuple[str, ...] = (
        "learn.microsoft.com",
        "docs.microsoft.com",
        "github.com",
        "stackoverflow.com",
    )
    work_domains: tuple[str, ...] = (
        "outlook.office.com",
        "teams.microsoft.com",
        "office.com",
        "sharepoint.com",
        "notion.so",
        "atlassian.net",
    )
    search_domains: tuple[str, ...] = (
        "google.com",
        "bing.com",
        "duckduckgo.com",
        "search.brave.com",
        "yahoo.com",
    )
    social_domains: tuple[str, ...] = (
        "youtube.com",
        "linkedin.com",
        "x.com",
        "twitter.com",
        "instagram.com",
        "facebook.com",
        "reddit.com",
    )
    vpn_domains: tuple[str, ...] = (
        "protonvpn.com",
        "nordvpn.com",
        "openvpn.net",
        "surfshark.com",
        "windscribe.com",
        "expressvpn.com",
        "tailscale.com",
        "wireguard.com",
        "1.1.1.1",
    )
