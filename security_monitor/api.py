from __future__ import annotations

from flask import Flask, Response, jsonify, request, send_from_directory

from .runtime import MonitorRuntime


def create_app(runtime: MonitorRuntime | None = None) -> Flask:
    runtime = runtime or MonitorRuntime()
    app = Flask(__name__, static_folder=None)
    app.config["MONITOR_RUNTIME"] = runtime

    @app.after_request
    def add_cors_headers(response):  # type: ignore[no-untyped-def]
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    @app.route("/api/health", methods=["GET"])
    def health() -> object:
        return jsonify(
            {
                "status": "ok",
                "running": runtime.snapshot()["runtime"]["running"],
                "api_version": "2026.04.scaled",
            }
        )

    @app.route("/api/dashboard", methods=["GET"])
    def dashboard() -> object:
        return jsonify(runtime.snapshot())

    @app.route("/api/control/start", methods=["POST"])
    def start_monitoring() -> object:
        return jsonify(runtime.start())

    @app.route("/api/control/stop", methods=["POST"])
    def stop_monitoring() -> object:
        return jsonify(runtime.stop())

    @app.route("/api/control/analyze", methods=["POST"])
    def analyze_once() -> object:
        return jsonify(runtime.analyze_once())

    @app.route("/api/control/mode", methods=["POST"])
    def set_mode() -> object:
        payload = request.get_json(silent=True) or {}
        mode = str(payload.get("mode", "live"))
        return jsonify(runtime.set_mode(mode))

    @app.route("/api/control/privacy-mode", methods=["POST"])
    def set_privacy_mode() -> object:
        payload = request.get_json(silent=True) or {}
        privacy_mode = str(payload.get("privacy_mode", "browser_aware"))
        return jsonify(runtime.set_privacy_mode(privacy_mode))

    @app.route("/api/control/user", methods=["POST"])
    def set_user() -> object:
        payload = request.get_json(silent=True) or {}
        user_name = str(payload.get("user_name", "")).strip()
        return jsonify(runtime.set_user(user_name))

    @app.route("/api/control/demo-scenario", methods=["POST"])
    def queue_demo_scenario() -> object:
        payload = request.get_json(silent=True) or {}
        scenario_name = str(payload.get("scenario_name", "")).strip()
        return jsonify(runtime.queue_demo_scenario(scenario_name))

    @app.route("/api/control/retention-run", methods=["POST"])
    def run_retention() -> object:
        return jsonify(runtime.run_retention())

    @app.route("/api/control/honeypots", methods=["POST"])
    def refresh_honeypots() -> object:
        return jsonify(runtime.refresh_honeypots())

    @app.route("/api/control/honeypots/trigger", methods=["POST"])
    def trigger_honeypot_demo() -> object:
        payload = request.get_json(silent=True) or {}
        file_name = str(payload.get("file_name", "")).strip() or None
        return jsonify(runtime.trigger_honeypot_demo(file_name))

    @app.route("/api/extension/browser-events", methods=["POST"])
    def ingest_browser_events() -> object:
        payload = request.get_json(silent=True) or {}
        return jsonify(runtime.ingest_browser_events(payload))

    @app.route("/api/alerts/<int:alert_id>/feedback", methods=["POST"])
    def set_alert_feedback(alert_id: int) -> object:
        payload = request.get_json(silent=True) or {}
        label = str(payload.get("label", "")).strip()
        note = str(payload.get("note", "")).strip()
        return jsonify(runtime.set_alert_feedback(alert_id, label, note))

    @app.route("/api/export/report.json", methods=["GET"])
    def export_report_json() -> object:
        return jsonify(runtime.report_payload())

    @app.route("/api/export/report.csv", methods=["GET"])
    def export_report_csv() -> object:
        return Response(
            runtime.report_csv(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=behavioral-security-report.csv"
            },
        )

    @app.route("/api/export/report.pdf", methods=["GET"])
    def export_report_pdf() -> object:
        return Response(
            runtime.report_pdf(),
            mimetype="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=behavioral-security-report.pdf"
            },
        )

    @app.route("/api/export/siem", methods=["POST"])
    def export_siem() -> object:
        payload = request.get_json(silent=True) or {}
        webhook_url = str(payload.get("webhook_url", "")).strip() or None
        return jsonify(runtime.export_siem(webhook_url=webhook_url))

    dist_path = runtime.config.frontend_dist_path.resolve()

    @app.route("/", defaults={"path": ""}, methods=["GET"])
    @app.route("/<path:path>", methods=["GET"])
    def serve_frontend(path: str) -> object:
        if path.startswith("api/"):
            return ("Not found", 404)

        if dist_path.exists():
            target = dist_path / path
            if path and target.exists() and target.is_file():
                return send_from_directory(str(dist_path), path)
            return send_from_directory(str(dist_path), "index.html")

        return (
            "<h1>Explainable Security Monitor API</h1>"
            "<p>The backend is running. Build the React dashboard in the "
            "<code>frontend</code> folder or run <code>npm.cmd run dev</code>.</p>"
        )

    return app
