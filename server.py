from __future__ import annotations

from security_monitor.api import create_app
from security_monitor.runtime import MonitorRuntime


def main() -> None:
    runtime = MonitorRuntime()
    app = create_app(runtime)
    try:
        app.run(
            host=runtime.config.api_host,
            port=runtime.config.api_port,
            debug=False,
            threaded=True,
        )
    finally:
        runtime.stop()


if __name__ == "__main__":
    main()
