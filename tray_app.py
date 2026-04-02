from __future__ import annotations

import threading
import webbrowser

from security_monitor.api import create_app
from security_monitor.runtime import MonitorRuntime

try:
    import pystray
    from PIL import Image, ImageDraw
    from werkzeug.serving import make_server
except ImportError as exc:  # pragma: no cover - optional desktop dependency
    pystray = None
    Image = None
    ImageDraw = None
    make_server = None
    _IMPORT_ERROR = exc
else:  # pragma: no cover - optional desktop dependency
    _IMPORT_ERROR = None


class TrayController:
    def __init__(self) -> None:
        self.runtime = MonitorRuntime()
        self.app = create_app(self.runtime)
        self._server = None
        self._server_thread: threading.Thread | None = None

    def start_backend(self) -> None:
        if make_server is None or self._server is not None:
            return
        self._server = make_server(
            self.runtime.config.api_host,
            self.runtime.config.api_port,
            self.app,
        )
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            name="tray-backend",
            daemon=True,
        )
        self._server_thread.start()

    def stop_backend(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        self.runtime.stop()

    def open_dashboard(self) -> None:
        webbrowser.open(
            f"http://{self.runtime.config.api_host}:{self.runtime.config.api_port}",
            new=2,
        )

    def start_monitoring(self) -> None:
        self.start_backend()
        self.runtime.start()

    def stop_monitoring(self) -> None:
        self.runtime.stop()

    def quit(self, icon: object) -> None:
        self.stop_backend()
        icon.stop()


def _icon_image() -> "Image.Image":  # pragma: no cover - optional desktop dependency
    image = Image.new("RGBA", (64, 64), (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((8, 6, 56, 58), radius=14, fill="#0A1F44")
    draw.ellipse((16, 18, 34, 40), fill="#4FC3F7")
    draw.line((39, 20, 48, 20), fill="#00E5FF", width=3)
    draw.line((39, 28, 48, 28), fill="#00E5FF", width=3)
    draw.line((39, 36, 48, 36), fill="#00E5FF", width=3)
    draw.ellipse((48, 18, 54, 24), fill="#00E5FF")
    draw.ellipse((48, 26, 54, 32), fill="#00E5FF")
    draw.ellipse((48, 34, 54, 40), fill="#00E5FF")
    return image


def main() -> None:
    if pystray is None or Image is None or make_server is None:  # pragma: no cover
        raise RuntimeError(
            "Tray mode requires pystray, pillow, and werkzeug. "
            f"Original import error: {_IMPORT_ERROR}"
        )

    controller = TrayController()
    controller.start_backend()

    icon = pystray.Icon(
        "CogniShield",
        _icon_image(),
        "CogniShield",
        menu=pystray.Menu(
            pystray.MenuItem("Open Dashboard", lambda icon, item: controller.open_dashboard()),
            pystray.MenuItem("Start Monitoring", lambda icon, item: controller.start_monitoring()),
            pystray.MenuItem("Stop Monitoring", lambda icon, item: controller.stop_monitoring()),
            pystray.MenuItem("Quit", lambda icon, item: controller.quit(icon)),
        ),
    )
    icon.run()


if __name__ == "__main__":
    main()
