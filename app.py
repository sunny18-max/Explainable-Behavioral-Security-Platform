from __future__ import annotations

import tkinter as tk

from security_monitor.config import MonitorConfig
from security_monitor.dashboard import Dashboard
from security_monitor.service import MonitorService


def main() -> None:
    config = MonitorConfig()
    service = MonitorService(config)
    root = tk.Tk()
    Dashboard(root, service, config)

    def _shutdown() -> None:
        service.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _shutdown)
    root.mainloop()


if __name__ == "__main__":
    main()
