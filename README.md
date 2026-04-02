# CogniShield

Real-time Windows behavior monitoring with explainable anomaly detection, a Python backend, and a React dashboard.

For the full project agenda, module overview, and feature-by-feature testing checklist, see [APPLICATION_GUIDE.md](./APPLICATION_GUIDE.md).

## Architecture

- `server.py`: Flask backend entrypoint
- `security_monitor/collectors.py`: live Windows collectors plus advanced demo scenarios
- `security_monitor/service.py`: behavior pipeline orchestration
- `security_monitor/runtime.py`: background monitoring loop for real-time operation
- `security_monitor/api.py`: REST API for the React dashboard
- `security_monitor/honeypot.py`: deception layer and decoy-file monitoring
- `security_monitor/exports.py`: PDF reporting and SIEM-style export helpers
- `tray_app.py`: optional Windows tray launcher
- `frontend/`: React dashboard
- `data/security_monitor.db`: local SQLite storage

## Backend setup

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1"
python -m pip install -r requirements.txt
python server.py
```

Backend URL: `http://127.0.0.1:8000`

## Key advanced features

- explainable anomaly detection with confidence scoring
- browser companion for exact active-tab and search-query telemetry
- process lineage tracking for parent-child execution analysis
- deception layer with honeypot decoy files
- privacy modes and archival rollups for scalable storage
- PDF reporting and SIEM-style JSONL export
- optional Windows tray launcher

## Frontend setup

Open a second PowerShell window:

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1\frontend"
npm.cmd install
npm.cmd run dev
```

Frontend URL: `http://127.0.0.1:5173`

## Browser companion setup

Load the extension from the [browser_companion](./browser_companion/README.md) folder in Chrome, Brave, or Edge.

Quick steps:

1. Start the backend with `python server.py`.
2. Open your browser extension page:
   - `chrome://extensions`
   - `brave://extensions`
   - `edge://extensions`
3. Enable `Developer mode`.
4. Click `Load unpacked`.
5. Select the `browser_companion` folder.
6. Open the extension popup and configure:
   - backend URL: `http://127.0.0.1:8000`
   - user profile
   - browser label like `brave.exe` or `chrome.exe`

This companion captures exact active-tab titles, URL domains, and supported search-engine queries, then stores them in SQLite through the backend.

## Production build

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1\frontend"
npm.cmd install
npm.cmd run build
```

After the build, `python server.py` will also serve the compiled React app directly from `frontend/dist`.

## Optional tray mode

After installing the extra desktop dependencies from `requirements.txt`, you can run:

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1"
python tray_app.py
```

This starts the backend behind a Windows tray icon and gives quick access to the dashboard and monitoring controls.

## How to test on a real Windows laptop

1. Start the backend and frontend.
2. In the dashboard, choose `live` mode and click `Start`.
3. Type normally, move the mouse, and switch between your regular applications for several windows so the baseline can form.
4. Watch the baseline sample count grow.
5. Trigger suspicious behavior:
   - type abnormally fast
   - switch apps rapidly
   - launch an unfamiliar executable
   - test at an unusual login time
   - open sensitive browser searches with the browser companion enabled
6. Check that the dashboard explains why the activity looks suspicious instead of only showing an alert.
7. Review the `Process and Deception` section for parent-child execution chains and honeypot hits.
8. Use `Export PDF` or `Export SIEM` from the topbar to show operational reporting.

## Guaranteed demo flow

1. Switch to `demo` mode.
2. Queue `normal` and run `Analyze Now`.
3. Queue `combined_attack`, `session_hijack`, `identity_mismatch`, or `time_warp`.
4. Run `Analyze Now` again and inspect the explanation cards, risk score, and recent alert feed.

## Privacy note

The collector stores keystroke timing only. It does not capture actual key contents.
