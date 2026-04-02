# Browser Companion

Chromium extension companion for the Explainable Security Monitor.

## What it does

- Captures the active browser tab title and URL
- Extracts exact search queries from supported search engines
- Sends events to the local backend at `http://127.0.0.1:8000`
- Tags events to a selected user profile

## How to load it

1. Open your browser extension page:
   - Chrome: `chrome://extensions`
   - Brave: `brave://extensions`
   - Edge: `edge://extensions`
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the `browser_companion` folder from this project.
5. Open the extension popup and set:
   - backend URL
   - user profile
   - browser label

## Notes

- The backend must be running with `python server.py`.
- Data is stored locally in SQLite through the backend.
- This extension captures only the active tab, not the full browser history.
