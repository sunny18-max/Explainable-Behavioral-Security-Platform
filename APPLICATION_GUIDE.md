# Explainable Behavioral Security Platform

## Main Agenda

This application is a real-time Windows behavior monitoring platform that:

1. collects privacy-safe user interaction telemetry
2. learns a personal baseline for each user
3. detects unusual or suspicious behavior
4. explains why the activity is suspicious in plain language
5. stores telemetry and alerts in SQLite for later analysis

The core goal is not only `detection`, but `explainable detection` that helps an operator, faculty reviewer, or project evaluator understand:

- what happened
- why it is suspicious
- how strongly the system believes it
- how the behavior differs from the usual user profile

## What The Platform Implements

### Core modules

- Windows activity collection
  - keystroke timing only
  - mouse movement speed
  - active foreground application tracking
  - session and login-time context
- Browser companion collection
  - exact active tab title
  - domain capture
  - supported search query extraction
- Feature extraction
  - typing speed
  - typing rhythm variance
  - mouse speed
  - app switching count
  - unique app count
  - session duration
  - activity intensity
- Behavior profiling
  - per-user baseline
  - known apps
  - dominant apps
- Detection
  - statistical anomaly scoring
  - optional Isolation Forest scoring
  - unknown app detection
  - suspicious query detection
- Explanation engine
  - human-readable reason generation
  - confidence scoring
  - severity grading
- Dashboard analytics
  - risk trends
  - confidence trends
  - fingerprint similarity trends
  - cross-user comparison
  - browser analytics
  - alert history

### Advanced and unique features now implemented

- Behavior Fingerprint Identity
  - compares the current behavior vector against the stored user fingerprint
  - helps detect impostor-like behavior even when credentials are correct
- Intent Detection Engine
  - checks suspicious behavior chains such as browser research plus shell usage plus new executable launch
- Time Warp Detection
  - detects sudden abnormal acceleration in typing or mouse behavior
- Confidence-Based Explanation
  - every scored signal carries confidence
  - the total alert also shows confidence
- Context-Aware Risk
  - the same behavior is interpreted differently based on context
  - example: fast typing in development tools is treated differently from fast typing around shell or login-like contexts
- Explainable Timeline Replay
  - shows the event sequence from the active window before the detection result
- Process Tree And Parent-Child Tracking
  - captures foreground process lineage and flags suspicious ancestry such as shell to unknown executable
- Deception And Honeypot Layer
  - plants decoy files and raises high-confidence alerts if they are touched
- Behavior Drift Tracking
  - estimates how much the user baseline is shifting over time
- Sequence-Aware Intent Detection
  - detects suspicious flows like browser research -> shell usage -> unfamiliar executable
- Confidence-Weighted Risk Factors
  - shows how much each factor contributed to the final alert
- Recommended Action Engine
  - each suspicious alert carries operator guidance for investigation or escalation
- Analyst Feedback Loop
  - alerts can be marked as true positive, false positive, or needs review
  - recent feedback influences the effective anomaly threshold
- Domain Intelligence
  - classifies browser domains into search, work, social, admin reference, or unknown
- Baseline Versioning
  - stores baseline snapshots over time so behavior drift and profile evolution can be shown
- Alert Clustering
  - repeated similar alerts are grouped into incident families
- Demo Evaluation Metrics
  - computes accuracy, precision, and recall on demo scenarios
- Exportable Reporting
  - dashboard state can be exported as JSON or CSV for review and viva discussion
- PDF Investigation Reports
  - one-click PDF export is available for faculty review packets or incident walkthroughs
- SIEM-Style Export Connectors
  - the current incident snapshot can be written to normalized JSONL and optionally sent to a webhook
- Windows Tray Runner
  - a tray-based launcher can keep the backend available like a lightweight desktop agent
- Privacy Modes
  - supports `basic`, `browser_aware`, and `high_detail` visibility levels
  - lets the same platform operate in stricter or richer telemetry modes
- Retention And Archival Rollups
  - old raw behavior and browser events are rolled into daily SQLite summaries
  - keeps long-term analytics scalable without keeping every raw event forever

## Data Storage

All major telemetry is stored locally in SQLite at:

`data/security_monitor.db`

Stored records include:

- user profiles
- behavior logs
- browser companion events
- alert history
- alert feedback labels
- alert cluster keys
- confidence score
- fingerprint similarity
- behavior drift
- intent matches
- timeline replay data
- recommended actions
- weighted risk factors
- watchlist hits
- domain categories
- baseline snapshots
- behavior daily rollups
- browser daily rollups
- process observations
- honeypot hits
- integration export history

## Runtime Architecture

1. Windows collector or demo collector captures one analysis window.
2. Privacy mode rules decide how much browser evidence can be merged or displayed.
3. Browser companion events are merged into that window when allowed.
4. Features are extracted and privacy-safe fields are sanitized if needed.
5. Baseline history is loaded from SQLite.
6. Advanced intelligence signals are computed.
7. Hybrid anomaly detection assigns scores.
8. Explanation engine produces readable reasoning.
9. The result is stored in SQLite.
10. Retention logic periodically archives older raw telemetry into daily rollups.
11. Optional SIEM-style exports and PDF reports are generated from the same snapshot payload.
12. The React dashboard reads the latest snapshot from the Flask API.

## How To Run

### Backend

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1"
python -m pip install -r requirements.txt
python server.py
```

### Frontend development mode

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1\frontend"
npm.cmd install
npm.cmd run dev
```

Open:

- `http://127.0.0.1:5173` for Vite dev mode
- `http://127.0.0.1:8000` if you build the frontend and let Flask serve it

### Production-style frontend build

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1\frontend"
npm.cmd install
npm.cmd run build
cd "c:\Users\saath\Downloads\PDP Idea 1"
python server.py
```

## How To Access And Use The Application

### Entry flow

1. Start the backend.
2. Start the frontend or use the built frontend through Flask.
3. Open the landing page.
4. Click `Go to Dashboard`.
5. Use the dashboard as the main control and analysis workspace.

### Operating modes

- `Live`
  - uses real Windows telemetry from the local machine
  - best for showing practical monitoring
- `Demo`
  - uses seeded scenarios such as `normal`, `combined_attack`, and `session_hijack`
  - best for reliable classroom or viva demonstrations

### Privacy modes

- `basic`
  - hides browser tab detail, query detail, URL detail, and domain detail from the active analysis
  - best for privacy-first demonstrations
- `browser_aware`
  - keeps browser tab and domain context but removes raw URL detail
  - best default mode for balanced visibility
- `high_detail`
  - keeps full browser evidence, including URL data when available from the companion
  - best for investigation-heavy demonstrations

### Important mode behavior

- In `demo` mode, clicking `Queue` immediately applies the selected scenario and refreshes the current analysis.
- The selected demo scenario stays active until you choose another one.
- `Analyze Now` can be used at any time to force another analysis cycle.
- In `live` mode, `Start` begins the background collection loop and `Stop` halts it.

## Dashboard Walkthrough

### Topbar

Use the topbar for:

- `Export CSV`
  - downloads a structured CSV report
- `Export PDF`
  - downloads a printable investigation summary
- `Export JSON`
  - opens the full current dashboard payload
- `Export SIEM`
  - writes a normalized JSONL event bundle and can optionally send it to a webhook
- `Home`
  - returns to the landing page
- `Analyze Now`
  - forces one immediate analysis cycle

### Control band

Use the control band to:

- switch user profiles
- change between `live` and `demo`
- start or stop background monitoring
- choose and queue demo scenarios
- switch privacy mode
- run archival immediately with `Archive Now`

### Metrics row

This row gives a high-level operational snapshot:

- `Risk Score`
- `Confidence`
- `Fingerprint Match`
- `Behavior Drift`
- `Baseline Samples`
- `Alert Rate`
- `Reviewed Alerts`

### Signal Trends

This section shows the recent trend lines for:

- risk
- confidence
- fingerprint similarity
- typing speed

Use it to show whether suspicious behavior is isolated or persistent.

### Current Assessment

This is one of the most important sections for explanation:

- human-readable summary
- detailed explanation
- replay summary
- intent detection chips
- visible search queries
- watchlist hits
- domain categories
- weighted risk factors
- recommended actions

This section is the best place to explain `why` the system flagged the activity.

### Timeline Replay

This section reconstructs the recent sequence:

- window opened
- foreground focus changes
- browser activity
- collector notes
- final detection result

This is the main explainable-forensics view.

### Browser And Window Activity

This section shows:

- recent browser telemetry from the extension
- current app observations for the active window
- browser tabs and visible searches

Use it to demonstrate exact tab capture and search-query evidence.

### Process And Deception

This section shows:

- foreground process lineage
- parent-child ancestry
- active honeypot or deception hits
- decoy directory posture

Use it to demonstrate process-aware investigation and high-confidence deception signals.

### Cross-User Comparison

This section is for peer analysis across users:

- average risk
- average confidence
- fingerprint similarity
- top apps

Use it to show that the system is per-user and not only a generic detector.

### Distribution Analytics

This section gives quick visual breakdowns:

- app mix
- severity mix
- domain mix
- repeated search queries

### Threat Analytics

This section contains the newer advanced analytics:

- domain category distribution
- 24-hour risk heatmap
- demo accuracy
- precision
- recall
- demo sample count

This is the best section to show measurable evaluation.

### Governance

This section shows the scalability and control layer:

- active privacy mode
- raw retention window for behavior logs
- raw retention window for browser events
- last archive run time
- raw sample and event counts
- archived daily rollup totals

Use it to explain that the platform is built for longer-term use, not just short demos.

### Integrations

This section shows:

- recent SIEM-style exports
- outbound integration status
- local file-export evidence

Use it to explain that the platform can scale beyond a single dashboard view.

### Incident Clusters

This section shows:

- grouped alert families
- cluster counts
- TP and FP review counts
- baseline version history

Use it to show maturity and incident-level analysis instead of raw alerts only.

### Feature Baseline Snapshot

This compares the latest behavior window with the learned baseline for:

- typing speed
- typing rhythm variance
- mouse speed
- app switching
- unique app count
- login hour
- session duration
- activity intensity

### Recent Alerts

This section is the analyst review area:

- stored alert explanation
- severity
- risk score
- feedback buttons
  - `True Positive`
  - `False Positive`
  - `Review`
- recommended response actions

This section shows that the system supports adaptive review, not just detection.

## Where To View Each Major Feature

- Behavior fingerprint identity
  - `Metrics row` and `Signal Trends`
- Sequence-based intent detection
  - `Current Assessment`
- Time warp detection
  - `Current Assessment` and `Feature Baseline Snapshot`
- Confidence-based explanation
  - `Metrics row` and `Current Assessment`
- Recommended actions
  - `Current Assessment` and `Recent Alerts`
- Browser extension evidence
  - `Browser And Window Activity`
- Process lineage tracking
  - `Process And Deception`
- Honeypot or deception signals
  - `Process And Deception` and `Current Assessment`
- Timeline replay
  - `Timeline Replay`
- User comparison
  - `Cross-User Comparison`
- Domain intelligence
  - `Current Assessment` and `Threat Analytics`
- Alert clustering
  - `Incident Clusters`
- Baseline versioning
  - `Incident Clusters`
- Analyst feedback loop
  - `Recent Alerts`
- Evaluation metrics
  - `Threat Analytics`
- Exportable reports
  - `Topbar`
- SIEM-style integrations
  - `Topbar` and `Integrations`
- Tray-based operations
  - `python tray_app.py`
- Privacy controls and archival posture
  - `Governance`

## Browser Companion Setup

1. Start the backend.
2. Open:
   - `chrome://extensions`
   - `brave://extensions`
   - `edge://extensions`
3. Enable `Developer mode`.
4. Click `Load unpacked`.
5. Select the `browser_companion` folder.
6. Open the extension popup.
7. Set:
   - backend URL to `http://127.0.0.1:8000`
   - browser label such as `chrome.exe` or `brave.exe`
   - user profile name
8. Enable capture.
9. Open a real browser tab and search something visible in the title.
10. Click `Capture Now`.

Expected result:

- `Browser companion` changes from `Waiting` to `Connected`
- stored event count increases
- domain count increases
- browser activity appears in the dashboard
- search queries and domains affect the analytics panels

Important:

- in `basic` privacy mode, browser evidence is intentionally redacted from the active analysis
- in `browser_aware` mode, URL detail is removed but tab or domain evidence can still appear
- in `high_detail` mode, the browser companion gives the richest evidence view

## Complete Testing Guide

### A. Basic system health

1. Start backend and frontend.
2. Confirm dashboard loads.
3. Confirm runtime section shows mode, user, and last sample status.
4. Confirm `data/security_monitor.db` is created.

### B. SQLite verification

Use:

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1"
@'
import sqlite3
conn = sqlite3.connect("data/security_monitor.db")
for table in ("users", "behavior_logs", "alerts", "browser_events", "baseline_snapshots"):
    count = conn.execute(f"select count(*) from {table}").fetchone()[0]
    print(table, count)
'@ | python -
```

You should see row counts for the stored data.

### C. Live Windows monitoring

1. Open the dashboard.
2. Select `live`.
3. Click `Start`.
4. Use your laptop normally for at least 10 to 15 windows.
5. Watch:
   - baseline sample count
   - typing speed chart
   - confidence chart
   - fingerprint similarity

Expected result:

- early windows show learning or low-confidence normal behavior
- after the baseline builds, current behavior should mostly stay near normal

### D. Multi-user testing

1. Create a first user like `primary_user`.
2. Collect baseline windows.
3. Switch to another user like `guest_user`.
4. Collect a separate baseline.
5. View the `Cross-User Comparison` section.

Expected result:

- both users appear separately
- average risk, confidence, fingerprint stats, and top apps differ

### E. Guaranteed demo scenarios

Switch to `demo` mode and test these one by one:

1. `normal`
   - expected: low risk or normal status
2. `combined_attack`
   - expected: suspicious search terms, shell usage, unfamiliar executable, higher risk
3. `session_hijack`
   - expected: remote-access context plus token or session search intent
4. `identity_mismatch`
   - expected: lower fingerprint similarity and strong suspicious reasoning
5. `time_warp`
   - expected: typing and mouse acceleration signals
6. `rapid_switching`
   - expected: increased switching count and operator-like behavior chain
7. `off_hours_login`
   - expected: unusual login hour signal

Recommended demo flow:

1. queue scenario
2. wait for the dashboard to refresh immediately
3. optionally click `Analyze Now` for another cycle
4. inspect summary, reasons, intent labels, timeline replay, and recent alerts

Important:

- in `demo` mode, `Queue` already applies the scenario
- use `Analyze Now` only if you want an extra immediate cycle
- the selected scenario remains active until another scenario is queued

### F. Browser companion testing

1. Enable the browser companion.
2. Visit several normal sites.
3. Search harmless queries.
4. Then search visible sensitive terms such as:
   - `credential dumping commands`
   - `session token replay`
   - `powershell encodedcommand`
5. Return to the dashboard.

Expected result:

- browser companion card changes to connected
- browser activity feed updates
- domain mix chart updates
- domain category chart updates
- repeated search query list updates
- suspicious query explanations affect risk scoring

### G. Behavior fingerprint testing

1. Build a normal baseline for one user.
2. Switch to demo mode.
3. run `identity_mismatch`

Expected result:

- fingerprint similarity drops
- the summary mentions stronger suspicious behavior
- the dashboard surfaces identity mismatch clearly

### H. Intent engine testing

Run:

- `combined_attack`
- `session_hijack`
- `rapid_switching`

Expected result:

- `Intent detection` chips appear
- explanations mention shell usage, search-driven execution, or remote access overlap

### I. Time warp testing

Run:

- `time_warp`
- `fast_typing`

Expected result:

- time-warp or speed-shift related deviations appear
- confidence should increase if the spike is strong

### J. Timeline replay testing

1. Run any suspicious scenario.
2. Open `Explainable Timeline Replay`.

Expected result:

- timeline entries show app focus, browser events, notes, and final detection result

### K. Analyst feedback testing

1. Trigger a suspicious demo scenario such as `combined_attack`.
2. Open `Recent Alerts`.
3. Mark the alert as:
   - `True Positive`
   - `False Positive`
   - `Review`
4. Watch the `Reviewed Alerts` metric and cluster counts update.

Expected result:

- feedback is stored in SQLite
- the reviewed alert count increases
- adaptive threshold offset changes when enough false positives accumulate
- incident cluster review counts also change

### L. Evaluation and baseline version testing

1. Run several demo scenarios including:
   - `normal`
   - `combined_attack`
   - `session_hijack`
2. Open:
   - `Threat Analytics`
   - `Incident Clusters`
3. Inspect:
   - demo accuracy
   - precision
   - recall
   - baseline version history

Expected result:

- the evaluation cards show non-zero values
- baseline version rows appear after more samples are collected
- clustered alert families appear in `Incident Clusters`

### M. Export report testing

1. Use the topbar `Export CSV` button.
2. Use the topbar `Export JSON` button.
3. Use the topbar `Export PDF` button.
4. Use the topbar `Export SIEM` button.

Expected result:

- a CSV report downloads with runtime, stats, current state, and alert rows
- a JSON report opens with the full snapshot payload
- a PDF report downloads with summary, reasoning, and response guidance
- a SIEM JSONL export is recorded in the integrations section

### N. Honeypot and process-lineage testing

1. Switch to `demo` mode.
2. Queue `honeypot_access`.
3. Inspect `Current Assessment`, `Process And Deception`, and `Timeline Replay`.
4. Then queue `combined_attack` and inspect the process ancestry rows.

Expected result:

- honeypot hits appear as high-confidence signals
- process lineage shows shell or remote-access ancestry
- replay summary mentions deception or process-lineage alerts

### O. Privacy mode testing

1. Open the dashboard control band.
2. Switch privacy mode to `basic`.
3. Run a browser-heavy scenario such as `combined_attack`.
4. Check `Current Assessment` and `Browser And Window Activity`.
5. Switch privacy mode to `browser_aware`.
6. Run the same scenario again.
7. Switch privacy mode to `high_detail`.
8. Run the same scenario again.

Expected result:

- `basic` shows the most redaction
- `browser_aware` shows tab or domain context without raw URL detail
- `high_detail` shows the richest browser evidence

### P. Archival and retention testing

1. Collect several samples in live or demo mode.
2. Open the `Governance` section.
3. Note raw behavior sample and raw browser event counts.
4. Click `Archive Now`.
5. Refresh the dashboard snapshot after a second.

Expected result:

- last archive run time updates
- archived daily totals increase when older data qualifies for rollup
- long-term counts remain available through archived summaries

### Q. Alert persistence testing

1. Trigger multiple suspicious demo scenarios.
2. Refresh the page.
3. Restart backend.
4. Reload the dashboard.

Expected result:

- alerts still appear because they were stored in SQLite

### R. Tray runner testing

1. Install optional desktop dependencies from `requirements.txt`.
2. Run:

```powershell
cd "c:\Users\saath\Downloads\PDP Idea 1"
python tray_app.py
```

3. Use the tray menu to open the dashboard.
4. Start or stop monitoring from the tray.

Expected result:

- a tray icon appears
- the backend is reachable from the tray launcher
- monitoring can be started without keeping a terminal-focused workflow

## What To Show In A Faculty Demo

Best short demo sequence:

1. Start in `demo` mode.
2. Run `normal`.
3. Show low-risk behavior.
4. Run `combined_attack`.
5. Show:
   - confidence score
   - reasons
   - weighted risk factors
   - recommended actions
   - context-aware risk
   - intent detection
   - fingerprint similarity
   - timeline replay
   - browser query evidence
   - process lineage
   - deception or honeypot hits
   - incident clusters
   - demo evaluation metrics
   - analyst feedback buttons
   - privacy mode changes
   - governance and archival posture
   - PDF or SIEM export from the topbar
6. Switch to another user and show `Cross-User Comparison`.
7. Open the browser companion and show live tab capture.

## Suggested User Workflow

If someone opens the application for the first time, this is the best order to use it:

1. Open the landing page and read the project overview.
2. Go to the dashboard.
3. Choose a user profile.
4. Decide whether to use `live` or `demo`.
5. In demo mode:
   - start with `normal`
   - then run `combined_attack`
   - then run `session_hijack` or `identity_mismatch`
6. Review:
   - current assessment
   - timeline replay
   - browser activity
   - threat analytics
   - recent alerts
7. Mark some alerts with analyst feedback.
8. Change privacy mode once to show governance controls.
9. Export the report.

This flow demonstrates collection, detection, explanation, analysis, review, and reporting in one continuous story.

## Privacy And Ethics

- no actual key contents are stored
- only timing and behavioral metadata are collected
- browser telemetry depends on explicit extension consent
- all storage is local SQLite by default


## Fresh live-session behavior

- Every time you start `live` mode, CogniShield now opens a fresh session scope for that selected user.
- Risk score, current charts, recent alerts, browser activity, and baseline samples are computed from the new live session instead of reusing older stored runs.
- Long-term evidence is still preserved in SQLite for exports and historical review, but the live dashboard now reflects the current run first.

## Automated decoy testing

1. Open the dashboard and switch to `live`.
2. Click `Start`.
3. In `Process and Deception`, click `Trigger Decoy Demo`.
4. Wait one analysis cycle or click `Analyze Now`.
5. Check `Current Assessment`, `Timeline Replay`, and `Decoy Hits` for the honeypot alert.

Manual decoy testing still works too. You can edit and save any file inside `data\honeypots`, then wait one cycle.

## macOS support

- The live collector now supports macOS foreground-application sampling through AppleScript.
- Keyboard and mouse timing still rely on `pynput` when it is installed.
- On macOS, run the same backend and dashboard, grant any accessibility permissions requested by the OS, and the collector will capture the frontmost app and window title with reduced process-detail depth compared with Windows.
