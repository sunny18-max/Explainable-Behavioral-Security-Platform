import { BRAND, INITIAL_SCENARIO, formatTimestamp, statusTone } from "../lib/dashboard.js";

export function DashboardSidebar({
  current,
  runtime,
  controls,
  draftUser,
  setDraftUser,
  scenario,
  setScenario,
  mutating,
  callControl,
  error
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-card brand-card" data-aos="fade-right">
        <div className="brand-lockup">
          <div className="brand-mark">Ni</div>
          <div>
            <span className="sidebar-eyebrow">{BRAND.label}</span>
            <h1 className="brand-title">{BRAND.name}</h1>
          </div>
        </div>
        <p className="brand-copy">{BRAND.tagline}</p>
      </div>

      <nav className="sidebar-card sidebar-nav" data-aos="fade-right" data-aos-delay="40">
        <a href="#overview">Overview</a>
        <a href="#signals">Signals</a>
        <a href="#activity">Activity</a>
        <a href="#analytics">Analytics</a>
        <a href="#alerts">Alerts</a>
      </nav>

      <div className={`sidebar-card runtime-card tone-${statusTone(current)}`} data-aos="fade-right" data-aos-delay="80">
        <div className="runtime-row">
          <span>Mode</span>
          <strong>{runtime.mode ?? "live"}</strong>
        </div>
        <div className="runtime-row">
          <span>Runtime</span>
          <strong>{runtime.running ? "Monitoring" : "Stopped"}</strong>
        </div>
        <div className="runtime-row">
          <span>User</span>
          <strong>{runtime.user_name ?? "primary_user"}</strong>
        </div>
        <div className="runtime-row">
          <span>Last sample</span>
          <strong>{formatTimestamp(runtime.last_collection_at)}</strong>
        </div>
      </div>

      <div className="sidebar-card" data-aos="fade-right" data-aos-delay="120">
        <h2 className="sidebar-section-title">Controls</h2>

        <div className="control-group">
          <label htmlFor="userName">User profile</label>
          <div className="inline-control">
            <input
              id="userName"
              value={draftUser}
              onChange={(event) => setDraftUser(event.target.value)}
              placeholder="primary_user"
            />
            <button
              type="button"
              onClick={() => callControl("/api/control/user", { user_name: draftUser })}
              disabled={mutating}
            >
              Switch
            </button>
          </div>
          <div className="helper-row">
            {(controls.users ?? []).map((userName) => (
              <button
                key={userName}
                type="button"
                className="tag-button"
                onClick={() => {
                  setDraftUser(userName);
                  callControl("/api/control/user", { user_name: userName });
                }}
              >
                {userName}
              </button>
            ))}
          </div>
        </div>

        <div className="control-group">
          <label>Mode</label>
          <div className="inline-control">
            <button
              type="button"
              className={runtime.mode === "live" ? "selected" : ""}
              onClick={() => callControl("/api/control/mode", { mode: "live" })}
              disabled={mutating}
            >
              Live
            </button>
            <button
              type="button"
              className={runtime.mode === "demo" ? "selected" : ""}
              onClick={() => callControl("/api/control/mode", { mode: "demo" })}
              disabled={mutating}
            >
              Demo
            </button>
          </div>
        </div>

        <div className="control-group">
          <label>Actions</label>
          <div className="inline-control">
            <button type="button" onClick={() => callControl("/api/control/start")} disabled={mutating}>
              Start
            </button>
            <button type="button" onClick={() => callControl("/api/control/stop")} disabled={mutating}>
              Stop
            </button>
            <button type="button" onClick={() => callControl("/api/control/analyze")} disabled={mutating}>
              Analyze
            </button>
          </div>
        </div>

        <div className="control-group">
          <label htmlFor="scenarioName">Demo scenario</label>
          <div className="inline-control">
            <select
              id="scenarioName"
              value={scenario}
              onChange={(event) => setScenario(event.target.value)}
            >
              {(controls.demo_scenarios ?? [INITIAL_SCENARIO]).map((scenarioName) => (
                <option key={scenarioName} value={scenarioName}>
                  {scenarioName}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => callControl("/api/control/demo-scenario", { scenario_name: scenario })}
              disabled={mutating || runtime.mode !== "demo"}
            >
              Queue
            </button>
          </div>
        </div>

        {error ? <p className="error-banner">{error}</p> : null}
        {runtime.last_error ? <p className="error-banner">{runtime.last_error}</p> : null}
      </div>
    </aside>
  );
}
