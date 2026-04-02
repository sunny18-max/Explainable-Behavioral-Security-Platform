import { DonutChart } from "./DonutChart.jsx";
import { BrandLockup } from "./BrandLockup.jsx";
import { HeatmapGrid } from "./HeatmapGrid.jsx";
import { MetricCard } from "./MetricCard.jsx";
import { Sparkline } from "./Sparkline.jsx";
import { Surface } from "./Surface.jsx";
import { BRAND, apiHref, formatMaybeNumber, formatTimestamp, statusTone, uniqueStrings } from "../lib/dashboard.js";

export function DashboardView({
  dashboard,
  draftUser,
  setDraftUser,
  scenario,
  setScenario,
  mutating,
  callControl,
  onBackHome,
  error
}) {
  const runtime = dashboard?.runtime ?? {};
  const stats = dashboard?.stats ?? {};
  const controls = dashboard?.controls ?? {};
  const analytics = dashboard?.analytics ?? {};
  const current = dashboard?.current;
  const history = dashboard?.history ?? [];
  const alerts = dashboard?.alerts ?? [];
  const browserCompanion = analytics.browser_companion ?? {};
  const userComparison = analytics.user_comparison ?? [];
  const currentTabs = uniqueStrings(current?.browser_tabs ?? []);
  const currentQueries = uniqueStrings(current?.search_queries ?? []);
  const contexts = uniqueStrings(current?.context_labels ?? []);
  const intents = uniqueStrings(current?.intent_matches ?? []);
  const timeline = current?.timeline ?? [];
  const featureRows = current?.features ?? [];
  const notes = current?.collector_notes ?? [];
  const appObservations = current?.app_observations ?? [];
  const recentBrowserActivity = analytics.recent_browser_activity ?? [];
  const appDistribution = analytics.app_distribution ?? [];
  const severityDistribution = analytics.severity_distribution ?? [];
  const queryDistribution = analytics.query_distribution ?? [];
  const domainDistribution = analytics.domain_distribution ?? [];
  const domainCategoryDistribution = analytics.domain_category_distribution ?? [];
  const alertClusters = analytics.alert_clusters ?? [];
  const riskHeatmap = analytics.risk_heatmap ?? [];
  const baselineVersions = analytics.baseline_versions ?? [];
  const demoEvaluation = analytics.demo_evaluation ?? {};
  const deviations = current?.deviations ?? [];
  const recommendedActions = current?.recommended_actions ?? [];
  const riskFactors = current?.risk_factors ?? [];
  const watchlistHits = current?.watchlist_hits ?? [];
  const honeypotHits = current?.honeypot_hits ?? [];
  const processObservations = current?.process_observations ?? [];
  const recentIntegrations = analytics.recent_integrations ?? [];
  const honeypotStatus = analytics.honeypot ?? {};
  const replaySummary = current?.replay_summary ?? "";
  const domainCategories = current?.domain_categories ?? [];
  const privacyModes = controls?.privacy_modes ?? ["basic", "browser_aware", "high_detail"];

  const alertRate = !stats.total_samples
    ? "0.0"
    : ((stats.anomaly_count / stats.total_samples) * 100).toFixed(1);
  const maxComparisonRisk = Math.max(
    ...userComparison.map((item) => Number(item.average_risk ?? 0)),
    1
  );

  return (
    <div className="dashboard-shell">
      <header className="dashboard-topbar">
        <div className="topbar-brand">
          <div className="topbar-copy">
            <BrandLockup variant="dashboard" subtitle="Dashboard" />
            <p>Live monitoring, explanation, analytics, and demo control surface.</p>
          </div>
        </div>
        <div className="topbar-actions">
          <button
            type="button"
            className="nav-btn secondary"
            onClick={() => window.open(apiHref("/api/export/report.csv"), "_blank", "noopener")}
          >
            Export CSV
          </button>
          <button
            type="button"
            className="nav-btn secondary"
            onClick={() => window.open(apiHref("/api/export/report.pdf"), "_blank", "noopener")}
          >
            Export PDF
          </button>
          <button
            type="button"
            className="nav-btn secondary"
            onClick={() => window.open(apiHref("/api/export/report.json"), "_blank", "noopener")}
          >
            Export JSON
          </button>
          <button type="button" className="nav-btn secondary" onClick={() => callControl("/api/export/siem")} disabled={mutating}>
            Export SIEM
          </button>
          <button type="button" className="nav-btn secondary" onClick={onBackHome}>
            Home
          </button>
          <button type="button" className="nav-btn primary" onClick={() => callControl("/api/control/analyze")} disabled={mutating}>
            Analyze Now
          </button>
        </div>
      </header>

      <section className="dashboard-hero-panel">
        <div className="hero-panel-main">
          <span className="hero-badge">Behavioral Security Workspace</span>
          <h2>{current?.summary ?? "Monitoring is ready. Start live mode or run a demo scenario."}</h2>
          <p>
            {current?.explanation ??
              `${BRAND.name} collects privacy-safe telemetry, learns per-user behavior, detects anomalies, and explains why a session looks suspicious.`}
          </p>
          <div className="hero-chip-row">
            {contexts.length ? (
              contexts.map((label) => (
                <span key={label} className="context-pill">
                  {label.replaceAll("_", " ")}
                </span>
              ))
            ) : (
              <span className="context-pill muted">Context labels will appear here</span>
            )}
          </div>
        </div>
        <div className="hero-panel-side">
          <div className={`hero-status-card status-${statusTone(current)}`}>
            <span className="status-title">Current posture</span>
            <strong>{current?.severity ?? "idle"}</strong>
            <p>Last sample {formatTimestamp(runtime.last_collection_at)} for {runtime.user_name ?? "primary_user"}.</p>
          </div>
          <div className="hero-status-card">
            <span className="status-title">Browser companion</span>
            <strong>{browserCompanion.active ? "Connected" : "Waiting"}</strong>
            <p>{browserCompanion.event_count ?? 0} stored events across {browserCompanion.distinct_domains ?? 0} domains.</p>
          </div>
        </div>
      </section>

      <section className="control-band">
        <div className="control-card">
          <label htmlFor="userName">User</label>
          <div className="inline-control">
            <input
              id="userName"
              value={draftUser}
              onChange={(event) => setDraftUser(event.target.value)}
              placeholder="primary_user"
            />
            <button type="button" onClick={() => callControl("/api/control/user", { user_name: draftUser })} disabled={mutating}>
              Switch
            </button>
          </div>
        </div>

        <div className="control-card">
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

        <div className="control-card">
          <label>Runtime</label>
          <div className="inline-control">
            <button type="button" onClick={() => callControl("/api/control/start")} disabled={mutating}>
              Start
            </button>
            <button type="button" onClick={() => callControl("/api/control/stop")} disabled={mutating}>
              Stop
            </button>
          </div>
        </div>

        <div className="control-card">
          <label htmlFor="scenarioName">Demo scenario</label>
          <div className="inline-control">
            <select id="scenarioName" value={scenario} onChange={(event) => setScenario(event.target.value)}>
              {(controls.demo_scenarios ?? []).map((scenarioName) => (
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

        <div className="control-card">
          <label htmlFor="privacyMode">Privacy mode</label>
          <div className="inline-control">
            <select
              id="privacyMode"
              value={runtime.privacy_mode ?? "browser_aware"}
              onChange={(event) => callControl("/api/control/privacy-mode", { privacy_mode: event.target.value })}
              disabled={mutating}
            >
              {privacyModes.map((modeName) => (
                <option key={modeName} value={modeName}>
                  {modeName}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => callControl("/api/control/retention-run")}
              disabled={mutating}
            >
              Archive Now
            </button>
          </div>
        </div>
      </section>

      {error ? <p className="error-banner">{error}</p> : null}
      {runtime.last_error ? <p className="error-banner">{runtime.last_error}</p> : null}

      <section className="metrics-row">
        <MetricCard label="Risk Score" value={current ? formatMaybeNumber(current.risk_score) : "0.0"} detail={current?.severity ?? "No signal yet"} tone={statusTone(current)} />
        <MetricCard label="Confidence" value={formatMaybeNumber(current?.confidence_score, "%")} detail={`Average ${formatMaybeNumber(stats.average_confidence, "%")}`} tone="neutral" />
        <MetricCard label="Fingerprint Match" value={formatMaybeNumber(current?.fingerprint_similarity, "%")} detail={`Average ${formatMaybeNumber(stats.average_fingerprint_similarity, "%")}`} tone={current?.fingerprint_similarity !== null && current?.fingerprint_similarity < 78 ? "critical" : "safe"} />
        <MetricCard label="Behavior Drift" value={formatMaybeNumber(current?.behavior_drift, "%")} detail={`Average ${formatMaybeNumber(stats.average_behavior_drift, "%")}`} tone="watch" />
        <MetricCard label="Baseline Samples" value={stats.profile_samples ?? 0} detail={`${stats.known_apps ?? 0} known apps`} tone="neutral" />
        <MetricCard label="Alert Rate" value={`${alertRate}%`} detail={`${stats.anomaly_count ?? 0} alerts`} tone="critical" />
        <MetricCard label="Decoy Hits" value={stats.honeypot_detection_count ?? 0} detail={`${honeypotStatus.decoy_count ?? 0} files armed`} tone={Number(stats.honeypot_detection_count ?? 0) > 0 ? "critical" : "neutral"} />
        <MetricCard label="Exports" value={stats.integration_export_count ?? 0} detail={stats.last_integration_export_at ? `Last ${formatTimestamp(stats.last_integration_export_at)}` : "No outbound exports yet"} tone="neutral" />
        <MetricCard label="Reviewed Alerts" value={stats.reviewed_alerts ?? 0} detail={`threshold ${formatMaybeNumber(stats.adaptive_threshold_offset)}`} tone="neutral" />
      </section>

      <section className="dashboard-grid">
        <Surface title="Signal Trends" subtitle="Risk, confidence, fingerprint similarity, and typing speed." className="span-8">
          <div className="chart-grid">
            <article className="chart-card">
              <div className="chart-head"><h3>Risk</h3><span>0-100</span></div>
              <Sparkline points={history} valueKey="risk_score" color="#2056df" domainMax={100} />
            </article>
            <article className="chart-card">
              <div className="chart-head"><h3>Confidence</h3><span>0-100%</span></div>
              <Sparkline points={history} valueKey="confidence_score" color="#169c71" domainMax={100} />
            </article>
            <article className="chart-card">
              <div className="chart-head"><h3>Fingerprint</h3><span>0-100%</span></div>
              <Sparkline points={history} valueKey="fingerprint_similarity" color="#7c3aed" domainMax={100} />
            </article>
            <article className="chart-card">
              <div className="chart-head"><h3>Typing Speed</h3><span>keys/sec</span></div>
              <Sparkline points={history} valueKey="typing_speed" color="#f59e0b" />
            </article>
          </div>
        </Surface>

        <Surface title="Current Assessment" subtitle="Current reasons, weighted factors, and operator guidance." className="span-4">
          <div className={`summary-panel tone-${statusTone(current)}`}>
            <strong>{current?.summary ?? "No suspicious activity explanation yet."}</strong>
            <p>{current?.explanation ?? "Start monitoring or run a demo scenario."}</p>
          </div>
          <div className="stack-list">
            <div className="info-block">
              <span className="mini-label">Replay summary</span>
              <p>{replaySummary || "No compact replay summary is available yet."}</p>
            </div>
            <div className="info-block">
              <span className="mini-label">Intent detection</span>
              <div className="pill-wrap">
                {intents.length ? intents.map((item) => <span key={item} className="intent-pill">{item}</span>) : <span className="muted-note">No suspicious intent chain matched.</span>}
              </div>
            </div>
            <div className="info-block">
              <span className="mini-label">Visible queries</span>
              <div className="pill-wrap">
                {currentQueries.length ? currentQueries.map((query) => <span key={query} className="context-pill">{query}</span>) : <span className="muted-note">No visible query in the latest window.</span>}
              </div>
            </div>
            <div className="info-block">
              <span className="mini-label">Watchlists</span>
              <div className="pill-wrap">
                {watchlistHits.length ? watchlistHits.map((item) => <span key={item} className="watch-pill">{item}</span>) : <span className="muted-note">No watchlist matches in the current window.</span>}
              </div>
            </div>
            <div className="info-block">
              <span className="mini-label">Deception layer</span>
              <div className="pill-wrap">
                {honeypotHits.length ? honeypotHits.map((item) => <span key={item} className="watch-pill">{item}</span>) : <span className="muted-note">No honeypot interactions in the current window.</span>}
              </div>
            </div>
            <div className="info-block">
              <span className="mini-label">Domain categories</span>
              <div className="pill-wrap">
                {domainCategories.length ? domainCategories.map((item) => <span key={item} className="context-pill">{item}</span>) : <span className="muted-note">No browser domain categories observed.</span>}
              </div>
            </div>
            <div className="weight-list">
              {riskFactors.length ? riskFactors.map((factor) => (
                <article key={factor.label} className="weight-row">
                  <div>
                    <strong>{factor.label}</strong>
                    <p>{factor.score} signal score</p>
                  </div>
                  <span>{factor.weight_pct}%</span>
                </article>
              )) : <p className="muted-note">Risk factor weighting appears after a scored window is analyzed.</p>}
            </div>
            <div className="action-list">
              <span className="mini-label">Recommended actions</span>
              {recommendedActions.length ? recommendedActions.map((action) => <p key={action}>{action}</p>) : <p className="muted-note">No response guidance yet.</p>}
            </div>
            <div className="reason-list">
              {deviations.slice(0, 3).map((item) => (
                <article key={`${item.feature_name}-${item.reason}`} className="reason-item">
                  <span className="reason-badge">{item.feature_name.replaceAll("_", " ")}</span>
                  <p>{item.reason}</p>
                </article>
              ))}
            </div>
          </div>
        </Surface>

        <Surface title="Timeline Replay" subtitle="Recent ordered activity before the detection result." className="span-6">
          <div className="timeline-list">
            {timeline.length ? timeline.map((entry, index) => (
              <article key={`${entry.time}-${entry.title}-${index}`} className={`timeline-row timeline-${entry.kind}`}>
                <div className="timeline-time">{entry.time}</div>
                <div>
                  <strong>{entry.title}</strong>
                  <p>{entry.detail}</p>
                </div>
              </article>
            )) : <p className="muted-note">No replay events are available yet.</p>}
          </div>
          <div className="notes-block">
            <span className="mini-label">Collector Notes</span>
            {notes.length ? notes.map((note) => <p key={note}>{note}</p>) : <p>No collector notes yet.</p>}
          </div>
        </Surface>

        <Surface title="Browser and Window Activity" subtitle="Recent browser telemetry and current app observations." className="span-6">
          <div className="activity-columns">
            <div className="activity-pane">
              <span className="mini-label">Recent browser activity</span>
              <div className="activity-feed">
                {recentBrowserActivity.slice(0, 5).map((item) => (
                  <article key={`${item.observed_at}-${item.app_name}-${item.window_title}`} className="feed-row">
                    <div>
                      <strong>{item.app_name}</strong>
                      <p>{item.tab_title || item.window_title}</p>
                    </div>
                    <div className="feed-meta">
                      <span>{item.domain || "No domain"}</span>
                      <span>{formatTimestamp(item.observed_at)}</span>
                    </div>
                  </article>
                ))}
              </div>
            </div>
            <div className="activity-pane">
              <span className="mini-label">Current observations</span>
              <div className="activity-feed">
                {appObservations.slice(0, 5).map((item, index) => (
                  <article key={`${item.app_name}-${index}`} className="feed-row">
                    <div>
                      <strong>{item.app_name}</strong>
                      <p>{item.tab_title || item.window_title}</p>
                    </div>
                    <div className="feed-meta">
                      <span>{item.search_query || item.domain || item.source}</span>
                    </div>
                  </article>
                ))}
              </div>
              <div className="pill-wrap">
                {currentTabs.length ? currentTabs.slice(0, 4).map((tab) => <span key={tab} className="context-pill">{tab}</span>) : <span className="muted-note">No browser tab title in the current view.</span>}
              </div>
            </div>
          </div>
        </Surface>

        <Surface title="Process and Deception" subtitle="Foreground process ancestry and decoy file status." className="span-6">
          <div className="activity-columns">
            <div className="activity-pane">
              <span className="mini-label">Process lineage</span>
              <div className="activity-feed">
                {processObservations.length ? processObservations.slice(0, 6).map((item, index) => (
                  <article key={`${item.process_name}-${item.pid ?? index}`} className="feed-row">
                    <div>
                      <strong>{item.process_name}</strong>
                      <p>{[item.parent_name, ...(item.ancestry ?? []).slice(1)].filter(Boolean).join(" <- ") || "No parent chain"}</p>
                    </div>
                    <div className="feed-meta">
                      <span>{item.pid ? `PID ${item.pid}` : item.source}</span>
                    </div>
                  </article>
                )) : <p className="muted-note">No process lineage is available yet.</p>}
              </div>
            </div>
            <div className="activity-pane">
              <span className="mini-label">Honeypot status</span>
              <div className="notes-block compact">
                <p><strong>{honeypotStatus.decoy_count ?? 0}</strong> decoy files armed.</p>
                <p>{honeypotStatus.directory ?? "No honeypot directory configured."}</p>
                {honeypotHits.length ? honeypotHits.map((item) => <p key={item}>{item}</p>) : <p>No current decoy interaction detected.</p>}
              </div>
              <div className="inline-control">
                <button type="button" onClick={() => callControl("/api/control/honeypots")} disabled={mutating}>
                  Refresh Decoys
                </button>
              </div>
            </div>
          </div>
        </Surface>

        <Surface title="Cross-User Comparison" subtitle="Average risk, confidence, fingerprint match, and top apps." className="span-6">
          <div className="comparison-list">
            {userComparison.length ? userComparison.map((row) => (
              <article key={row.user_name} className="comparison-row">
                <div>
                  <strong>{row.user_name}</strong>
                  <p>Top apps: {(row.top_apps ?? []).join(", ") || "No history yet"}</p>
                </div>
                <div className="comparison-bar-shell">
                  <div className="comparison-bar" style={{ width: `${(Number(row.average_risk ?? 0) / maxComparisonRisk) * 100}%` }} />
                </div>
                <div className="comparison-metrics">
                  <span>{formatMaybeNumber(row.average_risk)} avg risk</span>
                  <span>{formatMaybeNumber(row.average_confidence, "%")} confidence</span>
                  <span>{formatMaybeNumber(row.average_fingerprint_similarity, "%")} fingerprint</span>
                </div>
              </article>
            )) : <p className="muted-note">No comparison data yet.</p>}
          </div>
        </Surface>

        <Surface title="Distribution Analytics" subtitle="Usage mix, severity mix, domain mix, and repeated search queries." className="span-6">
          <div className="distribution-grid">
            <DonutChart title="App Mix" subtitle="dominant apps" data={appDistribution} />
            <DonutChart title="Severity Mix" subtitle="stored outcomes" data={severityDistribution} />
            <DonutChart title="Domain Mix" subtitle="browser telemetry" data={domainDistribution} />
          </div>
          <div className="query-list">
            <h3>Repeated Search Queries</h3>
            {queryDistribution.length ? queryDistribution.map((item) => (
              <div key={item.label} className="legend-row">
                <span className="legend-label">{item.label}</span>
                <strong>{item.value}</strong>
              </div>
            )) : <p className="muted-note">No repeated visible search queries stored yet.</p>}
          </div>
        </Surface>

        <Surface title="Threat Analytics" subtitle="Domain categories, risk heatmap, and demo evaluation metrics." className="span-6">
          <div className="distribution-grid">
            <DonutChart title="Domain Categories" subtitle="local domain classification" data={domainCategoryDistribution} />
          </div>
          <HeatmapGrid title="Risk Heatmap" data={riskHeatmap} />
          <div className="evaluation-grid">
            <article className="evaluation-card">
              <span className="mini-label">Demo accuracy</span>
              <strong>{formatMaybeNumber(demoEvaluation.accuracy, "%")}</strong>
            </article>
            <article className="evaluation-card">
              <span className="mini-label">Precision</span>
              <strong>{formatMaybeNumber(demoEvaluation.precision, "%")}</strong>
            </article>
            <article className="evaluation-card">
              <span className="mini-label">Recall</span>
              <strong>{formatMaybeNumber(demoEvaluation.recall, "%")}</strong>
            </article>
            <article className="evaluation-card">
              <span className="mini-label">Demo samples</span>
              <strong>{demoEvaluation.sample_count ?? 0}</strong>
            </article>
          </div>
        </Surface>

        <Surface title="Governance" subtitle="Privacy controls, archival posture, and retention settings." className="span-6">
          <div className="evaluation-grid">
            <article className="evaluation-card">
              <span className="mini-label">Privacy mode</span>
              <strong>{(runtime.privacy_mode ?? "browser_aware").replaceAll("_", " ")}</strong>
            </article>
            <article className="evaluation-card">
              <span className="mini-label">Raw behavior retention</span>
              <strong>{runtime.raw_behavior_retention_days ?? 0}d</strong>
            </article>
            <article className="evaluation-card">
              <span className="mini-label">Raw browser retention</span>
              <strong>{runtime.raw_browser_retention_days ?? 0}d</strong>
            </article>
            <article className="evaluation-card">
              <span className="mini-label">Last archive run</span>
              <strong>{formatTimestamp(runtime.last_retention_run_at)}</strong>
            </article>
          </div>
          <div className="cluster-list">
            <article className="cluster-card">
              <div className="alert-top">
                <strong>Raw storage</strong>
                <span>{stats.raw_behavior_samples ?? 0} windows</span>
              </div>
              <p>{stats.raw_browser_events ?? 0} raw browser events retained for fast recent analysis.</p>
            </article>
            <article className="cluster-card">
              <div className="alert-top">
                <strong>Archived rollups</strong>
                <span>{stats.archived_behavior_days ?? 0} days</span>
              </div>
              <p>{stats.archived_behavior_samples ?? 0} behavior samples and {stats.archived_browser_events ?? 0} browser events rolled up.</p>
            </article>
          </div>
        </Surface>

        <Surface title="Integrations" subtitle="Outbound exports for reports, SIEM-style events, and future connectors." className="span-6">
          <div className="cluster-list">
            {recentIntegrations.length ? recentIntegrations.map((item) => (
              <article key={`${item.created_at}-${item.target_kind}`} className="cluster-card">
                <div className="alert-top">
                  <strong>{item.target_kind}</strong>
                  <span>{item.status}</span>
                </div>
                <p>{item.target_name}</p>
                <div className="alert-meta">
                  <span>{formatTimestamp(item.created_at)}</span>
                  <span>{item.file_path ? "file written" : "no file"}</span>
                </div>
              </article>
            )) : <p className="muted-note">No integration exports recorded yet.</p>}
          </div>
        </Surface>

        <Surface title="Incident Clusters" subtitle="Repeated alert families, baseline versions, and analyst review state." className="span-5">
          <div className="cluster-list">
            {alertClusters.length ? alertClusters.map((cluster) => (
              <article key={cluster.cluster_key} className="cluster-card">
                <div className="alert-top">
                  <strong>{cluster.cluster_key}</strong>
                  <span>{cluster.count} alerts</span>
                </div>
                <p>{cluster.latest_summary}</p>
                <div className="alert-meta">
                  <span>{cluster.latest_severity}</span>
                  <span>{cluster.true_positive_count ?? 0} TP</span>
                  <span>{cluster.false_positive_count ?? 0} FP</span>
                </div>
              </article>
            )) : <p className="muted-note">No alert clusters are stored yet.</p>}
          </div>
          <div className="baseline-version-list">
            <span className="mini-label">Baseline versions</span>
            {baselineVersions.length ? baselineVersions.map((version) => (
              <article key={version.captured_at} className="baseline-version">
                <strong>{formatTimestamp(version.captured_at)}</strong>
                <p>{version.sample_count} samples | typing {version.typing_speed} | mouse {version.mouse_speed}</p>
              </article>
            )) : <p className="muted-note">No baseline snapshot history yet.</p>}
          </div>
        </Surface>

        <Surface title="Feature Baseline Snapshot" subtitle="Current window values versus the active user baseline." className="span-7">
          <div className="feature-table">
            <div className="table-head">
              <span>Feature</span>
              <span>Current</span>
              <span>Baseline</span>
            </div>
            {featureRows.map((row) => (
              <div key={row.name} className="table-row compact">
                <strong>{row.label}</strong>
                <span>{formatMaybeNumber(row.current)}</span>
                <span>{formatMaybeNumber(row.baseline)}</span>
              </div>
            ))}
          </div>
        </Surface>

        <Surface title="Recent Alerts" subtitle="Stored alerts with their explanations for later review." className="span-5">
          <div className="alert-list">
            {alerts.length ? alerts.map((alert) => (
              <article key={`${alert.created_at}-${alert.summary}`} className="alert-card">
                <div className="alert-top">
                  <strong>{alert.summary}</strong>
                  <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
                </div>
                <p>{alert.explanation}</p>
                <div className="feedback-row">
                  <button
                    type="button"
                    className={alert.feedback_label === "true_positive" ? "selected" : ""}
                    onClick={() => callControl(`/api/alerts/${alert.id}/feedback`, { label: "true_positive" })}
                    disabled={mutating}
                  >
                    True Positive
                  </button>
                  <button
                    type="button"
                    className={alert.feedback_label === "false_positive" ? "selected" : ""}
                    onClick={() => callControl(`/api/alerts/${alert.id}/feedback`, { label: "false_positive" })}
                    disabled={mutating}
                  >
                    False Positive
                  </button>
                  <button
                    type="button"
                    className={alert.feedback_label === "needs_review" ? "selected" : ""}
                    onClick={() => callControl(`/api/alerts/${alert.id}/feedback`, { label: "needs_review" })}
                    disabled={mutating}
                  >
                    Review
                  </button>
                </div>
                {alert.recommended_actions?.length ? (
                  <div className="action-list compact">
                    {alert.recommended_actions.map((action) => <p key={action}>{action}</p>)}
                  </div>
                ) : null}
                <div className="alert-meta">
                  <span>{formatTimestamp(alert.created_at)}</span>
                  <span>risk {formatMaybeNumber(alert.risk_score)}</span>
                  <span>{alert.user_name}</span>
                </div>
              </article>
            )) : <p className="muted-note">No alerts stored yet.</p>}
          </div>
        </Surface>
      </section>
    </div>
  );
}
