import { BRAND } from "../lib/dashboard.js";
import { BrandLockup } from "./BrandLockup.jsx";

export function LandingPage({ onOpenDashboard }) {
  return (
    <div className="landing-shell">
      <header className="landing-nav">
        <BrandLockup />
        <div className="landing-actions">
          <button
            type="button"
            className="nav-btn secondary"
            onClick={() =>
              document.getElementById("landing-about")?.scrollIntoView({
                behavior: "smooth"
              })
            }
          >
            Explore
          </button>
          <button type="button" className="nav-btn primary" onClick={onOpenDashboard}>
            Go to Dashboard
          </button>
        </div>
      </header>

      <section className="landing-hero" data-aos="fade-up">
        <div className="hero-copy-block">
          <span className="hero-badge">Explainable User Behavior Defense</span>
          <h1>Monitor behavior. Detect anomalies. Explain why it matters.</h1>
          <p>
            {BRAND.name} is a privacy-aware Windows security platform that watches behavioral
            patterns, learns what is normal for each user, and turns suspicious activity into
            readable evidence instead of vague alerts.
          </p>
          <div className="hero-actions">
            <button type="button" className="nav-btn primary" onClick={onOpenDashboard}>
              Open Dashboard
            </button>
            <button
              type="button"
              className="nav-btn ghost"
              onClick={() =>
                document.getElementById("landing-about")?.scrollIntoView({
                  behavior: "smooth"
                })
              }
            >
              Learn More
            </button>
          </div>
        </div>

        <div className="hero-visual-block">
          <div className="visual-stage">
            <div className="signal-card large">
              <span className="mini-label">Detection Flow</span>
              <strong>User Activity -&gt; Baseline -&gt; Anomaly -&gt; Explanation</strong>
              <p>Readable reasons backed by per-user behavior modeling.</p>
            </div>
            <div className="signal-row">
              <div className="signal-card">
                <span className="mini-label">Identity Match</span>
                <strong>Behavior fingerprint</strong>
                <p>Detects unusual operators even after valid login.</p>
              </div>
              <div className="signal-card">
                <span className="mini-label">Intent Analysis</span>
                <strong>Action sequence context</strong>
                <p>Looks beyond anomalies to infer suspicious purpose.</p>
              </div>
            </div>
            <div className="signal-card strip">
              <div>
                <span className="mini-label">Stored Locally</span>
                <strong>SQLite-backed analytics</strong>
              </div>
              <span className="context-pill">Privacy-safe telemetry</span>
            </div>
          </div>
        </div>
      </section>

      <section id="landing-about" className="landing-section" data-aos="fade-up">
        <div className="section-copy">
          <span className="section-kicker">Why this application exists</span>
          <h2>Most security tools detect events. Very few explain them clearly.</h2>
          <p>
            Traditional tools often stop at "threat detected". {BRAND.name} is built to show
            exactly what changed in user behavior, how confident the system is, and what sequence
            of actions led to the alert.
          </p>
        </div>
        <div className="feature-grid">
          <article className="feature-card">
            <span className="feature-index">01</span>
            <h3>Personalized monitoring</h3>
            <p>Each user has a separate baseline for typing, app usage, timing, and interaction flow.</p>
          </article>
          <article className="feature-card">
            <span className="feature-index">02</span>
            <h3>Explainable decisions</h3>
            <p>Alerts explain why the activity is suspicious, not just that it was detected.</p>
          </article>
          <article className="feature-card">
            <span className="feature-index">03</span>
            <h3>Evidence-rich analytics</h3>
            <p>Browser context, app activity, timeline replay, and risk trends are stored for review.</p>
          </article>
        </div>
      </section>

      <section className="landing-section workflow-section">
        <div className="section-copy narrow">
          <span className="section-kicker">How it works</span>
          <h2>A direct workflow from collection to explanation.</h2>
        </div>
        <div className="workflow-grid">
          <article className="workflow-card">
            <span className="workflow-number">1</span>
            <h3>Collect</h3>
            <p>Track privacy-safe keyboard timing, mouse activity, active apps, and browser telemetry.</p>
          </article>
          <article className="workflow-card">
            <span className="workflow-number">2</span>
            <h3>Learn</h3>
            <p>Build a behavioral baseline with known apps, timing ranges, and interaction patterns.</p>
          </article>
          <article className="workflow-card">
            <span className="workflow-number">3</span>
            <h3>Detect</h3>
            <p>Score anomalies, time-warps, identity mismatch, and suspicious intent sequences.</p>
          </article>
          <article className="workflow-card">
            <span className="workflow-number">4</span>
            <h3>Explain</h3>
            <p>Show confidence, contributing reasons, replay timeline, and affected features.</p>
          </article>
        </div>
      </section>

      <section className="landing-section capability-stage">
        <div className="section-copy">
          <span className="section-kicker">Core capabilities</span>
          <h2>Built for demos, analysis, and real-time behavioral monitoring.</h2>
        </div>
        <div className="capability-grid">
          <article className="capability-card">
            <h3>Behavior fingerprint identity</h3>
            <p>Measures whether the current operator still matches the learned user behavior signature.</p>
          </article>
          <article className="capability-card">
            <h3>Confidence-based reasoning</h3>
            <p>Every alert carries readable reasoning and a confidence score to reduce ambiguity.</p>
          </article>
          <article className="capability-card">
            <h3>Browser activity intelligence</h3>
            <p>Captures active tab details, visible search intent, and domain patterns for stronger context.</p>
          </article>
          <article className="capability-card">
            <h3>Timeline replay</h3>
            <p>Shows what happened in sequence before an anomaly was raised.</p>
          </article>
          <article className="capability-card">
            <h3>Cross-user analytics</h3>
            <p>Compares users by risk, confidence, fingerprint score, and usage patterns.</p>
          </article>
          <article className="capability-card">
            <h3>Local storage</h3>
            <p>Stores telemetry and alerts in SQLite for offline inspection and repeatable demos.</p>
          </article>
        </div>
      </section>

      <section className="landing-cta" data-aos="fade-up">
        <div className="cta-copy">
          <span className="section-kicker">Ready to inspect the live console?</span>
          <h2>Open the workspace and review the behavior analytics dashboard.</h2>
        </div>
        <button type="button" className="nav-btn primary large" onClick={onOpenDashboard}>
          Go to Dashboard
        </button>
      </section>
    </div>
  );
}
