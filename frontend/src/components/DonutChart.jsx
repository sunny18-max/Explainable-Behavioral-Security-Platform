import { CHART_COLORS } from "../lib/dashboard.js";

export function DonutChart({ title, subtitle, data }) {
  const sanitized = (data ?? []).filter((item) => Number(item.value) > 0);
  const total = sanitized.reduce((sum, item) => sum + Number(item.value), 0);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <article className="donut-card">
      <div className="chart-head">
        <div>
          <h3>{title}</h3>
          <span>{subtitle}</span>
        </div>
        <strong>{total}</strong>
      </div>
      {total ? (
        <div className="donut-layout">
          <svg className="donut-svg" viewBox="0 0 140 140">
            <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(15, 23, 42, 0.08)" strokeWidth="18" />
            {sanitized.map((item, index) => {
              const fraction = Number(item.value) / total;
              const segment = fraction * circumference;
              const element = (
                <circle
                  key={`${item.label}-${index}`}
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke={CHART_COLORS[index % CHART_COLORS.length]}
                  strokeWidth="18"
                  strokeDasharray={`${segment} ${circumference - segment}`}
                  strokeDashoffset={-offset}
                  strokeLinecap="round"
                  transform="rotate(-90 70 70)"
                />
              );
              offset += segment;
              return element;
            })}
            <text x="70" y="64" textAnchor="middle" className="donut-value">
              {total}
            </text>
            <text x="70" y="83" textAnchor="middle" className="donut-label">
              events
            </text>
          </svg>
          <div className="legend-list">
            {sanitized.map((item, index) => (
              <div key={`${item.label}-legend`} className="legend-row">
                <div className="legend-item-main">
                  <span
                    className="legend-swatch"
                    style={{ backgroundColor: CHART_COLORS[index % CHART_COLORS.length] }}
                  />
                  <span className="legend-label">{item.label}</span>
                </div>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="sparkline-empty">No distribution data yet</div>
      )}
    </article>
  );
}
