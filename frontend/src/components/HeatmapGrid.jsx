export function HeatmapGrid({ title, data }) {
  const cells = data ?? [];

  return (
    <div className="heatmap-card">
      <div className="chart-head">
        <div>
          <h3>{title}</h3>
          <span>24-hour risk intensity and alert density</span>
        </div>
      </div>
      <div className="heatmap-grid">
        {cells.map((cell) => {
          const intensity = Math.max(0.1, Number(cell.average_risk ?? 0) / 100);
          return (
            <article
              key={cell.hour}
              className="heatmap-cell"
              style={{ background: `rgba(32, 86, 223, ${intensity})` }}
            >
              <strong>{String(cell.hour).padStart(2, "0")}:00</strong>
              <span>{Number(cell.average_risk ?? 0).toFixed(1)} risk</span>
              <span>{cell.alert_count ?? 0} alerts</span>
            </article>
          );
        })}
      </div>
    </div>
  );
}
