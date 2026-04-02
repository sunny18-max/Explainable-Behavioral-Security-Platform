export function Sparkline({ points, valueKey, color, domainMax }) {
  if (!points.length) {
    return <div className="sparkline-empty">No recent telemetry</div>;
  }

  const values = points.map((point) => Number(point[valueKey] ?? 0));
  const maxValue = domainMax ?? Math.max(...values, 1);
  const height = 120;
  const width = 420;
  const stepX = width / Math.max(values.length - 1, 1);
  const path = values
    .map((value, index) => {
      const x = index * stepX;
      const y = height - (value / maxValue) * (height - 16) - 8;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg className="sparkline" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
      <polyline fill="none" stroke={color} strokeWidth="3" points={path} />
      {values.map((value, index) => {
        const x = index * stepX;
        const y = height - (value / maxValue) * (height - 16) - 8;
        return <circle key={`${valueKey}-${index}`} cx={x} cy={y} r="3" fill={color} />;
      })}
    </svg>
  );
}
