export function Surface({ id, title, subtitle, className = "", children }) {
  return (
    <section id={id} className={`surface ${className}`.trim()}>
      <div className="surface-head">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
      </div>
      {children}
    </section>
  );
}
