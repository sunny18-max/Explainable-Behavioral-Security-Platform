import { BRAND } from "../lib/dashboard.js";

export function BrandLockup({ variant = "default", subtitle }) {
  const className = `brand-lockup brand-lockup-${variant}`;

  return (
    <div className={className}>
      <img src="/cognishield-mark.svg" alt={`${BRAND.name} logo`} className="brand-logo" />
      <div className="brand-copy">
        <span className="nav-kicker">{BRAND.label}</span>
        <strong className="brand-wordmark">{BRAND.name}</strong>
        {subtitle ? <span className="brand-subtitle">{subtitle}</span> : null}
      </div>
    </div>
  );
}
