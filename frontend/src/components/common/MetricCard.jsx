import React from 'react';

export default function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'cyan',
  trend,
}) {
  return (
    <article className={`metric-card metric-${color}`} aria-label={`${title}: ${value}`}>
      <div className="flex items-start justify-between gap-3">
        <p className="metric-title">{title}</p>
        {Icon && (
          <span className="metric-icon" aria-hidden="true">
            <Icon size={18} strokeWidth={1.8} />
          </span>
        )}
      </div>
      <p className="metric-value" aria-live="polite">{value}</p>
      <div className="metric-footer">
        <span>{subtitle}</span>
        {trend && <span className="metric-trend">{trend}</span>}
      </div>
    </article>
  );
}
