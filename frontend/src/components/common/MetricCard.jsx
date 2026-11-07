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
    <div className={`metric-card metric-${color}`}>
      <div className="flex items-start justify-between gap-3">
        <p className="metric-title">{title}</p>
        {Icon && (
          <span className="metric-icon">
            <Icon size={19} aria-hidden="true" />
          </span>
        )}
      </div>
      <p className="metric-value">{value}</p>
      <div className="metric-footer">
        <span>{subtitle}</span>
        {trend && <span className="metric-trend">{trend}</span>}
      </div>
    </div>
  );
}
