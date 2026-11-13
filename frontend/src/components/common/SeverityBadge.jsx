import React from 'react';

const severityStyles = {
  CRITICAL: 'severity-critical',
  HIGH: 'severity-high',
  MEDIUM: 'severity-medium',
  LOW: 'severity-low',
  INFORMATIONAL: 'severity-info',
  BENIGN: 'severity-low',
  LEGITIMATE: 'severity-low',
  PHISHING: 'severity-critical',
  BUSINESS_EMAIL_COMPROMISE: 'severity-purple',
  IMPERSONATION: 'severity-purple',
  FRAUD: 'severity-medium',
  SUSPICIOUS: 'severity-medium',
  CREDENTIAL_HARVESTING: 'severity-critical',
};

const sizeClasses = {
  sm: 'px-2 py-0.5 text-[9px]',
  md: 'px-2.5 py-1 text-[10px] font-semibold',
  lg: 'px-3 py-1.5 text-xs font-bold tracking-wide',
};

export default function SeverityBadge({ severity = 'LOW', size = 'md', className = '' }) {
  const sev = (severity || 'LOW').toUpperCase();
  const tone = severityStyles[sev] || 'severity-neutral';

  return (
    <span
      role="status"
      aria-label={`Severity: ${sev.replace(/_/g, ' ')}`}
      className={`severity-badge inline-flex items-center gap-1.5 rounded border uppercase tracking-wider font-mono ${tone} ${sizeClasses[size] || sizeClasses.md} ${className}`}
    >
      <span className="severity-indicator w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
      {sev.replace(/_/g, ' ')}
    </span>
  );
}
