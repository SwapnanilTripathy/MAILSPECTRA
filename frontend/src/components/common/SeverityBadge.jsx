import React from 'react';

export default function SeverityBadge({ severity = 'LOW', size = 'md', className = '' }) {
  const sev = (severity || 'LOW').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    LOW: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    INFORMATIONAL: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    BENIGN: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    LEGITIMATE: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    PHISHING: 'bg-red-500/10 text-red-400 border-red-500/30',
    BUSINESS_EMAIL_COMPROMISE: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    IMPERSONATION: 'bg-pink-500/10 text-pink-400 border-pink-500/30',
    FRAUD: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    SUSPICIOUS: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    CREDENTIAL_HARVESTING: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  };

  const currentStyle = styles[sev] || 'bg-slate-700/30 text-slate-300 border-slate-600/30';

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs font-semibold',
    lg: 'px-3 py-1.5 text-sm font-bold tracking-wide',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border uppercase tracking-wider font-mono ${currentStyle} ${sizeClasses[size] || sizeClasses.md} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      {sev.replace(/_/g, ' ')}
    </span>
  );
}
