import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function DefangedIndicator({ value, defangedValue, type = 'generic', className = '' }) {
  const [copied, setCopied] = useState(false);

  const displayVal = defangedValue || String(value || '').replace(/^https:/i, 'hxxps:').replace(/^http:/i, 'hxxp:').replace(/\./g, '[.]');

  const handleCopy = async (e) => {
    e.stopPropagation();
    try { await navigator.clipboard.writeText(value || displayVal); } catch { return; }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-700/60 text-slate-300 font-mono text-xs max-w-full truncate group ${className}`}
      title={`Click copy button to copy raw ${type}: ${value || displayVal}`}
    >
      <span className="truncate">{displayVal}</span>
      <button
        onClick={handleCopy}
        className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-cyan-400 focus:opacity-100"
        aria-label="Copy original indicator" title="Copy original indicator"
      >
        {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
      </button>
    </span>
  );
}
