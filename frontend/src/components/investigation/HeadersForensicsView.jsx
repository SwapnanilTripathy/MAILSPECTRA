import React, { useState } from 'react';
import { Mail, AlertCircle, CheckCircle2, ChevronDown, ChevronUp, Copy } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

export default function HeadersForensicsView({ metadata, authentication }) {
  const [showRaw, setShowRaw] = useState(false);

  if (!metadata) return null;

  const sender = metadata.from_sender || {};
  const returnPath = metadata.return_path;
  const replyTo = metadata.reply_to || [];

  // Detect header identity anomalies
  const anomalies = [];
  if (returnPath && sender.domain && !returnPath.toLowerCase().includes(sender.domain.toLowerCase())) {
    anomalies.push(`Return-Path domain mismatch: Return-Path is <${returnPath}> but From is <${sender.address}>.`);
  }
  if (replyTo.length > 0 && replyTo[0].address && sender.address && replyTo[0].address.toLowerCase() !== sender.address.toLowerCase()) {
    anomalies.push(`Reply-To redirection detected: Replies will route to <${replyTo[0].address}> instead of sender.`);
  }
  if (sender.display_name && sender.display_name.includes('@') && !sender.display_name.includes(sender.address)) {
    anomalies.push(`Display name deception: Display name embeds external email address "${sender.display_name}".`);
  }

  const fields = [
    { label: 'Subject', value: metadata.subject || '(No Subject)' },
    { label: 'Date (Raw)', value: metadata.date_raw || 'N/A' },
    { label: 'Date (ISO)', value: metadata.date_iso || 'N/A' },
    { label: 'From Header', value: sender.raw || sender.address || 'N/A' },
    { label: 'Sender Address', value: sender.address || 'N/A' },
    { label: 'Sender Domain', value: sender.domain || 'N/A' },
    { label: 'Return-Path', value: returnPath || '(Not Specified)' },
    { label: 'Reply-To', value: replyTo.map((r) => r.raw || r.address).join(', ') || '(Same as From)' },
    { label: 'To Recipients', value: (metadata.to_recipients || []).map((t) => t.raw || t.address).join(', ') || 'N/A' },
    { label: 'Message-ID', value: metadata.message_id || 'N/A' },
  ];

  return (
    <div className="space-y-6">
      {/* Identity Anomalies Alert Box */}
      {anomalies.length > 0 && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300">
          <div className="flex items-center gap-2 font-semibold text-sm">
            <AlertCircle className="w-4 h-4 text-amber-400" />
            <span>Header & Sender Identity Anomalies Detected ({anomalies.length})</span>
          </div>
          <ul className="mt-2 space-y-1 text-xs font-mono">
            {anomalies.map((a, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-amber-400">•</span>
                <span>{a}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Header Fields Table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
        <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-400">
            <Mail className="w-4 h-4 text-cyan-400" />
            <span>RFC 822 Email Header Forensics</span>
          </div>
        </div>
        <div className="divide-y divide-slate-800/60 font-mono text-xs">
          {fields.map((f, i) => (
            <div key={i} className="grid grid-cols-1 md:grid-cols-12 px-5 py-3 hover:bg-slate-800/30 transition">
              <div className="md:col-span-3 text-slate-400 font-semibold">{f.label}</div>
              <div className="md:col-span-9 text-slate-200 break-all select-all flex items-center justify-between">
                <span>{f.value}</span>
                {f.value && f.value !== 'N/A' && (
                  <button
                    onClick={() => navigator.clipboard.writeText(f.value)}
                    className="opacity-40 hover:opacity-100 p-1 hover:text-cyan-400 transition ml-2"
                    title="Copy value"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
