import React, { useState } from 'react';
import { Link as LinkIcon, Server, Paperclip, Hash, Copy, Check, ShieldAlert, Download } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

export default function ObservablesView({ observables, attachments }) {
  const [activeTab, setActiveTab] = useState('ALL');
  const [copiedAll, setCopiedAll] = useState(false);

  const urls = observables?.filter((o) => o.type === 'URL') || [];
  const ips = observables?.filter((o) => o.type === 'IP') || [];
  const domains = observables?.filter((o) => o.type === 'DOMAIN') || [];
  const hashes = observables?.filter((o) => o.type?.includes('HASH') || o.type === 'MD5' || o.type === 'SHA256') || [];
  const allObservables = observables || [];

  const handleExportIOCs = () => {
    const lines = allObservables.map((o) => `${o.type}\t${o.value}\t${o.defanged_value || o.value}`);
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `deeptrace-iocs-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getFilteredItems = () => {
    switch (activeTab) {
      case 'URL':
        return urls;
      case 'IP':
        return ips;
      case 'DOMAIN':
        return domains;
      case 'ATTACHMENT':
        return [];
      default:
        return allObservables;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Filter Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 overflow-x-auto">
          {[
            { key: 'ALL', label: `All IOCs (${allObservables.length})` },
            { key: 'URL', label: `URLs (${urls.length})` },
            { key: 'IP', label: `IPs (${ips.length})` },
            { key: 'DOMAIN', label: `Domains (${domains.length})` },
            { key: 'ATTACHMENT', label: `Attachments (${(attachments || []).length})` },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeTab === tab.key
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <button
          onClick={handleExportIOCs}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono transition"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span>Export IOC List (TXT)</span>
        </button>
      </div>

      {/* Attachments Section if Selected */}
      {activeTab === 'ATTACHMENT' && (
        <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
          <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40 flex items-center gap-2">
            <Paperclip className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Extracted Email Attachments & Cryptographic Hashes
            </h3>
          </div>
          {(!attachments || attachments.length === 0) ? (
            <div className="p-8 text-center text-slate-400 font-mono text-xs">
              No binary attachments contained in this email.
            </div>
          ) : (
            <div className="divide-y divide-slate-800">
              {attachments.map((att, i) => (
                <div key={i} className="p-5 space-y-3 font-mono text-xs hover:bg-slate-800/20 transition">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-sm">{att.filename || `attachment_${i+1}`}</span>
                    <span className="text-slate-400">{att.size_bytes ? `${(att.size_bytes / 1024).toFixed(1)} KB` : 'N/A'}</span>
                  </div>
                  <div className="text-slate-400">MIME Type: <span className="text-slate-200">{att.content_type || 'application/octet-stream'}</span></div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-400">MD5: {att.md5 || 'N/A'}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-400 truncate">SHA-256: {att.sha256 || 'N/A'}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Main IOC Observables Table */}
      {activeTab !== 'ATTACHMENT' && (
        <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Type</th>
                  <th className="px-5 py-3">Defanged Safe Indicator (IOC)</th>
                  <th className="px-5 py-3">Provenance Source</th>
                  <th className="px-5 py-3">Safety Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {getFilteredItems().map((obs, i) => (
                  <tr key={i} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                        {obs.type}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <DefangedIndicator
                        value={obs.value}
                        defangedValue={obs.defanged_value}
                        type={obs.type}
                        className="text-slate-200"
                      />
                    </td>
                    <td className="px-5 py-3 text-slate-400 text-[11px]">
                      {obs.source || 'EMAIL_EXTRACTION'}
                    </td>
                    <td className="px-5 py-3">
                      <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400">
                        <Check className="w-3 h-3" />
                        DEFANGED
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
