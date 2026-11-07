import React from 'react';
import { Network, ShieldAlert, GitBranch, Database, CheckCircle2, AlertCircle, Info, ChevronRight } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

export default function CampaignAttributionView({ activeCampaign, campaignCorrelations, attributionSupport }) {
  const correlations = campaignCorrelations || [];
  const hypothesis = attributionSupport?.assessment || 'INSUFFICIENT_EVIDENCE';
  const confidence = attributionSupport?.confidence ?? 0;

  const hypothesisColors = {
    DIRECT_MALICIOUS_INFRASTRUCTURE: 'bg-red-500/20 text-red-300 border-red-500/40',
    SPOOFED_IDENTITY: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    SHARED_CAMPAIGN_INFRASTRUCTURE: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    LIKELY_COMPROMISED_ACCOUNT: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    ANONYMIZED_INFRASTRUCTURE: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
    LEGITIMATE_AUTHENTICATED_SENDER: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    INSUFFICIENT_EVIDENCE: 'bg-slate-700/30 text-slate-300 border-slate-600/40',
  };

  return (
    <div className="space-y-6">
      {/* Attribution Support Engine Card */}
      <div className="p-6 rounded-xl bg-gradient-to-br from-slate-900 via-[#111827] to-[#111827] border border-slate-800 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                FORENSIC ATTRIBUTION SUPPORT ENGINE
              </span>
              <div className="mt-1 flex items-center gap-3">
                <span className={`px-3 py-1 rounded-lg text-sm font-bold font-mono border ${hypothesisColors[hypothesis] || hypothesisColors.INSUFFICIENT_EVIDENCE}`}>
                  {hypothesis.replace(/_/g, ' ')}
                </span>
              </div>
            </div>
          </div>

          <div className="sm:text-right">
            <span className="text-[10px] font-mono uppercase text-slate-400 block">RULE SUPPORT (NOT PROBABILITY)</span>
            <span className="text-2xl font-extrabold font-mono text-cyan-400">
              {Math.round(confidence * 100)}%
            </span>
          </div>
        </div>

        {/* Evidentiary Basis */}
        <div className="mt-5 p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <h5 className="text-xs font-mono font-semibold text-slate-300 uppercase">Technical Evidentiary Basis</h5>
          <p className="mt-2 text-xs text-slate-300 leading-relaxed font-sans">
            {attributionSupport?.technical_justification ||
              attributionSupport?.evidentiary_basis ||
              'Attribution hypothesis formulated via cross-correlation of SPF/DKIM authentication state, relay origin IP provenance, domain registration age, and shared infrastructure indicators.'}
          </p>
        </div>

        {/* Forensic Limitations */}
        {attributionSupport?.limitations && (
          <div className="mt-3 text-[11px] font-mono text-amber-400/90 flex items-start gap-2">
            <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            <span>Forensic Disclaimer: {attributionSupport.limitations}</span>
          </div>
        )}
      </div>

      {/* Dynamic Campaign Cluster Entity */}
      {activeCampaign && (
        <div className="rounded-xl bg-[#111827] border border-cyan-500/30 overflow-hidden shadow-xl">
          <div className="px-5 py-4 border-b border-slate-800 bg-cyan-950/20 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <h4 className="text-xs font-mono uppercase tracking-wider text-white">
                Active Threat Campaign Cluster: {activeCampaign.name || activeCampaign.campaign_id}
              </h4>
            </div>
            <span className="px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              {activeCampaign.primary_threat_type || 'PHISHING'}
            </span>
          </div>

          <div className="p-5 space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <span className="text-slate-500 block text-[10px]">CAMPAIGN ID</span>
                <span className="text-slate-200 font-semibold">{activeCampaign.campaign_id}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">MEMBER CASES</span>
                <span className="text-cyan-400 font-bold">{activeCampaign.member_count || (activeCampaign.member_case_ids || []).length} Cases</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">FIRST OBSERVED</span>
                <span className="text-slate-300">{activeCampaign.first_seen ? activeCampaign.first_seen.substring(0, 10) : 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">LAST OBSERVED</span>
                <span className="text-slate-300">{activeCampaign.last_seen ? activeCampaign.last_seen.substring(0, 10) : 'N/A'}</span>
              </div>
            </div>

            {/* Shared Infrastructure Summary */}
            {activeCampaign.shared_infrastructure && (
              <div className="pt-3 border-t border-slate-800">
                <span className="text-slate-400 text-xs font-semibold block mb-2">
                  Shared Observed Infrastructure In Cluster:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">SHARED IPS</span>
                    <span className="text-white font-bold">{(activeCampaign.shared_infrastructure.ips || []).length}</span>
                  </div>
                  <div className="p-3 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">SHARED DOMAINS</span>
                    <span className="text-white font-bold">{(activeCampaign.shared_infrastructure.domains || []).length}</span>
                  </div>
                  <div className="p-3 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">SHARED URL TARGETS</span>
                    <span className="text-white font-bold">{(activeCampaign.shared_infrastructure.urls || []).length}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Cross-Case Correlations Table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
        <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Cross-Case Database Infrastructure Correlations ({correlations.length})
            </h4>
          </div>
        </div>

        {correlations.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-xs">
            No cross-case infrastructure matches found in the historical threat database for this email.
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {correlations.map((corr, idx) => (
              <div key={idx} className="p-4 hover:bg-slate-800/30 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-cyan-400">{corr.related_case_id}</span>
                    <span className="text-slate-400">• Match Score: <strong className="text-slate-200">{Math.round((corr.correlation_score ?? 0) * 100)}%</strong></span>
                  </div>
                  <p className="text-slate-300 font-sans text-xs">
                    Linked via shared {corr.shared_type || 'infrastructure'}: <DefangedIndicator value={(corr.shared_indicators || []).join(', ')} />
                  </p>
                </div>
                <div className="text-slate-400 text-[11px] shrink-0">
                  Relationship: <span className="text-purple-400 font-bold">{corr.relationship || 'SHARED_INFRASTRUCTURE'}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
