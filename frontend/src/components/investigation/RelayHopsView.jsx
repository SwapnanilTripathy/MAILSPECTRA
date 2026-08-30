import React from 'react';
import { Server, ArrowDown, Clock, ShieldCheck, ShieldAlert, Globe, Radio, ExternalLink } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

export default function RelayHopsView({ relayPath, originAssessment }) {
  const hops = relayPath?.hops || [];
  const totalHops = relayPath?.total_hops || hops.length;
  const originIP = originAssessment?.earliest_reliable_ip || relayPath?.origin_ip;

  if (hops.length === 0) {
    return (
      <div className="p-8 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400 font-mono text-sm">
        No Received header relay hops detected or parsed in this email artifact.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Origin Assessment Callout */}
      {originAssessment && (
        <div className="p-5 rounded-xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-900 border border-cyan-500/30 shadow-lg">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">CHRONOLOGICAL ORIGIN ASSESSMENT</span>
                <h3 className="text-lg font-bold text-white font-mono mt-0.5">
                  Earliest Observable Gateway: {originIP || 'UNKNOWN'}
                </h3>
              </div>
            </div>
            <div className="text-right">
              <span className="text-[10px] font-mono uppercase text-slate-400 block">CONFIDENCE</span>
              <span className="text-sm font-bold font-mono text-cyan-400">
                {Math.round((originAssessment.confidence || 0.8) * 100)}%
              </span>
            </div>
          </div>
          <p className="mt-3 text-xs text-slate-300 leading-relaxed">
            {originAssessment.evidentiary_basis || 'Determined by traversing the MTA Received: header chain in chronological sequence from the initial client submission hop.'}
          </p>
          {originAssessment.limitations && (
            <div className="mt-2 text-[11px] font-mono text-amber-400/90 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              Forensic Note: {originAssessment.limitations}
            </div>
          )}
        </div>
      )}

      {/* Relay Hops Timeline */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 p-6 shadow-xl">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-6">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              MTA Relay Path Reconstruction ({totalHops} Hops Traversed)
            </h4>
          </div>
          <span className="text-xs font-mono text-slate-400">Chronological Order (Hop 1 = Origin)</span>
        </div>

        <div className="relative pl-6 space-y-8 before:absolute before:left-[17px] before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-blue-500 before:to-slate-700">
          {hops.map((hop, index) => {
            const isOrigin = hop.hop_number === 1 || hop.ip === originIP;
            const isDestination = index === hops.length - 1;
            const hasAnomaly = hop.anomalies && hop.anomalies.length > 0;

            return (
              <div key={index} className="relative group">
                {/* Timeline node icon */}
                <div
                  className={`absolute -left-[30px] top-1.5 w-6 h-6 rounded-full border-2 flex items-center justify-center text-[10px] font-mono font-bold shadow-md ${
                    isOrigin
                      ? 'bg-cyan-500 border-cyan-300 text-black shadow-cyan-500/50 ring-4 ring-cyan-500/20'
                      : isDestination
                      ? 'bg-emerald-500 border-emerald-300 text-black'
                      : hasAnomaly
                      ? 'bg-red-500 border-red-300 text-white'
                      : 'bg-slate-800 border-slate-600 text-slate-300'
                  }`}
                >
                  {hop.hop_number || index + 1}
                </div>

                {/* Hop Card */}
                <div
                  className={`p-4 rounded-xl border transition-all ${
                    isOrigin
                      ? 'bg-cyan-950/20 border-cyan-500/40 shadow-lg shadow-cyan-950/30'
                      : hasAnomaly
                      ? 'bg-red-950/20 border-red-500/30'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-white">
                        HOP #{hop.hop_number || index + 1}
                      </span>
                      {isOrigin && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                          CLIENT SUBMISSION / ORIGIN
                        </span>
                      )}
                      {isDestination && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          FINAL MX INBOX
                        </span>
                      )}
                      {hop.is_private && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                          RFC1918 PRIVATE IP
                        </span>
                      )}
                    </div>

                    {hop.delay_seconds !== undefined && hop.delay_seconds !== null && (
                      <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        <span>Transit Delay: <strong className="text-slate-200">{hop.delay_seconds}s</strong></span>
                      </div>
                    )}
                  </div>

                  {/* Hop Details Grid */}
                  <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="space-y-1">
                      <div className="text-slate-400">
                        From Host: <span className="text-slate-200 font-semibold">{hop.from_host || 'N/A'}</span>
                      </div>
                      <div className="text-slate-400 flex items-center gap-1.5">
                        Relaying IP:
                        {hop.ip ? (
                          <DefangedIndicator value={hop.ip} type="IP" />
                        ) : (
                          <span className="text-slate-500">Unspecified</span>
                        )}
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="text-slate-400">
                        By Receiver: <span className="text-slate-200">{hop.by_host || 'N/A'}</span>
                      </div>
                      <div className="text-slate-400">
                        Protocol: <span className="text-cyan-300">{hop.protocol || hop.with_protocol || 'ESMTP'}</span>
                        {hop.tls_version && <span className="ml-2 text-emerald-400">({hop.tls_version})</span>}
                      </div>
                    </div>
                  </div>

                  {/* Timestamp & Auth */}
                  <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                    <div>
                      Timestamp: <span className="text-slate-300">{hop.timestamp || hop.date_raw || 'N/A'}</span>
                    </div>
                    {hop.auth_status && (
                      <div className="flex items-center gap-1 text-emerald-400">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Auth: {hop.auth_status}</span>
                      </div>
                    )}
                  </div>

                  {/* Hop Anomalies if any */}
                  {hasAnomaly && (
                    <div className="mt-2.5 p-2 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs font-mono flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                      <span>{hop.anomalies.join('; ')}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
