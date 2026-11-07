import React from 'react';
import { MessageSquare, AlertTriangle, AlertCircle, ShieldAlert, CheckCircle2, FileText, Info } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export default function ContentIntelligenceView({ contentIntelligence, bodyContent }) {
  if (!contentIntelligence) {
    return (
      <div className="p-8 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400 font-mono text-xs">
        No content intelligence analysis data available for this email artifact.
      </div>
    );
  }

  const signals = contentIntelligence.signals || [];
  const categories = contentIntelligence.detected_categories || [];

  return (
    <div className="space-y-6">
      {/* Top Overview Banner */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-slate-900 via-[#111827] to-slate-900 border border-slate-800 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <MessageSquare className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold font-mono text-white">
              Deterministic NLP & Content Intelligence Engine
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {contentIntelligence.summary || 'Explainable lexical pattern matching and social engineering indicators.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-center">
            <span className="text-[10px] text-slate-400 block uppercase">SIGNALS DETECTED</span>
            <span className="text-sm font-bold text-cyan-400">{contentIntelligence.total_signals_detected || 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-center">
            <span className="text-[10px] text-slate-400 block uppercase">HIGHEST SEVERITY</span>
            <SeverityBadge severity={contentIntelligence.highest_severity || 'INFORMATIONAL'} size="sm" />
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-center">
            <span className="text-[10px] text-slate-400 block uppercase">RISK IMPACT</span>
            <span className="text-sm font-bold text-amber-400">+{contentIntelligence.risk_score_contribution || 0} pts</span>
          </div>
        </div>
      </div>

      {/* Signals Grid */}
      {signals.length === 0 ? (
        <div className="p-8 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400 font-mono text-xs flex flex-col items-center gap-2">
          <CheckCircle2 className="w-6 h-6 text-emerald-400" />
          <span>No social engineering, urgency, or credential manipulation cues detected in text.</span>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Extracted Explainable Content Signals ({signals.length})</span>
            </h3>
            <div className="flex items-center gap-1 text-[11px] font-mono text-slate-400">
              <span>Categories:</span>
              <span className="text-slate-300">{categories.join(', ')}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {signals.map((sig, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-[#111827] border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-3"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/20">
                        {sig.category}
                      </span>
                      <h4 className="text-sm font-bold text-white font-mono mt-1.5">{sig.label}</h4>
                    </div>
                    <SeverityBadge severity={sig.severity} size="sm" />
                  </div>

                  <p className="text-xs text-slate-300 mt-2 font-sans leading-relaxed">
                    {sig.explanation}
                  </p>
                </div>

                {sig.evidence_snippet && (
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300">
                    <span className="text-[10px] text-slate-400 uppercase block mb-0.5">CONTEXT SNIPPET:</span>
                    <span className="text-amber-300/90 italic">"{sig.evidence_snippet}"</span>
                  </div>
                )}

                {sig.matches && sig.matches.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1 pt-1">
                    <span className="text-[10px] font-mono text-slate-400 mr-1">Matched cues:</span>
                    {sig.matches.slice(0, 4).map((m, mIdx) => (
                      <span
                        key={mIdx}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Extracted Body Preview */}
      {bodyContent && (bodyContent.text_plain || bodyContent.text_html) && (
        <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
          <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-400">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Decoded Plain-Text Body Stream</span>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Length: {bodyContent.text_plain_length || bodyContent.text_plain?.length || 0} characters
            </span>
          </div>
          <div className="p-5 font-mono text-xs text-slate-300 max-h-60 overflow-y-auto whitespace-pre-wrap selection:bg-cyan-500/30">
            {bodyContent.text_plain || "(HTML-only payload; clean text rendered from HTML DOM structure)"}
          </div>
        </div>
      )}
    </div>
  );
}
