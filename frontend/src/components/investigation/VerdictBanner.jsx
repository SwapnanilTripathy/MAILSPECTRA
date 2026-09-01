import React from 'react';
import { AlertTriangle, CheckCircle, ShieldAlert, FileDown, FolderPlus, Cpu } from 'lucide-react';
import SeverityBadge from '../common/SeverityBadge';

export default function VerdictBanner({ analysis, onSaveCase, onExportReport, isSaving = false, isExporting = false }) {
  if (!analysis) return null;

  const threatClass = analysis.risk_assessment?.classification || analysis.ai_inference?.predicted_class || analysis.threat_assessment?.classification || 'UNKNOWN';
  const riskScore = analysis.risk_assessment?.risk_score ?? analysis.threat_assessment?.risk_score ?? 0;
  const severity = analysis.risk_assessment?.severity || 'LOW';
  const confidence = analysis.risk_assessment?.model_confidence ?? analysis.ai_inference?.confidence ?? analysis.threat_assessment?.confidence ?? 1.0;
  const indicators = analysis.observed_evidence || analysis.risk_assessment?.indicators || [];

  const isThreat = riskScore >= 40 || (threatClass !== 'LEGITIMATE' && threatClass !== 'BENIGN');

  return (
    <div className="relative overflow-hidden rounded-2xl bg-[#111827] border border-slate-800 p-6 shadow-xl">
      {/* Background Accent Glow */}
      <div className={`absolute -right-16 -top-16 w-64 h-64 rounded-full blur-3xl opacity-20 pointer-events-none ${isThreat ? 'bg-red-500' : 'bg-emerald-500'}`} />

      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
        {/* Left Verdict Section */}
        <div className="flex items-start gap-4">
          <div className={`p-4 rounded-xl border ${isThreat ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'}`}>
            {isThreat ? <ShieldAlert className="w-8 h-8" /> : <CheckCircle className="w-8 h-8" />}
          </div>
          <div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono uppercase tracking-widest text-slate-400">THREAT VERDICT</span>
              <SeverityBadge severity={severity} size="sm" />
            </div>
            <h2 className="text-3xl font-bold font-mono tracking-tight text-white mt-1">
              {threatClass.replace(/_/g, ' ')}
            </h2>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Artifact: <span className="text-slate-200">{analysis.filename}</span> • Case Reference: <span className="text-cyan-400">{analysis.case_id}</span>
            </p>
          </div>
        </div>

        {/* Center Gauges (Risk & Confidence) */}
        <div className="flex items-center gap-8 w-full lg:w-auto justify-between lg:justify-start border-t lg:border-t-0 lg:border-l border-slate-800 pt-4 lg:pt-0 lg:pl-8">
          {/* Risk Score */}
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">RISK SCORE</div>
            <div className="flex items-baseline gap-1 mt-1">
              <span className={`text-4xl font-extrabold font-mono ${riskScore >= 70 ? 'text-red-400' : riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {riskScore}
              </span>
              <span className="text-slate-500 font-mono text-sm">/100</span>
            </div>
            <div className="w-28 h-2 bg-slate-800 rounded-full mt-2 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${riskScore >= 70 ? 'bg-red-500' : riskScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
              />
            </div>
          </div>

          {/* Model Confidence */}
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">AI CONFIDENCE</div>
            <div className="flex items-baseline gap-1 mt-1">
              <span className="text-3xl font-bold font-mono text-cyan-400">
                {Math.round(confidence * 100)}%
              </span>
            </div>
            <p className="text-[10px] text-slate-400 mt-2 font-mono">Multi-class L2 Model</p>
          </div>
        </div>

        {/* Right Actions */}
        <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto justify-end border-t lg:border-t-0 border-slate-800 pt-4 lg:pt-0">
          {onSaveCase && (
            <button
              onClick={onSaveCase}
              disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-xs font-medium transition shadow-md disabled:opacity-50"
            >
              <FolderPlus className="w-4 h-4 text-cyan-400" />
              <span>{isSaving ? 'Preserving...' : 'Save Case'}</span>
            </button>
          )}
          {onExportReport && (
            <button
              onClick={onExportReport}
              disabled={isExporting}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition shadow-lg shadow-cyan-600/20 disabled:opacity-50"
            >
              <FileDown className="w-4 h-4" />
              <span>{isExporting ? 'Generating...' : 'Export PDF Report'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Automated Security Alert Notification */}
      {analysis.security_alert && analysis.security_alert.requires_immediate_action && (
        <div className="mt-4 p-3 rounded-xl bg-red-950/40 border border-red-500/40 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
          <div className="text-xs font-mono">
            <span className="font-bold text-red-300 uppercase">
              HIGH-PRIORITY SECURITY ALERT DISPATCHED ({analysis.security_alert.alert_id}):
            </span>
            <span className="text-slate-300 ml-1.5">{analysis.security_alert.title}</span>
            {analysis.security_alert.recommended_actions && analysis.security_alert.recommended_actions.length > 0 && (
              <div className="text-[11px] text-amber-300/90 mt-1">
                Recommended Action: {analysis.security_alert.recommended_actions[0]}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Observed Indicators Pills */}
      {indicators.length > 0 && (
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400 mr-2 flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            Observed Signals ({indicators.length}):
          </span>
          {indicators.slice(0, 5).map((ind, i) => (
            <span
              key={i}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900/80 border border-slate-700/60 text-xs font-mono text-slate-300"
              title={ind.evidence || ind.description}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${ind.severity === 'CRITICAL' ? 'bg-red-400' : ind.severity === 'HIGH' ? 'bg-orange-400' : 'bg-amber-400'}`} />
              {(ind.indicator || ind.feature || '').replace(/_/g, ' ')}
            </span>
          ))}
          {indicators.length > 5 && (
            <span className="text-xs font-mono text-slate-400">+{indicators.length - 5} more</span>
          )}
        </div>
      )}
    </div>
  );
}

