import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FolderGit2,
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  FileDown,
  Clock,
  Search,
  UserCheck,
  Hash,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Activity,
  Layers,
} from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/common/SeverityBadge';
import DefangedIndicator from '../components/common/DefangedIndicator';

export default function CaseDetailPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const [caseData, setCaseData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [integrityStatus, setIntegrityStatus] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);

  useEffect(() => {
    fetchCase();
  }, [caseId]);

  const fetchCase = async () => {
    setLoading(true);
    try {
      const res = await api.getCaseDetail(caseId);
      setCaseData(res);
    } catch (err) {
      console.error('Failed to fetch case:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyReport(caseId);
      setIntegrityStatus(res);
    } catch (err) {
      setIntegrityStatus({ integrity_verified: false, status: err.message });
    } finally {
      setVerifying(false);
    }
  };

  const handleGenerateAndDownload = async () => {
    setGeneratingReport(true);
    try {
      await api.generateReport(caseId);
      window.open(api.getReportDownloadUrl(caseId), '_blank');
      fetchCase();
    } catch (err) {
      alert(`Report error: ${err.message}`);
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="p-16 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
        <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
        <span>Loading case evidence record...</span>
      </div>
    );
  }

  if (!caseData) {
    return (
      <div className="p-12 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400 font-mono text-sm space-y-4">
        <AlertTriangle className="w-8 h-8 mx-auto text-amber-400" />
        <p>Case '{caseId}' not found in the forensic registry.</p>
        <button
          onClick={() => navigate('/cases')}
          className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-mono"
        >
          Return to Cases
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Breadcrumb & Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <button
          onClick={() => navigate('/cases')}
          className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Case Management</span>
        </button>

        <div className="flex items-center gap-3">
          {caseData.full_analysis && Object.keys(caseData.full_analysis).length > 0 && (
            <button
              onClick={() => navigate('/investigate', { state: { initialAnalysis: caseData.full_analysis } })}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-400 text-xs font-semibold transition"
            >
              <Search className="w-4 h-4" />
              <span>Open in Investigation Workspace</span>
            </button>
          )}

          <button
            onClick={handleGenerateAndDownload}
            disabled={generatingReport}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 transition disabled:opacity-50"
          >
            <FileDown className="w-4 h-4" />
            <span>{generatingReport ? 'Generating PDF...' : 'Download PDF Report'}</span>
          </button>
        </div>
      </div>

      {/* Case Header Hero Card */}
      <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-cyan-400 font-bold">{caseData.case_id}</span>
              <SeverityBadge severity={caseData.classification} size="sm" />
              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-800 text-slate-300 border border-slate-700">
                STATUS: {caseData.status}
              </span>
            </div>
            <h1 className="text-2xl font-bold font-mono text-white tracking-tight">
              {caseData.subject || caseData.filename}
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Sender: <span className="text-slate-200">{caseData.from_address || 'Unknown Sender'}</span> • Created: <span className="text-slate-300">{caseData.created_at || 'N/A'}</span>
            </p>
          </div>

          <div className="flex items-center gap-8 border-t lg:border-t-0 lg:border-l border-slate-800 pt-4 lg:pt-0 lg:pl-8">
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-400 block">RISK SCORE</span>
              <span className={`text-3xl font-extrabold font-mono ${caseData.risk_score >= 60 ? 'text-red-400' : caseData.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {caseData.risk_score}/100
              </span>
            </div>
            <div>
              <span className="text-[10px] font-mono uppercase text-slate-400 block">ASSIGNED ANALYST</span>
              <span className="text-sm font-semibold font-mono text-slate-200 mt-1 block">
                {caseData.assigned_to || 'SOC Analyst'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Integrity & SHA-256 Chain of Custody Card */}
      <div className="p-5 rounded-xl bg-gradient-to-r from-slate-900 via-[#111827] to-[#111827] border border-cyan-500/30 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold font-mono text-white">
                Cryptographic Evidence Chain of Custody (SHA-256)
              </h3>
              <p className="text-xs text-slate-400 mt-0.5 font-sans">
                Cryptographic fingerprint guaranteeing evidence integrity verification and tamper detection.
              </p>

            </div>
          </div>

          <button
            onClick={handleVerifyIntegrity}
            disabled={verifying || !caseData.report_sha256}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-400 text-xs font-mono transition disabled:opacity-50"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>{verifying ? 'Verifying Integrity...' : 'Verify Cryptographic Hash'}</span>
          </button>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
            <span className="text-slate-500 text-[10px] block">ORIGINAL EML ARTIFACT SHA-256</span>
            <span className="text-slate-200 select-all break-all">{caseData.sha256 || 'Not Recorded'}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
            <span className="text-slate-500 text-[10px] block">GENERATED REPORT PDF SHA-256</span>
            <span className="text-cyan-400 select-all break-all">{caseData.report_sha256 || 'Generate report to compute hash'}</span>
          </div>
        </div>

        {integrityStatus && (
          <div
            className={`mt-4 p-3 rounded-lg border text-xs font-mono flex items-center gap-2 ${
              integrityStatus.integrity_verified
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-red-500/10 border-red-500/30 text-red-300'
            }`}
          >
            {integrityStatus.integrity_verified ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
            <span>
              {integrityStatus.integrity_verified
                ? 'CRYPTOGRAPHIC INTEGRITY VERIFIED: PDF hash matches on-disk SHA-256 fingerprint exactly (Zero Tampering Detected).'
                : `INTEGRITY CHECK ALERT: ${integrityStatus.status}`}
            </span>
          </div>
        )}
      </div>

      {/* 2-Column Grid: Timeline & Observables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Case Timeline */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 p-5 shadow-xl">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-xs font-mono uppercase tracking-wider text-slate-300">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Investigation Chronological Timeline</span>
          </div>

          <div className="mt-4 space-y-4 font-mono text-xs">
            {(!caseData.timeline_events || caseData.timeline_events.length === 0) ? (
              <p className="text-slate-500 italic">No timeline events recorded yet.</p>
            ) : (
              <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                {caseData.timeline_events.map((evt, i) => (
                  <div key={i} className="relative">
                    <span className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-[#111827]" />
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white">{evt.title}</span>
                        <span className="text-[10px] text-slate-500">{evt.timestamp ? evt.timestamp.substring(11, 19) : ''}</span>
                      </div>
                      <p className="text-slate-300 font-sans text-xs mt-1">{evt.description}</p>
                      <span className="text-[10px] text-slate-500 mt-1 block">Actor / Source: {evt.source}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Case Observables */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 p-5 shadow-xl">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-xs font-mono uppercase tracking-wider text-slate-300">
            <Hash className="w-4 h-4 text-cyan-400" />
            <span>Observed IOCs & Technical Artifacts ({(caseData.observables || []).length})</span>
          </div>

          <div className="mt-4 space-y-2 max-h-96 overflow-y-auto font-mono text-xs">
            {(!caseData.observables || caseData.observables.length === 0) ? (
              <p className="text-slate-500 italic">No discrete observables cataloged for this case.</p>
            ) : (
              caseData.observables.map((obs, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                      {obs.type}
                    </span>
                    <DefangedIndicator value={obs.value} defangedValue={obs.defanged_value} type={obs.type} />
                  </div>
                  <span className="text-[10px] text-slate-500">{obs.source}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
