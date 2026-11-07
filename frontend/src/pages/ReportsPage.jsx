import { useMasked } from '../context/PrivacyContext';
import React, { useState, useEffect } from 'react';
import {
  FileText,
  FileDown,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Hash,
  ExternalLink,
} from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/common/SeverityBadge';

export default function ReportsPage() {
  const [rawcases, setCases] = useState([]);
  const cases = useMasked(rawcases);
  const [loading, setLoading] = useState(true);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const pageSize = 50;
  const [verifyingId, setVerifyingId] = useState(null);
  const [verificationModalData, setVerificationModalData] = useState(null);

  useEffect(() => {
    fetchReports();
  }, [offset]);

  const fetchReports = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.listCases({ limit: pageSize, offset });
      setCases(res?.items || []);
      setTotal(res?.total || 0);
    } catch (err) {
      setError('Unable to load reports. Check the connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (caseId) => {
    setVerifyingId(caseId);
    try {
      const res = await api.verifyReport(caseId);
      setVerificationModalData(res);
    } catch (err) {
      alert(`Verification error: ${err.message}`);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleGenerate = async (caseId) => {
    try {
      await api.generateReport(caseId);
      fetchReports();
      await api.downloadReport(caseId);
    } catch (err) {
      alert(`Report error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl lg:text-2xl font-bold font-mono text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            Forensic Report Repository & Evidence Vault
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Evidence-preserving PDF forensic intelligence reports with
            cryptographic SHA-256 integrity verification.
          </p>
        </div>

        <button
          onClick={fetchReports}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-mono transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Vault</span>
        </button>
      </div>

      {/* Reports Table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
            <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
            <span>Loading forensic reports repository...</span>
          </div>
        ) : error ? (
          <div role="alert" className="p-8 text-center text-amber-300 text-sm">
            {error}{' '}
            <button onClick={fetchReports} className="text-cyan-300 underline">
              Retry
            </button>
          </div>
        ) : cases.length === 0 ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs space-y-2">
            <FileText className="w-8 h-8 mx-auto text-slate-600" />
            <p>No investigation cases available to generate reports from.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Case ID</th>
                  <th className="px-5 py-3">Email Subject / Artifact</th>
                  <th className="px-5 py-3">Threat Classification</th>
                  <th className="px-5 py-3">Report SHA-256 Fingerprint</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {cases.map((c) => {
                  const hasReport = Boolean(c.report_sha256);
                  return (
                    <tr
                      key={c.case_id}
                      className="hover:bg-slate-800/30 transition"
                    >
                      <td className="px-5 py-3.5 font-bold text-cyan-400">
                        {c.case_id}
                      </td>
                      <td
                        className="px-5 py-3.5 max-w-xs font-sans text-slate-200 truncate"
                        title={c.subject}
                      >
                        {c.subject || c.filename}
                      </td>
                      <td className="px-5 py-3.5">
                        <SeverityBadge severity={c.classification} size="sm" />
                      </td>
                      <td className="px-5 py-3.5 text-slate-300">
                        {hasReport ? (
                          <div className="flex items-center gap-2">
                            <span
                              className="truncate max-w-[140px] text-cyan-300"
                              title={c.report_sha256}
                            >
                              {c.report_sha256.substring(0, 16)}...
                            </span>
                            <button
                              onClick={() => handleVerify(c.case_id)}
                              disabled={verifyingId === c.case_id}
                              className="px-2 py-0.5 rounded text-[10px] bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition"
                            >
                              Verify
                            </button>
                          </div>
                        ) : (
                          <span className="text-slate-400 italic">
                            Not Generated Yet
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-3.5 text-right space-x-2">
                        {hasReport ? (
                          <button
                            onClick={() => api.downloadReport(c.case_id).catch(error => alert(error.message))}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded bg-cyan-700 hover:bg-cyan-800 text-white font-medium text-[11px] transition shadow-sm"
                          >
                            <FileDown className="w-3.5 h-3.5" />
                            <span>Download PDF</span>
                          </button>
                        ) : (
                          <button
                            onClick={() => handleGenerate(c.case_id)}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] transition"
                          >
                            <RefreshCw className="w-3 h-3" />
                            <span>Generate PDF</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {!loading && !error && total > pageSize && (
        <div className="flex items-center justify-between gap-4 text-sm text-slate-300">
          <span>
            Showing {offset + 1}–{Math.min(offset + pageSize, total)} of {total}
          </span>
          <div className="flex gap-2">
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
              className="px-3 py-2 rounded bg-slate-800 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              disabled={offset + pageSize >= total}
              onClick={() => setOffset(offset + pageSize)}
              className="px-3 py-2 rounded bg-slate-800 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Cryptographic Verification Modal */}
      {verificationModalData && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4 font-mono">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white uppercase">
                  Cryptographic Integrity Attestation
                </h3>
              </div>
              <button
                onClick={() => setVerificationModalData(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="text-xs space-y-3">
              <div>
                <span className="text-slate-400 block text-[10px]">
                  CASE IDENTIFIER:
                </span>
                <span className="text-cyan-400 font-bold">
                  {verificationModalData.case_id}
                </span>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px]">
                  STORED DATABASE HASH:
                </span>
                <span className="text-slate-200 break-all select-all">
                  {verificationModalData.stored_hash}
                </span>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px]">
                  RE-COMPUTED ON-DISK HASH:
                </span>
                <span className="text-slate-200 break-all select-all">
                  {verificationModalData.calculated_hash}
                </span>
              </div>

              <div
                className={`p-3 rounded-lg border flex items-center gap-2 ${
                  verificationModalData.integrity_verified
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-red-500/10 border-red-500/30 text-red-300'
                }`}
              >
                {verificationModalData.integrity_verified ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
                )}
                <span>
                  {verificationModalData.integrity_verified
                    ? 'EVIDENCE INTEGRITY INTACT: On-disk PDF bitstream SHA-256 hash matches database chain of custody record.'
                    : 'INTEGRITY MISMATCH: Hash does not match stored evidence record.'}
                </span>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setVerificationModalData(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
              >
                Close Attestation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
