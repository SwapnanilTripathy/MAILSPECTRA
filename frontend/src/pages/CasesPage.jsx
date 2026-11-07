import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderGit2,
  Search,
  Filter,
  PlusCircle,
  FileDown,
  Clock,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ChevronRight,
  MoreVertical,
  CheckCircle2,
} from 'lucide-react';
import api from '../api/client';
import SeverityBadge from '../components/common/SeverityBadge';
import DefangedIndicator from '../components/common/DefangedIndicator';

export default function CasesPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [submittedSearch, setSubmittedSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const pageSize = 50;
  const [statusFilter, setStatusFilter] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('');
  const [selectedCase, setSelectedCase] = useState(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [newStatus, setNewStatus] = useState('RESOLVED');
  const [statusComment, setStatusComment] = useState('');

  useEffect(() => {
    fetchCases();
  }, [statusFilter, classificationFilter, submittedSearch, offset]);

  const fetchCases = async () => {
    setLoading(true);
    setError('');
    try {
      const params = { limit: pageSize, offset };
      if (statusFilter) params.status = statusFilter;
      if (classificationFilter) params.classification = classificationFilter;
      if (submittedSearch) params.search = submittedSearch;

      const res = await api.listCases(params);
      setCases(res?.items || []);
      setTotal(res?.total || 0);
    } catch (err) {
      setError('Unable to load cases. Check the connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    if (offset === 0 && submittedSearch === search) fetchCases();
    else {
      setOffset(0);
      setSubmittedSearch(search);
    }
  };

  const handleUpdateStatus = async () => {
    if (!selectedCase) return;
    setUpdatingStatus(true);
    try {
      await api.updateCaseStatus(selectedCase.case_id, {
        status: newStatus,
        comment: statusComment,
        actor: 'SOC Analyst',
      });
      setSelectedCase(null);
      fetchCases();
    } catch (err) {
      alert(`Update error: ${err.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleExportPDF = async (caseId) => {
    try {
      await api.generateReport(caseId);
      await api.downloadReport(caseId);
    } catch (err) {
      alert(`Report error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl lg:text-2xl font-bold font-mono text-white flex items-center gap-2">
            <FolderGit2 className="w-6 h-6 text-cyan-400" />
            SOC Case Management & Chain of Custody
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Preserved email forensic cases with SHA-256 evidence tracking and
            investigation lifecycle.
          </p>
        </div>

        <button
          onClick={() => navigate('/investigate')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-lg shadow-cyan-600/20 transition self-start sm:self-auto"
        >
          <PlusCircle className="w-4 h-4" />
          <span>New Investigation</span>
        </button>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="p-4 rounded-xl bg-[#111827] border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
        <form
          onSubmit={handleSearchSubmit}
          className="flex-1 w-full flex items-center gap-2"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by Case ID, Subject, Sender address, or SHA-256..."
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-200 transition"
          >
            Filter
          </button>
        </form>

        <div className="flex items-center gap-3 w-full md:w-auto justify-end">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setOffset(0);
              setStatusFilter(e.target.value);
            }}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="ARCHIVED">ARCHIVED</option>
          </select>

          {/* Classification Filter */}
          <select
            value={classificationFilter}
            onChange={(e) => {
              setOffset(0);
              setClassificationFilter(e.target.value);
            }}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Threat Classes</option>
            <option value="PHISHING">PHISHING</option>
            <option value="BUSINESS_EMAIL_COMPROMISE">BEC</option>
            <option value="IMPERSONATION">IMPERSONATION</option>
            <option value="FRAUD">FRAUD</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="LEGITIMATE">LEGITIMATE</option>
          </select>
        </div>
      </div>

      {/* Cases Table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
            <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
            <span>Loading investigation cases from database...</span>
          </div>
        ) : error ? (
          <div role="alert" className="p-8 text-center text-amber-300 text-sm">
            {error}{' '}
            <button onClick={fetchCases} className="text-cyan-300 underline">
              Retry
            </button>
          </div>
        ) : cases.length === 0 ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs space-y-2">
            <FolderGit2 className="w-8 h-8 mx-auto text-slate-600" />
            <p>No investigation cases found matching the specified filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Case ID</th>
                  <th className="px-5 py-3">Email Subject / Artifact</th>
                  <th className="px-5 py-3">Threat Classification</th>
                  <th className="px-5 py-3">Risk Score</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Created</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {cases.map((c) => (
                  <tr
                    key={c.case_id}
                    className="hover:bg-slate-800/30 transition"
                  >
                    <td className="px-5 py-3.5 font-bold text-cyan-400">
                      <button
                        onClick={() => navigate(`/cases/${c.case_id}`)}
                        className="hover:underline text-left"
                      >
                        {c.case_id}
                      </button>
                    </td>
                    <td className="px-5 py-3.5 max-w-xs">
                      <p
                        className="text-slate-200 font-sans truncate font-medium"
                        title={c.subject}
                      >
                        {c.subject || c.filename}
                      </p>
                      <p className="text-slate-400 text-[11px] truncate mt-0.5">
                        {c.from_address || 'N/A'}
                      </p>
                    </td>
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={c.classification} size="sm" />
                    </td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`font-bold ${c.risk_score >= 60 ? 'text-red-400' : c.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}
                      >
                        {c.risk_score}/100
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <button
                        onClick={() => {
                          setSelectedCase(c);
                          setNewStatus(c.status);
                        }}
                        className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                      >
                        {c.status}
                      </button>
                    </td>
                    <td className="px-5 py-3.5 text-slate-400 text-[11px]">
                      {c.created_at ? c.created_at.substring(0, 10) : 'N/A'}
                    </td>
                    <td className="px-5 py-3.5 text-right space-x-2">
                      <button
                        onClick={() => navigate(`/cases/${c.case_id}`)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] transition"
                      >
                        Inspect
                      </button>
                      <button
                        onClick={() => handleExportPDF(c.case_id)}
                        className="p-1 rounded bg-slate-800 hover:bg-cyan-600/30 text-slate-300 hover:text-cyan-300 text-[11px] transition"
                        title="Download PDF Forensic Report"
                      >
                        <FileDown className="w-3.5 h-3.5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
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

      {/* Case Status Modal */}
      {selectedCase && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[#111827] border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4 font-mono">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-bold text-white uppercase">
                Update Case Lifecycle
              </h3>
              <button
                onClick={() => setSelectedCase(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="text-xs space-y-3">
              <div>
                <span className="text-slate-400 block mb-1">
                  Target Case ID:
                </span>
                <span className="text-cyan-400 font-bold">
                  {selectedCase.case_id}
                </span>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">
                  Investigation Status:
                </label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:border-cyan-500"
                >
                  <option value="OPEN">OPEN (Triage Queue)</option>
                  <option value="INVESTIGATING">
                    INVESTIGATING (In Progress)
                  </option>
                  <option value="RESOLVED">
                    RESOLVED (Threat Contained / Remediated)
                  </option>
                  <option value="ARCHIVED">
                    ARCHIVED (Evidence Preserved)
                  </option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">
                  Analyst Notes / Triage Justification:
                </label>
                <textarea
                  value={statusComment}
                  onChange={(e) => setStatusComment(e.target.value)}
                  placeholder="e.g., Domain blocked on edge firewall, user password reset issued."
                  rows={3}
                  className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:border-cyan-500 font-sans text-xs"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedCase(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleUpdateStatus}
                disabled={updatingStatus}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 disabled:opacity-50"
              >
                {updatingStatus ? 'Updating...' : 'Save Lifecycle Status'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
