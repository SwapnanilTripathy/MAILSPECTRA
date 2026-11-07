import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  UploadCloud,
  FileCode,
  Sparkles,
  Shield,
  Layers,
  Globe2,
  Database,
  Network,
  Cpu,
  Search,
  CheckCircle2,
  AlertCircle,
  FileText,
  Radio,
  FileDown,
  FolderPlus,
  MessageSquare,
  Eye,
  EyeOff,
} from 'lucide-react';
import api from '../api/client';
import { DEMO_SAMPLE_FILES } from '../demoSamples';
import { maskAnalysis } from '../utils/privacy';
import { usePrivacy } from '../context/PrivacyContext';
import VerdictBanner from '../components/investigation/VerdictBanner';
import HeadersForensicsView from '../components/investigation/HeadersForensicsView';
import RelayHopsView from '../components/investigation/RelayHopsView';
import GeoIntelligenceView from '../components/investigation/GeoIntelligenceView';
import DnsRdapView from '../components/investigation/DnsRdapView';
import ThreatGraphView from '../components/investigation/ThreatGraphView';
import ShapExplainerView from '../components/investigation/ShapExplainerView';
import ObservablesView from '../components/investigation/ObservablesView';
import CampaignAttributionView from '../components/investigation/CampaignAttributionView';
import ContentIntelligenceView from '../components/investigation/ContentIntelligenceView';

export default function InvestigatePage() {
  const location = useLocation();
  const [analysis, setAnalysis] = useState(
    location.state?.initialAnalysis || null,
  );
  const [activeTab, setActiveTab] = useState('summary');
  const [loading, setLoading] = useState(false);
  const [rawText, setRawText] = useState('');
  const [inputMode, setInputMode] = useState('file'); // 'file' | 'raw'
  const { masked: maskPii, setMasked: setMaskPii } = usePrivacy();
  const [isSaving, setIsSaving] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [alertMessage, setAlertMessage] = useState(null);

  useEffect(() => {
    if (location.state?.initialAnalysis) {
      setAnalysis(location.state.initialAnalysis);
    }
  }, [location.state]);

  const handleFileUpload = async (file) => {
    if (!file) return;
    setLoading(true);
    setAlertMessage(null);
    try {
      const res = await api.analyzeEmailFile(file);
      setAnalysis(res);
      setActiveTab('summary');
    } catch (err) {
      setAlertMessage({
        type: 'error',
        text: err.message || 'Analysis failed.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRawAnalyze = async () => {
    if (!rawText.trim()) return;
    setLoading(true);
    setAlertMessage(null);
    try {
      const res = await api.analyzeRawEmail(rawText, 'raw_investigation.eml');
      setAnalysis(res);
      setActiveTab('summary');
    } catch (err) {
      setAlertMessage({
        type: 'error',
        text: err.message || 'Analysis failed.',
      });
    } finally {
      setLoading(false);
    }
  };

  /** Load and analyze the canonical bundled synthetic email for a Quick Demo. */
  const loadSample = async (sampleType) => {
    const sampleFilename = DEMO_SAMPLE_FILES[sampleType];
    if (!sampleFilename) {
      setAlertMessage({ type: 'error', text: 'Unknown demonstration sample.' });
      return;
    }

    setLoading(true);
    setAlertMessage(null);
    try {
      // The Quick Demo buttons and downloadable sample files use the same
      // committed .eml artifacts so the walkthrough stays reproducible.
      const sampleUrl = `${import.meta.env.BASE_URL}demo-samples/${sampleFilename}`;
      const response = await fetch(sampleUrl, {
        headers: { Accept: 'message/rfc822, text/plain' },
        cache: 'no-store',
      });
      if (!response.ok) {
        throw new Error(`Could not load bundled sample (${response.status}).`);
      }

      const sampleContent = await response.text();
      if (!sampleContent.trim()) {
        throw new Error('The bundled demonstration email is empty.');
      }

      const res = await api.analyzeRawEmail(sampleContent, sampleFilename);
      setAnalysis(res);
      setActiveTab('summary');
      setAlertMessage({
        type: 'success',
        text: `Loaded and analyzed bundled sample: ${sampleType.toUpperCase()}`,
      });
    } catch (err) {
      setAlertMessage({
        type: 'error',
        text: err.message || 'Could not load the demonstration sample.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveCase = async () => {
    if (!analysis) return;
    setIsSaving(true);
    try {
      const saveResult = analysis.privacy_redaction_applied
        ? { status: 'EXISTS' }
        : await api.createCase({
            case_id: analysis.case_id,
            filename: analysis.filename,
            subject:
              (analysis.metadata || analysis.email_metadata)?.subject || '',
            from_address:
              (analysis.metadata || analysis.email_metadata)?.from_sender
                ?.address || '',
            sender_domain:
              (analysis.metadata || analysis.email_metadata)?.from_sender
                ?.domain || '',
            origin_ip:
              analysis.origin_assessment?.earliest_reliable_ip ||
              analysis.relay_path?.origin_ip,
            classification:
              analysis.risk_assessment?.classification ||
              analysis.ai_inference?.predicted_class ||
              'UNKNOWN',
            risk_score: analysis.risk_assessment?.risk_score || 0.0,
            confidence: analysis.risk_assessment?.model_confidence || 1.0,
            status: 'INVESTIGATING',
            priority:
              (analysis.risk_assessment?.risk_score || 0) >= 60
                ? 'HIGH'
                : 'MEDIUM',
            sha256:
              (analysis.evidence_hashes || analysis.evidence_provenance)
                ?.sha256 || '',
            full_analysis: analysis,
          });
      if (saveResult.status === 'EXISTS') {
        const stored = await api.getCaseDetail(analysis.case_id);
        if (
          !stored.full_analysis?.metadata ||
          !stored.full_analysis?.evidence_hashes
        ) {
          throw new Error(
            'This existing case has an incomplete analysis. Re-analyze the original email to create a complete record.',
          );
        }
      }
      setAlertMessage({
        type: 'success',
        text:
          saveResult.status === 'EXISTS'
            ? `Case ${analysis.case_id} already exists; its stored record was retained.`
            : `Case ${analysis.case_id} preserved in investigation database!`,
      });
      return true;
    } catch (err) {
      setAlertMessage({ type: 'error', text: `Save error: ${err.message}` });
      return false;
    } finally {
      setIsSaving(false);
    }
  };

  const handleExportReport = async () => {
    if (!analysis) return;
    setIsExporting(true);
    try {
      // First ensure case is saved so report generator has records
      if (!(await handleSaveCase())) return;
      const reportRes = await api.generateReport(analysis.case_id, maskPii);
      await api.downloadReport(analysis.case_id);
      setAlertMessage({
        type: 'success',
        text: `Forensic PDF report generated (SHA-256: ${reportRes.sha256.substring(0, 16)}...)`,
      });
    } catch (err) {
      setAlertMessage({ type: 'error', text: `Report error: ${err.message}` });
    } finally {
      setIsExporting(false);
    }
  };

  const displayAnalysis = maskPii ? maskAnalysis(analysis) : analysis;
  const observables = displayAnalysis?.observables ||
    displayAnalysis?.extracted_observables || [
      ...(displayAnalysis?.urls || []).map((url) => ({
        type: 'URL',
        value: url.url,
        defanged_value: url.defanged_url,
        source: url.source,
      })),
      ...(displayAnalysis?.ips || []).map((ip) => ({
        type: 'IP',
        value: ip.ip,
        defanged_value: ip.defanged_ip,
        source: ip.source,
      })),
    ];

  const tabs = [
    { id: 'evidence', label: 'Evidence Manifest', icon: FileText },
    { id: 'summary', label: 'Executive Summary & Headers', icon: FileText },
    { id: 'nlp', label: 'NLP Content Signals', icon: MessageSquare },
    { id: 'relay', label: 'Relay Path & Transit', icon: Radio },
    { id: 'geo', label: 'GeoIP & Cartography', icon: Globe2 },
    { id: 'dns', label: 'Safe DNS & RDAP', icon: Database },
    { id: 'graph', label: 'Threat Graph (NetworkX)', icon: Network },
    { id: 'shap', label: 'Explainable AI (SHAP)', icon: Cpu },
    { id: 'observables', label: 'Defanged IOCs', icon: Shield },
    { id: 'campaign', label: 'Campaign & Attribution', icon: Layers },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Alert banner if message */}
      {alertMessage && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between text-xs font-mono transition ${
            alertMessage.type === 'error'
              ? 'bg-red-500/10 border-red-500/30 text-red-300'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {alertMessage.type === 'error' ? (
              <AlertCircle className="w-4 h-4 text-red-400" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
            <span>{alertMessage.text}</span>
          </div>
          <button
            onClick={() => setAlertMessage(null)}
            className="text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Artifact Input Controls */}
      <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-lg font-bold text-white font-mono flex items-center gap-2">
              <Search className="w-5 h-5 text-cyan-400" />
              Forensic Artifact Ingestion
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Upload raw .EML / .MSG or paste RFC 822 MIME headers for automated
              forensic deconstruction.
            </p>
          </div>

          {/* Quick Demo Pre-loaders & Privacy Toggle */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setMaskPii(!maskPii)}
              aria-pressed={maskPii}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg border text-xs font-mono transition ${
                maskPii
                  ? 'bg-indigo-500/20 border-indigo-500/50 text-indigo-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
              title="Toggle PII Masking in presentation view"
            >
              {maskPii ? (
                <EyeOff className="w-3.5 h-3.5 text-indigo-400" />
              ) : (
                <Eye className="w-3.5 h-3.5 text-slate-400" />
              )}
              <span>PII Masking: {maskPii ? 'ON' : 'OFF'}</span>
            </button>

            <span className="text-xs font-mono text-slate-400 mr-1">
              Quick Demos:
            </span>
            <button
              onClick={() => loadSample('phishing')}
              disabled={loading}
              className="px-2.5 py-1 rounded bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-300 text-xs font-mono transition"
            >
              Phishing
            </button>
            <button
              onClick={() => loadSample('benign')}
              disabled={loading}
              className="px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-mono transition"
            >
              Benign
            </button>
            <button
              onClick={() => loadSample('spoofed')}
              disabled={loading}
              className="px-2.5 py-1 rounded bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs font-mono transition"
            >
              Spoofed BEC
            </button>
          </div>
        </div>

        {maskPii && (
          <p className="text-xs text-slate-300">
            Masking applies to displayed results; the source input may still
            contain sensitive data.
          </p>
        )}

        {/* Input Toggle & Upload Area */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <button
            onClick={() => setInputMode('file')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
              inputMode === 'file'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            File Upload (.EML)
          </button>
          <button
            onClick={() => setInputMode('raw')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
              inputMode === 'raw'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Paste RFC 822 Raw MIME
          </button>
        </div>

        {inputMode === 'file' ? (
          <label
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              if (!loading) handleFileUpload(event.dataTransfer.files?.[0]);
            }}
            className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer bg-slate-900/40 hover:bg-slate-900/60 focus-within:ring-2 focus-within:ring-cyan-300 transition group"
          >
            <UploadCloud className="w-10 h-10 text-slate-400 group-hover:text-cyan-400 transition" />
            <p className="mt-2 text-sm font-medium text-slate-300">
              Drag & Drop email artifact or{' '}
              <span className="text-cyan-400 underline">Browse Local File</span>
            </p>
            <p className="mt-1 text-xs text-slate-400 font-mono">
              Supports RFC 5322 .eml; Outlook .msg is unsupported
            </p>
            <input
              type="file"
              accept=".eml"
              onChange={async (event) => {
                const input = event.target;
                await handleFileUpload(input.files?.[0]);
                input.value = '';
              }}
              disabled={loading}
              className="sr-only"
            />
          </label>
        ) : (
          <div className="space-y-3">
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw email RFC 822 headers and body content here..."
              rows={6}
              className="w-full p-3 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 selection:bg-cyan-500/30"
            />
            <div className="flex justify-end">
              <button
                onClick={handleRawAnalyze}
                disabled={loading || !rawText.trim()}
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-800 text-white font-semibold text-xs shadow-lg shadow-cyan-600/20 transition disabled:opacity-50"
              >
                <Sparkles className="w-4 h-4" />
                <span>Execute Deep Forensic Pipeline</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Loading Progress State */}
      {loading && (
        <div className="p-12 rounded-2xl bg-[#111827] border border-slate-800 flex flex-col items-center justify-center space-y-4">
          <div className="w-12 h-12 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin" />
          <div className="text-center font-mono">
            <p className="text-sm font-bold text-white">
              DECONSTRUCTING EMAIL ARTIFACT...
            </p>
            <p className="text-xs text-slate-400 mt-1">
              Traversing MTA hops • Calculating Linear SHAP attributions •
              Building NetworkX Threat Graph
            </p>
          </div>
        </div>
      )}

      {/* Analysis Results View */}
      {displayAnalysis && !loading && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <VerdictBanner
            analysis={displayAnalysis}
            onSaveCase={handleSaveCase}
            onExportReport={handleExportReport}
            isSaving={isSaving}
            isExporting={isExporting}
          />

          {/* Navigation Sub-Tabs */}
          <div className="border-b border-slate-800 flex items-center gap-2 overflow-x-auto pb-1">
            {tabs.map((t) => {
              const Icon = t.icon;
              const isActive = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className={`flex items-center gap-2 px-4 py-2.5 border-b-2 text-xs font-mono font-semibold transition whitespace-nowrap ${
                    isActive
                      ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{t.label}</span>
                </button>
              );
            })}
          </div>

          {/* Tab Panes */}
          <div className="pt-2">
            {activeTab === 'evidence' && <section className="space-y-3"><h2 className="text-xl">Evidence manifest</h2><p>Original bytes and derived analysis are stored separately. Hash verification compares the current artifact with its stored digest.</p><pre className="whitespace-pre-wrap break-all text-xs">{JSON.stringify(displayAnalysis.evidence_manifest || { status: 'Unavailable for this legacy case' }, null, 2)}</pre></section>}
            {activeTab === 'summary' && (
              <div className="space-y-6">
                <HeadersForensicsView
                  metadata={
                    displayAnalysis.email_metadata || displayAnalysis.metadata
                  }
                  authentication={
                    displayAnalysis.authentication_results ||
                    displayAnalysis.authentication
                  }
                />
              </div>
            )}

            {activeTab === 'nlp' && (
              <div className="space-y-6">
                <ContentIntelligenceView
                  contentIntelligence={displayAnalysis.content_intelligence}
                  bodyContent={displayAnalysis.body}
                />
              </div>
            )}

            {activeTab === 'relay' && (
              <RelayHopsView
                relayPath={
                  displayAnalysis.relay_path || displayAnalysis.relay_chain
                }
                originAssessment={displayAnalysis.origin_assessment}
              />
            )}

            {activeTab === 'geo' && (
              <GeoIntelligenceView
                infrastructureIntel={
                  displayAnalysis.infrastructure_intelligence
                }
                originAssessment={displayAnalysis.origin_assessment}
              />
            )}

            {activeTab === 'dns' && (
              <DnsRdapView
                infrastructureIntel={
                  displayAnalysis.infrastructure_intelligence
                }
              />
            )}

            {activeTab === 'graph' && (
              <ThreatGraphView threatGraph={displayAnalysis.threat_graph} />
            )}

            {activeTab === 'shap' && (
              <ShapExplainerView
                shapExplanation={displayAnalysis.shap_explanation}
                aiInference={displayAnalysis.ai_inference}
              />
            )}

            {activeTab === 'observables' && (
              <ObservablesView
                observables={observables}
                attachments={displayAnalysis.attachments}
              />
            )}

            {activeTab === 'campaign' && (
              <CampaignAttributionView
                activeCampaign={displayAnalysis.active_campaign}
                campaignCorrelations={displayAnalysis.campaign_correlations}
                attributionSupport={displayAnalysis.attribution_support}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
