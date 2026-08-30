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
} from 'lucide-react';
import api from '../api/client';
import VerdictBanner from '../components/investigation/VerdictBanner';
import HeadersForensicsView from '../components/investigation/HeadersForensicsView';
import RelayHopsView from '../components/investigation/RelayHopsView';
import GeoIntelligenceView from '../components/investigation/GeoIntelligenceView';
import DnsRdapView from '../components/investigation/DnsRdapView';
import ThreatGraphView from '../components/investigation/ThreatGraphView';
import ShapExplainerView from '../components/investigation/ShapExplainerView';
import ObservablesView from '../components/investigation/ObservablesView';
import CampaignAttributionView from '../components/investigation/CampaignAttributionView';

export default function InvestigatePage() {
  const location = useLocation();
  const [analysis, setAnalysis] = useState(location.state?.initialAnalysis || null);
  const [activeTab, setActiveTab] = useState('summary');
  const [loading, setLoading] = useState(false);
  const [rawText, setRawText] = useState('');
  const [inputMode, setInputMode] = useState('file'); // 'file' | 'raw'
  const [isSaving, setIsSaving] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [alertMessage, setAlertMessage] = useState(null);

  useEffect(() => {
    if (location.state?.initialAnalysis) {
      setAnalysis(location.state.initialAnalysis);
    }
  }, [location.state]);

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setAlertMessage(null);
    try {
      const res = await api.analyzeEmailFile(file);
      setAnalysis(res);
      setActiveTab('summary');
    } catch (err) {
      setAlertMessage({ type: 'error', text: err.message || 'Analysis failed.' });
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
      setAlertMessage({ type: 'error', text: err.message || 'Analysis failed.' });
    } finally {
      setLoading(false);
    }
  };

  const loadSample = async (sampleType) => {
    setLoading(true);
    setAlertMessage(null);
    let sampleContent = '';

    if (sampleType === 'phishing') {
      sampleContent = `Received: by mx.target-organization.com (Postfix, from userid 1000) id 8F32B20045; Sun, 30 Aug 2026 01:15:20 +0530
Authentication-Results: mx.target-organization.com; spf=fail (domain of security-alert@global-banking-corp.com does not designate 203.0.113.88 as permitted sender); dkim=fail (bad signature); dmarc=fail (p=REJECT)
Received: from malicious-vps.attacker-net.org (malicious-vps.attacker-net.org [203.0.113.88]) by mx.target-organization.com (Postfix) with ESMTPS
From: "Global Banking Security" <security-alert@global-banking-corp.com>
Reply-To: "External Drop" <harvest-collector@darkweb-relay.ru>
To: <employee@target-organization.com>
Subject: URGENT: Immediate Action Required - Unauthorized Access Detected!
Date: Sun, 30 Aug 2026 01:14:55 +0530
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><h2>SECURITY ALERT: Immediate Action Required</h2><p>Click <a href="http://198.51.100.45/portal/login.php?session=928472910">VERIFY CREDENTIALS NOW</a> within 2 hours.</p></body></html>`;
    } else if (sampleType === 'benign') {
      sampleContent = `Received: by mail-wr1-x22e.google.com with SMTP id v18so8847648wrc.2 for <user@target.com>; Sun, 30 Aug 2026 00:10:00 -0700
Authentication-Results: mx.google.com; spf=pass (google.com: domain of newsletter@engineering-updates.com designates 142.250.190.46 as permitted sender); dkim=pass header.i=@engineering-updates.com; dmarc=pass
From: "Engineering Weekly" <newsletter@engineering-updates.com>
To: <user@target.com>
Subject: Engineering Digest: Python 3.14 & Cloud Security Architecture
Date: Sun, 30 Aug 2026 00:09:50 -0700
Content-Type: text/plain; charset="utf-8"

Hi Developer,\n\nHere is your weekly summary of distributed cloud security architectures and compiler optimizations.\n\nRead more at https://engineering-updates.com/digest-2026\n\nBest regards,\nEngineering Team`;
    } else if (sampleType === 'spoofed') {
      sampleContent = `Received: from mail.spoofed-server.net (unknown [198.51.100.99]) by mx.corporate.com with ESMTP id 4A1B2C; Sun, 30 Aug 2026 02:00:00 +0000
Authentication-Results: mx.corporate.com; spf=fail (domain of ceo@corporate.com does not designate 198.51.100.99 as permitted sender); dkim=none; dmarc=fail
From: "Chief Executive Officer" <ceo@corporate.com>
Reply-To: "Confidential Advisory" <ceo-offshore@protonmail.ch>
To: <cfo@corporate.com>
Subject: CONFIDENTIAL: Urgent Wire Transfer Request Before Close of Business
Date: Sun, 30 Aug 2026 01:59:00 +0000
Content-Type: text/plain; charset="utf-8"

Please execute urgent transfer of $450,000 for foreign acquisition before COB. Send wire receipt directly to my private inbox.`;
    }

    try {
      const res = await api.analyzeRawEmail(sampleContent, `${sampleType}_demo_sample.eml`);
      setAnalysis(res);
      setActiveTab('summary');
      setAlertMessage({ type: 'success', text: `Loaded and analyzed sample: ${sampleType.toUpperCase()}` });
    } catch (err) {
      setAlertMessage({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveCase = async () => {
    if (!analysis) return;
    setIsSaving(true);
    try {
      await api.createCase({
        case_id: analysis.case_id,
        filename: analysis.filename,
        subject: analysis.email_metadata?.subject || '',
        from_address: analysis.email_metadata?.from_sender?.address || '',
        sender_domain: analysis.email_metadata?.from_sender?.domain || '',
        origin_ip: analysis.origin_assessment?.earliest_reliable_ip || analysis.relay_path?.origin_ip,
        classification: analysis.risk_assessment?.classification || analysis.ai_inference?.predicted_class || 'UNKNOWN',
        risk_score: analysis.risk_assessment?.risk_score || 0.0,
        confidence: analysis.risk_assessment?.model_confidence || 1.0,
        status: 'INVESTIGATING',
        priority: (analysis.risk_assessment?.risk_score || 0) >= 60 ? 'HIGH' : 'MEDIUM',
        sha256: analysis.evidence_provenance?.sha256 || '',
        full_analysis: analysis,
      });
      setAlertMessage({ type: 'success', text: `Case ${analysis.case_id} preserved in investigation database!` });
    } catch (err) {
      setAlertMessage({ type: 'error', text: `Save error: ${err.message}` });
    } finally {
      setIsSaving(false);
    }
  };

  const handleExportReport = async () => {
    if (!analysis) return;
    setIsExporting(true);
    try {
      // First ensure case is saved so report generator has records
      await handleSaveCase();
      const reportRes = await api.generateReport(analysis.case_id);
      window.open(api.getReportDownloadUrl(analysis.case_id), '_blank');
      setAlertMessage({ type: 'success', text: `Forensic PDF report generated (SHA-256: ${reportRes.sha256.substring(0, 16)}...)` });
    } catch (err) {
      setAlertMessage({ type: 'error', text: `Report error: ${err.message}` });
    } finally {
      setIsExporting(false);
    }
  };

  const tabs = [
    { id: 'summary', label: 'Executive Summary & Headers', icon: FileText },
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
            {alertMessage.type === 'error' ? <AlertCircle className="w-4 h-4 text-red-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
            <span>{alertMessage.text}</span>
          </div>
          <button onClick={() => setAlertMessage(null)} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Artifact Input Controls */}
      <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
              <Search className="w-5 h-5 text-cyan-400" />
              Forensic Artifact Ingestion
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Upload raw .EML / .MSG or paste RFC 822 MIME headers for automated forensic deconstruction.
            </p>
          </div>

          {/* Quick Demo Pre-loaders */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400 mr-1">Quick Demos:</span>
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

        {/* Input Toggle & Upload Area */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <button
            onClick={() => setInputMode('file')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
              inputMode === 'file' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
            }`}
          >
            File Upload (.EML)
          </button>
          <button
            onClick={() => setInputMode('raw')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
              inputMode === 'raw' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-white'
            }`}
          >
            Paste RFC 822 Raw MIME
          </button>
        </div>

        {inputMode === 'file' ? (
          <label className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer bg-slate-900/40 hover:bg-slate-900/60 transition group">
            <UploadCloud className="w-10 h-10 text-slate-500 group-hover:text-cyan-400 transition" />
            <p className="mt-2 text-sm font-medium text-slate-300">
              Drag & Drop email artifact or <span className="text-cyan-400 underline">Browse Local File</span>
            </p>
            <p className="mt-1 text-xs text-slate-500 font-mono">Supports RFC 822 .eml, .msg, .txt (up to 25MB)</p>
            <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} disabled={loading} className="hidden" />
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
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-lg shadow-cyan-600/20 transition disabled:opacity-50"
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
            <p className="text-sm font-bold text-white">DECONSTRUCTING EMAIL ARTIFACT...</p>
            <p className="text-xs text-slate-400 mt-1">
              Traversing MTA hops • Calculating Linear SHAP attributions • Building NetworkX Threat Graph
            </p>
          </div>
        </div>
      )}

      {/* Analysis Results View */}
      {analysis && !loading && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <VerdictBanner
            analysis={analysis}
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
            {activeTab === 'summary' && (
              <div className="space-y-6">
                <HeadersForensicsView
                  metadata={analysis.email_metadata}
                  authentication={analysis.authentication_results}
                />
              </div>
            )}

            {activeTab === 'relay' && (
              <RelayHopsView
                relayPath={analysis.relay_path}
                originAssessment={analysis.origin_assessment}
              />
            )}

            {activeTab === 'geo' && (
              <GeoIntelligenceView
                infrastructureIntel={analysis.infrastructure_intelligence}
                originAssessment={analysis.origin_assessment}
              />
            )}

            {activeTab === 'dns' && (
              <DnsRdapView
                infrastructureIntel={analysis.infrastructure_intelligence}
              />
            )}

            {activeTab === 'graph' && (
              <ThreatGraphView
                threatGraph={analysis.threat_graph}
              />
            )}

            {activeTab === 'shap' && (
              <ShapExplainerView
                shapExplanation={analysis.shap_explanation}
                aiInference={analysis.ai_inference}
              />
            )}

            {activeTab === 'observables' && (
              <ObservablesView
                observables={analysis.observables || analysis.extracted_observables}
                attachments={analysis.attachments}
              />
            )}

            {activeTab === 'campaign' && (
              <CampaignAttributionView
                activeCampaign={analysis.active_campaign}
                campaignCorrelations={analysis.campaign_correlations}
                attributionSupport={analysis.attribution_support}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
