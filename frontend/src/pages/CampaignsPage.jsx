import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Network,
  ShieldAlert,
  Server,
  Globe,
  Link as LinkIcon,
  ChevronRight,
  FolderGit2,
  Calendar,
  Layers,
} from 'lucide-react';
import api from '../api/client';
import DefangedIndicator from '../components/common/DefangedIndicator';
import SeverityBadge from '../components/common/SeverityBadge';

export default function CampaignsPage() {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState(null);
  const [campaignDetail, setCampaignDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const fetchCampaigns = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.listCampaigns();
      const items = res?.items || [];
      setCampaigns(items);
      if (items.length > 0) {
        setSelectedCampaignId(items[0].campaign_id);
      }
    } catch (err) {
      setError('Unable to load campaigns. Check the connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedCampaignId) {
      fetchDetail(selectedCampaignId);
    }
  }, [selectedCampaignId]);

  const fetchDetail = async (id) => {
    setDetailLoading(true);
    try {
      const res = await api.getCampaignDetail(id);
      setCampaignDetail(res);
    } catch (err) {
      console.error('Failed to load campaign detail:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-xl lg:text-2xl font-bold font-mono text-white flex items-center gap-2">
          <Network className="w-6 h-6 text-cyan-400" />
          Threat Campaigns & Cross-Case Infrastructure Correlation
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Automated clustering of multi-case email attack infrastructure across
          shared IPs, domains, and phishing payloads.
        </p>
      </div>

      {loading ? (
        <div className="p-16 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
          <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
          <span>Discovering correlated campaign clusters...</span>
        </div>
      ) : error ? (
        <div role="alert" className="p-8 text-center text-amber-300 text-sm">
          {error}{' '}
          <button onClick={fetchCampaigns} className="text-cyan-300 underline">
            Retry
          </button>
        </div>
      ) : campaigns.length === 0 ? (
        <div className="p-12 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-500 font-mono text-xs space-y-2">
          <Network className="w-8 h-8 mx-auto text-slate-600" />
          <p>
            No active cross-case campaign clusters discovered yet. Analyze
            multiple related emails to trigger correlation.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Campaign List Sidebar */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Discovered Clusters ({campaigns.length})
            </h3>
            <div className="space-y-2.5">
              {campaigns.map((camp) => {
                const isSelected = selectedCampaignId === camp.campaign_id;
                return (
                  <div
                    key={camp.campaign_id}
                    onClick={() => setSelectedCampaignId(camp.campaign_id)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-cyan-950/30 border-cyan-500/80 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/40'
                        : 'bg-[#111827] border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <span className="font-bold font-mono text-xs text-cyan-400">
                        {camp.name || camp.campaign_id}
                      </span>
                      <SeverityBadge
                        severity={camp.primary_threat_type || 'PHISHING'}
                        size="sm"
                      />
                    </div>
                    <div className="mt-3 flex items-center justify-between text-xs font-mono text-slate-400">
                      <span>{camp.member_count || 1} Linked Cases</span>
                      <span>
                        {camp.last_seen
                          ? camp.last_seen.substring(0, 10)
                          : 'Recent'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Campaign Details Pane */}
          <div className="lg:col-span-2 space-y-6">
            {detailLoading || !campaignDetail ? (
              <div className="p-12 text-center text-slate-400 font-mono text-xs">
                Loading campaign cluster...
              </div>
            ) : (
              <div className="space-y-6">
                {/* Campaign Header Card */}
                <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 shadow-xl">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <span className="text-xs font-mono text-slate-400 uppercase">
                        THREAT CLUSTER ENTITY
                      </span>
                      <h2 className="text-2xl font-bold font-mono text-white mt-1">
                        {campaignDetail.name || campaignDetail.campaign_id}
                      </h2>
                      <p className="text-xs text-slate-400 font-mono mt-1">
                        Campaign ID:{' '}
                        <span className="text-cyan-400">
                          {campaignDetail.campaign_id}
                        </span>
                      </p>
                    </div>
                    <div className="sm:text-right">
                      <span className="text-[10px] font-mono text-slate-400 uppercase block">
                        CONFIDENCE
                      </span>
                      <span className="text-2xl font-extrabold font-mono text-cyan-400">
                        {Math.round((campaignDetail.confidence || 0.85) * 100)}%
                      </span>
                    </div>
                  </div>

                  <div className="mt-4 pt-4 border-t border-slate-800 grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs font-mono">
                    <div>
                      <span className="text-slate-500 text-[10px] block">
                        PRIMARY THREAT
                      </span>
                      <span className="text-slate-200 font-semibold">
                        {campaignDetail.primary_threat_type || 'PHISHING'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">
                        FIRST SEEN
                      </span>
                      <span className="text-slate-300">
                        {campaignDetail.first_seen || 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] block">
                        LAST SEEN
                      </span>
                      <span className="text-slate-300">
                        {campaignDetail.last_seen || 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Shared Attack Infrastructure */}
                <div className="rounded-xl bg-[#111827] border border-slate-800 p-5 shadow-xl space-y-4">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyan-400" />
                    Shared Threat Infrastructure Across Cluster
                  </h3>

                  <div className="space-y-4 font-mono text-xs">
                    {/* Shared IPs */}
                    {campaignDetail.shared_infrastructure?.ips?.length > 0 && (
                      <div>
                        <span className="text-slate-400 font-semibold block mb-1.5">
                          Shared Relaying / Origin IPs:
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {campaignDetail.shared_infrastructure.ips.map(
                            (ip, i) => (
                              <DefangedIndicator key={i} value={ip} type="IP" />
                            ),
                          )}
                        </div>
                      </div>
                    )}

                    {/* Shared Domains */}
                    {campaignDetail.shared_infrastructure?.domains?.length >
                      0 && (
                      <div>
                        <span className="text-slate-400 font-semibold block mb-1.5">
                          Shared Domains & Lookalikes:
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {campaignDetail.shared_infrastructure.domains.map(
                            (dom, i) => (
                              <DefangedIndicator
                                key={i}
                                value={dom}
                                type="DOMAIN"
                              />
                            ),
                          )}
                        </div>
                      </div>
                    )}

                    {/* Shared URLs */}
                    {campaignDetail.shared_infrastructure?.urls?.length > 0 && (
                      <div>
                        <span className="text-slate-400 font-semibold block mb-1.5">
                          Shared Attack URLs:
                        </span>
                        <div className="space-y-1 max-h-36 overflow-y-auto">
                          {campaignDetail.shared_infrastructure.urls.map(
                            (u, i) => (
                              <div
                                key={i}
                                className="p-2 rounded bg-slate-900 border border-slate-800"
                              >
                                <DefangedIndicator value={u} type="URL" />
                              </div>
                            ),
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Member Cases List */}
                <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-xl">
                  <div className="p-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <FolderGit2 className="w-4 h-4 text-cyan-400" />
                      <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                        Correlated Member Cases (
                        {(campaignDetail.member_cases || []).length})
                      </h3>
                    </div>
                  </div>

                  <div className="divide-y divide-slate-800 font-mono text-xs">
                    {(campaignDetail.member_cases || []).map((mc) => (
                      <div
                        key={mc.case_id}
                        onClick={() => navigate(`/cases/${mc.case_id}`)}
                        className="p-4 hover:bg-slate-800/30 transition cursor-pointer flex items-center justify-between"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-cyan-400">
                              {mc.case_id}
                            </span>
                            <SeverityBadge
                              severity={mc.classification}
                              size="sm"
                            />
                          </div>
                          <p className="text-slate-300 font-sans text-xs">
                            {mc.subject || mc.filename}
                          </p>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-bold text-slate-300">
                            {mc.risk_score}/100
                          </span>
                          <ChevronRight className="w-4 h-4 text-slate-500" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
