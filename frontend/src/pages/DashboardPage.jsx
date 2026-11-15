import AlertFeed from '../components/common/AlertFeed';
import { useMasked } from '../context/PrivacyContext';
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  FolderGit2,
  Network,
  UploadCloud,
  FileText,
  ArrowRight,
  Clock,
  Zap,
  PieChart as PieIcon,
  BarChart3,
  Inbox,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts';
import api from '../api/client';
import MetricCard from '../components/common/MetricCard';
import SeverityBadge from '../components/common/SeverityBadge';
import AccentTitle from '../components/common/AccentTitle.jsx';

const CLASSIFICATION_COLORS = {
  PHISHING: '#ff647d',
  CREDENTIAL_HARVESTING: '#eb78d4',
  BUSINESS_EMAIL_COMPROMISE: '#ffb65e',
  IMPERSONATION: '#9b91ff',
  FRAUD: '#bd8cff',
  SUSPICIOUS: '#f1c76e',
  LEGITIMATE: '#55d7a6',
  UNKNOWN: '#6bc9e8',
};

const RISK_COLORS = {
  CRITICAL: '#ff647d',
  HIGH: '#ffb65e',
  MEDIUM: '#9ca8ff',
  LOW: '#55d7a6',
};

const RISK_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const normalizeBucketName = (value) =>
  String(value || 'UNKNOWN').trim().replace(/[\s-]+/g, '_').toUpperCase();

const formatDistributionLabel = (value) =>
  String(value || 'Unknown')
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

const getClassificationColor = (name, index) => {
  const key = normalizeBucketName(name);
  if (CLASSIFICATION_COLORS[key]) return CLASSIFICATION_COLORS[key];
  if (key.includes('PHISH')) return CLASSIFICATION_COLORS.PHISHING;
  if (key.includes('CREDENTIAL')) return CLASSIFICATION_COLORS.CREDENTIAL_HARVESTING;
  return ['#6bc9e8', '#a8a0ff', '#e58cb5', '#9bcca8'][index % 4];
};

const getRiskColor = (name) =>
  RISK_COLORS[normalizeBucketName(name)] || '#9ca8ff';

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [rawrecentCases, setRecentCases] = useState(null);
  const recentCases = useMasked(rawrecentCases);
  const [distribution, setDistribution] = useState(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    const fetchDashboardData = async () => {
      const [statsRes, recentRes, distRes] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getDashboardRecent().catch(() => null),
        api.getDashboardDistribution().catch(() => null),
      ]);
      setStats(statsRes);
      setRecentCases(recentRes?.items || (recentRes ? [] : null));
      setDistribution(distRes);
      setLoading(false);
    };
    fetchDashboardData();
  }, []);

  const handleQuickUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const res = await api.analyzeEmailFile(file);
      navigate('/investigate', { state: { initialAnalysis: res } });
    } catch (err) {
      alert(`Analysis error: ${err.message}`);
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };
  const metricValue = (value) => (loading ? '…' : stats ? value : '—');
  const emptyText = (message) =>
    loading
      ? 'Loading data…'
      : !distribution
        ? 'Data is currently unavailable.'
        : message;

  const categoryItems = distribution?.category_distribution || [];
  const sortedCategoryItems = [...categoryItems].sort(
    (a, b) => (Number(b.value) || 0) - (Number(a.value) || 0),
  );
  const categoryTotal = categoryItems.reduce(
    (total, item) => total + Math.max(0, Number(item.value) || 0),
    0,
  );

  const riskItems = distribution?.risk_distribution || [];
  const riskMap = new Map(
    riskItems.map((item) => [normalizeBucketName(item.name), item]),
  );
  const riskRows = [
    ...RISK_ORDER.map((name) => ({
      name,
      value: Math.max(0, Number(riskMap.get(name)?.value) || 0),
    })),
    ...riskItems
      .filter((item) => !RISK_ORDER.includes(normalizeBucketName(item.name)))
      .map((item) => ({
        name: normalizeBucketName(item.name),
        value: Math.max(0, Number(item.value) || 0),
      })),
  ];
  const riskTotal = riskItems.reduce(
    (total, item) => total + Math.max(0, Number(item.value) || 0),
    0,
  );

  return (
    <div className="dashboard space-y-6 max-w-7xl mx-auto">
      <AlertFeed />
      <section className="overview-hero">
        <div className="overview-copy">
          <div className="eyebrow">
            <span className="eyebrow-line" /> EMAIL SECURITY WORKSPACE
          </div>
          <h1>
            Security <em className="hero-title-accent">overview</em><span className="heading-period">.</span>
          </h1>
          <p>
            Everything you need to investigate suspicious emails and understand
            the threats behind them.
          </p>
          <div className="hero-actions">
            <label
              className={`primary-action ${uploading ? 'opacity-60' : ''}`}
            >
              <UploadCloud size={17} aria-hidden="true" />
              <span>
                {uploading ? 'Processing email…' : 'Quick email triage'}
              </span>
              <input
                type="file"
                accept=".eml,.msg,.txt"
                onChange={handleQuickUpload}
                disabled={uploading}
                className="sr-only"
              />
            </label>
            <button
              onClick={() => navigate('/investigate')}
              className="secondary-action"
            >
              Open workspace <ArrowRight size={16} aria-hidden="true" />
            </button>
          </div>
          <div className="hero-supported-files" aria-label="Supported email formats">
            <FileText size={13} aria-hidden="true" />
            <span>SUPPORTED FORMATS</span>
            <i>.EML</i>
            <i>.MSG</i>
            <i>.TXT</i>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="hero-orbit hero-orbit-outer" />
          <div className="hero-orbit hero-orbit-inner" />
          <div className="hero-shield">
            <ShieldAlert size={42} strokeWidth={1.3} />
          </div>
          <span className="hero-orbit-dot dot-one" />
          <span className="hero-orbit-dot dot-two" />
          <span className="hero-cross cross-one">+</span>
          <span className="hero-cross cross-two">+</span>
        </div>
      </section>

      <section aria-labelledby="overview-heading">
        <div className="section-heading">
          <div>
            <p className="section-kicker">AT A GLANCE</p>
            <h2 id="overview-heading"><AccentTitle text="Your security landscape" /></h2>
          </div>
          <span className="section-aside">Overview</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <MetricCard
            title="Emails analyzed"
            value={metricValue(stats?.total_analyzed ?? 0)}
            subtitle="Processed artifacts"
            icon={FolderGit2}
            color="cyan"
          />
          <MetricCard
            title="Threats identified"
            value={metricValue(stats?.threats_detected ?? 0)}
            subtitle={
              stats
                ? `${stats.critical_threats ?? 0} critical / high severity`
                : 'Critical / high severity'
            }
            icon={ShieldAlert}
            color="red"
          />
          <MetricCard
            title="Active campaigns"
            value={metricValue(stats?.active_campaigns ?? 0)}
            subtitle="Correlated threat clusters"
            icon={Network}
            color="purple"
          />
          <MetricCard
            title="Average risk score"
            value={metricValue(`${stats?.average_risk_score ?? 0}/100`)}
            subtitle={
              stats
                ? `${stats.open_cases ?? 0} active triage cases`
                : 'Across analyzed emails'
            }
            icon={Zap}
            color="amber"
          />
        </div>
        {!loading && !stats && (
          <p className="data-note" role="status">
            Dashboard statistics are unavailable. Check the backend connection.
          </p>
        )}
      </section>

      <section aria-labelledby="insights-heading">
        <div className="section-heading">
          <div>
            <p className="section-kicker">THREAT INTELLIGENCE</p>
            <h2 id="insights-heading"><AccentTitle text="Analysis insights" /></h2>
          </div>
          <span className="section-aside">Based on analyzed emails</span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 insight-grid">
          <div className="insight-card insight-card--classification">
            <div className="card-heading">
              <div>
                <h3>Threat classification</h3>
                <p>Distribution by classification</p>
              </div>
              <span className="card-heading-icon insight-card-icon--violet">
                <PieIcon size={18} aria-hidden="true" />
              </span>
            </div>
            <div className="chart-area chart-area--distribution">
              {categoryItems.length > 0 && categoryTotal > 0 ? (
                <div className="category-visual">
                  <div className="category-donut-frame">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={categoryItems}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius="68%"
                          outerRadius="88%"
                          paddingAngle={categoryItems.length > 1 ? 3 : 0}
                          stroke="none"
                          isAnimationActive={true}
                          animationDuration={950}
                        >
                          {categoryItems.map((entry, index) => (
                            <Cell
                              key={`${entry.name}-${index}`}
                              aria-label={`${formatDistributionLabel(entry.name)}: ${entry.value} cases`}
                              fill={getClassificationColor(entry.name, index)}
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          formatter={(value, name) => [
                            value,
                            formatDistributionLabel(name),
                          ]}
                          contentStyle={{
                            background: 'rgba(12, 13, 22, .96)',
                            border: '1px solid rgba(151, 157, 199, .32)',
                            borderRadius: 10,
                            color: '#f4f1ea',
                            boxShadow: '0 12px 32px rgba(0,0,0,.3)',
                          }}
                          itemStyle={{ color: '#eeeaf3' }}
                          labelStyle={{ color: '#a9a9bd' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="category-donut-center" aria-label={`${categoryTotal} classified emails`}>
                      <strong>{categoryTotal.toLocaleString()}</strong>
                      <span>CLASSIFIED</span>
                    </div>
                  </div>

                  <div className="category-legend" role="list" aria-label="Classification totals">
                    {sortedCategoryItems.map((entry, index) => {
                      const count = Math.max(0, Number(entry.value) || 0);
                      const share = categoryTotal > 0 ? (count / categoryTotal) * 100 : 0;
                      const color = getClassificationColor(entry.name, index);
                      return (
                        <div className="category-legend-item" role="listitem" key={`${entry.name}-legend`}>
                          <div className="category-legend-heading">
                            <span className="category-legend-name">
                              <i style={{ background: color }} />
                              {formatDistributionLabel(entry.name)}
                            </span>
                            <strong>{count.toLocaleString()}</strong>
                          </div>
                          <div
                            className="category-legend-track"
                            role="progressbar"
                            aria-label={`${formatDistributionLabel(entry.name)} share`}
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-valuenow={Math.round(share)}
                          >
                            <span style={{ width: `${share}%`, background: color }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="empty-chart">
                  <div className="empty-icon">
                    <PieIcon size={22} aria-hidden="true" />
                  </div>
                  <strong>
                    {loading
                      ? 'Loading classification'
                      : !distribution
                        ? 'Classification unavailable'
                        : 'No classification data'}
                  </strong>
                  <span>
                    {emptyText(
                      'Analyze an email to see your threat breakdown.',
                    )}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="insight-card insight-card--risk">
            <div className="card-heading">
              <div>
                <h3>Risk distribution</h3>
                <p>Cases grouped by severity</p>
              </div>
              <span className="card-heading-icon insight-card-icon--cyan">
                <BarChart3 size={18} aria-hidden="true" />
              </span>
            </div>
            <div className="chart-area chart-area--distribution">
              {riskItems.length > 0 ? (
                <div className="risk-distribution">
                  <div className="risk-distribution-summary">
                    <div>
                      <strong>{riskTotal.toLocaleString()}</strong>
                      <span>risk-scored cases</span>
                    </div>
                    <span className="risk-distribution-tag">SEVERITY MIX</span>
                  </div>
                  <div className="risk-breakdown-list" role="list" aria-label="Cases by risk severity">
                    {riskRows.map((entry) => {
                      const count = entry.value;
                      const share = riskTotal > 0 ? (count / riskTotal) * 100 : 0;
                      const color = getRiskColor(entry.name);
                      return (
                        <div
                          className="risk-breakdown-row"
                          role="listitem"
                          key={entry.name}
                          style={{ '--risk-color': color }}
                        >
                          <div className="risk-breakdown-heading">
                            <span className="risk-level">
                              <i />
                              {formatDistributionLabel(entry.name)}
                            </span>
                            <span className="risk-breakdown-value">
                              <strong>{count.toLocaleString()}</strong>
                              <small>{Math.round(share)}%</small>
                            </span>
                          </div>
                          <div
                            className="risk-breakdown-track"
                            role="progressbar"
                            aria-label={`${formatDistributionLabel(entry.name)} share`}
                            aria-valuemin={0}
                            aria-valuemax={100}
                            aria-valuenow={Math.round(share)}
                          >
                            <span style={{ width: `${share}%` }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="empty-chart">
                  <div className="empty-icon">
                    <BarChart3 size={22} aria-hidden="true" />
                  </div>
                  <strong>
                    {loading
                      ? 'Loading risk data'
                      : !distribution
                        ? 'Risk data unavailable'
                        : 'No risk data yet'}
                  </strong>
                  <span>
                    {emptyText(
                      'Risk scores will appear as cases are analyzed.',
                    )}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="recent-card" aria-labelledby="recent-heading">
        <div className="recent-heading">
          <div className="flex items-center gap-3">
            <span className="card-heading-icon">
              <Clock size={18} aria-hidden="true" />
            </span>
            <div>
              <h2 id="recent-heading"><AccentTitle text="Recent investigations" /></h2>
              <p>Your latest triage activity</p>
            </div>
          </div>
          <button onClick={() => navigate('/cases')} className="text-link">
            View all cases <ArrowRight size={15} aria-hidden="true" />
          </button>
        </div>
        {!recentCases?.length ? (
          <div className="recent-empty">
            <Inbox size={22} aria-hidden="true" />
            <span>
              {loading
                ? 'Loading investigations…'
                : !recentCases
                  ? 'Recent investigations are currently unavailable.'
                  : 'No investigations yet. Start by analyzing an email.'}
            </span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/40 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Case ID</th>
                  <th className="px-5 py-3">Subject / Artifact</th>
                  <th className="px-5 py-3">Sender</th>
                  <th className="px-5 py-3">Verdict</th>
                  <th className="px-5 py-3">Risk Score</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentCases.map((c, i) => (
                  <tr
                    key={c.case_id || i}
                    className="hover:bg-slate-800/30 transition"
                  >
                    <td className="px-5 py-3 font-bold text-cyan-400">
                      {c.case_id}
                    </td>
                    <td
                      className="px-5 py-3 text-slate-200 truncate max-w-xs font-sans"
                      title={c.subject}
                    >
                      {c.subject || c.filename}
                    </td>
                    <td className="px-5 py-3 text-slate-400 truncate max-w-[180px]">
                      {c.from_address || 'N/A'}
                    </td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={c.classification} size="sm" />
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`font-bold ${c.risk_score >= 60 ? 'text-red-400' : c.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}
                      >
                        {c.risk_score}/100
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                        {c.status || 'OPEN'}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={() => navigate(`/cases/${c.case_id}`)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
