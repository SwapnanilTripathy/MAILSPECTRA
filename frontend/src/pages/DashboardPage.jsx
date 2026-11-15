import AlertFeed from '../components/common/AlertFeed';
import { useMasked } from '../context/PrivacyContext';
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Inbox, UploadCloud } from 'lucide-react';
import api from '../api/client';
import AccentTitle from '../components/common/AccentTitle.jsx';

const CATEGORY_COLORS = ['#ff5b78', '#ed70c4', '#ffb454', '#bd83ec', '#53d9a8', '#69c9ff'];
const RISK_COLORS = {
  CRITICAL: '#ff5b78',
  HIGH: '#ffb454',
  MEDIUM: '#9da9ff',
  LOW: '#53d9a8',
};

const formatLabel = (value = 'UNKNOWN') =>
  String(value).replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());

const categoryColor = (name, index) => {
  const key = String(name || '').toUpperCase();
  if (key.includes('PHISH')) return '#ff5b78';
  if (key.includes('CREDENTIAL')) return '#ed70c4';
  if (key.includes('BUSINESS') || key.includes('COMPROMISE')) return '#ffb454';
  if (key.includes('FRAUD')) return '#bd83ec';
  if (key.includes('LEGIT')) return '#53d9a8';
  return CATEGORY_COLORS[index % CATEGORY_COLORS.length];
};

function DistributionBars({ items, maxValue, colorFor, emptyTitle, emptyDescription, loading, unavailable }) {
  if (!items?.length) {
    return (
      <div className="distribution-empty">
        <strong>{loading ? 'Loading data…' : unavailable ? 'Data unavailable' : emptyTitle}</strong>
        <span>{loading ? 'Please wait while the dashboard loads.' : unavailable ? 'Check the backend connection and refresh.' : emptyDescription}</span>
      </div>
    );
  }

  return (
    <div className="distribution-list">
      {items.map((item, index) => {
        const value = Math.max(0, Number(item.value) || 0);
        const percent = Math.max(0, Math.min(100, (value / Math.max(1, maxValue)) * 100));
        const color = colorFor(item.name, index);
        return (
          <div className="distribution-row" key={`${item.name}-${index}`}>
            <span className="distribution-label">{formatLabel(item.name)}</span>
            <span
              className="distribution-track"
              role="progressbar"
              aria-label={`${formatLabel(item.name)} distribution`}
              aria-valuemin={0}
              aria-valuemax={maxValue}
              aria-valuenow={value}
            >
              <span className="distribution-fill" style={{ width: `${percent}%`, '--bar-color': color }} />
            </span>
            <span className="distribution-value">{value}</span>
          </div>
        );
      })}
    </div>
  );
}

const statusTone = (status = 'OPEN') => {
  const normalized = String(status).toUpperCase();
  if (normalized === 'RESOLVED') return 'resolved';
  if (normalized === 'INVESTIGATING') return 'investigating';
  if (normalized === 'ARCHIVED') return 'archived';
  return 'open';
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [rawRecentCases, setRecentCases] = useState(null);
  const recentCases = useMasked(rawRecentCases);
  const [distribution, setDistribution] = useState(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    let active = true;
    const fetchDashboardData = async () => {
      const [statsRes, recentRes, distRes] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getDashboardRecent().catch(() => null),
        api.getDashboardDistribution().catch(() => null),
      ]);
      if (!active) return;
      setStats(statsRes);
      setRecentCases(recentRes?.items || (recentRes ? [] : null));
      setDistribution(distRes);
      setLoading(false);
    };
    fetchDashboardData();
    return () => { active = false; };
  }, []);

  const handleQuickUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const result = await api.analyzeEmailFile(file);
      navigate('/investigate', { state: { initialAnalysis: result } });
    } catch (error) {
      alert(`Analysis error: ${error.message}`);
    } finally {
      setUploading(false);
      event.target.value = '';
    }
  };

  const metricValue = (value) => (loading ? '…' : stats ? value : '—');
  const categoryItems = distribution?.category_distribution || [];
  const riskItems = distribution?.risk_distribution || [];
  const categoryMax = Math.max(1, ...categoryItems.map((item) => Number(item.value) || 0));
  const riskMax = Math.max(1, ...riskItems.map((item) => Number(item.value) || 0));

  return (
    <div className="dashboard max-w-7xl mx-auto">
      <AlertFeed />

      <section className="overview-hero dashboard-command-hero" aria-labelledby="command-center-title">
        <div className="overview-copy">
          <div className="eyebrow">
            <span className="eyebrow-line" /> SECURITY OPERATIONS
          </div>
          <h1 id="command-center-title"><AccentTitle text="Command center" /></h1>
          <p>A consolidated view of your email security workload.</p>
        </div>
        <div className="hero-actions">
          <label className={`dashboard-quick-upload ${uploading ? 'is-uploading' : ''}`} title="Quick email triage">
            <UploadCloud size={15} aria-hidden="true" />
            <span>{uploading ? 'Processing…' : 'Quick triage'}</span>
            <input
              type="file"
              accept=".eml,.msg,.txt"
              onChange={handleQuickUpload}
              disabled={uploading}
              className="sr-only"
            />
          </label>
          <button onClick={() => navigate('/investigate')} className="dashboard-open-workspace">
            Open workspace <ArrowRight size={15} aria-hidden="true" />
          </button>
        </div>
      </section>

      <section className="dashboard-stats-section" aria-labelledby="overview-heading">
        <div className="section-heading">
          <div>
            <p className="section-kicker">AT A GLANCE</p>
            <h2 id="overview-heading"><AccentTitle text="Your security landscape" /></h2>
          </div>
          <span className="section-aside">Overview</span>
        </div>
        <div className="dashboard-metrics-ribbon">
          <article className="dashboard-stat">
            <span>Emails analyzed</span>
            <strong>{metricValue(stats?.total_analyzed ?? 0)}</strong>
            <small>Processed artifacts</small>
          </article>
          <article className="dashboard-stat">
            <span>Threats identified</span>
            <strong>{metricValue(stats?.threats_detected ?? 0)}</strong>
            <small>{stats ? `${stats.critical_threats ?? 0} critical / high severity` : 'Confirmed threats'}</small>
          </article>
          <article className="dashboard-stat">
            <span>Active campaigns</span>
            <strong>{metricValue(stats?.active_campaigns ?? 0)}</strong>
            <small>Correlated threat clusters</small>
          </article>
          <article className="dashboard-stat">
            <span>Average risk score</span>
            <strong>{metricValue(stats?.average_risk_score ?? 0)}</strong>
            <small>Across all cases</small>
          </article>
        </div>
        {!loading && !stats && (
          <p className="data-note" role="status">Dashboard statistics are unavailable. Check the backend connection.</p>
        )}
      </section>

      <section aria-labelledby="insights-heading" className="dashboard-insights-section">
        <div className="section-heading">
          <div>
            <p className="section-kicker">THREAT INTELLIGENCE</p>
            <h2 id="insights-heading"><AccentTitle text="Analysis insights" /></h2>
          </div>
          <span className="section-aside">Based on analyzed emails</span>
        </div>
        <div className="dashboard-insights-grid">
          <article className="insight-card">
            <div className="card-heading">
              <div>
                <h3>Threat classification</h3>
                <p>Distribution by classification</p>
              </div>
            </div>
            <DistributionBars
              items={categoryItems}
              maxValue={categoryMax}
              colorFor={categoryColor}
              emptyTitle="No classification data"
              emptyDescription="Analyze an email to see your threat breakdown."
              loading={loading}
              unavailable={!distribution}
            />
          </article>
          <article className="insight-card">
            <div className="card-heading">
              <div>
                <h3>Risk distribution</h3>
                <p>Cases grouped by severity</p>
              </div>
            </div>
            <DistributionBars
              items={riskItems}
              maxValue={riskMax}
              colorFor={(name) => RISK_COLORS[String(name || '').toUpperCase()] || '#9da9ff'}
              emptyTitle="No risk data yet"
              emptyDescription="Risk scores will appear as cases are analyzed."
              loading={loading}
              unavailable={!distribution}
            />
          </article>
        </div>
      </section>

      <section className="recent-section" aria-labelledby="recent-heading">
        <div className="section-heading">
          <div>
            <p className="section-kicker">TRIAGE</p>
            <h2 id="recent-heading"><AccentTitle text="Recent investigations" /></h2>
          </div>
          <span className="section-aside">Your latest triage activity</span>
        </div>

        <div className="recent-investigations-card">
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
              {!loading && (
                <button onClick={() => navigate('/cases')} className="recent-open-btn">View all cases</button>
              )}
            </div>
          ) : (
            <div className="recent-table-wrap">
              <table className="recent-table">
                <thead>
                  <tr>
                    <th>Case ID</th>
                    <th>Subject and artifact</th>
                    <th>Sender</th>
                    <th>Verdict</th>
                    <th>Risk score</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {recentCases.map((item, index) => {
                    const score = Math.max(0, Math.min(100, Number(item.risk_score) || 0));
                    const status = item.status || 'OPEN';
                    return (
                      <tr key={item.case_id || index}>
                        <td className="recent-case-id">{item.case_id || '—'}</td>
                        <td className="recent-subject" title={item.subject || item.filename || ''}>
                          {item.subject || item.filename || 'Untitled artifact'}
                        </td>
                        <td className="recent-sender" title={item.from_address || ''}>{item.from_address || 'N/A'}</td>
                        <td><span className="recent-verdict">{formatLabel(item.classification || 'UNKNOWN')}</span></td>
                        <td>
                          <span className="recent-risk">
                            <span className="recent-risk-track"><i style={{ width: `${score}%` }} /></span>
                            <b>{score}</b>
                          </span>
                        </td>
                        <td>
                          <span className={`recent-status recent-status--${statusTone(status)}`}>
                            <i />{formatLabel(status)}
                          </span>
                        </td>
                        <td>
                          <button onClick={() => navigate(`/cases/${item.case_id}`)} className="recent-open-btn">
                            Open
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
