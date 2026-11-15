import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertCircle, Check, CheckCircle2, Clock3, Cpu, Database,
  Fingerprint, Gauge, Globe2, HardDrive, KeyRound, LockKeyhole, Moon,
  Radio, RefreshCw, Server, ShieldCheck, Sparkles, Sun, Waves, Zap,
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import api from '../api/client';

const readPref = (key, fallback) => {
  try { return localStorage.getItem(key) || fallback; } catch { return fallback; }
};
const pretty = (value = '') => String(value).replaceAll('_', ' ').replaceAll('-', ' ').toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());

function StatusPill({ value }) {
  const raw = String(value || 'UNKNOWN').toUpperCase();
  const tone = /UNAVAILABLE|DISCONNECTED|FAILED|ERROR/.test(raw) ? 'danger'
    : /NOT_CHECKED|OFFLINE|UNKNOWN|FALLBACK|UNCONFIGURED/.test(raw) ? 'warning'
      : /ACTIVE|CONNECTED|AVAILABLE|DISABLED|CONFIGURED/.test(raw) ? 'success' : 'info';
  return <span className={'aurora-pill aurora-pill--' + tone}><i />{pretty(raw)}</span>;
}

function Metric({ icon: Icon, label, value, note, tone }) {
  return (
    <article className={'aurora-metric aurora-metric--' + tone}>
      <span className="aurora-metric-icon"><Icon size={17} /></span>
      <span className="aurora-metric-label">{label}</span>
      <strong title={String(value)}>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function Preference({ active, icon: Icon, label, detail, onClick }) {
  return (
    <button type="button" className={'aurora-preference' + (active ? ' is-active' : '')} onClick={onClick} aria-pressed={active}>
      <span className="aurora-preference-icon"><Icon size={17} /></span>
      <span className="aurora-preference-text"><strong>{label}</strong><small>{detail}</small></span>
      <span className="aurora-preference-check">{active ? <Check size={13} /> : null}</span>
    </button>
  );
}

function PanelHeading({ icon: Icon, title, note, index, tone = 'violet' }) {
  return (
    <div className="aurora-panel-heading">
      <span className={'aurora-panel-icon aurora-panel-icon--' + tone}><Icon size={17} /></span>
      <div><h3>{title}</h3><p>{note}</p></div>
      <span className="aurora-panel-index">{index}</span>
    </div>
  );
}

export default function SettingsPage() {
  const { theme, toggleTheme } = useTheme();
  const [systemStatus, setSystemStatus] = useState(null);
  const [systemSettings, setSystemSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [ambience, setAmbience] = useState(() => readPref('mailspectra-ambience', 'vivid'));
  const [motionMode, setMotionMode] = useState(() => readPref('mailspectra-motion', 'smooth'));

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setLoadError(false);
    try {
      const [status, settings] = await Promise.all([
        api.getSystemStatus().catch(() => null),
        api.getSystemSettings().catch(() => null),
      ]);
      setSystemStatus(status);
      setSystemSettings(settings);
      setLoadError(!status && !settings);
    } catch (error) {
      console.error('Failed to load system diagnostics:', error);
      setLoadError(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    document.documentElement.dataset.ambience = ambience;
    try { localStorage.setItem('mailspectra-ambience', ambience); } catch { /* session-only preference */ }
  }, [ambience]);
  useEffect(() => {
    document.documentElement.dataset.motion = motionMode;
    try { localStorage.setItem('mailspectra-motion', motionMode); } catch { /* session-only preference */ }
  }, [motionMode]);

  const providers = useMemo(() => Object.entries(systemStatus?.providers || {}), [systemStatus]);
  const mode = (systemSettings?.intelligence_mode || systemStatus?.intelligence_mode || 'UNKNOWN').toUpperCase();
  const database = systemStatus?.database?.status || 'UNKNOWN';
  const mlState = providers.find(([key]) => key === 'ml_engine')?.[1] || 'UNKNOWN';
  const privacy = systemStatus?.privacy || {};
  const configuredCount = providers.filter(([, value]) => /ACTIVE|AVAILABLE|CONFIGURED/i.test(String(value))).length;
  const providerIcon = (key) => ({ geoip: Globe2, dns: Activity, rdap: Database, ml_engine: Cpu, threat_graph: Fingerprint, threat_intel: ShieldCheck })[key] || Radio;

  return (
    <div className="aurora-settings">
      <header className="aurora-settings-header">
        <div>
          <p className="aurora-settings-kicker"><Sparkles size={13} /> CONTROL ROOM / CONFIGURATION</p>
          <h2>Platform <em>settings</em></h2>
          <p>Configure the feel of your workspace and inspect the systems powering every investigation.</p>
        </div>
        <button className="aurora-refresh" type="button" onClick={refresh} disabled={refreshing}>
          <RefreshCw size={15} className={refreshing ? 'aurora-spin' : ''} />{refreshing ? 'Refreshing…' : 'Refresh diagnostics'}
        </button>
      </header>

      {loadError && <div className="aurora-settings-error" role="status"><AlertCircle size={17} /><span><strong>Diagnostics unavailable</strong><small>The settings screen is active, but the system endpoints did not return data. Check the API connection and refresh.</small></span></div>}

      <section className="aurora-health-card">
        <div className="aurora-health-content">
          <span className="aurora-live-label"><i /> LIVE PLATFORM OVERVIEW</span>
          <h3>{loading ? 'Connecting to your environment…' : loadError ? 'Status needs attention' : 'Your workspace is ready.'}</h3>
          <p>A live view of the services supporting your email investigations.</p>
          <div className="aurora-health-meta"><span><Server size={13} />{systemStatus?.environment || 'Environment not reported'}</span><span><Radio size={13} />{mode === 'UNKNOWN' ? 'Mode unknown' : pretty(mode) + ' intelligence'}</span></div>
        </div>
        <div className="aurora-health-orb" aria-hidden="true"><span className="aurora-orbit orbit-a" /><span className="aurora-orbit orbit-b" /><span className="aurora-orb-core"><ShieldCheck size={31} /></span><i className="aurora-spark spark-a" /><i className="aurora-spark spark-b" /></div>
        <div className="aurora-health-footer"><span>DATABASE LINK</span><StatusPill value={database} /><b /><span>INTELLIGENCE MODE</span><StatusPill value={mode} /></div>
      </section>

      <section className="aurora-metrics-grid" aria-label="System indicators">
        <Metric icon={Database} label="Database" value={loading ? 'Checking' : database} note={systemStatus?.database?.type || 'Connection details pending'} tone="mint" />
        <Metric icon={Radio} label="Intelligence" value={pretty(mode)} note="Provider execution mode" tone="violet" />
        <Metric icon={Cpu} label="ML engine" value={pretty(mlState)} note="Detection engine availability" tone="pink" />
        <Metric icon={Globe2} label="Providers" value={configuredCount + ' / ' + providers.length} note="Configured or active providers" tone="cyan" />
      </section>

      <div className="aurora-settings-columns">
        <section className="aurora-panel">
          <PanelHeading icon={Server} title="System identity" note="Deployment and runtime information" index="01" />
          <div className="aurora-detail-list">
            <div><span>Platform</span><strong>{systemStatus?.platform || 'MAILSPECTRA'}</strong></div>
            <div><span>Version</span><strong>{systemStatus?.version || systemSettings?.version || 'Unavailable'}</strong></div>
            <div><span>Created by</span><strong>Swamp</strong></div>
            <div><span>Environment</span><strong>{systemStatus?.environment || 'Not reported'}</strong></div>
          </div>
        </section>
        <section className="aurora-panel">
          <PanelHeading icon={Gauge} title="Runtime configuration" note="Read-only values supplied by the API" index="02" tone="cyan" />
          <div className="aurora-runtime-grid">
            <div><Clock3 size={15} /><span>DNS timeout</span><strong>{systemSettings?.dns_timeout_seconds ?? '—'}<small> sec</small></strong></div>
            <div><Activity size={15} /><span>HTTP timeout</span><strong>{systemSettings?.http_timeout_seconds ?? '—'}<small> sec</small></strong></div>
            <div><RefreshCw size={15} /><span>Cache lifetime</span><strong>{systemSettings?.cache_ttl_hours ?? '—'}<small> hrs</small></strong></div>
            <div><HardDrive size={15} /><span>Maximum upload</span><strong>{systemSettings?.max_upload_size_mb ?? '—'}<small> MB</small></strong></div>
          </div>
        </section>
      </div>

      <section className="aurora-panel aurora-providers-panel">
        <PanelHeading icon={Zap} title="Forensic & intelligence providers" note="Live-reported state. Secret values are never displayed." index="03" tone="pink" />
        {providers.length ? <div className="aurora-provider-grid">{providers.map(([key, value]) => {
          const Icon = providerIcon(key);
          return <article className="aurora-provider" key={key}><span className="aurora-provider-icon"><Icon size={17} /></span><span className="aurora-provider-copy"><strong>{pretty(key)}</strong><small>{pretty(value)}</small></span><StatusPill value={value} /></article>;
        })}</div> : <div className="aurora-empty-state">{loading ? 'Loading provider diagnostics…' : 'Provider diagnostics are not available.'}</div>}
        <div className="aurora-credentials"><KeyRound size={15} /><span>Credential presence</span><StatusPill value={systemSettings?.has_ipinfo_key ? 'IPINFO CONFIGURED' : 'IPINFO UNCONFIGURED'} /><StatusPill value={systemSettings?.has_abuseipdb_key ? 'ABUSEIPDB CONFIGURED' : 'ABUSEIPDB UNCONFIGURED'} /><StatusPill value={systemSettings?.virustotal_status || 'VIRUSTOTAL UNKNOWN'} /><StatusPill value={systemSettings?.shodan_status || 'SHODAN UNKNOWN'} /></div>
      </section>

      <section className="aurora-panel aurora-appearance-panel">
        <PanelHeading icon={Sparkles} title="Workspace appearance" note="Personal preferences saved in this browser" index="04" />
        <div className="aurora-setting-group">
          <div className="aurora-setting-label"><span><strong>Colour theme</strong><small>Choose the canvas that feels right for your workspace.</small></span><b>{theme === 'dark' ? 'OBSIDIAN' : 'DAYLIGHT'}</b></div>
          <div className="aurora-choice-grid two">
            <Preference active={theme === 'dark'} icon={Moon} label="Obsidian" detail="Deep contrast and vivid ambient colour" onClick={() => theme !== 'dark' && toggleTheme()} />
            <Preference active={theme === 'light'} icon={Sun} label="Daylight" detail="Soft surfaces with crisp colour" onClick={() => theme !== 'light' && toggleTheme()} />
          </div>
        </div>
        <div className="aurora-setting-group">
          <div className="aurora-setting-label"><span><strong>Ambient colour</strong><small>Set the glow intensity of the animated aurora background.</small></span><b>{pretty(ambience).toUpperCase()}</b></div>
          <div className="aurora-choice-grid three">
            <Preference active={ambience === 'subtle'} icon={Waves} label="Subtle" detail="Quiet colour wash" onClick={() => setAmbience('subtle')} />
            <Preference active={ambience === 'balanced'} icon={Sparkles} label="Balanced" detail="Soft layered glow" onClick={() => setAmbience('balanced')} />
            <Preference active={ambience === 'vivid'} icon={Zap} label="Vivid" detail="Full aurora colour" onClick={() => setAmbience('vivid')} />
          </div>
        </div>
        <div className="aurora-setting-group last">
          <div className="aurora-setting-label"><span><strong>Interface motion</strong><small>Control page transitions, hover effects and ambient movement.</small></span><b>{motionMode.toUpperCase()}</b></div>
          <div className="aurora-choice-grid two">
            <Preference active={motionMode === 'smooth'} icon={Waves} label="Smooth motion" detail="Fluid transitions and ambient drift" onClick={() => setMotionMode('smooth')} />
            <Preference active={motionMode === 'reduced'} icon={Activity} label="Reduced motion" detail="Minimise movement and animation" onClick={() => setMotionMode('reduced')} />
          </div>
        </div>
      </section>

      <section className="aurora-panel aurora-privacy-panel">
        <PanelHeading icon={LockKeyhole} title="Privacy & execution safeguards" note="Protection boundaries reported by MAILSPECTRA" index="05" tone="mint" />
        <div className="aurora-privacy-list">
          <div><span className="aurora-privacy-icon"><Fingerprint size={17} /></span><span><strong>PII masking</strong><small>{privacy.masking_available ? 'Presentation masking is available in the workspace.' : 'Masking availability was not reported.'}</small></span><StatusPill value={privacy.masking_available ? 'AVAILABLE' : 'UNKNOWN'} /></div>
          <div><span className="aurora-privacy-icon"><ShieldCheck size={17} /></span><span><strong>Payload execution</strong><small>Untrusted email content is not executed in a dynamic sandbox.</small></span><StatusPill value={privacy.payload_execution_sandbox || 'UNKNOWN'} /></div>
          <div><span className="aurora-privacy-icon"><LockKeyhole size={17} /></span><span><strong>Third-party body transmission</strong><small>Raw email bodies are not sent to external intelligence providers.</small></span><StatusPill value={privacy.body_transmission_to_third_parties || 'UNKNOWN'} /></div>
        </div>
        <div className="aurora-privacy-note"><CheckCircle2 size={15} />Only discrete indicators such as IP addresses and domains are used for external intelligence lookups. Review exported reports before sharing them.</div>
      </section>

      <footer className="aurora-settings-footer"><span><ShieldCheck size={14} /> MAILSPECTRA / DEFENSE WORKSPACE</span><span>Server secrets and deployment settings remain read-only and are never exposed here.</span></footer>
    </div>
  );
}
