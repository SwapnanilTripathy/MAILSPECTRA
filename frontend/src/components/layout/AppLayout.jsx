import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  ChevronRight,
  Cpu,
  Eye,
  EyeOff,
  FileText,
  FolderKanban,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Plus,
  Radio,
  Search,
  Settings,
  X,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { usePrivacy } from '../../context/PrivacyContext';
import api from '../../api/client';

const navigationGroups = [
  {
    label: 'OPERATIONS',
    items: [
      { label: 'Dashboard', path: '/', icon: LayoutDashboard },
      { label: 'Investigate', path: '/investigate', icon: Search, accent: true },
      { label: 'Cases', path: '/cases', icon: FolderKanban },
    ],
  },
  {
    label: 'THREAT INTELLIGENCE',
    items: [
      { label: 'Campaigns', path: '/campaigns', icon: Network },
      { label: 'Intelligence', path: '/intelligence', icon: Globe2 },
    ],
  },
  {
    label: 'WORKSPACE',
    items: [
      { label: 'Reports', path: '/reports', icon: FileText },
      { label: 'Settings', path: '/settings', icon: Settings },
    ],
  },
];

const allItems = navigationGroups.flatMap((group) => group.items);

const pageMeta = {
  Dashboard: { eyebrow: 'SECURITY OPERATIONS', title: 'Command center', note: 'A consolidated view of your email security workload.' },
  Investigate: { eyebrow: 'ARTIFACT ANALYSIS', title: 'Investigation workspace', note: 'Inspect suspicious messages and preserve forensic evidence.' },
  Cases: { eyebrow: 'CASE MANAGEMENT', title: 'Investigation cases', note: 'Track triage status, evidence and analyst activity.' },
  Campaigns: { eyebrow: 'THREAT CORRELATION', title: 'Campaign intelligence', note: 'Explore related cases and shared infrastructure.' },
  Intelligence: { eyebrow: 'EXTERNAL CONTEXT', title: 'Threat intelligence', note: 'Enrich domains, IP addresses and other indicators.' },
  Reports: { eyebrow: 'FORENSIC OUTPUT', title: 'Evidence reports', note: 'Generate, download and verify investigation reports.' },
  Settings: { eyebrow: 'PLATFORM ADMINISTRATION', title: 'System settings', note: 'Review deployment, intelligence and privacy diagnostics.' },
};

export default function AppLayout() {
  const { user, logout } = useAuth();
  const { masked, setMasked } = usePrivacy();
  const location = useLocation();
  const navigate = useNavigate();
  const [systemMode, setSystemMode] = useState('UNKNOWN');
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    let active = true;
    api.getSystemSettings()
      .then((res) => {
        if (active && res?.intelligence_mode) setSystemMode(res.intelligence_mode.toUpperCase());
      })
      .catch(() => {
        if (active) setSystemMode('UNKNOWN');
      });
    return () => { active = false; };
  }, []);

  useEffect(() => setMobileOpen(false), [location.pathname]);

  const currentPage = allItems.find((item) =>
    item.path === location.pathname ||
    (item.path !== '/' && location.pathname.startsWith(`${item.path}/`))
  )?.label || 'Dashboard';
  const meta = pageMeta[currentPage] || pageMeta.Dashboard;
  const initials = (user?.username || 'AN').slice(0, 2).toUpperCase();
  const modeLabel = systemMode === 'UNKNOWN'
    ? 'MODE UNKNOWN'
    : `${systemMode} INTELLIGENCE`;

  const renderNavigation = (mobile = false) => (
    <nav aria-label="Primary navigation" className="soc-nav">
      {navigationGroups.map((group) => (
        <div className="soc-nav-group" key={group.label}>
          <p className="soc-nav-label">{group.label}</p>
          {group.items.map(({ label, path, icon: Icon, accent }) => (
            <NavLink
              key={path}
              to={path}
              end={path === '/'}
              onClick={() => mobile && setMobileOpen(false)}
              className={({ isActive }) =>
                `soc-nav-link ${isActive ? 'is-active' : ''} ${accent ? 'is-accent' : ''}`
              }
            >
              <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
              {label === currentPage && <span className="soc-nav-indicator" aria-hidden="true" />}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="app-shell soc-shell flex h-screen overflow-hidden font-sans">
      <a href="#main-content" className="skip-link">Skip to content</a>

      <aside className="app-sidebar soc-sidebar hidden lg:flex w-[264px] shrink-0 flex-col">
        <div className="soc-brand">
          <div className="soc-brand-mark"><Cpu size={21} strokeWidth={1.8} aria-hidden="true" /></div>
          <div className="min-w-0">
            <div className="brand-name">MAIL<span>SPECTRA</span></div>
            <div className="brand-caption">EMAIL FORENSICS PLATFORM</div>
          </div>
          <span className="soc-build-tag">SOC</span>
        </div>

        <div className="soc-sidebar-context">
          <span className="soc-context-led" />
          <span>ANALYST CONSOLE</span>
          <span className="soc-context-version">v1.0</span>
        </div>

        <div className="flex-1 overflow-y-auto soc-sidebar-scroll">
          {renderNavigation()}
        </div>

        <div className="soc-sidebar-bottom">
          <button onClick={() => navigate('/investigate')} className="soc-new-case">
            <Plus size={16} aria-hidden="true" />
            <span>New investigation</span>
            <span className="soc-shortcut">N</span>
          </button>
          <div className="soc-mode-card">
            <div className="soc-mode-icon"><Radio size={15} aria-hidden="true" /></div>
            <div className="min-w-0 flex-1">
              <p>INTELLIGENCE MODE</p>
              <strong className={systemMode === 'LIVE' ? 'is-live' : ''}>{systemMode}</strong>
            </div>
            <span className={`soc-mode-dot ${systemMode === 'LIVE' ? 'is-live' : systemMode === 'UNKNOWN' ? 'is-unknown' : ''}`} />
          </div>
          <div className="soc-user-card">
            <div className="profile-avatar">{initials}</div>
            <div className="min-w-0 flex-1">
              <p className="profile-name truncate">{user?.full_name || user?.username || 'SOC Analyst'}</p>
              <p className="profile-role truncate">{user?.role || 'Analyst'}</p>
            </div>
            <button onClick={handleLogout} className="icon-button soc-logout" aria-label="Log out" title="Log out">
              <LogOut size={16} aria-hidden="true" />
            </button>
          </div>
        </div>
      </aside>

      <div className="soc-workspace flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="workspace-header soc-topbar">
          <div className="soc-topbar-left">
            <button
              onClick={() => setMobileOpen((open) => !open)}
              className="icon-button soc-mobile-toggle lg:hidden"
              aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
              aria-expanded={mobileOpen}
              aria-controls="mobile-navigation"
            >
              {mobileOpen ? <X size={19} /> : <Menu size={19} />}
            </button>
            <div className="soc-breadcrumb">
              <span>MAILSPECTRA</span>
              <ChevronRight size={13} aria-hidden="true" />
              <strong>{currentPage.toUpperCase()}</strong>
            </div>
          </div>

          <div className="soc-topbar-right">
            <div className="soc-live-status" title={modeLabel}>
              <span className={`soc-status-light ${systemMode === 'UNKNOWN' ? 'is-unknown' : ''}`} />
              <span>{systemMode === 'UNKNOWN' ? 'STATUS UNKNOWN' : `INTEL · ${systemMode}`}</span>
            </div>
            <span className="soc-topbar-divider" />
            <button
              className={`soc-privacy-toggle ${masked ? 'is-enabled' : ''}`}
              onClick={() => setMasked(!masked)}
              aria-pressed={masked}
              title={masked ? 'Turn privacy masking off' : 'Turn privacy masking on'}
            >
              {masked ? <Eye size={15} /> : <EyeOff size={15} />}
              <span>PII MASKING {masked ? 'ON' : 'OFF'}</span>
            </button>
            <span className="soc-topbar-divider soc-user-divider" />
            <div className="soc-topbar-user" title={user?.username || 'Analyst'}>
              <span className="soc-topbar-avatar">{initials}</span>
              <span>{user?.username || 'Analyst'}</span>
            </div>
            <button onClick={handleLogout} className="icon-button soc-topbar-logout" aria-label="Log out" title="Log out">
              <LogOut size={16} aria-hidden="true" />
            </button>
          </div>
        </header>

        {mobileOpen && (
          <div id="mobile-navigation" className="mobile-navigation soc-mobile-navigation lg:hidden">
            {renderNavigation(true)}
            <button onClick={handleLogout} className="soc-nav-link soc-mobile-logout">
              <LogOut size={17} aria-hidden="true" /> Log out
            </button>
          </div>
        )}

        <main id="main-content" tabIndex="-1" className="workspace-main soc-main flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <div className="soc-page-heading">
            <div>
              <p className="soc-page-eyebrow"><Activity size={13} aria-hidden="true" /> {meta.eyebrow}</p>
              <div className="soc-page-title-row">
                <h1>{meta.title}</h1>
                {currentPage === 'Dashboard' && <span className="soc-page-chip">OVERVIEW</span>}
              </div>
              <p className="soc-page-note">{meta.note}</p>
            </div>
            <div className="soc-page-context">
              <span className="soc-context-label">WORKSPACE</span>
              <strong>MAILSPECTRA / {currentPage.toUpperCase()}</strong>
            </div>
          </div>
          <div className="soc-page-content">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
