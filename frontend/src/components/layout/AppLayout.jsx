import React, { useCallback, useEffect, useLayoutEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  ChevronRight,
  Eye,
  EyeOff,
  FileText,
  FolderKanban,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Plus,
  Radio,
  Search,
  Settings,
  Sun,
  X,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { usePrivacy } from '../../context/PrivacyContext';
import { useTheme } from '../../context/ThemeContext';
import api from '../../api/client';
import AccentTitle from '../common/AccentTitle.jsx';

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
  'Case detail': { eyebrow: 'CASE INVESTIGATION', title: 'Case detail', note: 'Review findings, evidence integrity and the investigation timeline.' },
};

const routePreloaders = {
  '/': () => import('../../pages/DashboardPage'),
  '/investigate': () => import('../../pages/InvestigatePage'),
  '/cases': () => import('../../pages/CasesPage'),
  '/campaigns': () => import('../../pages/CampaignsPage'),
  '/intelligence': () => import('../../pages/IntelligencePage'),
  '/reports': () => import('../../pages/ReportsPage'),
  '/settings': () => import('../../pages/SettingsPage'),
};

const preloadRoute = (path) => {
  const preload = routePreloaders[path];
  if (preload) void preload();
};

export default function AppLayout() {
  const { user, logout } = useAuth();
  const { masked, setMasked } = usePrivacy();
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const [systemMode, setSystemMode] = useState('UNKNOWN');
  const [mobileOpen, setMobileOpen] = useState(false);

  useLayoutEffect(() => {
    let savedMotion = 'smooth';
    try {
      savedMotion = localStorage.getItem('mailspectra-motion') === 'reduced'
        ? 'reduced'
        : 'smooth';
    } catch {
      // Default to smooth motion when browser storage is unavailable.
    }
    document.documentElement.dataset.motion = savedMotion;
  }, []);

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

  const handleNewInvestigation = useCallback(() => {
    setMobileOpen(false);
    navigate('/investigate', { state: { startNewInvestigation: true } });
  }, [navigate]);

  useEffect(() => {
    const handleShortcut = (event) => {
      const target = event.target;
      const isEditableTarget = target instanceof HTMLElement && (
        target.isContentEditable ||
        ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)
      );

      if (
        event.defaultPrevented ||
        event.isComposing ||
        event.repeat ||
        event.key.toLowerCase() !== 'n' ||
        event.altKey ||
        event.ctrlKey ||
        event.metaKey ||
        isEditableTarget
      ) {
        return;
      }

      event.preventDefault();
      handleNewInvestigation();
    };

    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [handleNewInvestigation]);

  useEffect(() => setMobileOpen(false), [location.pathname]);

  const currentPage = location.pathname.startsWith('/cases/')
    ? 'Case detail'
    : allItems.find((item) =>
        item.path === location.pathname ||
        (item.path !== '/' && location.pathname.startsWith(`${item.path}/`))
      )?.label || 'Dashboard';
  const activeNavPage = currentPage === 'Case detail' ? 'Cases' : currentPage;
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
              onPointerEnter={() => preloadRoute(path)}
              onFocus={() => preloadRoute(path)}
              className={({ isActive }) =>
                `soc-nav-link ${isActive ? 'is-active' : ''} ${accent ? 'is-accent' : ''}`
              }
            >
              <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
              <span>{label}</span>
              {label === activeNavPage && <span className="soc-nav-indicator" aria-hidden="true" />}
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
          <div className="soc-brand-mark" aria-hidden="true">
            <svg className="mailspectra-mark-svg" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="mailspectra-mark-stroke" x1="8" y1="8" x2="40" y2="40" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#6DE7E2" />
                  <stop offset=".52" stopColor="#82B9FF" />
                  <stop offset="1" stopColor="#B48BFF" />
                </linearGradient>
                <linearGradient id="mailspectra-mark-fold" x1="14" y1="19" x2="34" y2="33" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#E7FFFF" />
                  <stop offset="1" stopColor="#A8B4FF" />
                </linearGradient>
              </defs>
              <path d="M24 4.5 39 10v12.1c0 10.1-6 17-15 21.4-9-4.4-15-11.3-15-21.4V10L24 4.5Z"
                fill="rgba(117,139,255,.075)" stroke="url(#mailspectra-mark-stroke)" strokeWidth="1.7" strokeLinejoin="round"/>
              <path d="M15.7 18.8h16.6c1.3 0 2.3 1 2.3 2.3v10.1c0 1.3-1 2.3-2.3 2.3H15.7c-1.3 0-2.3-1-2.3-2.3V21.1c0-1.3 1-2.3 2.3-2.3Z"
                fill="rgba(10,18,38,.5)" stroke="url(#mailspectra-mark-fold)" strokeWidth="1.55"/>
              <path d="m14.2 20.5 9.8 7.6 9.8-7.6" stroke="url(#mailspectra-mark-fold)" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="m17 31.1 5.1-4M31 31.1l-5.1-4" stroke="url(#mailspectra-mark-stroke)" strokeWidth="1.45" strokeLinecap="round"/>
              <circle cx="35.6" cy="13.1" r="2" fill="#F18BD0"/>
              <circle cx="35.6" cy="13.1" r="4.1" stroke="#F18BD0" strokeOpacity=".24"/>
            </svg>
          </div>
          <div className="soc-brand-copy">
            <div className="brand-name" aria-label="MAILSPECTRA">
              <span className="brand-name-primary">MAIL</span><span className="brand-name-accent">SPECTRA</span>
            </div>
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
          <button
            type="button"
            onClick={handleNewInvestigation}
            className="soc-new-case"
            aria-keyshortcuts="N"
            title="Start a new investigation (N)"
          >
            <Plus size={16} aria-hidden="true" />
            <span>New investigation</span>
            <span className="soc-shortcut" aria-hidden="true">N</span>
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
              <span className={`soc-status-light ${systemMode === 'UNKNOWN' ? 'is-unknown' : systemMode === 'OFFLINE' ? 'is-offline' : systemMode === 'LIVE' ? 'is-live' : ''}`} />
              <span>{systemMode === 'UNKNOWN' ? 'STATUS UNKNOWN' : `INTEL · ${systemMode}`}</span>
            </div>
            <button
              type="button"
              className="soc-theme-toggle"
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`}
            >
              {theme === 'dark' ? (
                <Sun size={16} aria-hidden="true" />
              ) : (
                <Moon size={16} aria-hidden="true" />
              )}
              <span>{theme === 'dark' ? 'LIGHT MODE' : 'DARK MODE'}</span>
            </button>
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
                <h1><AccentTitle text={meta.title} /></h1>
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
