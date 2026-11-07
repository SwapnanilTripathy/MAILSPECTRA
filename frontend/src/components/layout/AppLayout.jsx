import React, { useState, useEffect } from 'react';
import { usePrivacy } from '../../context/PrivacyContext';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  FolderGit2,
  Network,
  Globe2,
  FileText,
  Settings,
  LogOut,
  Radio,
  Cpu,
  Plus,
  Menu,
  X,
  ChevronRight,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import api from '../../api/client';

const navItems = [
  { label: 'Dashboard', path: '/', icon: ShieldAlert },
  { label: 'Investigate', path: '/investigate', icon: Search },
  { label: 'Cases', path: '/cases', icon: FolderGit2 },
  { label: 'Campaigns', path: '/campaigns', icon: Network },
  { label: 'Intelligence', path: '/intelligence', icon: Globe2 },
  { label: 'Reports', path: '/reports', icon: FileText },
  { label: 'Settings', path: '/settings', icon: Settings },
];

export default function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const { masked, setMasked } = usePrivacy();
  const [systemMode, setSystemMode] = useState('UNKNOWN');
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    api
      .getSystemSettings()
      .then((res) => {
        if (res?.intelligence_mode)
          setSystemMode(res.intelligence_mode.toUpperCase());
      })
      .catch(() => {});
  }, []);

  const currentPage =
    navItems.find(
      (item) =>
        item.path === location.pathname ||
        (item.path !== '/' && location.pathname.startsWith(`${item.path}/`)),
    )?.label || 'Workspace';
  const navigation = (mobile = false) => (
    <nav aria-label="Main navigation" className="space-y-1">
      {navItems.map(({ label, path, icon: Icon }) => (
        <NavLink
          key={path}
          to={path}
          end={path === '/'}
          onClick={() => mobile && setMobileOpen(false)}
          className={({ isActive }) =>
            `nav-link ${isActive ? 'nav-link-active' : ''}`
          }
        >
          <Icon size={18} aria-hidden="true" />
          <span>{label}</span>
          {label === currentPage && (
            <ChevronRight size={14} className="ml-auto" aria-hidden="true" />
          )}
        </NavLink>
      ))}
    </nav>
  );

  return (
    <div className="app-shell flex h-screen overflow-hidden font-sans">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <button className="fixed bottom-3 right-3 z-50 rounded border border-slate-500 bg-slate-900 px-3 py-2 text-xs text-white" aria-pressed={masked} onClick={() => setMasked(!masked)}>Privacy masking: {masked ? 'On' : 'Off'}</button>
      <aside className="app-sidebar hidden lg:flex w-[248px] shrink-0 flex-col">
        <div className="brand-lockup">
          <div className="brand-mark">
            <Cpu size={21} aria-hidden="true" />
          </div>
          <div>
            <div className="brand-name">
              MAIL<span>SPECTRA</span>
            </div>
            <div className="brand-caption">THREAT INTELLIGENCE</div>
          </div>
        </div>
        <div className="flex-1 px-4 py-7 overflow-y-auto">
          <p className="sidebar-label">WORKSPACE</p>
          {navigation()}
        </div>
        <div className="sidebar-footer">
          <button
            onClick={() => navigate('/investigate')}
            className="sidebar-action"
          >
            <Plus size={17} aria-hidden="true" /> New investigation
          </button>
          <div className="mode-row">
            <span>
              <Radio size={15} aria-hidden="true" /> Intelligence mode
            </span>
            <strong className={systemMode === 'LIVE' ? 'mode-live' : ''}>
              {systemMode}
            </strong>
          </div>
          <div className="profile-row">
            <div className="profile-avatar">
              {user?.username
                ? user.username.substring(0, 2).toUpperCase()
                : 'AN'}
            </div>
            <div className="min-w-0 flex-1">
              <p className="profile-name truncate">
                {user?.full_name || 'SOC Analyst'}
              </p>
              <p className="profile-role truncate">
                {user?.role || 'Tier 2 Analyst'}
              </p>
            </div>
            <button
              onClick={logout}
              className="icon-button"
              aria-label="Log out"
              title="Log out"
            >
              <LogOut size={17} aria-hidden="true" />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="workspace-header">
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="icon-button lg:hidden"
              aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
              aria-expanded={mobileOpen}
              aria-controls="mobile-navigation"
            >
              {mobileOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <span className="header-workspace">Workspace</span>
            <ChevronRight
              size={14}
              className="header-chevron"
              aria-hidden="true"
            />
            <span className="header-current">{currentPage}</span>
          </div>
          <div className="header-right">
            <span className="header-status">
              <span
                className={`status-dot ${systemMode === 'UNKNOWN' ? 'status-unknown' : ''}`}
              />
              {systemMode === 'UNKNOWN'
                ? 'Mode unavailable'
                : `${systemMode.charAt(0)}${systemMode.slice(1).toLowerCase()} mode`}
            </span>
            <span className="header-divider" />
            <span className="header-user">{user?.username || 'Analyst'}</span>
          </div>
        </header>
        {mobileOpen && (
          <div id="mobile-navigation" className="mobile-navigation lg:hidden">
            {navigation(true)}
            <button onClick={logout} className="nav-link w-full">
              <LogOut size={18} aria-hidden="true" /> Log out
            </button>
          </div>
        )}
        <main
          id="main-content"
          tabIndex="-1"
          className="workspace-main flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8"
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
}
