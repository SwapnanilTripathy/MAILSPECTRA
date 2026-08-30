import React, { useState, useEffect } from 'react';
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
  PlusCircle,
  Menu,
  X,
  UserCheck,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import api from '../../api/client';

export default function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [systemMode, setSystemMode] = useState('OFFLINE');
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    api.getSystemSettings()
      .then((res) => {
        if (res?.intelligence_mode) {
          setSystemMode(res.intelligence_mode.toUpperCase());
        }
      })
      .catch(() => {});
  }, []);

  const navItems = [
    { label: 'Dashboard', path: '/', icon: ShieldAlert },
    { label: 'Investigate', path: '/investigate', icon: Search },
    { label: 'Cases', path: '/cases', icon: FolderGit2 },
    { label: 'Campaigns', path: '/campaigns', icon: Network },
    { label: 'Intelligence', path: '/intelligence', icon: Globe2 },
    { label: 'Reports', path: '/reports', icon: FileText },
    { label: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <div className="flex h-screen bg-[#0B0F19] text-slate-200 overflow-hidden font-sans">
      {/* Sidebar Desktop */}
      <aside className="hidden lg:flex flex-col w-64 bg-[#111827] border-r border-slate-800/80 shadow-2xl">
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-800/80 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 shadow-md shadow-cyan-500/20">
            <Cpu className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wider text-white flex items-center gap-1.5">
              DEEP<span className="text-cyan-400">TRACE</span>
            </h1>
            <p className="text-[10px] uppercase font-mono tracking-widest text-slate-400">SIH26106 SOC Engine</p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* Quick Action & System Status */}
        <div className="p-3 border-t border-slate-800/80 space-y-3">
          <button
            onClick={() => navigate('/investigate')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-lg shadow-cyan-600/20 transition"
          >
            <PlusCircle className="w-4 h-4" />
            <span>New Investigation</span>
          </button>

          <div className="px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <Radio className={`w-3.5 h-3.5 ${systemMode === 'LIVE' ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
              <span className="text-slate-400">MODE:</span>
            </div>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${systemMode === 'LIVE' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'}`}>
              {systemMode}
            </span>
          </div>

          {/* User profile footer */}
          <div className="pt-2 flex items-center justify-between">
            <div className="flex items-center gap-2 truncate">
              <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-cyan-400">
                {user?.username ? user.username.substring(0, 2).toUpperCase() : 'AN'}
              </div>
              <div className="truncate text-xs">
                <p className="font-medium text-slate-200 truncate">{user?.full_name || 'SOC Analyst'}</p>
                <p className="text-[10px] text-slate-500 truncate">{user?.role || 'Tier 2 Analyst'}</p>
              </div>
            </div>
            <button
              onClick={logout}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-red-400 transition"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-14 bg-[#111827]/80 backdrop-blur border-b border-slate-800/80 px-4 lg:px-6 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="lg:hidden p-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              <span className="text-xs font-mono text-slate-400 hidden sm:inline">DEFENSE GRID ACTIVE</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/60 border border-slate-700/60 text-xs font-mono text-slate-300">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Team: DEEP thinkers</span>
            </div>
            <div className="text-xs font-mono text-slate-400">
              UTC: <span className="text-slate-200">{new Date().toISOString().substring(11, 19)}</span>
            </div>
          </div>
        </header>

        {/* Mobile Navigation Drawer */}
        {mobileOpen && (
          <div className="lg:hidden fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex">
            <div className="w-64 bg-[#111827] h-full flex flex-col p-4">
              <div className="flex justify-between items-center pb-4 border-b border-slate-800">
                <span className="font-bold text-white">DEEPTRACE SOC</span>
                <button onClick={() => setMobileOpen(false)} className="p-1 rounded hover:bg-slate-800 text-slate-400">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <nav className="flex-1 py-4 space-y-1 overflow-y-auto">
                {navItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    onClick={() => setMobileOpen(false)}
                    className="flex items-center gap-3 px-3 py-2 rounded text-sm text-slate-300 hover:bg-slate-800"
                  >
                    <item.icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </NavLink>
                ))}
              </nav>
            </div>
          </div>
        )}

        {/* Workspace Page Outlet */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6 bg-[#0B0F19]">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
