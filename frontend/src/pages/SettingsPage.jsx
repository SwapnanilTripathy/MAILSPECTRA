import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Radio,
  Database,
  ShieldCheck,
  Cpu,
  Key,
  Server,
  Lock,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';
import api from '../api/client';

export default function SettingsPage() {
  const [systemStatus, setSystemStatus] = useState(null);
  const [systemSettings, setSystemSettings] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const [statusRes, settingsRes] = await Promise.all([
        api.getSystemStatus().catch(() => null),
        api.getSystemSettings().catch(() => null),
      ]);
      setSystemStatus(statusRes);
      setSystemSettings(settingsRes);
    } catch (err) {
      console.error('Failed to load system settings:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl lg:text-2xl font-bold font-mono text-white flex items-center gap-2">
            <SettingsIcon className="w-6 h-6 text-cyan-400" />
            Platform Architecture & Defense Grid Diagnostics
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            System configuration, offline intelligence provider statuses, and
            privacy controls.
          </p>
        </div>

        <button
          onClick={fetchStatus}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-mono transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Diagnostics</span>
        </button>
      </div>

      {/* Platform Metadata Card */}
      <div className="p-6 rounded-xl bg-[#111827] border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-300">
            System Identity & Deployment
          </span>
          <span
            className={`px-2.5 py-0.5 rounded text-[10px] font-bold font-mono border ${systemStatus?.database?.status === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-amber-500/20 text-amber-300 border-amber-500/40'}`}
          >
            {loading
              ? 'LOADING DIAGNOSTICS'
              : systemStatus
                ? `DATABASE: ${systemStatus.database?.status || 'UNKNOWN'}`
                : 'STATUS UNAVAILABLE'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <span className="text-slate-500 text-[10px] block">PLATFORM</span>
            <span className="text-white font-bold">
              {systemStatus?.platform || 'DEEPTRACE'}
            </span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block">VERSION</span>
            <span className="text-cyan-400">
              {systemStatus?.version || 'Unavailable'}
            </span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block">TEAM</span>
            <span className="text-slate-200">
              {systemStatus?.team || 'DEEP thinkers'}
            </span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block">
              PROBLEM STATEMENT
            </span>
            <span className="text-cyan-400 font-bold">
              {systemStatus?.problem_statement || 'SIH26106'}
            </span>
          </div>
        </div>
      </div>

      {/* Provider & Engine Status */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 p-6 shadow-xl space-y-4">
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          Forensic & Machine Learning Subsystems
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {systemStatus?.providers &&
            Object.entries(systemStatus.providers).map(([key, val]) => (
              <div
                key={key}
                className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-start justify-between gap-2"
              >
                <div>
                  <span className="text-slate-400 uppercase font-bold block">
                    {key.replace('_', ' ')}:
                  </span>
                  <span className="text-slate-300 text-[11px] mt-0.5 block">
                    {val}
                  </span>
                </div>
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              </div>
            ))}
        </div>
      </div>

      {/* Privacy Guarantee & Safety Sandbox */}
      <div className="p-6 rounded-xl bg-gradient-to-r from-slate-900 via-[#111827] to-[#111827] border border-slate-800 shadow-xl space-y-3">
        <div className="flex items-center gap-2 text-white font-mono text-sm font-bold">
          <Lock className="w-4 h-4 text-cyan-400" />
          <span>Zero Third-Party Raw Body Transmission Guarantee</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          DeepTrace operates under strict evidentiary privacy guarantees. Full
          email bodies and sensitive internal communication are{' '}
          <strong>never</strong> transmitted to third-party APIs. Only
          sanitized, discrete indicators (IP, domain name) are checked against
          intelligence feeds.
        </p>
        <div className="flex items-center gap-4 text-xs font-mono text-emerald-400 pt-2">
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> Static Offline Defanging
            Active
          </span>
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> Non-Executing Dynamic
            Sandbox Safe
          </span>
        </div>
      </div>
    </div>
  );
}
