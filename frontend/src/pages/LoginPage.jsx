import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Cpu, Lock, User, ArrowRight, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, loading } = useAuth();
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('deeptrace2026');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const res = await login(username, password);
    if (res.success) {
      navigate('/');
    } else {
      setError(res.error || 'Authentication failed. Please verify credentials.');
    }
  };

  const fillDemoCredentials = (u, p) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-200 flex items-center justify-center p-4 relative overflow-hidden font-sans selection:bg-cyan-500/30">
      {/* Ambient background glow */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-600/15 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/15 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-[#111827]/90 backdrop-blur-xl border border-slate-800 rounded-2xl p-8 shadow-2xl relative z-10">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-2xl bg-gradient-to-tr from-cyan-600 to-blue-600 shadow-xl shadow-cyan-500/20 mb-2">
            <Cpu className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-extrabold tracking-wider text-white font-mono">
            DEEP<span className="text-cyan-400">TRACE</span>
          </h1>
          <p className="text-xs uppercase font-mono tracking-widest text-slate-400">
            SIH26106 SOC Intelligence Platform
          </p>
        </div>

        {error && (
          <div className="mt-6 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="mt-6 space-y-4 font-mono text-xs">
          <div>
            <label className="text-slate-400 block mb-1">ANALYST IDENTIFIER</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
                placeholder="analyst"
              />
            </div>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">SECURITY TOKEN / PASSWORD</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs uppercase tracking-wider shadow-lg shadow-cyan-600/30 transition flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
          >
            <span>{loading ? 'Authenticating...' : 'Access Defense Grid'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Quick Demo Credentials Footer */}
        <div className="mt-8 pt-6 border-t border-slate-800 text-center space-y-2">
          <p className="text-[11px] font-mono text-slate-400">SIH Evaluation Fast-Track Credentials:</p>
          <div className="flex items-center justify-center gap-2">
            <button
              onClick={() => fillDemoCredentials('analyst', 'deeptrace2026')}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-cyan-400 border border-slate-700 transition"
            >
              analyst / deeptrace2026
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
