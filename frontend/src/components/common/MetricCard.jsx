import React from 'react';

export default function MetricCard({ title, value, subtitle, icon: Icon, color = 'cyan', trend }) {
  const colorMap = {
    cyan: 'from-cyan-500/10 to-transparent text-cyan-400 border-cyan-500/20',
    red: 'from-red-500/10 to-transparent text-red-400 border-red-500/20',
    amber: 'from-amber-500/10 to-transparent text-amber-400 border-amber-500/20',
    emerald: 'from-emerald-500/10 to-transparent text-emerald-400 border-emerald-500/20',
    purple: 'from-purple-500/10 to-transparent text-purple-400 border-purple-500/20',
    blue: 'from-blue-500/10 to-transparent text-blue-400 border-blue-500/20',
  };

  const currentTheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`relative overflow-hidden rounded-xl bg-[#111827] border p-5 shadow-lg ${currentTheme}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</p>
          <h3 className="mt-2 text-2xl font-bold font-mono tracking-tight text-white">{value}</h3>
        </div>
        {Icon && (
          <div className="p-3 rounded-lg bg-slate-800/80 border border-slate-700/50">
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      {(subtitle || trend) && (
        <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
          <span>{subtitle}</span>
          {trend && <span className="font-mono text-cyan-400">{trend}</span>}
        </div>
      )}
    </div>
  );
}
