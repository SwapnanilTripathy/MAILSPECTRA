import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ReferenceLine } from 'recharts';
import { Sparkles, TrendingUp, TrendingDown, Info } from 'lucide-react';

export default function ShapExplainerView({ shapExplanation, aiInference }) {
  if (!shapExplanation) {
    return (
      <div className="p-8 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400">
        No SHAP explainability data available for this email.
      </div>
    );
  }

  const topFeatures = shapExplanation.top_features || [];
  const chartData = topFeatures.map((f) => ({
    name: f.feature_name || f.feature,
    value: f.contribution,
    direction: f.direction,
    description: f.description,
  })).reverse();

  return (
    <div className="space-y-6">
      {/* Explanation Summary Header */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 shadow-md">
        <div className="flex items-center gap-2 text-sm font-semibold text-cyan-400">
          <Sparkles className="w-4 h-4" />
          <span>Explainable AI (XAI) Threat Attribution</span>
        </div>
        <p className="mt-2 text-sm text-slate-300 leading-relaxed">
          {shapExplanation.explanation_summary || 'SHAP linear attribution highlights the key positive and negative signals that drove the threat classification.'}
        </p>
        <div className="mt-3 flex items-center gap-4 text-xs font-mono text-slate-400">
          <span>Method: <strong className="text-slate-200">{shapExplanation.method || 'SHAP LinearExplainer'}</strong></span>
          <span>Target Class: <strong className="text-cyan-300">{shapExplanation.predicted_class}</strong></span>
        </div>
      </div>

      {/* SHAP Contribution Bar Chart */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 shadow-md">
        <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-4">
          Local Feature Contribution (SHAP Margin Impact)
        </h4>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 30, left: 140, bottom: 5 }}>
              <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11, fill: '#94a3b8' }} />
              <YAxis type="category" dataKey="name" stroke="#64748b" tick={{ fontSize: 11, fill: '#cbd5e1' }} width={130} />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="p-3 bg-[#0B0F19] border border-slate-700 rounded-lg shadow-xl text-xs font-mono">
                        <p className="font-bold text-white">{data.name}</p>
                        <p className={`mt-1 font-semibold ${data.direction === 'increases_risk' ? 'text-red-400' : 'text-emerald-400'}`}>
                          Impact: {data.value > 0 ? `+${data.value}` : data.value} ({data.direction.replace('_', ' ')})
                        </p>
                        <p className="mt-1 text-slate-400 font-sans">{data.description}</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <ReferenceLine x={0} stroke="#475569" strokeDasharray="3 3" />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {chartData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.direction === 'increases_risk' ? '#ef4444' : '#10b981'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Feature Attribution Table */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
        <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Attribution Feature Breakdown
          </h4>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Feature Name</th>
                <th className="px-4 py-3">Observed Value</th>
                <th className="px-4 py-3">SHAP Value</th>
                <th className="px-4 py-3">Risk Impact</th>
                <th className="px-4 py-3 font-sans">Analyst Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {topFeatures.map((f, i) => (
                <tr key={i} className="hover:bg-slate-800/30 transition">
                  <td className="px-4 py-3 font-semibold text-slate-200">{f.feature_name || f.feature}</td>
                  <td className="px-4 py-3 text-slate-400">{f.value}</td>
                  <td className="px-4 py-3 font-bold text-slate-100">{f.contribution}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold ${
                      f.direction === 'increases_risk' ? 'bg-red-500/10 text-red-400' : 'bg-emerald-500/10 text-emerald-400'
                    }`}>
                      {f.direction === 'increases_risk' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                      {f.direction === 'increases_risk' ? 'INCREASES RISK' : 'DECREASES RISK'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300 font-sans text-xs">{f.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
