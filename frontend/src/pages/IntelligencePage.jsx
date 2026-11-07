import React, { useState } from 'react';
import api from '../api/client';
import {
  Globe2,
  Search,
  Server,
  Database,
  ShieldAlert,
  Sparkles,
  Layers,
  Lock,
  ExternalLink,
  Cpu,
} from 'lucide-react';
import DefangedIndicator from '../components/common/DefangedIndicator';

export default function IntelligencePage() {
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [queryType, setQueryType] = useState('DOMAIN'); // 'DOMAIN' | 'IP' | 'HASH'
  const [result, setResult] = useState(null);
  const [calculating, setCalculating] = useState(false);

  // Entropy calculator state
  const [entropyInput, setEntropyInput] = useState('');
  const [calculatedEntropy, setCalculatedEntropy] = useState(null);

  const calculateShannonEntropy = (str) => {
    if (!str) return 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  };

  const handleEntropyCalc = () => {
    const val = calculateShannonEntropy(entropyInput);
    setCalculatedEntropy(val);
  };

  const handleQuery = async () => {
    if (!query.trim()) return;
    setCalculating(true); setError(''); setResult(null);
    try {
      const data = await api.lookupIndicator(query, queryType);
      setResult({ indicator: data.indicator, type: data.indicator_type, entropy: data.lexical_entropy.toFixed(2), status: data.status, reputation: data.verdict, timestamp: data.last_checked, provider: data.provider, source: data.source, cache: data.cache_hit });
    } catch (error) { setError(error.message); }
    finally { setCalculating(false); }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-xl lg:text-2xl font-bold font-mono text-white flex items-center gap-2">
          <Globe2 className="w-6 h-6 text-cyan-400" />
          Threat Intelligence & IOC Workbench
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Query configured backend providers. Live mode may disclose the indicator to a provider; offline results are fixtures or unavailable. URLs are never fetched.
        </p>
      </div>

      {error && <p role="alert" className="text-red-300">{error}</p>}
      {/* Query Search Bar */}
      <div className="p-6 rounded-2xl bg-[#111827] border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          {['DOMAIN', 'IP', 'HASH'].map((type) => (
            <button
              key={type}
              onClick={() => setQueryType(type)}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition ${
                queryType === type
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {type} LOOKUP
            </button>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={
                queryType === 'DOMAIN'
                  ? 'e.g. login-secure-portal.com or micr0s0ft.net'
                  : queryType === 'IP'
                    ? 'e.g. 203.0.113.88 or 198.51.100.45'
                    : 'e.g. 5d41402abc4b2a76b9719d911017c592'
              }
              className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={handleQuery}
            disabled={calculating || !query.trim()}
            className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-cyan-700 hover:bg-cyan-800 text-white font-semibold text-xs shadow-lg shadow-cyan-600/20 transition disabled:opacity-50"
          >
            {calculating ? 'Analyzing...' : 'Run Query'}
          </button>
        </div>

        {/* Query Result Card */}
        {result && (
          <div className="mt-4 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-bold uppercase">
                Lexical Analysis Result
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 border border-slate-700">
                {result.type}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-slate-800">
              <div>
                <span className="text-slate-400 text-[10px] block">
                  INDICATOR VALUE
                </span>
                <DefangedIndicator
                  value={result.indicator}
                  type={result.type}
                  className="text-white"
                />
              </div>
              <div>
                <span className="text-slate-400 text-[10px] block">
                  REPUTATION LOOKUP
                </span>
                <span className="font-bold text-slate-300">
                  {result.reputation} — {result.status} ({result.provider}; {result.source}{result.cache ? "; cached" : ""})
                </span>
              </div>
              <div>
                <span className="text-slate-400 text-[10px] block">
                  SHANNON ENTROPY SCORE
                </span>
                <span className="text-cyan-400 font-bold">
                  {result.entropy} bits / char
                </span>
              </div>
              <div>
                <span className="text-slate-400 text-[10px] block">
                  QUERY TIMESTAMP
                </span>
                <span className="text-slate-300">
                  {result.timestamp.substring(0, 19)}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* DGA Shannon Entropy Interactive Calculator */}
      <div className="rounded-2xl bg-[#111827] border border-slate-800 p-6 shadow-xl space-y-4">
        <div className="flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
            Local Shannon Entropy Calculator
          </h2>
        </div>
        <p className="text-xs text-slate-400">
          Measures character unpredictability. Entropy alone does not establish DGA activity or maliciousness.
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-3">
          <input
            type="text"
            value={entropyInput}
            onChange={(e) => setEntropyInput(e.target.value)}
            placeholder="Type any domain string e.g., 'asdkjhqw98y712398hkj.com' or 'google.com'..."
            className="w-full flex-1 p-2.5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:border-cyan-500"
          />
          <button
            onClick={handleEntropyCalc}
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-400 text-xs font-mono font-semibold"
          >
            Compute Entropy
          </button>
        </div>

        {calculatedEntropy !== null && (
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs flex items-center justify-between">
            <div>
              <span className="text-slate-400 block text-[10px]">
                COMPUTED SHANNON ENTROPY
              </span>
              <span
                className={`text-xl font-bold ${calculatedEntropy > 3.8 ? 'text-red-400' : 'text-emerald-400'}`}
              >
                {calculatedEntropy.toFixed(3)} bits
              </span>
            </div>
            <div className="text-right">
              <span className="text-slate-400 block text-[10px]">
                DGA THRESHOLD (&gt; 3.8)
              </span>
              <span
                className={`font-bold ${calculatedEntropy > 3.8 ? 'text-red-400' : 'text-emerald-400'}`}
              >
                {calculatedEntropy > 3.8
                  ? 'LIKELY ALGORITHMIC DGA'
                  : 'STANDARD LEXICAL DISTRIBUTION'}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
