import React, { useState } from 'react';
import { Globe2, Shield, Calendar, Database, AlertTriangle, CheckCircle2, Lock, FileSearch } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

export default function DnsRdapView({ infrastructureIntel }) {
  const rawDomains = infrastructureIntel?.domain_intelligence || [];
  const domains = Array.isArray(rawDomains) ? rawDomains : Object.values(rawDomains);
  const [selectedDomainIndex, setSelectedDomainIndex] = useState(0);

  if (domains.length === 0) {
    return (
      <div className="p-8 rounded-xl bg-[#111827] border border-slate-800 text-center text-slate-400 font-mono text-sm">
        No sender domains or external URL domains identified in this artifact.
      </div>
    );
  }

  const currentDomain = domains[selectedDomainIndex] || domains[0];
  const dnsRecords = currentDomain.dns || {};
  const rdap = currentDomain.rdap || {};
  const lexical = currentDomain;

  return (
    <div className="space-y-6">
      {/* Domain Selector Pills */}
      {domains.length > 1 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          <span className="text-xs font-mono text-slate-400 mr-2">Domains ({domains.length}):</span>
          {domains.map((d, idx) => (
            <button
              key={idx}
              onClick={() => setSelectedDomainIndex(idx)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                selectedDomainIndex === idx
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
              }`}
            >
              {d.domain}
            </button>
          ))}
        </div>
      )}

      {/* Domain Overview Header */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Globe2 className="w-6 h-6" />
          </div>
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">TARGET DOMAIN</span>
            <div className="flex items-center gap-2 mt-0.5">
              <h3 className="text-xl font-bold font-mono text-white select-all">
                {currentDomain.domain}
              </h3>
              {currentDomain.is_punycode && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-red-500/20 text-red-300 border border-red-500/40">
                  IDN PUNYCODE
                </span>
              )}
              {currentDomain.is_dga && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-red-500/20 text-red-300 border border-red-500/40">
                  DGA DETECTED
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Entropy & Lexical Quick Stats */}
        <div className="flex items-center gap-6 border-t md:border-t-0 md:border-l border-slate-800 pt-3 md:pt-0 md:pl-6">
          <div>
            <span className="text-[10px] font-mono uppercase text-slate-400 block">SHANNON ENTROPY</span>
            <span className={`text-lg font-bold font-mono ${lexical.entropy > 3.8 ? 'text-red-400' : 'text-emerald-400'}`}>
              {lexical.entropy != null ? Number(lexical.entropy).toFixed(2) : 'Unavailable'}
            </span>
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-slate-400 block">SUBDOMAIN DEPTH</span>
            <span className="text-lg font-bold font-mono text-slate-200">
              {lexical.subdomain ? lexical.subdomain.split('.').length : 0}
            </span>
          </div>
        </div>
      </div>

      {/* 2-Column Grid: DNS Records & RDAP Registration */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Safe DNS Records Card */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
          <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                Safe DNS Record Resolution
              </h3>
            </div>
            <span className="text-[11px] font-mono text-emerald-400">{dnsRecords.status || 'Unavailable'}</span>
          </div>

          <div className="p-5 space-y-4 font-mono text-xs">
            {/* A Records */}
            <div>
              <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                <span>A (IPv4 Addresses):</span>
                <span className="text-[10px] text-slate-400">{(dnsRecords.a_records || []).length} found</span>
              </div>
              <div className="space-y-1">
                {(dnsRecords.a_records && dnsRecords.a_records.length > 0) ? (
                  dnsRecords.a_records.map((ip, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900/80 border border-slate-800 text-slate-200 flex items-center justify-between">
                      <DefangedIndicator value={ip} type="IP" />
                    </div>
                  ))
                ) : (
                  <p className="text-slate-400 italic">No A records available</p>
                )}
              </div>
            </div>

            {/* MX Records */}
            <div>
              <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                <span>MX (Mail Exchanger):</span>
                <span className="text-[10px] text-slate-400">{(dnsRecords.mx_hosts || []).length} found</span>
              </div>
              <div className="space-y-1">
                {(dnsRecords.mx_hosts && dnsRecords.mx_hosts.length > 0) ? (
                  dnsRecords.mx_hosts.map((mx, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900/80 border border-slate-800 text-slate-200 truncate" title={typeof mx === 'object' ? JSON.stringify(mx) : mx}>
                      {typeof mx === 'object' ? `${mx.preference || ''} ${mx.exchange || ''}` : mx}
                    </div>
                  ))
                ) : (
                  <p className="text-slate-400 italic">No MX records resolved</p>
                )}
              </div>
            </div>

            {/* TXT Records (SPF / DMARC verification) */}
            <div>
              <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                <span>TXT Records:</span>
                <span className="text-[10px] text-slate-400">{(dnsRecords.txt_records || []).length} found</span>
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {(dnsRecords.txt_records && dnsRecords.txt_records.length > 0) ? (
                  dnsRecords.txt_records.map((txt, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900/80 border border-slate-800 text-slate-300 break-all text-[11px]">
                      {txt}
                    </div>
                  ))
                ) : (
                  <p className="text-slate-400 italic">No TXT records resolved</p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* RDAP Registration Metadata Card */}
        <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-md">
          <div className="px-5 py-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
                RDAP Registration Metadata — {rdap.lookup_status || 'Unavailable'}
              </h3>
            </div>
            {rdap.privacy_protected && (
              <span className="flex items-center gap-1 text-[10px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                <Lock className="w-3 h-3" />
                WHOIS PRIVACY ENABLED
              </span>
            )}
          </div>

          <div className="p-5 space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-slate-400 block text-[10px]">REGISTRAR</span>
                <span className="text-slate-200 font-semibold">{rdap.registrar || 'Unavailable'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">DOMAIN STATUS</span>
                <span className="text-slate-200 truncate block">{(rdap.domain_status || []).join(', ') || 'Unknown'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">CREATION DATE</span>
                <span className="text-emerald-400 font-semibold">{rdap.created_date || rdap.creation_date || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px]">EXPIRATION DATE</span>
                <span className="text-slate-200">{rdap.expiration_date || rdap.expires_date || 'N/A'}</span>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800">
              <span className="text-slate-400 block text-[10px] mb-1">NAMESERVERS</span>
              <div className="flex flex-wrap gap-2">
                {(rdap.nameservers && rdap.nameservers.length > 0) ? (
                  rdap.nameservers.map((ns, i) => (
                    <span key={i} className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[11px]">
                      {ns}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-400 italic">No nameservers returned in RDAP response</span>
                )}
              </div>
            </div>

            {/* Typosquatting / Lookalike analysis */}
            {lexical.lookalike_target && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300">
                <div className="flex items-center gap-1.5 font-bold">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span>Target Brand Impersonation Detected!</span>
                </div>
                <p className="mt-1 text-[11px] font-sans">
                  Domain appears to spoof <strong className="text-white">{lexical.lookalike_target}</strong> using character substitution / typosquatting.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
