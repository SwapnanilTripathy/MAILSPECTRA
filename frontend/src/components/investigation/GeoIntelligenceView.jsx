import React, { useState, useEffect, useRef, useMemo } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Globe, MapPin, Shield, Building2, Server, Radio, AlertTriangle } from 'lucide-react';
import DefangedIndicator from '../common/DefangedIndicator';

// Custom Map Marker Icons using SVG
const createCustomIcon = (color = '#06b6d4', isOrigin = false) => {
  const svgHtml = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="${color}" width="${isOrigin ? 32 : 24}" height="${isOrigin ? 32 : 24}">
      <path d="M12 0c-4.418 0-8 3.582-8 8 0 5.25 8 16 8 16s8-10.75 8-16c0-4.418-3.582-8-8-8zm0 11c-1.657 0-3-1.343-3-3s1.343-3 3-3 3 1.343 3 3-1.343 3-3 3z"/>
    </svg>`;
  return L.divIcon({
    html: svgHtml,
    className: 'custom-map-pin',
    iconSize: [isOrigin ? 32 : 24, isOrigin ? 32 : 24],
    iconAnchor: [isOrigin ? 16 : 12, isOrigin ? 32 : 24],
    popupAnchor: [0, isOrigin ? -32 : -24],
  });
};

function InfrastructureMap({ items, originIp, onSelect }) {
  const element = useRef(null);
  useEffect(() => {
    const map = L.map(element.current, { scrollWheelZoom: false }).setView([items[0].latitude, items[0].longitude], items.length === 1 ? 5 : 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { attribution: '&copy; <a href="https://carto.com/">CARTO</a>' }).addTo(map);
    for (const item of items) {
      const isOrigin = item.ip === originIp;
      const marker = L.marker([item.latitude, item.longitude], { icon: createCustomIcon(isOrigin ? '#ef4444' : '#06b6d4', isOrigin), title: item.ip, alt: item.ip }).addTo(map);
      const popup = document.createElement('div');
      popup.textContent = [isOrigin ? 'Observed source' : 'Infrastructure', item.ip, item.city, item.country || item.country_name, item.organization || item.isp, item.asn, item.status].filter(Boolean).join(' · ');
      marker.bindPopup(popup).on('click', () => onSelect(item.ip));
    }
    return () => map.remove();
  }, [items, originIp, onSelect]);
  return <div ref={element} className="h-full w-full" role="region" aria-label="Approximate infrastructure locations map" />;
}

export default function GeoIntelligenceView({ infrastructureIntel, originAssessment }) {
  const [selectedIp, setSelectedIp] = useState(null);
  const [mapEnabled, setMapEnabled] = useState(false);

  const rawIpIntel = infrastructureIntel?.ip_intelligence || [];
  const ipList = Array.isArray(rawIpIntel) ? rawIpIntel : Object.values(rawIpIntel);
  const originIp = originAssessment?.confidence > 0 ? originAssessment?.earliest_reliable_ip : null;

  // Filter IPs with valid latitude & longitude
  const mappedIps = useMemo(() => ipList.filter(
    (item) =>
      item.latitude !== undefined &&
      item.longitude !== undefined &&
      item.latitude !== null &&
      item.longitude !== null &&
      !isNaN(item.latitude) &&
      !isNaN(item.longitude) && Math.abs(Number(item.latitude)) <= 90 && Math.abs(Number(item.longitude)) <= 180
  ), [rawIpIntel]);

  const defaultCenter = mappedIps.length > 0
    ? [mappedIps[0].latitude, mappedIps[0].longitude]
    : [20.0, 0.0];



  return (
    <div className="space-y-6">
      {/* Map Section */}
      <div className="rounded-xl bg-[#111827] border border-slate-800 overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300">
              Approximate infrastructure locations
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {mappedIps.length} Geolocated Observables
          </span>
        </div>

        <p className="p-4 text-xs text-slate-400">Locations describe network infrastructure, not a sender’s physical location. Fixture results are synthetic. Loading the map contacts CARTO for map tiles.</p>
        {mappedIps.length > 0 && !mapEnabled && <button className="m-4 btn-secondary" onClick={() => setMapEnabled(true)}>Load external map tiles</button>}
        <div className="h-96 w-full relative z-0">
          {mappedIps.length > 0 && mapEnabled ? (
            <InfrastructureMap items={mappedIps} originIp={originIp} onSelect={setSelectedIp} />
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-400 font-mono text-xs">
              <MapPin className="w-8 h-8 text-slate-600 mb-2" />
              <span>{mappedIps.length ? "Map tiles have not been loaded." : "No geolocation coordinates available."}</span>
            </div>
          )}
        </div>
      </div>

      {/* IP Intelligence Telemetry Grid */}
      <div className="space-y-4">
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          Extracted IP Telemetry & Infrastructure Attribution ({ipList.length})
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {ipList.map((ipData, i) => {
            const isOrigin = ipData.ip === originIp;
            const isSelected = selectedIp === ipData.ip;

            return (
              <div
                key={i}
                className={`p-5 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-cyan-950/30 border-cyan-500 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500'
                    : isOrigin
                    ? 'bg-red-950/10 border-red-500/40 hover:border-red-500/60'
                    : 'bg-[#111827] border-slate-800 hover:border-slate-700'
                }`}
              >
                <button className="text-xs text-cyan-300 mb-2" onClick={() => setSelectedIp(ipData.ip)}>Select observable</button>
                <p className="text-xs text-slate-400 mb-3">{ipData.status || "unknown"} · {ipData.source || "Source unavailable"} · {ipData.looked_up_at || "Lookup time unavailable"}</p>
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <DefangedIndicator value={ipData.ip} type="IP" className="text-sm font-bold text-white" />
                      {isOrigin && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-red-500/20 text-red-300 border border-red-500/40">
                          OBSERVED SOURCE
                        </span>
                      )}
                      {ipData.is_private && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                          NONPUBLIC / SPECIAL USE
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 mt-1 font-sans">
                      {ipData.city ? `${ipData.city}, ` : ''}{ipData.region ? `${ipData.region}, ` : ''}{ipData.country || ipData.country_name || ipData.country_code || 'Unspecified Country'}
                    </p>
                  </div>

                  {(ipData.proxy_or_vpn || ipData.is_proxy_or_vpn) && (
                    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      <AlertTriangle className="w-3 h-3" />
                      ANONYMIZER / VPN
                    </span>
                  )}
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block text-[10px]">ASN / REGISTRY</span>
                    <span className="text-slate-200 font-semibold">{ipData.asn || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">ORGANIZATION</span>
                    <span className="text-slate-200 truncate block" title={ipData.organization}>
                      {ipData.organization || ipData.isp || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">ISP / HOSTING</span>
                    <span className="text-slate-200 truncate block" title={ipData.isp}>
                      {ipData.isp || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">COORDINATES</span>
                    <span className="text-cyan-400">
                      {ipData.latitude != null && ipData.longitude != null ? `${ipData.latitude}, ${ipData.longitude}` : 'N/A'}
                    </span>
                  </div>
                </div>

                {ipData.reputation_score !== undefined && (
                  <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400">Threat Feed Reputation:</span>
                    <span className={`font-bold ${ipData.reputation_score > 50 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {ipData.reputation_score > 50 ? 'ELEVATED PROVIDER SCORE' : 'NO ADVERSE SIGNAL REPORTED'}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
