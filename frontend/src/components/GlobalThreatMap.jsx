import React, { useMemo } from 'react';
import { WORLD_MAP_PATH } from './worldMapPath';
import { Activity, ShieldCheck, AlertTriangle, Network } from 'lucide-react';

export default function GlobalThreatMap({ threatNodes = [] }) {
  // Destination Target: "Your System (Host)" - Indian Subcontinent (New Delhi / Bangalore region)
  // Formula: lon 77.2 -> x 714, lat 28.6 -> y 171
  const targetCoord = { x: 714, y: 171, label: 'Your System (Host)' };

  // Separate genuine public geolocated threats from internal / private subnet traffic
  const { publicThreats, localThreats } = useMemo(() => {
    const publicList = [];
    const localList = [];

    (threatNodes || []).forEach((node, idx) => {
      const ip = node.ip || '';
      const isPrivateOrLoopback = 
        ip === '127.0.0.1' || 
        ip === '::1' || 
        ip.startsWith('192.168.') || 
        ip.startsWith('10.') || 
        ip.startsWith('172.16.') || 
        ip.startsWith('172.20.') || 
        ip.startsWith('fe80:') ||
        ip.startsWith('2409:');

      if (isPrivateOrLoopback) {
        localList.push({
          id: idx,
          ip: ip,
          category: node.category || 'Threat',
          severity: node.severity || 'HIGH',
          type: ip === '127.0.0.1' ? 'LOOPBACK' : 'INTERNAL_LAN'
        });
      } else if (node.lat && node.lon) {
        // Genuine public geolocated IP
        const x = Math.round(((node.lon + 180.0) / 360.0) * 1000.0);
        const y = Math.round(((90.0 - node.lat) / 180.0) * 500.0);
        publicList.push({
          id: idx,
          x: Math.max(60, Math.min(940, x)),
          y: Math.max(50, Math.min(450, y)),
          ip: ip,
          city: `${node.city || 'Unknown City'}, ${node.country || 'Public Host'}`,
          sev: node.severity || 'HIGH',
          cat: node.category || 'Threat'
        });
      }
    });

    return { publicThreats: publicList, localThreats: localList };
  }, [threatNodes]);

  return (
    <div className="relative w-full h-[330px] bg-[#040814] border border-cyan-900/35 rounded-xl overflow-hidden shadow-[0_4px_30px_rgba(0,0,0,0.85)] flex flex-col justify-between p-3.5 select-none">
      {/* Top Header & Legend */}
      <div className="flex items-center justify-between z-10">
        <div className="flex items-center space-x-2">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping"></span>
          <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center">
            GLOBAL THREAT MAP (LIVE)
          </h4>
        </div>

        {/* Legend */}
        <div className="flex items-center space-x-4 text-[11px] font-mono text-slate-300 bg-[#060D1E]/90 px-3 py-1 rounded-lg border border-cyan-950 shadow-sm backdrop-blur">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 border border-cyan-200 shadow-[0_0_8px_#38bdf8]"></span>
            <span className="text-white font-semibold">Your System</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse border border-red-300 shadow-[0_0_8px_#ef4444]"></span>
            <span className="text-white font-semibold">Public Attack Source</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-3.5 h-0.5 bg-red-500 rounded"></span>
            <span className="text-slate-300">Attack Flow</span>
          </div>
        </div>
      </div>

      {/* High-Resolution SVG Canvas */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <svg viewBox="0 0 1000 500" className="w-full h-full">
          <defs>
            <filter id="mapGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <pattern id="continentDotMatrix" width="7" height="7" patternUnits="userSpaceOnUse">
              <circle cx="3.5" cy="3.5" r="1.1" fill="#38bdf8" opacity="0.35" />
            </pattern>

            <linearGradient id="attackBeamGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
              <stop offset="70%" stopColor="#f87171" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.95" />
            </linearGradient>
          </defs>

          {/* Precision Coordinate Latitude & Longitude Grid Lines */}
          <g stroke="#09182d" strokeWidth="0.6" strokeDasharray="3 4">
            {[100, 200, 300, 400, 500, 600, 700, 800, 900].map((x) => (
              <line key={x} x1={x} y1="0" x2={x} y2="500" />
            ))}
            {[70, 140, 210, 280, 350, 420].map((y) => (
              <line key={y} x1="0" y1={y} x2="1000" y2={y} />
            ))}
            <line x1="0" y1="250" x2="1000" y2="250" stroke="#0e2a4f" strokeWidth="1" strokeDasharray="4 2" />
          </g>

          {/* Authentic Real-World Continent Landmasses */}
          <g>
            <path
              d={WORLD_MAP_PATH}
              fill="#08152b"
              stroke="#0e335f"
              strokeWidth="0.75"
              strokeLinejoin="round"
            />
            <path
              d={WORLD_MAP_PATH}
              fill="url(#continentDotMatrix)"
              stroke="#0284c7"
              strokeWidth="0.65"
              strokeOpacity="0.45"
              strokeLinejoin="round"
            />
          </g>

          {/* Genuine Public Attack Nodes and Beams */}
          {publicThreats.map((src) => {
            const midX = (src.x + targetCoord.x) / 2;
            const dist = Math.abs(src.x - targetCoord.x);
            const elevation = Math.min(100, Math.max(45, dist * 0.22));
            const midY = Math.min(src.y, targetCoord.y) - elevation;
            const arcPath = `M ${src.x} ${src.y} Q ${midX} ${midY} ${targetCoord.x} ${targetCoord.y}`;

            return (
              <g key={src.id}>
                <path
                  d={arcPath}
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="1.5"
                  strokeOpacity="0.3"
                  strokeDasharray="4 4"
                />
                <path
                  d={arcPath}
                  fill="none"
                  stroke="url(#attackBeamGrad)"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeDasharray="10 140"
                  filter="url(#mapGlow)"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    from="150"
                    to="0"
                    dur="2.2s"
                    repeatCount="indefinite"
                  />
                </path>
                <circle cx={src.x} cy={src.y} r="4" fill="#ef4444" filter="url(#mapGlow)" />
                <circle cx={src.x} cy={src.y} r="8" fill="none" stroke="#ef4444" strokeWidth="1.2">
                  <animate attributeName="r" values="4;15;4" dur="2.2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.9;0;0.9" dur="2.2s" repeatCount="indefinite" />
                </circle>
                <g transform={`translate(${src.x}, ${src.y - 12})`}>
                  <rect
                    x="-42"
                    y="-9"
                    width="84"
                    height="13"
                    rx="3"
                    fill="#050a16"
                    stroke="#ef4444"
                    strokeWidth="0.6"
                    opacity="0.9"
                  />
                  <text
                    x="0"
                    y="1"
                    fill="#fca5a5"
                    fontSize="8"
                    fontFamily="monospace"
                    textAnchor="middle"
                    fontWeight="bold"
                  >
                    {src.ip}
                  </text>
                </g>
              </g>
            );
          })}

          {/* Central Target Node: "Your System (Host)" */}
          <g>
            <circle cx={targetCoord.x} cy={targetCoord.y} r="6.5" fill="#38bdf8" filter="url(#mapGlow)" />
            <circle cx={targetCoord.x} cy={targetCoord.y} r="15" fill="none" stroke="#38bdf8" strokeWidth="1.4">
              <animate attributeName="r" values="6.5;24;6.5" dur="2.4s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="1;0;1" dur="2.4s" repeatCount="indefinite" />
            </circle>
            <circle cx={targetCoord.x} cy={targetCoord.y} r="30" fill="none" stroke="#0284c7" strokeWidth="0.8" strokeDasharray="3 3" />
            
            <g transform={`translate(${targetCoord.x}, ${targetCoord.y + 20})`}>
              <rect
                x="-46"
                y="-8"
                width="92"
                height="14"
                rx="3"
                fill="#030814"
                stroke="#38bdf8"
                strokeWidth="0.8"
                opacity="0.92"
              />
              <text
                x="0"
                y="2.5"
                fill="#38bdf8"
                fontSize="8.5"
                fontFamily="monospace"
                textAnchor="middle"
                fontWeight="bold"
              >
                {targetCoord.label}
              </text>
            </g>
          </g>
        </svg>
      </div>

      {/* Internal Subnet / Loopback Activity Overlay Badge */}
      {localThreats.length > 0 && (
        <div className="absolute top-14 left-4 z-20 max-w-xs bg-[#030712]/90 border border-amber-500/40 rounded-lg p-2.5 font-mono text-[10px] text-slate-300 shadow-xl backdrop-blur">
          <div className="flex items-center space-x-1.5 text-amber-400 font-bold uppercase mb-1">
            <Network className="w-3.5 h-3.5" />
            <span>Local Subnet / Host Threat Activity</span>
          </div>
          <div className="space-y-1">
            {localThreats.slice(0, 3).map((lt) => (
              <div key={lt.id} className="flex items-center justify-between text-[10px]">
                <span className="text-cyan-300 font-bold">{lt.ip}</span>
                <span className="text-red-400 font-semibold">{lt.category}</span>
                <span className="text-slate-400">({lt.type})</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Bottom Live Threat Summary Footer */}
      <div className="z-10 flex items-center justify-between text-[11px] font-mono text-slate-300 bg-[#060D1E]/90 px-3 py-1.5 rounded-lg border border-cyan-950 backdrop-blur shadow-sm">
        <div className="flex items-center space-x-2">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>
            External Public Vectors: <strong className="text-white">{publicThreats.length} Active</strong>
            {localThreats.length > 0 && (
              <span className="ml-2 text-amber-400 font-semibold">({localThreats.length} Local Detections)</span>
            )}
          </span>
        </div>
        <div className="text-slate-400">
          Target Interface: <span className="text-cyan-400 font-bold">127.0.0.1 / Physical Adapter</span>
        </div>
      </div>
    </div>
  );
}
