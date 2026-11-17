import React, { useMemo } from 'react';
import { WORLD_MAP_PATH } from './worldMapPath';
import { Activity } from 'lucide-react';

export default function GlobalThreatMap({ threatNodes = [] }) {
  // Destination Target: "Your System (Host)" - Indian Subcontinent (New Delhi / Bangalore region)
  // Formula: lon 77.2 -> x 714, lat 28.6 -> y 171
  const targetCoord = { x: 714, y: 171, label: 'Your System (Host)' };

  // Pre-calibrated global threat sectors matching enterprise cybersecurity command centers
  const defaultGlobalSectors = [
    { id: 1, x: 286, y: 142, ip: '198.51.100.24', city: 'Ashburn, US', sev: 'HIGH', cat: 'DoS' },
    { id: 2, x: 524, y: 111, ip: '185.199.108.153', city: 'Frankfurt, DE', sev: 'MEDIUM', cat: 'BruteForce' },
    { id: 3, x: 888, y: 151, ip: '203.0.113.88', city: 'Tokyo, JP', sev: 'HIGH', cat: 'PortScan' },
    { id: 4, x: 370, y: 315, ip: '177.136.242.12', city: 'Sao Paulo, BR', sev: 'CRITICAL', cat: 'Botnet' },
    { id: 5, x: 604, y: 95, ip: '91.240.118.50', city: 'Moscow, RU', sev: 'HIGH', cat: 'DoS' }
  ];

  // Map real threat telemetry to geographical nodes, ensuring no node overlaps with the host
  const sources = useMemo(() => {
    if (!threatNodes || threatNodes.length === 0) {
      return defaultGlobalSectors;
    }

    // Assign threat nodes to distinct global vantage points
    return threatNodes.slice(0, 5).map((node, idx) => {
      let x, y;
      const isLocalOrPrivate = 
        !node.lat || !node.lon || 
        node.ip === '127.0.0.1' || 
        node.ip?.startsWith('192.168.') || 
        node.ip?.startsWith('10.') || 
        node.ip?.startsWith('172.') ||
        node.ip?.startsWith('2409:');

      if (isLocalOrPrivate) {
        // Map local test vectors to a default global threat ingress sector
        const fallbackSector = defaultGlobalSectors[idx % defaultGlobalSectors.length];
        x = fallbackSector.x;
        y = fallbackSector.y;
      } else {
        // Standard Equirectangular projection
        x = Math.round(((node.lon + 180.0) / 360.0) * 1000.0);
        y = Math.round(((90.0 - node.lat) / 180.0) * 500.0);
        
        // Prevent stacking right on host (within 40px radius)
        if (Math.abs(x - targetCoord.x) < 45 && Math.abs(y - targetCoord.y) < 45) {
          x = defaultGlobalSectors[idx % defaultGlobalSectors.length].x;
          y = defaultGlobalSectors[idx % defaultGlobalSectors.length].y;
        }
      }

      x = Math.max(60, Math.min(940, x));
      y = Math.max(50, Math.min(450, y));

      return {
        id: idx,
        x,
        y,
        ip: node.ip || '198.51.100.23',
        city: `${node.city || 'Remote Node'}, ${node.country || 'External'}`,
        sev: node.severity || 'HIGH',
        cat: node.category || 'Threat'
      };
    });
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
            <span className="text-white font-semibold">Attack Source</span>
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
            {/* High-Tech Glowing Filter */}
            <filter id="mapGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Matrix Dot Pattern Fill for Continents */}
            <pattern id="continentDotMatrix" width="7" height="7" patternUnits="userSpaceOnUse">
              <circle cx="3.5" cy="3.5" r="1.1" fill="#38bdf8" opacity="0.38" />
            </pattern>

            {/* Attack Beam Gradient */}
            <linearGradient id="attackBeamGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
              <stop offset="70%" stopColor="#f87171" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.95" />
            </linearGradient>
          </defs>

          {/* Precision Coordinate Latitude & Longitude Grid Lines */}
          <g stroke="#09182d" strokeWidth="0.6" strokeDasharray="3 4">
            {/* Longitude Meridians */}
            {[100, 200, 300, 400, 500, 600, 700, 800, 900].map((x) => (
              <line key={x} x1={x} y1="0" x2={x} y2="500" />
            ))}
            {/* Latitude Parallels */}
            {[70, 140, 210, 280, 350, 420].map((y) => (
              <line key={y} x1="0" y1={y} x2="1000" y2={y} />
            ))}
            {/* Equator */}
            <line x1="0" y1="250" x2="1000" y2="250" stroke="#0e2a4f" strokeWidth="1" strokeDasharray="4 2" />
          </g>

          {/* Authentic Real-World Continent Landmasses */}
          <g>
            {/* 1. Base Landmass Silhouette Fill */}
            <path
              d={WORLD_MAP_PATH}
              fill="#08152b"
              stroke="#0e335f"
              strokeWidth="0.75"
              strokeLinejoin="round"
            />
            {/* 2. Cyber Matrix Dot Overlay Fill */}
            <path
              d={WORLD_MAP_PATH}
              fill="url(#continentDotMatrix)"
              stroke="#0284c7"
              strokeWidth="0.65"
              strokeOpacity="0.5"
              strokeLinejoin="round"
            />
          </g>

          {/* Dynamic Animated Attack Arcs & Shockwaves */}
          {sources.map((src) => {
            // Elevated parabolic curve
            const midX = (src.x + targetCoord.x) / 2;
            const dist = Math.abs(src.x - targetCoord.x);
            const elevation = Math.min(100, Math.max(45, dist * 0.22));
            const midY = Math.min(src.y, targetCoord.y) - elevation;
            const arcPath = `M ${src.x} ${src.y} Q ${midX} ${midY} ${targetCoord.x} ${targetCoord.y}`;

            return (
              <g key={src.id}>
                {/* Background Shadow Arc */}
                <path
                  d={arcPath}
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="1.5"
                  strokeOpacity="0.3"
                  strokeDasharray="4 4"
                />

                {/* Animated Flowing Laser Pulse */}
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

                {/* Attacker Pulsing Beacon */}
                <circle cx={src.x} cy={src.y} r="4" fill="#ef4444" filter="url(#mapGlow)" />
                <circle cx={src.x} cy={src.y} r="8" fill="none" stroke="#ef4444" strokeWidth="1.2">
                  <animate attributeName="r" values="4;15;4" dur="2.2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.9;0;0.9" dur="2.2s" repeatCount="indefinite" />
                </circle>

                {/* Floating IP Badge */}
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
                    opacity="0.88"
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
            
            {/* Host Tooltip Label */}
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

      {/* Bottom Live Threat Summary Footer */}
      <div className="z-10 flex items-center justify-between text-[11px] font-mono text-slate-300 bg-[#060D1E]/90 px-3 py-1.5 rounded-lg border border-cyan-950 backdrop-blur shadow-sm">
        <div className="flex items-center space-x-2">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>Active Threat Arcs: <strong className="text-white">{sources.length} Detected Vectors</strong></span>
        </div>
        <div className="text-slate-400">
          Target Interface: <span className="text-cyan-400 font-bold">127.0.0.1 / Physical Adapter</span>
        </div>
      </div>
    </div>
  );
}
