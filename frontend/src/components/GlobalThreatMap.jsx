import React, { useMemo } from 'react';
import { Globe, Shield, Radio, Activity } from 'lucide-react';

export default function GlobalThreatMap({ threatNodes = [] }) {
  // Destination target: "Your System" (User Host)
  const targetCoord = { x: 710, y: 260, label: 'Your System (Host)' };

  // Generate realistic attack nodes based on actual threat data or default active threat sectors
  const sources = useMemo(() => {
    const defaultSectors = [
      { id: 1, x: 230, y: 170, ip: '198.51.100.24', city: 'Ashburn, US', sev: 'HIGH', cat: 'DoS' },
      { id: 2, x: 505, y: 155, ip: '185.199.108.153', city: 'Frankfurt, DE', sev: 'MEDIUM', cat: 'BruteForce' },
      { id: 3, x: 820, y: 200, ip: '203.0.113.88', city: 'Tokyo, JP', sev: 'HIGH', cat: 'PortScan' },
      { id: 4, x: 330, y: 360, ip: '177.136.242.12', city: 'Sao Paulo, BR', sev: 'CRITICAL', cat: 'Botnet' },
      { id: 5, x: 670, y: 140, ip: '91.240.118.50', city: 'Moscow, RU', sev: 'HIGH', cat: 'DoS' }
    ];

    if (!threatNodes || threatNodes.length === 0) {
      return defaultSectors;
    }

    return threatNodes.slice(0, 5).map((node, idx) => {
      // Map lat/lon to SVG 1000x500 canvas coordinates
      let sx = 500 + (node.lon || 0) * (500 / 180);
      let sy = 250 - (node.lat || 0) * (250 / 90);
      sx = Math.max(80, Math.min(920, sx));
      sy = Math.max(60, Math.min(440, sy));

      return {
        id: idx,
        x: Math.round(sx),
        y: Math.round(sy),
        ip: node.ip || '198.51.100.23',
        city: `${node.city || 'Remote'}, ${node.country || 'Host'}`,
        sev: node.severity || 'HIGH',
        cat: node.category || 'Threat'
      };
    });
  }, [threatNodes]);

  return (
    <div className="relative w-full h-[320px] bg-[#070D19] border border-cyan-900/30 rounded-xl overflow-hidden shadow-[0_4px_25px_rgba(0,0,0,0.7)] flex flex-col justify-between p-4">
      {/* Top Header & Legend */}
      <div className="flex items-center justify-between z-10 select-none">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
          <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center">
            GLOBAL THREAT MAP (LIVE)
          </h4>
        </div>

        {/* Legend */}
        <div className="flex items-center space-x-4 text-[11px] font-mono text-slate-300 bg-slate-950/70 px-3 py-1 rounded-lg border border-slate-800">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 border border-cyan-200"></span>
            <span>Your System</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse border border-red-300"></span>
            <span>Attack Source</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-3 h-0.5 bg-red-500"></span>
            <span>Attack Flow</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas for High-Tech World Map & Animated Attack Arcs */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <svg viewBox="0 0 1000 500" className="w-full h-full opacity-90">
          <defs>
            {/* Glow Filter */}
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Red Arc Gradient */}
            <linearGradient id="attackGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.9" />
            </linearGradient>
          </defs>

          {/* Grid Background Lines */}
          <g stroke="#0f2238" strokeWidth="0.5" strokeDasharray="3 3">
            {[100, 200, 300, 400, 500, 600, 700, 800, 900].map((x) => (
              <line key={x} x1={x} y1="0" x2={x} y2="500" />
            ))}
            {[100, 200, 300, 400].map((y) => (
              <line key={y} x1="0" y1={y} x2="1000" y2={y} />
            ))}
          </g>

          {/* Continent Landmass Silhouettes (World Map Vector Dots) */}
          <g fill="#142c47" opacity="0.65">
            {/* North America */}
            <path d="M 150 80 Q 220 90 280 120 T 320 200 Q 250 250 210 240 T 170 170 Z" />
            <path d="M 180 130 Q 270 140 290 190 T 210 220 Z" fill="#1b395b" />
            {/* South America */}
            <path d="M 280 260 Q 350 280 370 340 T 320 440 Q 270 410 280 320 Z" />
            {/* Europe */}
            <path d="M 460 110 Q 540 100 580 150 T 520 200 Q 470 190 460 140 Z" fill="#1b395b" />
            {/* Africa */}
            <path d="M 480 200 Q 560 210 580 280 T 550 400 Q 490 380 470 270 Z" />
            {/* Asia */}
            <path d="M 600 100 Q 750 90 850 140 T 890 240 Q 780 310 680 250 T 600 160 Z" fill="#1b395b" />
            {/* India Subcontinent */}
            <path d="M 680 220 Q 720 230 740 270 T 700 310 Q 670 270 680 220 Z" fill="#20456e" />
            {/* Australia */}
            <path d="M 800 340 Q 880 330 900 390 T 830 430 Q 780 400 800 340 Z" />
          </g>

          {/* Animated Curved Attack Arcs */}
          {sources.map((src) => {
            // Cubic bezier with an elevated arch control point
            const midX = (src.x + targetCoord.x) / 2;
            const midY = Math.min(src.y, targetCoord.y) - 60;
            const pathD = `M ${src.x} ${src.y} Q ${midX} ${midY} ${targetCoord.x} ${targetCoord.y}`;

            return (
              <g key={src.id}>
                {/* Background glow arc */}
                <path
                  d={pathD}
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="2"
                  strokeOpacity="0.4"
                  strokeDasharray="4 4"
                />

                {/* Animated beam */}
                <path
                  d={pathD}
                  fill="none"
                  stroke="url(#attackGrad)"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeDasharray="8 120"
                  filter="url(#glow)"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    from="128"
                    to="0"
                    dur="2.5s"
                    repeatCount="indefinite"
                  />
                </path>

                {/* Attack Source Point */}
                <circle cx={src.x} cy={src.y} r="4" fill="#ef4444" filter="url(#glow)" />
                <circle cx={src.x} cy={src.y} r="8" fill="none" stroke="#ef4444" strokeWidth="1" opacity="0.7">
                  <animate attributeName="r" values="4;14;4" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.8;0;0.8" dur="2s" repeatCount="indefinite" />
                </circle>

                {/* Attacker Tooltip Pill in SVG */}
                <text x={src.x} y={src.y - 12} fill="#fca5a5" fontSize="9" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
                  {src.ip}
                </text>
              </g>
            );
          })}

          {/* Destination Node: "Your System" (Target) */}
          <g>
            <circle cx={targetCoord.x} cy={targetCoord.y} r="7" fill="#38bdf8" filter="url(#glow)" />
            <circle cx={targetCoord.x} cy={targetCoord.y} r="16" fill="none" stroke="#38bdf8" strokeWidth="1.5">
              <animate attributeName="r" values="7;24;7" dur="2.5s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="1;0;1" dur="2.5s" repeatCount="indefinite" />
            </circle>
            <circle cx={targetCoord.x} cy={targetCoord.y} r="28" fill="none" stroke="#0284c7" strokeWidth="1" strokeDasharray="2 2" />
            
            <text x={targetCoord.x} y={targetCoord.y + 24} fill="#38bdf8" fontSize="10" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
              {targetCoord.label}
            </text>
          </g>
        </svg>
      </div>

      {/* Bottom Live Threat Summary Indicator */}
      <div className="z-10 flex items-center justify-between text-[11px] font-mono text-slate-400 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800/80 backdrop-blur">
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
