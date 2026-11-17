import React, { useState, useEffect } from 'react';
import { 
  Terminal, 
  ShieldAlert, 
  ShieldCheck, 
  Radio, 
  Zap, 
  Crosshair, 
  Lock, 
  Cpu, 
  Activity,
  AlertTriangle,
  Globe,
  Flame,
  ArrowRight
} from 'lucide-react';

const COMMON_PORTS = [
  { port: 21, service: 'FTP', status: 'SAFE', hits: 0 },
  { port: 22, service: 'SSH', status: 'MONITORED', hits: 0 },
  { port: 23, service: 'Telnet', status: 'SAFE', hits: 0 },
  { port: 53, service: 'DNS', status: 'ACTIVE', hits: 0 },
  { port: 80, service: 'HTTP', status: 'ACTIVE', hits: 0 },
  { port: 443, service: 'HTTPS', status: 'BUSY', hits: 0 },
  { port: 3389, service: 'RDP', status: 'SAFE', hits: 0 },
  { port: 8080, service: 'Web Proxy', status: 'SAFE', hits: 0 },
];

export default function HackerAttackMatrix({ 
  liveAlerts = [], 
  liveEvents = [], 
  pps = 0, 
  blockedCount = 0,
  onBlockIp,
  onExplainAlert
}) {
  const [pulse, setPulse] = useState(false);
  const [portAssaultGrid, setPortAssaultGrid] = useState(COMMON_PORTS);

  // Pulse animation on packet receipt
  useEffect(() => {
    const timer = setInterval(() => setPulse((p) => !p), 1500);
    return () => clearInterval(timer);
  }, []);

  // Update target ports hits based on live events and alerts
  useEffect(() => {
    if (!liveEvents.length) return;
    setPortAssaultGrid((prev) => {
      const copy = [...prev];
      const latest = liveEvents[0];
      const targetPort = latest?.dst_port;
      const found = copy.find((p) => p.port === targetPort);
      if (found) {
        found.hits += 1;
        if (latest.is_malicious) {
          found.status = 'UNDER_ATTACK';
        }
      }
      return copy;
    });
  }, [liveEvents]);

  const latestAlert = liveAlerts.length > 0 ? liveAlerts[0] : null;
  const isUnderAttack = latestAlert && (Date.now() - new Date(latestAlert.timestamp).getTime() < 30000);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Hacker Matrix Top HUD Bar */}
      <div className="bg-black/90 border border-red-500/40 rounded-xl p-5 shadow-2xl relative overflow-hidden backdrop-blur-md">
        {/* Animated Matrix scanline effect */}
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-red-500/5 to-transparent pointer-events-none animate-pulse"></div>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="flex items-center space-x-3">
            <div className={`p-3 rounded-lg border ${
              isUnderAttack 
                ? 'bg-red-600/20 border-red-500 text-red-400 animate-pulse' 
                : 'bg-emerald-600/20 border-emerald-500 text-emerald-400'
            }`}>
              <Crosshair className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-red-400">
                  ⚡ Cyber Warfare & Attack Vector Matrix
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                  isUnderAttack 
                    ? 'bg-red-950 text-red-300 border-red-500 animate-ping' 
                    : 'bg-emerald-950 text-emerald-300 border-emerald-600'
                }`}>
                  {isUnderAttack ? 'INTRUSION IN PROGRESS' : 'PERIMETER SECURE'}
                </span>
              </div>
              <h3 className="text-lg font-bold text-white font-mono mt-0.5 tracking-wide">
                Live Attack Radar & Host Defense Visualization
              </h3>
            </div>
          </div>

          {/* Defense & Threat Stats */}
          <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
            <div className="px-3.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg">
              <span className="text-slate-400 block text-[10px]">Host Interception Rate</span>
              <span className="text-cyan-400 font-bold text-sm">{pps} pkts/sec</span>
            </div>
            <div className="px-3.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg">
              <span className="text-slate-400 block text-[10px]">Active IPS Firewall Blocks</span>
              <span className="text-emerald-400 font-bold text-sm">{blockedCount} Hosts Isolated</span>
            </div>
            <div className="px-3.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg">
              <span className="text-slate-400 block text-[10px]">Defense State</span>
              <span className="text-blue-400 font-bold text-sm">ACTIVE IPS ARMED</span>
            </div>
          </div>
        </div>
      </div>

      {/* Cyber Warfare Battlefield: Attacker Node -> IPS Firewall Shield -> Victim Host */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-6 shadow-2xl relative overflow-hidden">
        <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-cyan-400 mb-6 flex items-center">
          <Zap className="w-4 h-4 mr-2 text-amber-400" />
          Interactive Attack Vector & Threat Mitigation Topology
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center relative z-10">
          {/* 1. Attacker Node (Hacker View) */}
          <div className={`p-5 rounded-xl border transition-all ${
            latestAlert 
              ? 'bg-red-950/40 border-red-500/60 shadow-lg shadow-red-500/10' 
              : 'bg-slate-900/60 border-slate-800'
          }`}>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-mono uppercase font-bold text-red-400 flex items-center">
                <Flame className="w-3.5 h-3.5 mr-1" />
                Adversary / Threat Origin
              </span>
              <span className="text-[10px] font-mono text-slate-500">External Node</span>
            </div>
            <div className="text-sm font-bold font-mono text-white truncate">
              {latestAlert ? latestAlert.src_ip : 'No Hostile Host Detected'}
            </div>
            <div className="mt-2 text-xs font-mono text-slate-400 space-y-1">
              <div>Vector: <span className="text-red-300 font-semibold">{latestAlert ? latestAlert.threat_category : 'Quiescent'}</span></div>
              <div>Engine: <span className="text-cyan-300">{latestAlert ? latestAlert.detection_type : 'Monitoring'}</span></div>
              <div>Severity: <span className={`font-bold ${latestAlert?.severity === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'}`}>{latestAlert ? latestAlert.severity : 'LOW'}</span></div>
            </div>
            {latestAlert && onBlockIp && (
              <button
                onClick={() => onBlockIp(latestAlert.src_ip, latestAlert.threat_category)}
                className="mt-4 w-full py-2 px-3 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-mono font-bold flex items-center justify-center space-x-1 shadow transition"
              >
                <Lock className="w-3.5 h-3.5 mr-1" />
                <span>ISOLATE VIA FIREWALL (IPS)</span>
              </button>
            )}
          </div>

          {/* 2. Middle: Active Defense Shield & Vector Animation */}
          <div className="flex flex-col items-center justify-center space-y-3 text-center px-4">
            <div className="relative">
              <div className={`w-20 h-20 rounded-full flex items-center justify-center border-2 transition-all ${
                isUnderAttack 
                  ? 'border-red-500 bg-red-950/40 shadow-lg shadow-red-500/30 animate-pulse' 
                  : 'border-cyan-500 bg-cyan-950/20 shadow-lg shadow-cyan-500/20'
              }`}>
                {isUnderAttack ? (
                  <ShieldAlert className="w-10 h-10 text-red-400" />
                ) : (
                  <ShieldCheck className="w-10 h-10 text-cyan-400" />
                )}
              </div>
              <span className="absolute -bottom-2.5 left-1/2 -translate-x-1/2 px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-slate-900 border border-slate-700 text-slate-300">
                CYBERSOC IPS
              </span>
            </div>

            <div className="text-[11px] font-mono text-slate-400 mt-2">
              <div className="flex items-center justify-center space-x-2 text-cyan-300">
                <span>Packet Inspection</span>
                <ArrowRight className="w-3.5 h-3.5 animate-pulse" />
                <span>AI Filtering</span>
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">
                Dual Gate: Conf &ge; 0.80 &bull; Margin &ge; 0.25
              </div>
            </div>
          </div>

          {/* 3. Victim Target Node (Host Machine) */}
          <div className="p-5 rounded-xl border bg-slate-900/60 border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-mono uppercase font-bold text-cyan-400 flex items-center">
                <Cpu className="w-3.5 h-3.5 mr-1" />
                Protected Host (Target)
              </span>
              <span className="text-[10px] font-mono text-emerald-400">Windows 11</span>
            </div>
            <div className="text-sm font-bold font-mono text-white truncate">
              {latestAlert ? latestAlert.dst_ip : 'Local Host Network'}
            </div>
            <div className="mt-2 text-xs font-mono text-slate-400 space-y-1">
              <div>Target Port: <span className="text-cyan-300 font-bold">{latestAlert?.dst_port || 'All Listening'}</span></div>
              <div>Protocol: <span className="text-purple-300 font-bold">{latestAlert?.protocol || 'TCP / UDP'}</span></div>
              <div>Firewall State: <span className="text-emerald-400 font-bold">ARMED & PROTECTED</span></div>
            </div>
            {latestAlert && onExplainAlert && (
              <button
                onClick={() => onExplainAlert(latestAlert.id)}
                className="mt-4 w-full py-2 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-bold flex items-center justify-center space-x-1 shadow transition"
              >
                <Activity className="w-3.5 h-3.5 mr-1" />
                <span>EXPLAIN AI DECISION</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Target Ports Assault Grid (How Hackers Scan Ports) */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300 flex items-center">
            <Crosshair className="w-4 h-4 text-red-400 mr-2" />
            Target Listening Ports Assault Radar (Hacker Target Matrix)
          </h4>
          <span className="text-[11px] font-mono text-slate-500">Live Port Probes</span>
        </div>
        <p className="text-[11px] text-slate-400">
          Visual radar indicating which service ports on this machine are receiving connection probes or scanning sweeps:
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-3 pt-2">
          {portAssaultGrid.map((p) => {
            const isAttacked = p.status === 'UNDER_ATTACK' || (latestAlert && latestAlert.dst_port === p.port);
            return (
              <div
                key={p.port}
                className={`p-3 rounded-lg border text-center font-mono transition-all ${
                  isAttacked
                    ? 'bg-red-950/60 border-red-500 text-red-300 shadow-md shadow-red-500/20 animate-pulse'
                    : 'bg-slate-900 border-slate-800 text-slate-300'
                }`}
              >
                <div className="text-xs font-bold text-white">{p.port}</div>
                <div className="text-[10px] text-slate-400 truncate">{p.service}</div>
                <div className={`text-[10px] font-bold mt-1.5 ${
                  isAttacked ? 'text-red-400' : 'text-emerald-400'
                }`}>
                  {isAttacked ? 'HIT' : 'NORMAL'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Cyber Attack Terminal Log (Hacker Feed) */}
      <div className="bg-black border border-slate-800 rounded-xl p-5 shadow-2xl font-mono text-xs space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center space-x-2 text-emerald-400 font-bold">
            <Terminal className="w-4 h-4" />
            <span className="uppercase text-[11px] tracking-wider">Hacker Reconnaissance & Intrusion Feed</span>
          </div>
          <span className="text-[10px] text-slate-500">RAW FORENSIC TELEMETRY</span>
        </div>

        <div className="space-y-1.5 max-h-48 overflow-y-auto text-[11px]">
          {liveEvents.slice(0, 8).map((ev, i) => (
            <div key={i} className="flex items-center justify-between text-slate-400 hover:text-white font-mono py-0.5 border-b border-slate-900">
              <div className="flex items-center space-x-2 truncate">
                <span className="text-slate-600">[{ev.timestamp ? ev.timestamp.slice(11, 19) : 'LIVE'}]</span>
                <span className={`font-bold ${ev.is_malicious ? 'text-red-400' : 'text-emerald-400'}`}>
                  {ev.is_malicious ? '⚡ MALICIOUS_FLOW' : '✓ BENIGN_STREAM'}
                </span>
                <span className="text-slate-300 truncate">
                  {ev.src_ip}:{ev.src_port} &rarr; {ev.dst_ip}:{ev.dst_port}
                </span>
              </div>
              <div className="flex items-center space-x-2 shrink-0 ml-2">
                <span className="text-cyan-400">{ev.protocol}</span>
                <span className={`px-1.5 py-0.2 rounded text-[10px] ${
                  ev.is_malicious ? 'bg-red-950 text-red-300 border border-red-500/40' : 'text-slate-500'
                }`}>
                  {ev.prediction} ({((ev.confidence || 0) * 100).toFixed(0)}%)
                </span>
              </div>
            </div>
          ))}
          {liveEvents.length === 0 && (
            <div className="text-slate-600 py-4 text-center">
              Listening for packet streams on active adapter...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
