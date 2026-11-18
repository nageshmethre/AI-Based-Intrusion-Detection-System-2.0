import React, { useEffect, useState, useMemo } from 'react';
import { 
  X, 
  Maximize2, 
  Minimize2, 
  ShieldAlert, 
  Activity, 
  Globe, 
  Terminal as TerminalIcon, 
  BarChart3, 
  PieChart as PieChartIcon, 
  Search, 
  Filter, 
  Download, 
  CheckCircle, 
  AlertTriangle, 
  Cpu, 
  Network, 
  Radio, 
  Copy,
  Layers
} from 'lucide-react';
import { 
  AreaChart, Area, PieChart, Pie, Cell, 
  XAxis, YAxis, Tooltip, ResponsiveContainer 
} from 'recharts';
import GlobalThreatMap from './GlobalThreatMap';
import LiveTerminal from './LiveTerminal';

export default function MaximizedPanelModal({
  panelType,
  onClose,
  data = {},
  pulseHistory = [],
  liveEvents = [],
  liveAlerts = [],
  currentPps = 0,
  currentInterface = 'Default',
  flowStats = {},
  donutData = [],
  trafficData = [],
  combinedEvents = [],
  filteredAlerts = [],
  topSourceIps = [],
  topDestPorts = [],
  systemStatus = {},
  onStatusChange,
  onSelectAlertForExplanation
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [predictionFilter, setPredictionFilter] = useState('ALL');
  const [copiedLog, setCopiedLog] = useState(false);

  // Close modal on Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!panelType) return null;

  // Filtered event stream for maximized event stream view
  const modalEvents = useMemo(() => {
    const list = [...liveEvents, ...(data?.recent_events || [])];
    return list.filter((ev) => {
      if (protocolFilter !== 'ALL' && ev.protocol !== protocolFilter) return false;
      if (predictionFilter === 'MALICIOUS' && ev.prediction === 'BENIGN') return false;
      if (predictionFilter === 'BENIGN' && ev.prediction !== 'BENIGN') return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          ev.src_ip?.toLowerCase().includes(q) ||
          ev.dst_ip?.toLowerCase().includes(q) ||
          ev.prediction?.toLowerCase().includes(q) ||
          String(ev.src_port).includes(q) ||
          String(ev.dst_port).includes(q)
        );
      }
      return true;
    });
  }, [liveEvents, data?.recent_events, protocolFilter, predictionFilter, searchTerm]);

  // Panel titles and badges
  const titles = {
    MAP: { label: 'GLOBAL NETWORK THREAT MAP', icon: Globe, color: 'text-cyan-400' },
    ATTACK_STATS: { label: 'LIVE ATTACK STATISTICS & FORENSIC BREAKDOWN', icon: PieChartIcon, color: 'text-amber-400' },
    TRAFFIC_GRAPH: { label: 'REAL-TIME NETWORK TRAFFIC TELEMETRY ANALYZER', icon: Activity, color: 'text-purple-400' },
    EVENT_STREAM: { label: 'LIVE NETWORK EVENT STREAM (FULL FLOW INSPECTOR)', icon: BarChart3, color: 'text-blue-400' },
    TERMINAL: { label: 'HACKER COMMAND TERMINAL & IDS KERNEL LOGS', icon: TerminalIcon, color: 'text-emerald-400' },
    ALERTS: { label: 'SECURITY INCIDENT MANAGEMENT CONSOLE', icon: ShieldAlert, color: 'text-rose-400' },
    SYSTEM_STATUS: { label: 'SYSTEM SERVICES & NETWORK INTERFACE HEALTH', icon: Cpu, color: 'text-emerald-400' },
    TOP_TRAFFIC: { label: 'TOP TALKERS & DESTINATION PORTS MATRIX', icon: Network, color: 'text-cyan-400' }
  };

  const currentInfo = titles[panelType] || { label: 'ENLARGED SOC PANEL', icon: Maximize2, color: 'text-cyan-400' };
  const IconComponent = currentInfo.icon;

  return (
    <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md p-2 sm:p-5 flex items-center justify-center animate-in fade-in duration-200">
      {/* Click outside backdrop detector */}
      <div className="absolute inset-0" onClick={onClose} />

      {/* Main Modal Card */}
      <div className="relative w-full h-full max-w-7xl max-h-[94vh] bg-[#060B18] border-2 border-cyan-500/70 rounded-2xl shadow-[0_0_50px_rgba(6,182,212,0.35)] flex flex-col overflow-hidden z-10">
        {/* Modal Top Header Bar */}
        <div className="flex items-center justify-between px-5 py-3.5 bg-[#081024] border-b border-cyan-800/60 select-none">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-950/80 border border-cyan-600/40 rounded-lg">
              <IconComponent className={`w-5 h-5 ${currentInfo.color} animate-pulse`} />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  {currentInfo.label}
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-500/50 text-cyan-300">
                  BIG SIZE MODE
                </span>
              </div>
              <span className="text-[11px] font-mono text-slate-400 block">
                Live Interactive View &bull; High Resolution Telemetry
              </span>
            </div>
          </div>

          {/* Normal 'X' Close/Minimize Button */}
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-600 text-rose-300 hover:text-white border border-rose-500/50 hover:border-rose-400 transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body / Enlarged Content */}
        <div className="flex-1 p-4 sm:p-6 overflow-y-auto bg-[#040813] text-slate-200 font-mono space-y-4">
          {/* ========================================================= */}
          {/* 1. GLOBAL THREAT MAP MAXIMIZED                            */}
          {/* ========================================================= */}
          {panelType === 'MAP' && (
            <div className="h-full flex flex-col space-y-4">
              <div className="flex-1 min-h-[480px]">
                <GlobalThreatMap threatNodes={data?.threat_map_nodes || []} />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 bg-[#081024] p-3 rounded-xl border border-cyan-900/40 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Active Threat Nodes</span>
                  <span className="text-sm font-bold text-cyan-300">
                    {(data?.threat_map_nodes || []).length} Detected Sources
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Target Coordinates</span>
                  <span className="text-sm font-bold text-white">Your System (Host Machine)</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Projection Engine</span>
                  <span className="text-sm font-bold text-emerald-400">Equirectangular Live Mercator SVG</span>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 2. ATTACK STATISTICS MAXIMIZED                            */}
          {/* ========================================================= */}
          {panelType === 'ATTACK_STATS' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Large Donut Chart */}
                <div className="bg-[#081024] border border-cyan-900/40 rounded-xl p-5 flex flex-col items-center justify-center">
                  <h4 className="text-sm font-bold text-white uppercase tracking-wider mb-2">
                    Traffic Classification Breakdown
                  </h4>
                  <div className="relative w-64 h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={donutData}
                          innerRadius={75}
                          outerRadius={110}
                          paddingAngle={4}
                          dataKey="value"
                        >
                          {donutData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#050811',
                            borderColor: '#06B6D4',
                            borderRadius: '8px',
                            fontFamily: 'monospace'
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center font-mono select-none">
                      <span className="text-2xl font-black text-white">
                        {flowStats.total_flows?.toLocaleString()}
                      </span>
                      <span className="text-xs text-slate-400">Total Analyzed Flows</span>
                    </div>
                  </div>
                </div>

                {/* Granular Attack Stats Grid */}
                <div className="grid grid-cols-2 gap-3.5">
                  <div className="bg-[#09142A] border border-cyan-800/40 p-4 rounded-xl flex flex-col justify-between">
                    <span className="text-xs text-cyan-400 font-bold uppercase">Legitimate (BENIGN)</span>
                    <span className="text-3xl font-black text-white">{flowStats.normal?.toLocaleString()}</span>
                    <span className="text-[10px] text-emerald-400">Verified normal traffic stream</span>
                  </div>

                  <div className="bg-[#1A0A10] border border-rose-800/40 p-4 rounded-xl flex flex-col justify-between">
                    <span className="text-xs text-rose-400 font-bold uppercase">DoS / Flood</span>
                    <span className="text-3xl font-black text-rose-300">{flowStats.dos?.toLocaleString()}</span>
                    <span className="text-[10px] text-rose-400">High-volume packet bursts</span>
                  </div>

                  <div className="bg-[#1A1408] border border-amber-800/40 p-4 rounded-xl flex flex-col justify-between">
                    <span className="text-xs text-amber-400 font-bold uppercase">Port Reconnaissance</span>
                    <span className="text-3xl font-black text-amber-300">{flowStats.portscan?.toLocaleString()}</span>
                    <span className="text-[10px] text-amber-400">TCP Connect & Stealth sweeps</span>
                  </div>

                  <div className="bg-[#140A1A] border border-purple-800/40 p-4 rounded-xl flex flex-col justify-between">
                    <span className="text-xs text-purple-400 font-bold uppercase">Brute Force</span>
                    <span className="text-3xl font-black text-purple-300">{flowStats.bruteforce?.toLocaleString()}</span>
                    <span className="text-[10px] text-purple-400">Authentication failure clusters</span>
                  </div>

                  <div className="bg-[#1A0815] border border-pink-800/40 p-4 rounded-xl flex flex-col justify-between">
                    <span className="text-xs text-pink-400 font-bold uppercase">Botnet & C2</span>
                    <span className="text-3xl font-black text-pink-300">{flowStats.botnet?.toLocaleString()}</span>
                    <span className="text-[10px] text-pink-400">Periodic beaconing activity</span>
                  </div>

                  <div className="bg-red-950/60 border border-red-500 p-4 rounded-xl flex flex-col justify-between">
                    <span className="text-xs text-red-300 font-bold uppercase">Active Threats</span>
                    <span className="text-3xl font-black text-red-400">{flowStats.active_alerts?.toLocaleString()}</span>
                    <span className="text-[10px] text-red-300 font-bold animate-pulse">Critical escalation required</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 3. REAL-TIME TRAFFIC GRAPH MAXIMIZED                      */}
          {/* ========================================================= */}
          {panelType === 'TRAFFIC_GRAPH' && (
            <div className="space-y-4 h-full flex flex-col">
              <div className="flex items-center justify-between bg-[#081024] p-3 rounded-xl border border-cyan-900/40">
                <div className="flex items-center space-x-6 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Current Throughput</span>
                    <span className="text-base font-bold text-white">{currentPps} pkt/s</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Active Interface</span>
                    <span className="text-base font-bold text-cyan-300">{currentInterface}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Rolling Window</span>
                    <span className="text-base font-bold text-emerald-400">1-Second Pulse Stream</span>
                  </div>
                </div>

                <div className="flex items-center space-x-4 text-xs">
                  <span className="flex items-center text-cyan-400 font-bold">
                    <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 mr-2"></span>
                    Incoming Packets
                  </span>
                  <span className="flex items-center text-purple-400 font-bold">
                    <span className="w-2.5 h-2.5 rounded-full bg-purple-400 mr-2"></span>
                    Outgoing Packets
                  </span>
                </div>
              </div>

              {/* Big Area Chart */}
              <div className="flex-1 min-h-[420px] bg-[#070E20] border border-cyan-900/40 rounded-xl p-4">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trafficData}>
                    <defs>
                      <linearGradient id="modalIncGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.7}/>
                        <stop offset="95%" stopColor="#06B6D4" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="modalOutGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.6}/>
                        <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="#64748B" fontSize={11} />
                    <YAxis stroke="#64748B" fontSize={11} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#050811', borderColor: '#06B6D4', fontSize: '12px' }}
                    />
                    <Area type="monotone" dataKey="incoming" stroke="#06B6D4" strokeWidth={3} fillOpacity={1} fill="url(#modalIncGrad)" />
                    <Area type="monotone" dataKey="outgoing" stroke="#8B5CF6" strokeWidth={3} fillOpacity={1} fill="url(#modalOutGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 4. EVENT STREAM MAXIMIZED                                 */}
          {/* ========================================================= */}
          {panelType === 'EVENT_STREAM' && (
            <div className="space-y-4">
              {/* Filter controls */}
              <div className="flex flex-wrap items-center justify-between gap-3 bg-[#081024] p-3 rounded-xl border border-cyan-900/40">
                <div className="flex items-center space-x-2 flex-1 max-w-md">
                  <Search className="w-4 h-4 text-slate-500" />
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Search source IP, destination IP, port or classification..."
                    className="w-full bg-[#050811] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-400"
                  />
                </div>

                <div className="flex items-center space-x-2 text-xs">
                  <select
                    value={protocolFilter}
                    onChange={(e) => setProtocolFilter(e.target.value)}
                    className="bg-[#050811] border border-slate-700 text-slate-300 rounded px-3 py-1.5"
                  >
                    <option value="ALL">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>

                  <select
                    value={predictionFilter}
                    onChange={(e) => setPredictionFilter(e.target.value)}
                    className="bg-[#050811] border border-slate-700 text-slate-300 rounded px-3 py-1.5"
                  >
                    <option value="ALL">All Predictions</option>
                    <option value="MALICIOUS">Threats Only</option>
                    <option value="BENIGN">Benign Only</option>
                  </select>
                </div>
              </div>

              {/* Full Expanded Table */}
              <div className="overflow-x-auto rounded-xl border border-cyan-900/40 bg-[#070D1C]">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-[#0A142C] text-slate-400 uppercase text-[11px] border-b border-cyan-950">
                    <tr>
                      <th className="py-2.5 px-3">TIMESTAMP</th>
                      <th className="py-2.5 px-3">SOURCE ENDPOINT</th>
                      <th className="py-2.5 px-3">DESTINATION ENDPOINT</th>
                      <th className="py-2.5 px-3">PROTOCOL</th>
                      <th className="py-2.5 px-3">PREDICTION</th>
                      <th className="py-2.5 px-3">CONFIDENCE</th>
                      <th className="py-2.5 px-3">CLASSIFICATION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {modalEvents.slice(0, 35).map((ev, idx) => {
                      const isThreat = ev.prediction !== 'BENIGN';
                      const timeStr = ev.timestamp?.split('T')[1]?.slice(0, 8) || '00:00:00';

                      return (
                        <tr key={idx} className="hover:bg-cyan-950/20 transition-colors">
                          <td className={`py-2.5 px-3 ${isThreat ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                            {timeStr}
                          </td>
                          <td className="py-2.5 px-3 text-cyan-300 font-bold">
                            {ev.src_ip}:{ev.src_port || 0}
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">
                            {ev.dst_ip}:{ev.dst_port || 0}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 font-bold">{ev.protocol || 'TCP'}</td>
                          <td className="py-2.5 px-3 font-bold">
                            <span className={isThreat ? 'text-rose-400' : 'text-emerald-400'}>
                              {ev.prediction}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-white">
                            {((ev.confidence || 0.95) * 100).toFixed(1)}%
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              isThreat ? 'bg-red-950 text-red-300 border border-red-500/40' : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                            }`}>
                              {isThreat ? 'MALICIOUS' : 'BENIGN'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 5. TERMINAL MAXIMIZED                                     */}
          {/* ========================================================= */}
          {panelType === 'TERMINAL' && (
            <div className="h-full min-h-[500px]">
              <LiveTerminal 
                liveEvents={liveEvents} 
                liveAlerts={liveAlerts}
                currentInterface={currentInterface}
              />
            </div>
          )}

          {/* ========================================================= */}
          {/* 6. ALERTS MAXIMIZED                                       */}
          {/* ========================================================= */}
          {panelType === 'ALERTS' && (
            <div className="space-y-4">
              <div className="overflow-x-auto rounded-xl border border-cyan-900/40 bg-[#070D1C]">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-[#0A142C] text-slate-400 uppercase text-[11px] border-b border-cyan-950">
                    <tr>
                      <th className="py-3 px-3">TIME</th>
                      <th className="py-3 px-3">SEVERITY</th>
                      <th className="py-3 px-3">CATEGORY</th>
                      <th className="py-3 px-3">DESCRIPTION</th>
                      <th className="py-3 px-3">SOURCE IP</th>
                      <th className="py-3 px-3">DEST IP</th>
                      <th className="py-3 px-3">DETECTION METHOD</th>
                      <th className="py-3 px-3">CONF.</th>
                      <th className="py-3 px-3">STATUS</th>
                      <th className="py-3 px-3 text-center">ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredAlerts.map((alert) => {
                      const timeStr = alert.timestamp?.split('T')[1]?.slice(0, 8) || '00:00:00';
                      return (
                        <tr key={alert.id} className="hover:bg-cyan-950/20 transition-colors">
                          <td className="py-2.5 px-3 text-slate-400">{timeStr}</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500' :
                              alert.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-400 border border-rose-500' :
                              'bg-amber-500/20 text-amber-400 border border-amber-500'
                            }`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-bold text-white">{alert.threat_category}</td>
                          <td className="py-2.5 px-3 text-slate-300">{alert.description}</td>
                          <td className="py-2.5 px-3 text-cyan-300 font-bold">{alert.src_ip}</td>
                          <td className="py-2.5 px-3 text-slate-300">{alert.dst_ip}:{alert.dst_port || 0}</td>
                          <td className="py-2.5 px-3 text-slate-400">{alert.detection_type}</td>
                          <td className="py-2.5 px-3 text-emerald-400 font-bold">{((alert.confidence || 0.95) * 100).toFixed(0)}%</td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              alert.status === 'RESOLVED' ? 'bg-emerald-950 text-emerald-300' :
                              alert.status === 'FALSE_POSITIVE' ? 'bg-slate-800 text-slate-400' :
                              'bg-rose-950 text-rose-300 border border-rose-500/50 animate-pulse'
                            }`}>
                              {alert.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-center">
                            <div className="flex items-center justify-center space-x-1.5">
                              {onSelectAlertForExplanation && (
                                <button
                                  onClick={() => onSelectAlertForExplanation(alert)}
                                  className="px-2 py-1 bg-cyan-900/60 hover:bg-cyan-800 text-cyan-200 rounded text-[10px]"
                                  title="Explain AI Prediction"
                                >
                                  AI Explain
                                </button>
                              )}
                              {onStatusChange && (
                                <>
                                  <button
                                    onClick={() => onStatusChange(alert.id, 'RESOLVED')}
                                    className="px-2 py-1 bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 rounded text-[10px]"
                                    title="Mark Resolved"
                                  >
                                    Resolve
                                  </button>
                                  <button
                                    onClick={() => onStatusChange(alert.id, 'FALSE_POSITIVE')}
                                    className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px]"
                                    title="Mark False Positive"
                                  >
                                    False Pos
                                  </button>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 7. SYSTEM STATUS MAXIMIZED                                */}
          {/* ========================================================= */}
          {panelType === 'SYSTEM_STATUS' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-[#081024] p-5 rounded-xl border border-cyan-900/40 space-y-3">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                  Core Daemon & Service Health
                </h4>
                <div className="space-y-2 text-xs">
                  <div className="flex items-center justify-between p-2 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-300">Packet Capture Engine (Scapy + Npcap)</span>
                    <span className="text-emerald-400 font-bold">RUNNING</span>
                  </div>
                  <div className="flex items-center justify-between p-2 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-300">Random Forest AI Model (CIC-IDS2017)</span>
                    <span className="text-emerald-400 font-bold">ONLINE & INFERENCING</span>
                  </div>
                  <div className="flex items-center justify-between p-2 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-300">Rule-Based Threat Detection Kernel</span>
                    <span className="text-emerald-400 font-bold">ACTIVE (STEALTH/DDOS/SSH)</span>
                  </div>
                  <div className="flex items-center justify-between p-2 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-300">WebSocket Real-Time Broadcast Feeder</span>
                    <span className="text-emerald-400 font-bold">STREAMING</span>
                  </div>
                  <div className="flex items-center justify-between p-2 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-300">SQLite Forensic Database (WAL Mode)</span>
                    <span className="text-emerald-400 font-bold">CONNECTED & COMMITTING</span>
                  </div>
                  <div className="flex items-center justify-between p-2 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-300">Windows Defender Firewall IPS Module</span>
                    <span className="text-emerald-400 font-bold">ARMED & SAFEGUARDED</span>
                  </div>
                </div>
              </div>

              <div className="bg-[#081024] p-5 rounded-xl border border-cyan-900/40 space-y-3">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                  Interface & Hardware Telemetry
                </h4>
                <div className="space-y-2 text-xs">
                  <div className="p-3 bg-[#050811] rounded border border-slate-800">
                    <span className="text-slate-400 text-[10px] block uppercase">Selected Interface</span>
                    <span className="text-cyan-300 font-bold text-sm">{currentInterface}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-3 bg-[#050811] rounded border border-slate-800">
                      <span className="text-slate-400 text-[10px] block uppercase">Throughput</span>
                      <span className="text-white font-bold text-base">{currentPps} pkt/s</span>
                    </div>
                    <div className="p-3 bg-[#050811] rounded border border-slate-800">
                      <span className="text-slate-400 text-[10px] block uppercase">Database Total Flows</span>
                      <span className="text-emerald-400 font-bold text-base">{flowStats.total_flows?.toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 8. TOP TRAFFIC MAXIMIZED                                  */}
          {/* ========================================================= */}
          {panelType === 'TOP_TRAFFIC' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Top Source IPs */}
              <div className="bg-[#081024] p-5 rounded-xl border border-cyan-900/40 space-y-3">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                  Top Source IP Addresses
                </h4>
                <div className="space-y-2.5 text-xs">
                  {topSourceIps.map((item, idx) => (
                    <div key={idx} className="p-2.5 bg-[#050811] rounded border border-slate-800">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-cyan-300 font-bold">{item.ip}</span>
                        <span className="text-white font-black">{item.percentage}% ({item.count || 0} pkts)</span>
                      </div>
                      <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                          style={{ width: `${Math.min(100, Math.max(5, item.percentage))}%` }}
                        />
                      </div>
                    </div>
                  ))}
                  {topSourceIps.length === 0 && (
                    <div className="text-slate-500 italic py-4 text-center">
                      Awaiting source network traffic...
                    </div>
                  )}
                </div>
              </div>

              {/* Top Destination Ports */}
              <div className="bg-[#081024] p-5 rounded-xl border border-cyan-900/40 space-y-3">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                  Top Destination Service Ports
                </h4>
                <div className="space-y-2.5 text-xs">
                  {topDestPorts.map((item, idx) => (
                    <div key={idx} className="p-2.5 bg-[#050811] rounded border border-slate-800">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-purple-300 font-bold">Port {item.port} ({item.service || 'Unknown'})</span>
                        <span className="text-white font-black">{item.percentage}% ({item.count || 0} pkts)</span>
                      </div>
                      <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full"
                          style={{ width: `${Math.min(100, Math.max(5, item.percentage))}%` }}
                        />
                      </div>
                    </div>
                  ))}
                  {topDestPorts.length === 0 && (
                    <div className="text-slate-500 italic py-4 text-center">
                      Awaiting destination service traffic...
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Bottom Status Bar */}
        <div className="px-5 py-2.5 bg-[#081024] border-t border-cyan-950 flex items-center justify-between text-[11px] font-mono text-slate-400 select-none">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span>Real-time WebSocket feed active &bull; Live SOC Session</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-rose-950/60 text-slate-400 hover:text-rose-400 transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
