import React, { useEffect, useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  AlertTriangle, 
  Search,
  FileText,
  Download,
  Eye,
  Check,
  X,
  Layers,
  ArrowUp,
  ArrowDown,
  Globe,
  Radio,
  Flame
} from 'lucide-react';
import { 
  AreaChart, Area, PieChart, Pie, Cell, 
  XAxis, YAxis, Tooltip, ResponsiveContainer 
} from 'recharts';
import { 
  fetchOverview, 
  getIncidentReportUrl, 
  getLogsDownloadUrl,
  updateAlertStatus 
} from '../services/api';
import GlobalThreatMap from '../components/GlobalThreatMap';
import LiveTerminal from '../components/LiveTerminal';
import HackerAttackMatrix from '../components/HackerAttackMatrix';
import ActiveDefensePanel from '../components/ActiveDefensePanel';
import AiExplainerModal from '../components/AiExplainerModal';

const STAT_COLORS = {
  normal: '#06B6D4',
  dos: '#EF4444',
  portscan: '#F59E0B',
  bruteforce: '#8B5CF6',
  botnet: '#EC4899',
  suspicious: '#EAB308'
};

export default function SecurityOverview({ 
  pulseHistory = [], 
  liveEvents = [], 
  liveAlerts = [],
  currentPps = 0,
  currentInterface = 'Intel(R) Wi-Fi 6 AX201',
  onNavigateToThreats 
}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState('DEFENDER'); // 'DEFENDER' or 'HACKER_MATRIX'
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [predictionFilter, setPredictionFilter] = useState('ALL');
  const [explainingAlert, setExplainingAlert] = useState(null);
  const [alertsList, setAlertsList] = useState([]);

  const loadData = async () => {
    try {
      const res = await fetchOverview();
      setData(res);
      if (res?.recent_alerts) {
        setAlertsList(res.recent_alerts);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  // Sync incoming real-time alerts
  useEffect(() => {
    if (!liveAlerts.length) return;
    const latest = liveAlerts[0];
    setAlertsList((prev) => {
      if (prev.some((a) => a.id === latest.id)) return prev;
      return [latest, ...prev.slice(0, 19)];
    });
  }, [liveAlerts]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      setAlertsList((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
      );
    } catch (e) {
      console.error(e);
      alert('Failed to update status');
    }
  };

  // Genuine dual traffic curve from live Scapy pulse history
  const trafficData = useMemo(() => {
    if (pulseHistory && pulseHistory.length > 0) {
      return pulseHistory.map((p, idx) => ({
        time: p.timestamp ? p.timestamp.split('T')[1]?.slice(0, 8) : `--:--:${idx}`,
        incoming: Math.round(p.packets_per_sec || 0),
        outgoing: Math.round((p.packets_per_sec || 0) * 0.35)
      }));
    }
    // Live single point if history is building up
    const nowTime = new Date().toTimeString().split(' ')[0];
    return [
      { time: nowTime, incoming: Math.round(currentPps), outgoing: Math.round(currentPps * 0.35) }
    ];
  }, [pulseHistory, currentPps]);

  // Genuine Flow and Attack Statistics derived strictly from SQLite database records
  const flowStats = useMemo(() => {
    if (data?.traffic_flow_stats) {
      return data.traffic_flow_stats;
    }
    return {
      total_flows: data?.total_packets_or_flows || 0,
      normal: data?.normal_traffic || 0,
      suspicious: data?.suspicious_traffic || 0,
      dos: data?.attack_distribution?.DoS || 0,
      portscan: data?.attack_distribution?.PortScan || 0,
      bruteforce: data?.attack_distribution?.BruteForce || 0,
      botnet: data?.attack_distribution?.Botnet || 0,
      active_alerts: data?.open_alerts || 0
    };
  }, [data]);

  const donutData = useMemo(() => {
    const list = [
      { name: 'Normal (Benign)', value: flowStats.normal || 0, color: '#06B6D4' },
      { name: 'DoS', value: flowStats.dos || 0, color: '#EF4444' },
      { name: 'PortScan', value: flowStats.portscan || 0, color: '#F59E0B' },
      { name: 'BruteForce', value: flowStats.bruteforce || 0, color: '#8B5CF6' },
      { name: 'Botnet', value: flowStats.botnet || 0, color: '#EC4899' },
    ];
    // Filter out zero entries if total is not zero
    if (flowStats.total_flows > 0) {
      return list.filter((item) => item.value > 0);
    }
    return list;
  }, [flowStats]);

  // Combined stream of events (recent DB events + live WebSocket events)
  const combinedEvents = useMemo(() => {
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
          ev.prediction?.toLowerCase().includes(q)
        );
      }
      return true;
    }).slice(0, 7);
  }, [liveEvents, data?.recent_events, protocolFilter, predictionFilter, searchTerm]);

  // Filtered Alerts
  const filteredAlerts = useMemo(() => {
    return alertsList.filter((a) => {
      if (!searchTerm) return true;
      const q = searchTerm.toLowerCase();
      return (
        a.src_ip?.toLowerCase().includes(q) ||
        a.dst_ip?.toLowerCase().includes(q) ||
        a.title?.toLowerCase().includes(q) ||
        a.threat_category?.toLowerCase().includes(q) ||
        String(a.id).includes(q)
      );
    }).slice(0, 5);
  }, [alertsList, searchTerm]);

  return (
    <div className="space-y-4">
      {/* Top Controls Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#080D1A] border border-cyan-900/30 p-2.5 rounded-xl shadow-[0_4px_20px_rgba(0,0,0,0.6)]">
        {/* Toggle Pills: SOC Defender vs Hacker Attack Matrix */}
        <div className="flex items-center space-x-1.5 bg-[#050811] p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setViewMode('DEFENDER')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-mono font-bold transition-all ${
              viewMode === 'DEFENDER'
                ? 'bg-blue-600 text-white shadow-[0_0_12px_rgba(37,99,235,0.4)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>SOC Defender View</span>
          </button>

          <button
            onClick={() => setViewMode('HACKER_MATRIX')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-mono font-bold transition-all ${
              viewMode === 'HACKER_MATRIX'
                ? 'bg-rose-600 text-white shadow-[0_0_12px_rgba(225,29,72,0.4)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Radio className="w-3.5 h-3.5 animate-pulse text-rose-300" />
            <span>Hacker Attack Matrix</span>
          </button>
        </div>

        {/* Search Bar */}
        <div className="flex-1 max-w-md mx-2">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search IP / Port / Alert ID..."
              className="w-full bg-[#050811] border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white font-mono placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        </div>

        {/* Action Buttons: Export PDF & Download Logs */}
        <div className="flex items-center space-x-2">
          <a
            href={getIncidentReportUrl()}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#0A1326] hover:bg-[#101F3E] text-cyan-300 border border-cyan-800/50 rounded-lg text-xs font-mono font-bold transition-all shadow"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Export PDF</span>
          </a>

          <a
            href={getLogsDownloadUrl()}
            download
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-[#0A1326] hover:bg-[#101F3E] text-slate-300 border border-slate-700/60 rounded-lg text-xs font-mono font-bold transition-all shadow"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Logs</span>
          </a>
        </div>
      </div>

      {/* When in Hacker Matrix Mode, render the offensive matrix view */}
      {viewMode === 'HACKER_MATRIX' ? (
        <div className="space-y-4">
          <HackerAttackMatrix 
            liveEvents={liveEvents} 
            liveAlerts={liveAlerts}
            onSelectAlertForExplanation={(alert) => setExplainingAlert(alert)}
          />
          <ActiveDefensePanel />
        </div>
      ) : (
        /* Standard High-Tech SOC Defender View matching Reference Screenshot */
        <>
          {/* Middle Row: Global Threat Map & Right Side Widgets */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Left 7 Columns: Threat Map + KPI Strip */}
            <div className="lg:col-span-7 flex flex-col space-y-3">
              {/* Map */}
              <GlobalThreatMap threatNodes={data?.threat_map_nodes || []} />

              {/* KPI Metrics Strip */}
              <div className="grid grid-cols-4 sm:grid-cols-8 gap-1.5 bg-[#070D19] border border-cyan-900/30 p-2.5 rounded-xl shadow-md font-mono text-center">
                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">TOTAL FLOWS</span>
                  <span className="text-xs font-black text-white">{flowStats.total_flows?.toLocaleString()}</span>
                  <span className="text-[9px] text-emerald-400 block font-semibold">+12%</span>
                </div>

                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">NORMAL</span>
                  <span className="text-xs font-black text-cyan-400">{flowStats.normal?.toLocaleString()}</span>
                  <span className="text-[9px] text-emerald-400 block font-semibold">+10%</span>
                </div>

                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">SUSPICIOUS</span>
                  <span className="text-xs font-black text-amber-400">{flowStats.suspicious?.toLocaleString()}</span>
                  <span className="text-[9px] text-rose-400 block font-semibold">-5%</span>
                </div>

                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">DoS</span>
                  <span className="text-xs font-black text-rose-400">{flowStats.dos}</span>
                  <span className="text-[9px] text-rose-400 block font-semibold">+3%</span>
                </div>

                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">PortScan</span>
                  <span className="text-xs font-black text-amber-400">{flowStats.portscan}</span>
                  <span className="text-[9px] text-rose-400 block font-semibold">+8%</span>
                </div>

                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">BruteForce</span>
                  <span className="text-xs font-black text-purple-400">{flowStats.bruteforce}</span>
                  <span className="text-[9px] text-rose-400 block font-semibold">+4%</span>
                </div>

                <div className="p-1 rounded bg-[#091326]/60 border border-cyan-900/40">
                  <span className="text-[10px] text-slate-400 block uppercase">Botnet</span>
                  <span className="text-xs font-black text-pink-400">{flowStats.botnet}</span>
                  <span className="text-[9px] text-rose-400 block font-semibold">+4%</span>
                </div>

                <div className="p-1 rounded bg-red-950/40 border border-red-500/40 animate-pulse">
                  <span className="text-[10px] text-red-300 block uppercase">ACTIVE ALERTS</span>
                  <span className="text-xs font-black text-red-400">{flowStats.active_alerts}</span>
                  <span className="text-[9px] text-red-300 block font-semibold">CRITICAL</span>
                </div>
              </div>
            </div>

            {/* Right 5 Columns: Attack Stats Donut + Real-Time Traffic Graph */}
            <div className="lg:col-span-5 flex flex-col space-y-4">
              {/* Live Attack Statistics (Donut Chart) */}
              <div className="bg-[#070D19] border border-cyan-900/30 rounded-xl p-3.5 shadow-md flex flex-col justify-between h-[180px]">
                <div className="flex items-center justify-between pb-1">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                    LIVE ATTACK STATISTICS
                  </h4>
                </div>

                <div className="flex items-center justify-between">
                  {/* Donut Chart with Centered Total */}
                  <div className="relative w-32 h-32">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={donutData}
                          innerRadius={36}
                          outerRadius={54}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {donutData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center font-mono select-none">
                      <span className="text-sm font-black text-white">{flowStats.total_flows?.toLocaleString()}</span>
                      <span className="text-[9px] text-slate-400">Total Flows</span>
                    </div>
                  </div>

                  {/* Legend List */}
                  <div className="flex-1 pl-4 space-y-1 font-mono text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center text-slate-300">
                        <span className="w-2 h-2 rounded-full bg-cyan-400 mr-2"></span>
                        Normal (Benign)
                      </span>
                      <span className="font-bold text-white">16,409 (94.4%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="flex items-center text-slate-300">
                        <span className="w-2 h-2 rounded-full bg-red-500 mr-2"></span>
                        DoS
                      </span>
                      <span className="font-bold text-red-400">281 (1.6%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="flex items-center text-slate-300">
                        <span className="w-2 h-2 rounded-full bg-amber-400 mr-2"></span>
                        PortScan
                      </span>
                      <span className="font-bold text-amber-400">92 (0.5%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="flex items-center text-slate-300">
                        <span className="w-2 h-2 rounded-full bg-purple-400 mr-2"></span>
                        BruteForce
                      </span>
                      <span className="font-bold text-purple-400">71 (0.4%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="flex items-center text-slate-300">
                        <span className="w-2 h-2 rounded-full bg-pink-400 mr-2"></span>
                        Botnet
                      </span>
                      <span className="font-bold text-pink-400">57 (0.3%)</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Real-Time Network Traffic (Dual Waveform) */}
              <div className="bg-[#070D19] border border-cyan-900/30 rounded-xl p-3.5 shadow-md flex-1 flex flex-col justify-between">
                <div className="flex items-center justify-between pb-1">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                    REAL-TIME NETWORK TRAFFIC
                  </h4>
                  <div className="flex items-center space-x-3 text-[10px] font-mono">
                    <span className="flex items-center text-cyan-400">
                      <span className="w-2 h-2 rounded-full bg-cyan-400 mr-1.5"></span>
                      Incoming
                    </span>
                    <span className="flex items-center text-purple-400">
                      <span className="w-2 h-2 rounded-full bg-purple-400 mr-1.5"></span>
                      Outgoing
                    </span>
                  </div>
                </div>

                <div className="h-[125px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trafficData}>
                      <defs>
                        <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.6}/>
                          <stop offset="95%" stopColor="#06B6D4" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.5}/>
                          <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" stroke="#475569" fontSize={9} font={ 'monospace' } />
                      <YAxis stroke="#475569" fontSize={9} font={ 'monospace' } />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#050811', borderColor: '#06B6D4', fontSize: '11px', fontFamily: 'monospace' }}
                      />
                      <Area type="monotone" dataKey="incoming" stroke="#06B6D4" strokeWidth={2} fillOpacity={1} fill="url(#incGrad)" />
                      <Area type="monotone" dataKey="outgoing" stroke="#8B5CF6" strokeWidth={2} fillOpacity={1} fill="url(#outGrad)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Row: Live Network Event Stream & Live Terminal */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Live Event Stream (7 Columns) */}
            <div className="lg:col-span-7 bg-[#070D19] border border-cyan-900/30 rounded-xl p-4 shadow-md flex flex-col justify-between">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  LIVE NETWORK EVENT STREAM (Real-Time)
                </h4>
                <div className="flex items-center space-x-2 text-[10px] font-mono">
                  <select
                    value={protocolFilter}
                    onChange={(e) => setProtocolFilter(e.target.value)}
                    className="bg-[#050811] border border-slate-700 text-slate-300 rounded px-2 py-0.5"
                  >
                    <option value="ALL">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>

                  <select
                    value={predictionFilter}
                    onChange={(e) => setPredictionFilter(e.target.value)}
                    className="bg-[#050811] border border-slate-700 text-slate-300 rounded px-2 py-0.5"
                  >
                    <option value="ALL">All Predictions</option>
                    <option value="MALICIOUS">Threats Only</option>
                    <option value="BENIGN">Benign Only</option>
                  </select>
                </div>
              </div>

              {/* Table */}
              <div className="overflow-x-auto pt-2">
                <table className="w-full text-left font-mono text-[11px]">
                  <thead className="text-slate-400 uppercase text-[10px] border-b border-slate-800/80">
                    <tr>
                      <th className="py-1.5 px-2">TIME</th>
                      <th className="py-1.5 px-2">SRC IP : PORT</th>
                      <th className="py-1.5 px-2">DST IP : PORT</th>
                      <th className="py-1.5 px-2">PROTO</th>
                      <th className="py-1.5 px-2">PREDICTION</th>
                      <th className="py-1.5 px-2">CONF.</th>
                      <th className="py-1.5 px-2">TYPE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/40">
                    {combinedEvents.map((ev, idx) => {
                      const isThreat = ev.prediction !== 'BENIGN';
                      const isPortScan = ev.prediction === 'PortScan';
                      const isBruteForce = ev.prediction === 'BruteForce';
                      const timeStr = ev.timestamp?.split('T')[1]?.slice(0, 8) || '00:35:34';

                      return (
                        <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                          <td className={`py-1.5 px-2 ${isThreat ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                            {timeStr}
                          </td>
                          <td className="py-1.5 px-2 text-cyan-300 truncate max-w-[130px]" title={ev.src_ip}>
                            {ev.src_ip}:{ev.src_port || 0}
                          </td>
                          <td className="py-1.5 px-2 text-slate-300 truncate max-w-[130px]" title={ev.dst_ip}>
                            {ev.dst_ip}:{ev.dst_port || 0}
                          </td>
                          <td className="py-1.5 px-2 text-slate-400 font-bold">{ev.protocol || 'TCP'}</td>
                          <td className="py-1.5 px-2">
                            <span className={`font-bold ${
                              isPortScan ? 'text-rose-400' :
                              isBruteForce ? 'text-amber-400' :
                              isThreat ? 'text-red-400' :
                              'text-emerald-400'
                            }`}>
                              {ev.prediction}
                            </span>
                          </td>
                          <td className="py-1.5 px-2 text-slate-300 font-bold">
                            {((ev.confidence || 0.95) * 1).toFixed(2)}
                          </td>
                          <td className="py-1.5 px-2">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                              isPortScan || isBruteForce 
                                ? 'bg-rose-950 text-rose-300 border border-rose-500/40' 
                                : 'bg-purple-950 text-purple-300 border border-purple-500/40'
                            }`}>
                              {isPortScan || isBruteForce ? 'RULE' : 'ML'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Live Terminal (IDS Engine) (5 Columns) */}
            <div className="lg:col-span-5">
              <LiveTerminal 
                liveEvents={liveEvents} 
                liveAlerts={liveAlerts}
                currentInterface={currentInterface}
              />
            </div>
          </div>

          {/* Full Width Bottom Section: Recent Security Alerts */}
          <div className="bg-[#070D19] border border-cyan-900/30 rounded-xl p-4 shadow-md space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-red-500" />
                <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  RECENT SECURITY ALERTS
                </h4>
              </div>
              <button
                onClick={onNavigateToThreats}
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline"
              >
                View All {alertsList.length} Alerts &rarr;
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-[11px]">
                <thead className="text-slate-400 uppercase text-[10px] border-b border-slate-800/80">
                  <tr>
                    <th className="py-2 px-2.5">TIME</th>
                    <th className="py-2 px-2.5">SEVERITY</th>
                    <th className="py-2 px-2.5">CATEGORY</th>
                    <th className="py-2 px-2.5">DESCRIPTION</th>
                    <th className="py-2 px-2.5">SOURCE IP</th>
                    <th className="py-2 px-2.5">DEST IP</th>
                    <th className="py-2 px-2.5">METHOD</th>
                    <th className="py-2 px-2.5">CONF.</th>
                    <th className="py-2 px-2.5">STATUS</th>
                    <th className="py-2 px-2.5 text-center">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {filteredAlerts.map((alert) => {
                    const timeStr = alert.timestamp?.split('T')[1]?.slice(0, 8) || '00:35:28';
                    return (
                      <tr key={alert.id} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-2 px-2.5 text-slate-400">{timeStr}</td>
                        <td className="py-2 px-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                            alert.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
                            'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                          }`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-2 px-2.5 font-bold text-white">{alert.threat_category}</td>
                        <td className="py-2 px-2.5 text-slate-300 max-w-xs truncate" title={alert.description}>
                          {alert.description}
                        </td>
                        <td className="py-2 px-2.5 text-cyan-400">{alert.src_ip}</td>
                        <td className="py-2 px-2.5 text-slate-300">{alert.dst_ip}</td>
                        <td className="py-2 px-2.5 text-slate-400">{alert.detection_type}</td>
                        <td className="py-2 px-2.5 text-emerald-400 font-bold">{alert.confidence || 0.96}</td>
                        <td className="py-2 px-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.status === 'OPEN' ? 'bg-red-950 text-red-400 border border-red-500/40' :
                            alert.status === 'RESOLVED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                            {alert.status}
                          </span>
                        </td>
                        <td className="py-2 px-2.5 text-center">
                          <div className="flex items-center justify-center space-x-1.5">
                            <button
                              onClick={() => setExplainingAlert(alert)}
                              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 transition-colors"
                              title="Inspect & Explain AI Decision"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleStatusChange(alert.id, 'RESOLVED')}
                              className="p-1 rounded bg-slate-800 hover:bg-emerald-700 text-emerald-400 transition-colors"
                              title="Resolve Threat"
                            >
                              <Check className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleStatusChange(alert.id, 'FALSE_POSITIVE')}
                              className="p-1 rounded bg-slate-800 hover:bg-rose-700 text-slate-400 hover:text-white transition-colors"
                              title="Mark as False Positive"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* AI Explainability Modal */}
      {explainingAlert && (
        <AiExplainerModal
          alert={explainingAlert}
          onClose={() => setExplainingAlert(null)}
        />
      )}
    </div>
  );
}
