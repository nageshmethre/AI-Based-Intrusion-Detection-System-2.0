import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  AlertTriangle, 
  Layers, 
  ArrowUpRight,
  Crosshair,
  Lock,
  Cpu,
  FileText,
  Info,
  ExternalLink,
  Flame,
  Radio
} from 'lucide-react';
import { 
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, 
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend 
} from 'recharts';
import { fetchOverview, blockAttackerIp, getIncidentReportUrl } from '../services/api';
import HackerAttackMatrix from '../components/HackerAttackMatrix';
import ActiveDefensePanel from '../components/ActiveDefensePanel';
import AiExplainerModal from '../components/AiExplainerModal';

const ATTACK_COLORS = {
  PortScan: '#F59E0B',
  DoS: '#EF4444',
  BruteForce: '#8B5CF6',
  Botnet: '#EC4899',
  BENIGN: '#10B981',
};

const PROTOCOL_COLORS = {
  TCP: '#3B82F6',
  UDP: '#06B6D4',
  ICMP: '#EAB308',
  OTHER: '#6B7280',
};

export default function SecurityOverview({ 
  pulseHistory = [], 
  liveEvents = [], 
  liveAlerts = [],
  currentPps = 0,
  onNavigateToThreats 
}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState('DEFENDER'); // 'DEFENDER' or 'HACKER_MATRIX'
  const [explainingAlertId, setExplainingAlertId] = useState(null);
  const [actionMsg, setActionMsg] = useState('');

  const loadData = async () => {
    try {
      const res = await fetchOverview();
      setData(res);
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

  const handleQuickBlock = async (ip, category) => {
    try {
      const res = await blockAttackerIp({
        ip,
        reason: `Automated 1-Click Isolation: ${category}`,
        duration_seconds: 300,
        threat_category: category
      });
      setActionMsg(res.message);
      setTimeout(() => setActionMsg(''), 4000);
    } catch (err) {
      alert('Failed to isolate IP: ' + err.message);
    }
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <Activity className="w-6 h-6 animate-spin mr-3 text-blue-500" />
        <span>Loading SOC Overview Telemetry...</span>
      </div>
    );
  }

  // Format charts data
  const attackData = Object.entries(data?.attack_distribution || {}).map(([name, value]) => ({
    name,
    value,
    color: ATTACK_COLORS[name] || '#9CA3AF'
  }));

  const protocolData = Object.entries(data?.protocol_distribution || {}).map(([name, value]) => ({
    name,
    value,
    color: PROTOCOL_COLORS[name] || '#6B7280'
  }));

  const latestPps = pulseHistory.length > 0 ? pulseHistory[pulseHistory.length - 1].packets_per_sec : currentPps;

  return (
    <div className="space-y-6">
      {/* View Mode Switcher & Report Export Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        {/* Toggle Mode */}
        <div className="flex items-center space-x-2 bg-slate-950 p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => setViewMode('DEFENDER')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition ${
              viewMode === 'DEFENDER'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-4 h-4 mr-1 text-cyan-300" />
            <span>🛡️ SOC Defender View</span>
          </button>

          <button
            onClick={() => setViewMode('HACKER_MATRIX')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold font-mono transition ${
              viewMode === 'HACKER_MATRIX'
                ? 'bg-red-600 text-white shadow shadow-red-600/30'
                : 'text-slate-400 hover:text-red-400'
            }`}
          >
            <Crosshair className="w-4 h-4 mr-1 text-red-300 animate-pulse" />
            <span>⚡ Hacker Attack Matrix</span>
          </button>
        </div>

        {/* Forensic Report Download */}
        <div className="flex items-center space-x-3">
          <a
            href={getIncidentReportUrl()}
            target="_blank"
            rel="noreferrer"
            className="flex items-center space-x-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 border border-slate-700 rounded-lg text-xs font-semibold shadow transition"
          >
            <FileText className="w-4 h-4" />
            <span>Export Forensic Incident Report (PDF)</span>
            <ExternalLink className="w-3 h-3 ml-1" />
          </a>
        </div>
      </div>

      {actionMsg && (
        <div className="p-3 bg-red-950/80 border border-red-500 text-white rounded-lg text-xs font-mono font-semibold flex items-center space-x-2 animate-in fade-in">
          <Lock className="w-4 h-4 text-red-400 shrink-0" />
          <span>{actionMsg}</span>
        </div>
      )}

      {/* Conditionally render Hacker Matrix view vs Defender View */}
      {viewMode === 'HACKER_MATRIX' ? (
        <HackerAttackMatrix 
          liveAlerts={liveAlerts.length > 0 ? liveAlerts : data?.recent_alerts || []}
          liveEvents={liveEvents}
          pps={latestPps}
          blockedCount={0}
          onBlockIp={handleQuickBlock}
          onExplainAlert={(alertId) => setExplainingAlertId(alertId)}
        />
      ) : (
        <>
          {/* Metrics Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Packets / Flows */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Analyzed Network Events</p>
                  <h3 className="text-2xl font-bold text-white mt-1 font-mono">
                    {data?.total_packets_or_flows?.toLocaleString() || 0}
                  </h3>
                </div>
                <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg">
                  <Layers className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 flex items-center text-xs text-slate-400">
                <span className="text-emerald-400 font-semibold mr-1.5">100%</span>
                <span>Real-time inspection active</span>
              </div>
            </div>

            {/* Normal Traffic */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Normal Traffic (BENIGN)</p>
                  <h3 className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                    {data?.normal_traffic?.toLocaleString() || 0}
                  </h3>
                </div>
                <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg">
                  <ShieldCheck className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 text-xs text-slate-400">
                Legitimate verified communication
              </div>
            </div>

            {/* Suspicious Traffic */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Suspicious Traffic</p>
                  <h3 className="text-2xl font-bold text-amber-400 mt-1 font-mono">
                    {data?.suspicious_traffic?.toLocaleString() || 0}
                  </h3>
                </div>
                <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-lg">
                  <AlertTriangle className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 text-xs text-slate-400">
                Flagged by Random Forest ML
              </div>
            </div>

            {/* Active Threat Alerts */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Threat Alerts</p>
                  <h3 className="text-2xl font-bold text-red-500 mt-1 font-mono">
                    {data?.open_alerts || 0}
                  </h3>
                </div>
                <div className="p-2.5 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg">
                  <ShieldAlert className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 text-xs text-slate-400">
                Total recorded: {data?.total_alerts || 0}
              </div>
            </div>
          </div>

          {/* Real-time Throughput Area Chart with Contextual Explanation Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
                  <Activity className="w-4 h-4 text-cyan-400 mr-2" />
                  Live Network Traffic Activity (Packets / Second)
                </h3>
                <p className="text-xs text-slate-400">Continuous 1-second pulse telemetry stream from Scapy sniffer</p>
              </div>

              <div className="flex items-center space-x-3">
                <span className="text-xs font-mono text-cyan-400 font-bold bg-slate-950 px-3 py-1 rounded-lg border border-slate-800">
                  Rate: {latestPps} pkts/s
                </span>
                <div className="flex items-center space-x-1.5 text-xs text-emerald-400 font-semibold bg-emerald-950/40 px-3 py-1 rounded-full border border-emerald-800/40">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                  <span>LIVE FEED</span>
                </div>
              </div>
            </div>

            {/* Plain English Graph Guide Banner */}
            <div className="p-3 bg-blue-950/30 border border-blue-500/20 rounded-lg flex items-start space-x-2 text-[11px] text-slate-300">
              <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>
                <strong>How to Read This Graph:</strong> The horizontal axis is time; the vertical axis is packets per second. A steady line around 50–150 pkts/s represents normal background internet traffic. Sudden sharp spikes above 400+ pkts/s indicate intensive video streaming or potential denial-of-service/port scan probes.
              </span>
            </div>

            <div className="h-64 w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={pulseHistory}>
                  <defs>
                    <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="timestamp" stroke="#64748B" fontSize={11} />
                  <YAxis stroke="#64748B" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                    formatter={(val) => [`${val} packets/sec`, 'Traffic Rate']}
                  />
                  <Area type="monotone" dataKey="packets_per_sec" stroke="#06B6D4" strokeWidth={2.5} fillOpacity={1} fill="url(#colorPps)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Active Defense & Host IPS Firewall Component */}
          <ActiveDefensePanel />

          {/* Distribution Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attack Distribution Bar Chart */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2">
                Threat Attack Classification Distribution
              </h3>
              <p className="text-xs text-slate-400 mb-4">Categorized by AI model & security detection rules</p>
              <div className="h-60 w-full">
                {attackData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={attackData} layout="vertical" margin={{ left: 20 }}>
                      <XAxis type="number" stroke="#64748B" fontSize={11} />
                      <YAxis type="category" dataKey="name" stroke="#64748B" fontSize={11} width={80} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                      />
                      <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                        {attackData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-xs text-slate-500">
                    No threat alerts recorded yet. Network traffic is clean.
                  </div>
                )}
              </div>
            </div>

            {/* Protocol Distribution Donut Chart */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2">
                Transport Protocol Breakdown
              </h3>
              <p className="text-xs text-slate-400 mb-4">Live distribution of TCP, UDP, and ICMP frames</p>
              <div className="h-60 w-full flex items-center justify-center">
                {protocolData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={protocolData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={80}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {protocolData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                      />
                      <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: '12px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-xs text-slate-500">No protocol traffic captured yet.</div>
                )}
              </div>
            </div>
          </div>

          {/* Recent Alerts Feed Table with 1-Click IPS Block and AI Explain */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Recent Security Threat Incidents
                </h3>
                <p className="text-xs text-slate-400">High-priority detections requiring SOC analyst review</p>
              </div>
              <button
                onClick={onNavigateToThreats}
                className="flex items-center text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
              >
                <span>View All Alerts</span>
                <ArrowUpRight className="w-4 h-4 ml-1" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-800/60 text-slate-400 uppercase tracking-wider font-semibold">
                  <tr>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Threat Alert</th>
                    <th className="py-2.5 px-3">Source IP</th>
                    <th className="py-2.5 px-3">Target IP:Port</th>
                    <th className="py-2.5 px-3">Engine Type</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3 text-right">Defense Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono">
                  {data?.recent_alerts?.length > 0 ? (
                    data.recent_alerts.map((alert) => (
                      <tr key={alert.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2.5 px-3 text-slate-400">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 font-semibold text-white font-sans">
                          {alert.title}
                        </td>
                        <td className="py-2.5 px-3 text-cyan-400 font-medium">
                          {alert.src_ip}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {alert.dst_ip}:{alert.dst_port || 0}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            alert.detection_type === 'MACHINE_LEARNING' 
                              ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' 
                              : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                          }`}>
                            {alert.detection_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                            alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                            'bg-slate-700 text-slate-300'
                          }`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-right space-x-1.5 font-sans">
                          <button
                            onClick={() => setExplainingAlertId(alert.id)}
                            className="px-2 py-1 bg-blue-600/20 hover:bg-blue-600/40 text-cyan-300 rounded text-[10px] font-semibold border border-blue-500/30 transition"
                            title="Analyze Random Forest Decision Trees"
                          >
                            Explain AI
                          </button>
                          <button
                            onClick={() => handleQuickBlock(alert.src_ip, alert.threat_category)}
                            className="px-2 py-1 bg-red-600 hover:bg-red-500 text-white rounded text-[10px] font-bold shadow transition"
                            title="Block via Windows Firewall"
                          >
                            Block IP
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={7} className="py-6 text-center text-slate-500 font-sans">
                        No threat alerts detected yet. System is monitoring network.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* AI Decision Explainer Modal */}
      <AiExplainerModal 
        alertId={explainingAlertId} 
        onClose={() => setExplainingAlertId(null)} 
      />
    </div>
  );
}
