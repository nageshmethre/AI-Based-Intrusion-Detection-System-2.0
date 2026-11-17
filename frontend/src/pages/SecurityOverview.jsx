import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  AlertTriangle, 
  Layers, 
  ArrowUpRight 
} from 'lucide-react';
import { 
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, 
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend 
} from 'recharts';
import { fetchOverview } from '../services/api';

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

export default function SecurityOverview({ pulseHistory = [], onNavigateToThreats }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="space-y-6">
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

      {/* Real-time Throughput Area Chart */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Live Network Traffic Activity (Packets / Second)
            </h3>
            <p className="text-xs text-slate-400">Continuous 1-second pulse telemetry stream</p>
          </div>
          <div className="flex items-center space-x-2 text-xs text-cyan-400 font-semibold bg-cyan-950/40 px-3 py-1 rounded-full border border-cyan-800/40">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            <span>STREAMING</span>
          </div>
        </div>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={pulseHistory}>
              <defs>
                <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.6}/>
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="timestamp" stroke="#64748B" fontSize={11} />
              <YAxis stroke="#64748B" fontSize={11} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
              />
              <Area type="monotone" dataKey="packets_per_sec" stroke="#3B82F6" strokeWidth={2} fillOpacity={1} fill="url(#colorPps)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

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

      {/* Recent Alerts Feed Table */}
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
                <th className="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {data?.recent_alerts?.length > 0 ? (
                data.recent_alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-3 text-slate-400 font-mono">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-white">
                      {alert.title}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-cyan-400 font-medium">
                      {alert.src_ip}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {alert.dst_ip}:{alert.dst_port || 0}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        alert.detection_type === 'MACHINE_LEARNING' 
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' 
                          : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                      }`}>
                        {alert.detection_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                        alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                        alert.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        'bg-slate-700 text-slate-300'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        alert.status === 'OPEN' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {alert.status}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500">
                    No threat alerts detected yet. System is monitoring network.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
