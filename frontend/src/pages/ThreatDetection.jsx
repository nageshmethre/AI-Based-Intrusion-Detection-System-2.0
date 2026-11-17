import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Filter, 
  Cpu, 
  FileCode,
  ExternalLink
} from 'lucide-react';
import { fetchThreatAlerts, updateAlertStatus } from '../services/api';

export default function ThreatDetection({ liveAlerts = [] }) {
  const [alerts, setAlerts] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterType, setFilterType] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const loadAlerts = async () => {
    try {
      const res = await fetchThreatAlerts(100, 0);
      if (res?.items) setAlerts(res.items);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  // Merge live incoming alerts
  useEffect(() => {
    if (!liveAlerts.length) return;
    const latest = liveAlerts[0];
    setAlerts((prev) => {
      if (prev.some((a) => a.id === latest.id)) return prev;
      return [latest, ...prev];
    });
  }, [liveAlerts]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
      );
    } catch (e) {
      console.error(e);
      alert('Failed to update alert status');
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && a.status !== filterStatus) return false;
    if (filterType !== 'ALL' && a.detection_type !== filterType) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header and Filter Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider flex items-center">
            <ShieldAlert className="w-5 h-5 text-red-500 mr-2" />
            Threat Detection & Incident Response Center
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time correlation of AI model classifications and signature rules
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Detection Engine Type Filter */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Detection Types</option>
            <option value="MACHINE_LEARNING">Machine Learning</option>
            <option value="RULE_BASED">Rule-Based</option>
          </select>
        </div>
      </div>

      {/* Alerts Grid */}
      <div className="space-y-4">
        {filteredAlerts.length > 0 ? (
          filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`bg-slate-900 border rounded-xl p-5 shadow-lg transition-all ${
                alert.status === 'OPEN'
                  ? alert.severity === 'CRITICAL'
                    ? 'border-red-500/40 bg-gradient-to-r from-red-950/20 via-slate-900 to-slate-900'
                    : 'border-slate-800'
                  : 'border-slate-800/60 opacity-80'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                {/* Alert Body */}
                <div className="space-y-2 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Severity Badge */}
                    <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                      alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      alert.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-slate-700 text-slate-300'
                    }`}>
                      {alert.severity}
                    </span>

                    {/* Detection Type Badge */}
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold flex items-center ${
                      alert.detection_type === 'MACHINE_LEARNING'
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                        : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                    }`}>
                      {alert.detection_type === 'MACHINE_LEARNING' ? (
                        <Cpu className="w-3.5 h-3.5 mr-1 text-purple-400" />
                      ) : (
                        <FileCode className="w-3.5 h-3.5 mr-1 text-blue-400" />
                      )}
                      {alert.detection_type}
                    </span>

                    {/* Status Badge */}
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      alert.status === 'OPEN' ? 'bg-red-500/20 text-red-400' :
                      alert.status === 'INVESTIGATING' ? 'bg-amber-500/20 text-amber-400' :
                      alert.status === 'RESOLVED' ? 'bg-emerald-500/20 text-emerald-400' :
                      'bg-slate-700 text-slate-400'
                    }`}>
                      {alert.status}
                    </span>

                    <span className="text-xs text-slate-500 font-mono">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <h4 className="text-base font-bold text-white tracking-wide">
                    {alert.title}
                  </h4>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {alert.description}
                  </p>

                  {/* Flow Endpoint Metadata */}
                  <div className="flex flex-wrap items-center gap-4 text-xs font-mono pt-1 text-slate-400">
                    <div>
                      Source IP: <span className="text-cyan-400 font-bold">{alert.src_ip}</span>
                    </div>
                    <div>
                      Target: <span className="text-white font-bold">{alert.dst_ip}:{alert.dst_port || 0}</span>
                    </div>
                    <div>
                      Category: <span className="text-amber-400 font-bold">{alert.threat_category}</span>
                    </div>
                    <div>
                      Confidence: <span className="text-emerald-400 font-bold">{((alert.confidence || 1) * 100).toFixed(1)}%</span>
                    </div>
                  </div>

                  {/* Extra Details JSON preview if exists */}
                  {alert.details && Object.keys(alert.details).length > 0 && (
                    <div className="mt-2 p-2.5 bg-slate-950/80 rounded border border-slate-800 text-[11px] font-mono text-slate-400 overflow-x-auto">
                      <span className="text-slate-500 uppercase block mb-1">Telemetry Evidence:</span>
                      {JSON.stringify(alert.details, null, 2)}
                    </div>
                  )}
                </div>

                {/* Workflow Actions */}
                <div className="flex md:flex-col items-center gap-2 pt-2 md:pt-0">
                  {alert.status !== 'RESOLVED' && (
                    <button
                      onClick={() => handleStatusChange(alert.id, 'RESOLVED')}
                      className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center shadow transition-colors w-full justify-center"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                      Resolve
                    </button>
                  )}

                  {alert.status === 'OPEN' && (
                    <button
                      onClick={() => handleStatusChange(alert.id, 'INVESTIGATING')}
                      className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold flex items-center shadow transition-colors w-full justify-center"
                    >
                      <Clock className="w-3.5 h-3.5 mr-1.5" />
                      Investigate
                    </button>
                  )}

                  {alert.status !== 'FALSE_POSITIVE' && (
                    <button
                      onClick={() => handleStatusChange(alert.id, 'FALSE_POSITIVE')}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold border border-slate-700 transition-colors w-full justify-center"
                    >
                      False Positive
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-500">
            <ShieldAlert className="w-10 h-10 mx-auto mb-3 text-slate-600" />
            <p className="text-sm font-semibold">No threat alerts matching your filter criteria.</p>
          </div>
        )}
      </div>
    </div>
  );
}
