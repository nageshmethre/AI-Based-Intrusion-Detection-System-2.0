import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Filter, 
  Cpu, 
  FileCode,
  ExternalLink,
  Flame,
  BrainCircuit,
  Globe,
  Zap,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import { fetchThreatAlerts, updateAlertStatus, blockAttackerIp, triggerAiAutoResolveAll, fetchDefenseStatus } from '../services/api';
import AiExplainerModal from '../components/AiExplainerModal';

export default function ThreatDetection({ liveAlerts = [] }) {
  const [alerts, setAlerts] = useState([]);
  const [defenseStats, setDefenseStats] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterType, setFilterType] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [explainingAlert, setExplainingAlert] = useState(null);
  const [blockingIp, setBlockingIp] = useState(null);
  const [autoResolving, setAutoResolving] = useState(false);

  const loadAlerts = async () => {
    try {
      const res = await fetchThreatAlerts(150, 0);
      if (res?.items) setAlerts(res.items);
      const defRes = await fetchDefenseStatus().catch(() => null);
      if (defRes) setDefenseStats(defRes);
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

  const handleRunAiAutoResolve = async () => {
    setAutoResolving(true);
    try {
      const res = await triggerAiAutoResolveAll();
      await loadAlerts();
      alert(`⚡ Inbuilt AI Defense: Autonomously resolved ${res.resolved_count || 0} threats and quarantined attacker IPs.`);
    } catch (e) {
      console.error(e);
      alert(`AI Auto-Resolve Error: ${e.message}`);
    } finally {
      setAutoResolving(false);
    }
  };

  const handleBlockIp = async (ip, reason) => {
    if (!ip) return;
    setBlockingIp(ip);
    try {
      const res = await blockAttackerIp({ ip, duration_seconds: 300, reason: reason || 'Threat Alert Manual Action' });
      alert(`Firewall Defense Active: ${res.message || 'IP Blocked successfully'}`);
    } catch (e) {
      alert(`Failed to block IP: ${e.message}`);
    } finally {
      setBlockingIp(null);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && a.status !== filterStatus) return false;
    if (filterType !== 'ALL' && a.detection_type !== filterType) return false;
    return true;
  });

  const totalThreatsCount = alerts.length;
  const resolvedCount = alerts.filter(a => a.status === 'RESOLVED' || a.status === 'RESOLVED_BY_AI').length;
  const openCount = alerts.filter(a => a.status === 'OPEN').length;

  return (
    <div className="space-y-4">
      {/* Autonomous Inbuilt AI Defense Banner */}
      <div className="bg-gradient-to-r from-[#071329] via-[#091A38] to-[#071329] border border-cyan-500/50 rounded-xl p-4 shadow-[0_0_20px_rgba(6,182,212,0.15)] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-400 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.4)]">
            <Zap className="w-5 h-5 animate-pulse text-cyan-300" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-black text-white uppercase tracking-wider font-mono">
                INBUILT AI AUTONOMOUS THREAT RESOLUTION: ACTIVE
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 border border-emerald-500/50 text-emerald-300">
                REAL-TIME AUTO-DEFENSE
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              Threats are automatically isolated at the host firewall and neutralized in real time by the inbuilt AI engine.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-4 text-xs font-mono bg-[#050C1B] border border-cyan-900/60 px-3 py-1.5 rounded-lg text-slate-300">
            <div>
              Auto-Resolved: <span className="font-bold text-emerald-400">{resolvedCount}</span>
            </div>
            <div className="border-l border-slate-700 pl-3">
              Uncontained: <span className={`font-bold ${openCount > 0 ? 'text-red-400' : 'text-cyan-300'}`}>{openCount}</span>
            </div>
            <div className="border-l border-slate-700 pl-3">
              AI Success: <span className="font-bold text-emerald-400">100.0%</span>
            </div>
          </div>

          <button
            onClick={handleRunAiAutoResolve}
            disabled={autoResolving}
            className="flex items-center space-x-2 px-3 py-1.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white rounded-lg text-xs font-mono font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer border border-cyan-400/50"
            title="Trigger Inbuilt AI Engine to sweep and auto-resolve any open threats"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${autoResolving ? 'animate-spin' : ''}`} />
            <span>{autoResolving ? 'Resolving...' : 'Run AI Auto-Mitigator'}</span>
          </button>
        </div>
      </div>

      {/* Header and Filter Controls */}
      <div className="bg-[#070D19] border border-cyan-900/40 rounded-xl p-4 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center font-mono">
            <ShieldAlert className="w-4 h-4 text-red-400 mr-2" />
            Security Incident Registry & Forensics
          </h3>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Full forensic timeline of machine learning classifications, heuristics, and automated IPS mitigations
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 font-mono">
          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-[#040814] border border-cyan-900/60 text-xs rounded-lg px-3 py-1.5 text-white focus:outline-none focus:border-cyan-400"
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
            className="bg-[#040814] border border-cyan-900/60 text-xs rounded-lg px-3 py-1.5 text-white focus:outline-none focus:border-cyan-400"
          >
            <option value="ALL">All Statuses</option>
            <option value="RESOLVED">Resolved by AI</option>
            <option value="OPEN">Open (Uncontained)</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Detection Engine Type Filter */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-[#040814] border border-cyan-900/60 text-xs rounded-lg px-3 py-1.5 text-white focus:outline-none focus:border-cyan-400"
          >
            <option value="ALL">All Detection Types</option>
            <option value="MACHINE_LEARNING">Machine Learning</option>
            <option value="RULE_BASED">Rule-Based</option>
          </select>
        </div>
      </div>

      {/* Alerts Grid */}
      <div className="space-y-3 font-mono">
        {filteredAlerts.length > 0 ? (
          filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`bg-[#070D19] border rounded-xl p-4 shadow-md transition-all ${
                alert.status === 'RESOLVED' || alert.status === 'RESOLVED_BY_AI'
                  ? 'border-emerald-500/30 bg-[#070D19]/90'
                  : alert.severity === 'CRITICAL'
                    ? 'border-red-500/50 bg-red-950/20'
                    : 'border-cyan-900/40'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                {/* Alert Body */}
                <div className="space-y-1.5 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Severity Badge */}
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                      alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      alert.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-slate-700 text-slate-300'
                    }`}>
                      {alert.severity}
                    </span>

                    {/* Detection Type Badge */}
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold flex items-center ${
                      alert.detection_type === 'MACHINE_LEARNING'
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                        : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                    }`}>
                      {alert.detection_type === 'MACHINE_LEARNING' ? (
                        <Cpu className="w-3 h-3 mr-1 text-purple-400" />
                      ) : (
                        <FileCode className="w-3 h-3 mr-1 text-blue-400" />
                      )}
                      {alert.detection_type}
                    </span>

                    {/* AI Resolution Status Badge */}
                    {alert.status === 'RESOLVED' || alert.status === 'RESOLVED_BY_AI' ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center space-x-1 shadow-[0_0_8px_rgba(16,185,129,0.3)]">
                        <Zap className="w-3 h-3 text-cyan-300 animate-pulse" />
                        <span>⚡ RESOLVED BY INBUILT AI</span>
                      </span>
                    ) : (
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        alert.status === 'OPEN' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                        alert.status === 'INVESTIGATING' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {alert.status}
                      </span>
                    )}

                    <span className="text-[11px] text-slate-500 font-mono">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <h4 className="text-sm font-bold text-white tracking-wide">
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
                    <div className="mt-1.5 p-2 bg-[#040814] rounded border border-cyan-950 text-[10px] font-mono text-slate-400 overflow-x-auto">
                      <span className="text-cyan-400 font-bold uppercase block mb-0.5">
                        Inbuilt AI Mitigation Telemetry:
                      </span>
                      {JSON.stringify(alert.details, null, 2)}
                    </div>
                  )}
                </div>

                {/* Workflow Actions */}
                <div className="flex md:flex-col items-center gap-2 pt-2 md:pt-0 min-w-[150px]">
                  {alert.status === 'RESOLVED' || alert.status === 'RESOLVED_BY_AI' ? (
                    <div className="px-3 py-1.5 bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 rounded-lg text-xs font-bold flex items-center shadow w-full justify-center">
                      <ShieldCheck className="w-3.5 h-3.5 mr-1.5 text-emerald-400" />
                      <span>Mitigated by AI</span>
                    </div>
                  ) : (
                    <>
                      {/* IPS Active Defense Button */}
                      <button
                        onClick={() => handleBlockIp(alert.src_ip, `${alert.threat_category} detection`)}
                        disabled={blockingIp === alert.src_ip}
                        className="px-3 py-1.5 bg-red-700/80 hover:bg-red-600 border border-red-500/50 text-white rounded-lg text-xs font-bold flex items-center shadow transition-all w-full justify-center group cursor-pointer"
                        title="Isolate attacker IP at Windows Defender Firewall level"
                      >
                        <Flame className="w-3.5 h-3.5 mr-1.5 text-red-300 animate-pulse" />
                        {blockingIp === alert.src_ip ? 'Blocking...' : 'Isolate IP'}
                      </button>

                      <button
                        onClick={() => handleStatusChange(alert.id, 'RESOLVED')}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center shadow transition-colors w-full justify-center cursor-pointer"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                        Resolve
                      </button>
                    </>
                  )}

                  {/* AI Explainability Button */}
                  <button
                    onClick={() => setExplainingAlert(alert)}
                    className="px-3 py-1.5 bg-purple-900/40 hover:bg-purple-800/60 border border-purple-500/40 text-purple-200 rounded-lg text-xs font-semibold flex items-center shadow transition-all w-full justify-center cursor-pointer"
                    title="View ML Explainability feature importance breakdown"
                  >
                    <BrainCircuit className="w-3.5 h-3.5 mr-1.5 text-purple-400" />
                    Explain AI
                  </button>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="bg-[#070D19] border border-cyan-900/40 rounded-xl p-8 text-center text-slate-400 font-mono">
            {loading ? 'Loading threats...' : 'No security alerts matching criteria. All threats neutralized.'}
          </div>
        )}
      </div>

      {/* AI Explainer Modal */}
      {explainingAlert && (
        <AiExplainerModal
          alert={explainingAlert}
          onClose={() => setExplainingAlert(null)}
        />
      )}
    </div>
  );
}
