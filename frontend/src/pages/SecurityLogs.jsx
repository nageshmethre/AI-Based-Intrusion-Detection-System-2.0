import React, { useState, useEffect } from 'react';
import { FileText, Send, RefreshCw, Terminal, CheckCircle2, AlertTriangle } from 'lucide-react';
import { fetchSystemLogs, ingestAuthLog } from '../services/api';

export default function SecurityLogs() {
  const [logs, setLogs] = useState([]);
  const [logInput, setLogInput] = useState('');
  const [ingestStatus, setIngestStatus] = useState(null);
  const [filterLevel, setFilterLevel] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const loadLogs = async () => {
    try {
      const res = await fetchSystemLogs(100);
      setLogs(res || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  const handleIngest = async (e) => {
    e?.preventDefault();
    if (!logInput.trim()) return;

    try {
      const res = await ingestAuthLog(logInput.trim());
      setIngestStatus(res);
      setLogInput('');
      await loadLogs();
      setTimeout(() => setIngestStatus(null), 5000);
    } catch (err) {
      console.error(err);
      alert('Failed to ingest log line');
    }
  };

  const handleSimulateSSHAttack = async () => {
    const fakeIp = `192.168.1.${Math.floor(Math.random() * 100) + 100}`;
    for (let i = 0; i < 6; i++) {
      const line = `Nov 14 ${new Date().toLocaleTimeString()} sshd[${2000 + i}]: Failed password for invalid user root from ${fakeIp} port ${40000 + i} ssh2`;
      const res = await ingestAuthLog(line);
      if (res?.alert_triggered) {
        setIngestStatus(res);
      }
    }
    await loadLogs();
  };

  const filteredLogs = logs.filter((l) => {
    if (filterLevel !== 'ALL' && l.level !== filterLevel) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Log Ingest & Test Simulator Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Authorized Authentication Log Ingest & SSH Monitor
            </h3>
          </div>
          <button
            onClick={handleSimulateSSHAttack}
            className="px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 rounded-lg text-xs font-semibold flex items-center transition-colors"
          >
            <AlertTriangle className="w-3.5 h-3.5 mr-1 text-red-400" />
            Simulate 6x SSH Auth Failures (Trigger Rule)
          </button>
        </div>

        <p className="text-xs text-slate-400 mb-3">
          Feed authorized system logs (OpenSSH / Syslog / Windows Event Log) into the rule-based brute force correlation engine.
        </p>

        <form onSubmit={handleIngest} className="flex gap-2">
          <input
            type="text"
            value={logInput}
            onChange={(e) => setLogInput(e.target.value)}
            placeholder="e.g.: Failed password for root from 192.168.1.50 port 55432 ssh2"
            className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3.5 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold flex items-center transition-colors"
          >
            <Send className="w-3.5 h-3.5 mr-1.5" />
            Ingest Log
          </button>
        </form>

        {ingestStatus && (
          <div className={`mt-3 p-3 rounded-lg text-xs border flex items-center ${
            ingestStatus.alert_triggered
              ? 'bg-red-950/40 border-red-500/40 text-red-300'
              : 'bg-slate-800 border-slate-700 text-slate-300'
          }`}>
            <CheckCircle2 className="w-4 h-4 mr-2 flex-shrink-0 text-emerald-400" />
            <span>
              Log ingested. {ingestStatus.alert_triggered 
                ? `🚨 Threat Rule Alert Triggered: ${ingestStatus.alert_title}`
                : 'No threshold exceeded.'}
            </span>
          </div>
        )}
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-lg overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FileText className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              SOC Audit & Event Logs
            </h3>
          </div>

          <div className="flex items-center space-x-3">
            <select
              value={filterLevel}
              onChange={(e) => setFilterLevel(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-3 py-1.5 text-white focus:outline-none focus:border-blue-500"
            >
              <option value="ALL">All Levels</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
            </select>

            <button
              onClick={loadLogs}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              title="Refresh Logs"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-800/80 text-slate-400 uppercase font-semibold sticky top-0 backdrop-blur">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Level</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40">
                    <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.level === 'ERROR' ? 'bg-red-500/20 text-red-400' :
                        log.level === 'WARNING' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {log.level}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-cyan-400 font-bold whitespace-nowrap">
                      {log.source}
                    </td>
                    <td className="py-2 px-3 text-slate-300 break-all">
                      {log.message}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500">
                    No logs recorded.
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
