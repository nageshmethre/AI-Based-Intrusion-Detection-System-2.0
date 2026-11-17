import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Unlock, 
  Flame, 
  Clock, 
  AlertTriangle,
  Plus,
  RefreshCw,
  Sliders
} from 'lucide-react';
import { fetchBlockedIps, blockAttackerIp, unblockAttackerIp, toggleAutoBlock } from '../services/api';

export default function ActiveDefensePanel() {
  const [blockedData, setBlockedData] = useState({ blocked_ips: [], auto_block_enabled: false });
  const [loading, setLoading] = useState(true);
  const [manualIp, setManualIp] = useState('');
  const [manualReason, setManualReason] = useState('Manual isolation by SOC analyst');
  const [actionMsg, setActionMsg] = useState('');

  const loadBlocked = async () => {
    try {
      const res = await fetchBlockedIps();
      setBlockedData(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadBlocked();
    const interval = setInterval(loadBlocked, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!manualIp) return;
    try {
      const res = await blockAttackerIp({
        ip: manualIp.trim(),
        reason: manualReason,
        duration_seconds: 300,
        threat_category: 'Manual Isolation'
      });
      setActionMsg(res.message);
      setManualIp('');
      await loadBlocked();
      setTimeout(() => setActionMsg(''), 4000);
    } catch (err) {
      alert('Failed to block IP: ' + err.message);
    }
  };

  const handleUnblock = async (ip) => {
    try {
      const res = await unblockAttackerIp(ip);
      setActionMsg(res.message);
      await loadBlocked();
      setTimeout(() => setActionMsg(''), 4000);
    } catch (err) {
      alert('Failed to unblock IP');
    }
  };

  const handleToggleAuto = async () => {
    try {
      const newState = !blockedData.auto_block_enabled;
      await toggleAutoBlock(newState);
      await loadBlocked();
    } catch (err) {
      alert('Failed to toggle auto block');
    }
  };

  const blockedList = blockedData.blocked_ips || [];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
              <ShieldAlert className="w-5 h-5 text-red-500 mr-2" />
              Active Defense & Host IPS Firewall (Intrusion Prevention)
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              ACTIVE DEFENSE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Isolates confirmed malicious hosts by injecting inbound block rules directly into Windows Defender Firewall
          </p>
        </div>

        {/* Auto-Block Switch */}
        <div className="flex items-center space-x-3 bg-slate-950 p-2 px-3 rounded-lg border border-slate-800">
          <span className="text-xs text-slate-300 font-semibold">Auto-Block High Threats:</span>
          <button
            onClick={handleToggleAuto}
            className={`px-3 py-1 rounded text-xs font-bold transition ${
              blockedData.auto_block_enabled
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            {blockedData.auto_block_enabled ? 'ENABLED' : 'DISABLED'}
          </button>
        </div>
      </div>

      {actionMsg && (
        <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-xs font-semibold text-cyan-300 animate-in fade-in">
          {actionMsg}
        </div>
      )}

      {/* Manual Isolation Input Form */}
      <form onSubmit={handleManualBlock} className="bg-slate-950 p-3.5 rounded-lg border border-slate-800/80 flex flex-col md:flex-row items-center gap-3">
        <div className="flex-1 w-full">
          <input
            type="text"
            placeholder="Enter hostile IP to block (e.g. 198.51.100.44)..."
            value={manualIp}
            onChange={(e) => setManualIp(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono placeholder-slate-500 focus:outline-none focus:border-red-500"
          />
        </div>
        <div className="flex-1 w-full">
          <input
            type="text"
            placeholder="Reason (e.g. SYN Flood probe / Rogue Scanner)..."
            value={manualReason}
            onChange={(e) => setManualReason(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 placeholder-slate-500 focus:outline-none focus:border-red-500"
          />
        </div>
        <button
          type="submit"
          className="w-full md:w-auto px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-bold font-mono flex items-center justify-center space-x-1.5 transition shrink-0"
        >
          <Lock className="w-3.5 h-3.5" />
          <span>FIREWALL ISOLATE</span>
        </button>
      </form>

      {/* Blocked Hosts Table */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-semibold text-slate-300 uppercase tracking-wider">
          <span>Active Host Isolation Rules ({blockedList.length})</span>
          <span className="text-slate-500 font-mono text-[10px]">Auto-expires after 300s</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold">
              <tr>
                <th className="py-2.5 px-3">Blocked Host</th>
                <th className="py-2.5 px-3">Isolation Reason</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Expires In</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {blockedList.map((item) => (
                <tr key={item.ip} className="hover:bg-slate-800/40">
                  <td className="py-2.5 px-3 font-bold text-red-400 flex items-center">
                    <Flame className="w-3.5 h-3.5 mr-1.5 text-red-500" />
                    <span>{item.ip}</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 text-[11px] truncate max-w-xs">{item.reason}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-500/30">
                      {item.threat_category}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-cyan-400 font-bold">
                    {item.remaining_seconds > 0 ? `${item.remaining_seconds}s` : 'Manual'}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={() => handleUnblock(item.ip)}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[10px] font-bold border border-slate-700 transition"
                    >
                      UNBLOCK
                    </button>
                  </td>
                </tr>
              ))}
              {blockedList.length === 0 && (
                <tr>
                  <td colSpan="5" className="py-6 text-center text-slate-500 font-sans">
                    No hosts are currently isolated by the firewall. Click "ISOLATE VIA FIREWALL" on any alert to block.
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
