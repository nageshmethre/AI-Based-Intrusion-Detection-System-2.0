import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Search, 
  Filter, 
  Pause, 
  Play, 
  Trash2, 
  ShieldCheck, 
  AlertTriangle,
  Info,
  X
} from 'lucide-react';
import { fetchMonitoringEvents } from '../services/api';

export default function LiveMonitoring({ liveEvents = [] }) {
  const [events, setEvents] = useState([]);
  const [filterProto, setFilterProto] = useState('ALL');
  const [filterMalicious, setFilterMalicious] = useState('ALL');
  const [isPaused, setIsPaused] = useState(false);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Initial load
  useEffect(() => {
    fetchMonitoringEvents(50, 0).then((res) => {
      if (res?.items) setEvents(res.items);
    }).catch(console.error);
  }, []);

  // Merge live incoming events if not paused
  useEffect(() => {
    if (isPaused || !liveEvents.length) return;
    const latest = liveEvents[0];
    setEvents((prev) => {
      if (prev.some((e) => e.id === latest.id)) return prev;
      return [latest, ...prev.slice(0, 199)];
    });
  }, [liveEvents, isPaused]);

  // Filter events
  const filteredEvents = events.filter((e) => {
    if (filterProto !== 'ALL' && e.protocol !== filterProto) return false;
    if (filterMalicious === 'MALICIOUS' && !e.is_malicious) return false;
    if (filterMalicious === 'BENIGN' && e.is_malicious) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchSrc = e.src_ip.toLowerCase().includes(q);
      const matchDst = e.dst_ip.toLowerCase().includes(q);
      const matchPred = (e.prediction || '').toLowerCase().includes(q);
      if (!matchSrc && !matchDst && !matchPred) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Controls Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP, prediction..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-xs rounded-lg pl-9 pr-3 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 w-56"
            />
          </div>

          {/* Protocol Filter */}
          <select
            value={filterProto}
            onChange={(e) => setFilterProto(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>

          {/* Classification Filter */}
          <select
            value={filterMalicious}
            onChange={(e) => setFilterMalicious(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Classifications</option>
            <option value="MALICIOUS">Malicious Only</option>
            <option value="BENIGN">Normal Only</option>
          </select>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              isPaused 
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30' 
                : 'bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>

          <button
            onClick={() => setEvents([])}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 text-slate-400 border border-slate-700 hover:text-white hover:bg-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear View</span>
          </button>
        </div>
      </div>

      {/* Real-time Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-lg overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Aggregated Network Flow Stream
            </h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Displaying {filteredEvents.length} flows
          </span>
        </div>

        <div className="overflow-x-auto max-h-[620px] overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-800/80 text-slate-400 uppercase tracking-wider font-semibold sticky top-0 z-10 backdrop-blur">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source Endpoint</th>
                <th className="py-2.5 px-3">Destination Endpoint</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Volume</th>
                <th className="py-2.5 px-3">AI Prediction</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredEvents.length > 0 ? (
                filteredEvents.map((event) => (
                  <tr 
                    key={event.id || `${event.src_ip}-${event.timestamp}`} 
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                    onClick={() => setSelectedFlow(event)}
                  >
                    <td className="py-2.5 px-3 font-mono text-slate-400">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-cyan-400">
                      {event.src_ip}:{event.src_port || 0}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">
                      {event.dst_ip}:{event.dst_port || 0}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-slate-300">
                      {event.protocol}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono">
                      {event.total_packets || 0} pkts ({((event.total_bytes || 0) / 1024).toFixed(1)} KB)
                    </td>
                    <td className="py-2.5 px-3 font-semibold">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        event.is_malicious 
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30' 
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {event.prediction || 'BENIGN'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono font-bold text-slate-200">
                      {((event.confidence || 0) * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-3">
                      {event.is_malicious ? (
                        <span className="flex items-center text-red-400 text-xs">
                          <AlertTriangle className="w-3.5 h-3.5 mr-1" />
                          SUSPICIOUS
                        </span>
                      ) : (
                        <span className="flex items-center text-emerald-400 text-xs">
                          <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                          NORMAL
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFlow(event);
                        }}
                        className="text-blue-400 hover:text-blue-300 font-semibold text-xs"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    No matching network flow events found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Flow Details Modal */}
      {selectedFlow && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 animate-in fade-in duration-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Info className="w-5 h-5 text-blue-400" />
                <h3 className="text-base font-bold text-white uppercase tracking-wider">
                  Network Flow Inspection & Telemetry
                </h3>
              </div>
              <button 
                onClick={() => setSelectedFlow(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Source Endpoint</span>
                <span className="font-mono font-bold text-cyan-400">{selectedFlow.src_ip}:{selectedFlow.src_port}</span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Destination Endpoint</span>
                <span className="font-mono font-bold text-white">{selectedFlow.dst_ip}:{selectedFlow.dst_port}</span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Protocol</span>
                <span className="font-bold text-slate-200">{selectedFlow.protocol}</span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">AI Classification</span>
                <span className={`font-bold font-mono ${selectedFlow.is_malicious ? 'text-red-400' : 'text-emerald-400'}`}>
                  {selectedFlow.prediction}
                </span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Prediction Confidence</span>
                <span className="font-mono font-bold text-white">
                  {((selectedFlow.confidence || 0) * 100).toFixed(2)}%
                </span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Threat Severity</span>
                <span className="font-bold text-amber-400">{selectedFlow.severity || 'INFO'}</span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Total Flow Packets</span>
                <span className="font-mono font-bold text-white">{selectedFlow.total_packets || 0}</span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Total Flow Bytes</span>
                <span className="font-mono font-bold text-white">{selectedFlow.total_bytes || 0} B</span>
              </div>
              <div className="bg-slate-800/60 p-3 rounded-lg border border-slate-700/50">
                <span className="text-slate-400 block mb-0.5">Flow Duration</span>
                <span className="font-mono font-bold text-white">{((selectedFlow.flow_duration_us || 0) / 1000).toFixed(2)} ms</span>
              </div>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-slate-400 leading-relaxed">
              <span className="font-semibold text-slate-300">SOC Analyst Note:</span> This flow was extracted directly from Scapy bidirectional packet aggregation, normalized across 40 CIC-IDS2017 features, and evaluated against the trained Random Forest model.
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedFlow(null)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold"
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
