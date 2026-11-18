import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Maximize2 } from 'lucide-react';
import { fetchSystemLogs } from '../services/api';

export default function LiveTerminal({ liveEvents = [], liveAlerts = [], currentInterface = 'Default', onMaximize }) {
  const [logs, setLogs] = useState([]);
  const containerRef = useRef(null);

  // Load genuine system logs from database on mount
  useEffect(() => {
    fetchSystemLogs(30)
      .then((records) => {
        if (records && records.length > 0) {
          const formatted = records.reverse().map((r) => {
            const time = r.timestamp ? r.timestamp.split('T')[1]?.slice(0, 8) : '--:--:--';
            return {
              id: r.id || Math.random(),
              text: `> [${time}] [${r.source || 'SYSTEM'}] ${r.message}`,
              type: r.level || 'INFO'
            };
          });
          setLogs(formatted);
        } else {
          const nowStr = new Date().toTimeString().split(' ')[0];
          setLogs([
            { id: 1, text: `> [${nowStr}] [INITIALIZE] Sniffer active on interface: ${currentInterface}`, type: 'INFO' },
            { id: 2, text: `> [${nowStr}] [MONITOR] Real-time packet inspection active. Awaiting traffic...`, type: 'INFO' }
          ]);
        }
      })
      .catch((err) => {
        console.error('Failed to load initial system logs', err);
      });
  }, [currentInterface]);

  // Append genuine incoming live alerts from WebSocket
  useEffect(() => {
    if (!liveAlerts || liveAlerts.length === 0) return;
    const alert = liveAlerts[0];
    const time = alert.timestamp ? alert.timestamp.split('T')[1]?.slice(0, 8) : new Date().toTimeString().split(' ')[0];
    const confPct = ((alert.confidence || 0.95) * 100).toFixed(0);
    const newLog = {
      id: Date.now() + Math.random(),
      text: `> [${time}] [ALERT] [${alert.detection_type || 'RULE'}] ${alert.threat_category || 'Threat'} from ${alert.src_ip} -> ${alert.dst_ip}:${alert.dst_port || 0} (${confPct}% Conf)`,
      type: 'ALERT'
    };
    setLogs((prev) => [...prev.slice(-40), newLog]);
  }, [liveAlerts]);

  // Append genuine incoming live network flows from WebSocket
  useEffect(() => {
    if (!liveEvents || liveEvents.length === 0) return;
    const ev = liveEvents[0];
    const time = ev.timestamp ? ev.timestamp.split('T')[1]?.slice(0, 8) : new Date().toTimeString().split(' ')[0];
    const isThreat = ev.is_malicious || ev.prediction !== 'BENIGN';
    const confPct = ((ev.confidence || 0.9) * 100).toFixed(0);
    const newLog = {
      id: Date.now() + Math.random(),
      text: `> [${time}] [FLOW] ${ev.protocol || 'TCP'} ${ev.src_ip}:${ev.src_port || 0} -> ${ev.dst_ip}:${ev.dst_port || 0} | ${ev.prediction || 'BENIGN'} (${confPct}%)`,
      type: isThreat ? 'ATTACK' : 'BENIGN'
    };
    setLogs((prev) => [...prev.slice(-40), newLog]);
  }, [liveEvents]);

  // Auto scroll to bottom
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-[#050811] border border-cyan-900/40 rounded-xl p-4 flex flex-col h-[280px] shadow-[0_4px_25px_rgba(0,0,0,0.8)]">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 select-none">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
            LIVE TERMINAL (IDS ENGINE)
          </h4>
        </div>
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1.5 mr-1">
            <span className="w-2 h-2 rounded-full bg-red-500/80 inline-block"></span>
            <span className="w-2 h-2 rounded-full bg-amber-500/80 inline-block"></span>
            <span className="w-2 h-2 rounded-full bg-emerald-500/80 inline-block"></span>
          </div>
          {onMaximize && (
            <button
              onClick={onMaximize}
              className="p-1 bg-[#060D1E] hover:bg-emerald-950 border border-slate-700/60 hover:border-emerald-500 text-slate-300 hover:text-emerald-300 rounded transition-all cursor-pointer"
              title="Expand Terminal to Big Size"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Terminal Scroll Feed */}
      <div 
        ref={containerRef} 
        className="flex-1 overflow-y-auto font-mono text-[11px] leading-relaxed py-2.5 space-y-1.5 scrollbar-thin scrollbar-thumb-slate-800"
      >
        {logs.map((log) => {
          let colorClass = 'text-slate-300';
          if (log.type === 'ALERT' || log.type === 'CRITICAL') {
            colorClass = 'text-red-400 font-bold bg-red-950/30 px-1 rounded';
          } else if (log.type === 'ATTACK' || log.type === 'WARNING') {
            colorClass = 'text-orange-400 font-bold';
          } else if (log.type === 'BENIGN') {
            colorClass = 'text-emerald-400';
          } else if (log.type === 'RULE') {
            colorClass = 'text-amber-300';
          } else if (log.type === 'INFO') {
            colorClass = 'text-cyan-300';
          }

          return (
            <div key={log.id} className={`${colorClass} hover:bg-slate-900/40 px-1 rounded transition-colors`}>
              {log.text}
            </div>
          );
        })}
        {/* Blinking Prompt Cursor */}
        <div className="flex items-center text-emerald-400 font-mono text-xs pt-1">
          <span>&gt;&nbsp;</span>
          <span className="w-2 h-3.5 bg-emerald-400 animate-pulse inline-block"></span>
        </div>
      </div>
    </div>
  );
}
