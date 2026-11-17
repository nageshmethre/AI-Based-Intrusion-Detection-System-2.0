import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Shield, RefreshCw } from 'lucide-react';

export default function LiveTerminal({ liveEvents = [], liveAlerts = [], currentInterface = 'Intel(R) Wi-Fi 6 AX201' }) {
  const [logs, setLogs] = useState([]);
  const containerRef = useRef(null);

  // Initialize baseline logs
  useEffect(() => {
    const now = new Date();
    const time = now.toTimeString().split(' ')[0];
    const initialLogs = [
      { id: 1, text: `> [${time}] Capturing packets on: ${currentInterface || 'Intel(R) Wi-Fi 6 AX201'}...`, type: 'INFO' },
      { id: 2, text: `> [${time}] Flow aggregated: 172.20.10.2 -> 127.0.0.1`, type: 'FLOW' },
      { id: 3, text: `> [${time}] [RULE] PortScan check: 14 unique ports monitored`, type: 'RULE' },
      { id: 4, text: `> [${time}] [ALERT] Port Scanning Activity Detected!`, type: 'ALERT' },
      { id: 5, text: `> [${time}] [ML] Prediction: BENIGN (0.98)`, type: 'BENIGN' },
      { id: 6, text: `> [${time}] [ML] Prediction: DoS (0.81)`, type: 'ATTACK' },
      { id: 7, text: `> [${time}] Alert stored in SQLite (ID: 509)`, type: 'DB' }
    ];
    setLogs(initialLogs);
  }, [currentInterface]);

  // Append incoming live alerts
  useEffect(() => {
    if (!liveAlerts || liveAlerts.length === 0) return;
    const alert = liveAlerts[0];
    const time = new Date().toTimeString().split(' ')[0];
    const newLog = {
      id: Date.now() + Math.random(),
      text: `> [${time}] [${alert.detection_type || 'ALERT'}] ${alert.threat_category || 'Threat'} from ${alert.src_ip} (Conf: ${((alert.confidence || 0.95)*100).toFixed(0)}%)`,
      type: 'ALERT'
    };
    setLogs((prev) => [...prev.slice(-40), newLog]);
  }, [liveAlerts]);

  // Append incoming live events
  useEffect(() => {
    if (!liveEvents || liveEvents.length === 0) return;
    const ev = liveEvents[0];
    const time = new Date().toTimeString().split(' ')[0];
    const isMalicious = ev.is_malicious || ev.prediction !== 'BENIGN';
    const newLog = {
      id: Date.now() + Math.random(),
      text: `> [${time}] [ML] Flow ${ev.src_ip}:${ev.src_port || 0} -> ${ev.dst_ip}:${ev.dst_port || 0} | ${ev.prediction || 'BENIGN'} (${((ev.confidence || 0.9)*100).toFixed(0)}%)`,
      type: isMalicious ? 'ATTACK' : 'BENIGN'
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
        <div className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block"></span>
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block"></span>
        </div>
      </div>

      {/* Terminal Scroll Feed */}
      <div 
        ref={containerRef} 
        className="flex-1 overflow-y-auto font-mono text-[11px] leading-relaxed py-2.5 space-y-1.5 scrollbar-thin scrollbar-thumb-slate-800"
      >
        {logs.map((log) => {
          let colorClass = 'text-slate-300';
          if (log.type === 'ALERT') colorClass = 'text-red-400 font-bold bg-red-950/30 px-1 rounded';
          else if (log.type === 'ATTACK') colorClass = 'text-orange-400 font-bold';
          else if (log.type === 'BENIGN') colorClass = 'text-emerald-400';
          else if (log.type === 'RULE') colorClass = 'text-amber-300';
          else if (log.type === 'DB') colorClass = 'text-cyan-400';
          else if (log.type === 'INFO') colorClass = 'text-blue-300';

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
