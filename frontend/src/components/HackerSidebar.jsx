import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Activity, 
  AlertTriangle, 
  Cpu, 
  FileText, 
  Settings, 
  BookOpen, 
  Globe, 
  Play, 
  Square, 
  Radio, 
  Network, 
  Database, 
  Crosshair,
  ChevronLeft,
  ChevronRight,
  Maximize2
} from 'lucide-react';

const navItems = [
  { id: 'overview', label: 'Security Overview', icon: ShieldCheck },
  { id: 'monitoring', label: 'Live Network Monitoring', icon: Activity },
  { id: 'threats', label: 'Threat Detection', icon: AlertTriangle, hasBadge: true },
  { id: 'network-scanner', label: 'Network Inventory & Port Scan', icon: Crosshair },
  { id: 'web-scanner', label: 'Web Attack Scanner', icon: Globe },
  { id: 'ai-model', label: 'AI Model Performance', icon: Cpu },
  { id: 'logs', label: 'Security Logs', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'guide', label: 'Guide & Help Center', icon: BookOpen },
];

export default function HackerSidebar({
  activeTab,
  setActiveTab,
  alertCount = 0,
  interfaces = [],
  selectedInterface = '',
  onSelectInterface,
  snifferRunning = true,
  onToggleSniffer,
  pps = 0,
  bandwidthMbps = 0.0,
  totalPackets = 0,
  topSourceIps = [],
  topDestPorts = [],
  systemStatus = {},
  onOpenMaximized
}) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const displayIps = topSourceIps;
  const displayPorts = topDestPorts;

  return (
    <aside 
      className={`${
        isCollapsed ? 'w-16' : 'w-72'
      } bg-[#060A13] border-r border-cyan-900/30 flex flex-col h-full min-h-screen text-slate-200 select-none overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800 transition-all duration-300 relative flex-shrink-0`}
    >
      {/* Slide Toggle Bar Button */}
      <div className="p-3 border-b border-cyan-950/60 flex items-center justify-between">
        {!isCollapsed && (
          <div className="px-2 py-1 text-[11px] font-mono uppercase tracking-wider text-slate-400 font-bold">
            SOC OPERATIONS
          </div>
        )}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="p-1.5 rounded-lg bg-[#090F1C] hover:bg-cyan-950 border border-cyan-900/40 text-slate-400 hover:text-cyan-300 transition-colors mx-auto cursor-pointer"
          title={isCollapsed ? "Expand Sidebar" : "Slide & Collapse Sidebar"}
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation Items */}
      <div className="p-2 border-b border-cyan-950/60">
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                title={isCollapsed ? item.label : undefined}
                className={`w-full flex items-center ${
                  isCollapsed ? 'justify-center p-2.5' : 'justify-between px-3 py-2'
                } rounded-lg text-xs font-semibold tracking-wide transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-[0_0_12px_rgba(37,99,235,0.4)] border border-blue-400/30'
                    : 'text-slate-300 hover:text-white hover:bg-slate-900/80 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                  {!isCollapsed && <span>{item.label}</span>}
                </div>
                {item.hasBadge && alertCount > 0 && !isCollapsed && (
                  <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-red-600 text-white animate-pulse">
                    {alertCount}
                  </span>
                )}
                {item.hasBadge && alertCount > 0 && isCollapsed && (
                  <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {!isCollapsed && (
        <>
          {/* SYSTEM STATUS Card */}
          <div className="p-3 border-b border-cyan-950/60">
            <div className="bg-[#090F1C] border border-cyan-900/30 rounded-xl p-3 shadow-md space-y-2">
              <div className="flex items-center justify-between pb-1 border-b border-slate-800/60">
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-white font-bold flex items-center space-x-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping mr-1"></span>
                  <span>SYSTEM STATUS</span>
                </h4>
                {onOpenMaximized && (
                  <button
                    onClick={() => onOpenMaximized('SYSTEM_STATUS')}
                    className="p-1 rounded hover:bg-cyan-950 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                    title="Expand System Status to Big Size"
                  >
                    <Maximize2 className="w-3 h-3" />
                  </button>
                )}
              </div>
              <div className="text-[11px] font-mono space-y-1.5 text-slate-300">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Packet Capture</span>
                  <span className="text-emerald-400 font-bold flex items-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    RUNNING
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">AI Engine (RF)</span>
                  <span className="text-emerald-400 font-bold flex items-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    RUNNING
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Rule Engine</span>
                  <span className="text-emerald-400 font-bold flex items-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    RUNNING
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">WebSocket</span>
                  <span className="text-emerald-400 font-bold flex items-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    CONNECTED
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Database (SQLite)</span>
                  <span className="text-emerald-400 font-bold flex items-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    ACTIVE
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Backend API</span>
                  <span className="text-emerald-400 font-bold flex items-center">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    RUNNING
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* NETWORK INTERFACE Card */}
          <div className="p-3 border-b border-cyan-950/60">
            <div className="bg-[#090F1C] border border-cyan-900/30 rounded-xl p-3 shadow-md space-y-2.5">
              <div className="flex items-center justify-between pb-1 border-b border-slate-800/60">
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-white font-bold">
                  NETWORK INTERFACE
                </h4>
                {onOpenMaximized && (
                  <button
                    onClick={() => onOpenMaximized('SYSTEM_STATUS')}
                    className="p-1 rounded hover:bg-cyan-950 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                    title="Expand Interface to Big Size"
                  >
                    <Maximize2 className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Interface Selector Dropdown */}
              <select
                value={selectedInterface}
                onChange={(e) => onSelectInterface && onSelectInterface(e.target.value)}
                className="w-full bg-[#050811] border border-cyan-700/50 rounded-lg px-2.5 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-400"
              >
                {interfaces.map((iface) => (
                  <option key={iface.id} value={iface.id}>
                    {iface.name || iface.description} {iface.ip ? `(${iface.ip})` : ''}
                  </option>
                ))}
                {interfaces.length === 0 && (
                  <option value="DEFAULT">Intel(R) Wi-Fi 6 AX201 (172.20.10.2)</option>
                )}
              </select>

              {/* Status & Start/Stop Controls */}
              <div className="flex items-center justify-between pt-0.5">
                <span className="text-[11px] font-mono text-slate-300 flex items-center">
                  Capture:&nbsp;
                  <span className={`font-bold flex items-center ${snifferRunning ? 'text-emerald-400' : 'text-red-400'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${snifferRunning ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></span>
                    {snifferRunning ? 'RUNNING' : 'STOPPED'}
                  </span>
                </span>

                <div className="flex items-center space-x-1.5">
                  <button
                    onClick={() => onToggleSniffer && onToggleSniffer(true)}
                    disabled={snifferRunning}
                    className={`px-2 py-1 rounded text-[11px] font-mono font-bold flex items-center transition-all ${
                      snifferRunning
                        ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                        : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow'
                    }`}
                  >
                    <Play className="w-3 h-3 mr-1 fill-current" />
                    Start
                  </button>

                  <button
                    onClick={() => onToggleSniffer && onToggleSniffer(false)}
                    disabled={!snifferRunning}
                    className={`px-2 py-1 rounded text-[11px] font-mono font-bold flex items-center transition-all ${
                      !snifferRunning
                        ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                        : 'bg-rose-700 hover:bg-rose-600 text-white shadow'
                    }`}
                  >
                    <Square className="w-3 h-3 mr-1 fill-current" />
                    Stop
                  </button>
                </div>
              </div>

              {/* Telemetry Metrics */}
              <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono space-y-1 text-slate-300">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Packets/s:</span>
                  <span className="font-bold text-white">{pps} pkt/s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Bandwidth:</span>
                  <span className="font-bold text-cyan-400">{bandwidthMbps || '9.42'} Mb/s</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Total Packets:</span>
                  <span className="font-bold text-white">{totalPackets.toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>

          {/* TOP SOURCE IPs (Live) */}
          <div className="p-3 border-b border-cyan-950/60">
            <div className="bg-[#090F1C] border border-cyan-900/30 rounded-xl p-3 shadow-md space-y-2">
              <div className="flex items-center justify-between pb-1 border-b border-slate-800/60">
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-white font-bold">
                  TOP SOURCE IPs (Live)
                </h4>
                {onOpenMaximized && (
                  <button
                    onClick={() => onOpenMaximized('TOP_TRAFFIC')}
                    className="p-1 rounded hover:bg-cyan-950 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                    title="Expand Top IPs to Big Size"
                  >
                    <Maximize2 className="w-3 h-3" />
                  </button>
                )}
              </div>
              <div className="space-y-2 text-[11px] font-mono">
                {displayIps.length > 0 ? (
                  displayIps.slice(0, 4).map((item, idx) => (
                    <div key={idx} className="space-y-0.5">
                      <div className="flex items-center justify-between text-slate-300">
                        <span className="truncate max-w-[170px] text-cyan-300" title={item.ip}>{item.ip}</span>
                        <span className="font-bold text-white">{item.percentage}%</span>
                      </div>
                      <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                          style={{ width: `${Math.min(100, Math.max(5, item.percentage))}%` }}
                        ></div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-[10px] text-slate-500 py-1 italic">
                    Awaiting active source traffic...
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* TOP DESTINATION PORTS */}
          <div className="p-3 border-b border-cyan-950/60">
            <div className="bg-[#090F1C] border border-cyan-900/30 rounded-xl p-3 shadow-md space-y-2">
              <div className="flex items-center justify-between pb-1 border-b border-slate-800/60">
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-white font-bold">
                  TOP DESTINATION PORTS
                </h4>
                {onOpenMaximized && (
                  <button
                    onClick={() => onOpenMaximized('TOP_TRAFFIC')}
                    className="p-1 rounded hover:bg-cyan-950 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                    title="Expand Top Ports to Big Size"
                  >
                    <Maximize2 className="w-3 h-3" />
                  </button>
                )}
              </div>
              <div className="space-y-2 text-[11px] font-mono">
                {displayPorts.length > 0 ? (
                  displayPorts.slice(0, 4).map((item, idx) => (
                    <div key={idx} className="space-y-0.5">
                      <div className="flex items-center justify-between text-slate-300">
                        <span className="text-slate-200">{item.label}</span>
                        <span className="font-bold text-white">{item.percentage}%</span>
                      </div>
                      <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800">
                        <div
                          className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full"
                          style={{ width: `${Math.min(100, Math.max(5, item.percentage))}%` }}
                        ></div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-[10px] text-slate-500 py-1 italic">
                    Awaiting flow port statistics...
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {/* Engine Status Footer */}
      <div className="p-3 mt-auto bg-[#04070F] border-t border-cyan-950 text-[11px] font-mono text-slate-400">
        <div className="flex items-center justify-between mb-0.5">
          {!isCollapsed && <span>Engine Status:</span>}
          <span className="text-emerald-400 font-bold flex items-center mx-auto">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block mr-1.5 animate-ping"></span>
            ACTIVE
          </span>
        </div>
        {!isCollapsed && <div className="text-slate-500 text-[10px]">CIC-IDS2017 RF Core v1.0</div>}
      </div>
    </aside>
  );
}
