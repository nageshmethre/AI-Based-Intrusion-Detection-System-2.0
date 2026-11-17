import React from 'react';
import { Wifi, WifiOff, Bell, Clock, Activity, Network, HelpCircle } from 'lucide-react';

export default function Header({ 
  wsStatus, 
  totalPackets = 0, 
  pps = 0, 
  activeFlows = 0, 
  currentInterface = '',
  onOpenHelp
}) {
  const isConnected = wsStatus === 'CONNECTED';
  const isLoopback = currentInterface.toLowerCase().includes('loopback') || currentInterface.includes('127.0.0.1');

  return (
    <header className="h-16 bg-slate-900/90 backdrop-blur border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-4">
        <h2 className="text-base font-semibold text-white tracking-wide">
          Security Operations Center (SOC) Console
        </h2>
        <span className="hidden md:inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
          Environment: Windows 11 Host
        </span>
        {currentInterface && (
          <span className={`hidden xl:inline-flex items-center space-x-1.5 px-3 py-0.5 rounded-full text-xs font-medium border ${
            isLoopback 
              ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' 
              : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
          }`}>
            <Network className="w-3.5 h-3.5" />
            <span className="text-slate-400">NIC:</span>
            <span className="font-mono font-bold max-w-[220px] truncate" title={currentInterface}>
              {currentInterface}
            </span>
          </span>
        )}
      </div>

      <div className="flex items-center space-x-4 sm:space-x-6 text-sm">
        {/* Live Traffic Rate */}
        <div className="hidden lg:flex items-center space-x-2 text-slate-300">
          <Activity className="w-4 h-4 text-cyan-400" />
          <span>Throughput:</span>
          <span className="font-mono font-bold text-white">{pps} pkts/s</span>
        </div>

        {/* Active Connections */}
        <div className="hidden sm:flex items-center space-x-2 text-slate-300">
          <span>Active Flows:</span>
          <span className="font-mono font-bold text-cyan-400">{activeFlows}</span>
        </div>

        {/* Interactive Guide & Help Button */}
        <button
          onClick={onOpenHelp}
          className="flex items-center space-x-1.5 px-3 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 hover:text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-semibold transition-all shadow-sm"
          title="Open Interactive SOC Knowledge Base & Quick Commands"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Guide & Help</span>
        </button>

        {/* WebSocket Status Pill */}
        <div className="flex items-center space-x-2">
          {isConnected ? (
            <div className="flex items-center space-x-2 px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-emerald-400 text-xs font-semibold">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>LIVE FEED</span>
            </div>
          ) : (
            <div className="flex items-center space-x-2 px-3 py-1 bg-red-500/10 border border-red-500/30 rounded-full text-red-400 text-xs font-semibold">
              <span className="w-2 h-2 rounded-full bg-red-400"></span>
              <span>RECONNECTING...</span>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
