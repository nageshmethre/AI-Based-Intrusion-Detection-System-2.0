import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Cpu, 
  FileText, 
  HelpCircle,
  Clock,
  Crosshair,
  Settings,
  Zap
} from 'lucide-react';

export default function TopNav({ activeTab, setActiveTab, wsStatus, alertCount = 0 }) {
  const [currentTime, setCurrentTime] = useState(() => {
    const now = new Date();
    const day = now.getDate().toString().padStart(2, '0');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[now.getMonth()];
    const year = now.getFullYear();
    const timeStr = now.toTimeString().split(' ')[0];
    return `${day} ${month} ${year} | ${timeStr}`;
  });

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const day = now.getDate().toString().padStart(2, '0');
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const month = months[now.getMonth()];
      const year = now.getFullYear();
      const timeStr = now.toTimeString().split(' ')[0];
      setCurrentTime(`${day} ${month} ${year} | ${timeStr}`);
    };

    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'overview', label: 'Live Monitor', icon: Activity },
    { id: 'attack-simulator', label: '⚡ Attack Lab', icon: Zap },
    { id: 'threats', label: 'Threats', icon: Shield, badge: alertCount },
    { id: 'network-scanner', label: 'Scanner', icon: Crosshair },
    { id: 'ai-model', label: 'AI Model', icon: Cpu },
    { id: 'logs', label: 'Logs', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'guide', label: 'Guide & Help', icon: HelpCircle },
  ];

  return (
    <header className="h-14 bg-[#070B13] border-b border-cyan-900/30 px-3 sm:px-4 flex items-center justify-between sticky top-0 z-40 select-none shadow-[0_4px_25px_rgba(0,0,0,0.7)] w-full">
      {/* Brand with right separator */}
      <div 
        className="flex items-center space-x-2.5 cursor-pointer border-r border-cyan-900/40 pr-3 sm:pr-4 mr-2 flex-shrink-0" 
        onClick={() => setActiveTab('overview')}
      >
        <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/50 flex items-center justify-center text-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.3)] flex-shrink-0">
          <Shield className="w-4 h-4 text-blue-400" />
        </div>
        <div className="flex-shrink-0">
          <h1 className="text-sm sm:text-base font-black tracking-wider text-white uppercase leading-none">
            CYBERSOC IDS
          </h1>
          <p className="text-[10px] text-cyan-400 font-medium tracking-wide mt-0.5">
            AI-Based Intrusion Detection System
          </p>
        </div>
      </div>

      {/* Center Nav Pills */}
      <nav className="hidden md:flex items-center space-x-1 lg:space-x-1.5 flex-shrink-0">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold tracking-wide transition-all cursor-pointer whitespace-nowrap flex-shrink-0 ${
                isActive
                  ? 'bg-blue-600 text-white shadow-[0_0_12px_rgba(37,99,235,0.5)] border border-blue-400/40 font-bold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              <span>{item.label}</span>
              {item.badge > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-500 text-white font-bold ml-1 animate-pulse font-mono">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Right Status & Live Clock */}
      <div className="flex items-center space-x-2 sm:space-x-2.5 flex-shrink-0">
        {/* AI Auto-Resolve Defense Badge */}
        <div 
          className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-cyan-950/70 border border-cyan-500/50 text-cyan-300 text-[11px] font-mono font-bold shadow-[0_0_10px_rgba(6,182,212,0.2)] flex-shrink-0 whitespace-nowrap"
          title="Inbuilt AI Engine autonomously quarantines and resolves threats in real time"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
          <span>AI AUTO-RESOLVE ⚡</span>
        </div>

        {/* REAL MONITORING Mode Indicator Badge */}
        <div 
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-emerald-950/70 border border-emerald-500/50 text-emerald-400 text-[11px] font-mono font-bold shadow-[0_0_10px_rgba(16,185,129,0.2)] flex-shrink-0 whitespace-nowrap"
          title="Mode: Real Network Sniffing & Live AI Inspection Active"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
          <span>REAL MONITORING</span>
        </div>

        {/* Live System Time */}
        <div className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-300 bg-[#0A101D] border border-cyan-900/40 px-2.5 py-1 rounded-lg shadow flex-shrink-0 whitespace-nowrap">
          <Clock className="w-3 h-3 text-cyan-400" />
          <span className="tracking-wide font-medium">{currentTime}</span>
        </div>
      </div>
    </header>
  );
}
