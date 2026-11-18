import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Cpu, 
  FileText, 
  Database, 
  HelpCircle,
  Radio,
  Clock,
  Crosshair,
  CheckCircle2
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
    { id: 'threats', label: 'Threats', icon: Shield, badge: alertCount },
    { id: 'network-scanner', label: 'Scanner', icon: Crosshair },
    { id: 'ai-model', label: 'AI Model', icon: Cpu },
    { id: 'logs', label: 'Logs', icon: FileText },
    { id: 'guide', label: 'Guide & Help', icon: HelpCircle },
  ];

  return (
    <header className="h-16 bg-[#070B13] border-b border-cyan-900/30 px-5 flex items-center justify-between sticky top-0 z-40 select-none shadow-[0_4px_20px_rgba(0,0,0,0.6)]">
      {/* Brand */}
      <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('overview')}>
        <div className="w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/50 flex items-center justify-center text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.3)]">
          <Shield className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h1 className="text-base font-black tracking-widest text-white uppercase font-mono">
            CYBERSOC IDS
          </h1>
          <p className="text-[11px] text-cyan-400 font-medium tracking-wide">
            AI-Based Intrusion Detection System
          </p>
        </div>
      </div>

      {/* Center Nav Pills */}
      <nav className="hidden md:flex items-center space-x-2">
        {navItems.map((item, idx) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={idx}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                isActive
                  ? 'bg-blue-600 text-white shadow-[0_0_12px_rgba(37,99,235,0.5)] border border-blue-400/40'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              <span>{item.label}</span>
              {item.badge > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-500 text-white font-bold ml-1 animate-pulse">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Right Status & Live Clock */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        {/* REAL MONITORING Mode Indicator Badge */}
        <div 
          className="flex items-center space-x-2 px-3 py-1 rounded-full bg-emerald-950/70 border border-emerald-500/50 text-emerald-400 text-xs font-mono font-bold shadow-[0_0_12px_rgba(16,185,129,0.25)]"
          title="Mode: Real Network Sniffing & Live AI Inspection Active"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping inline-block"></span>
          <span className="tracking-wider">REAL MONITORING</span>
        </div>

        {/* Live Clock */}
        <div className="hidden lg:flex items-center text-xs font-mono text-slate-300 tracking-wider">
          <Clock className="w-3.5 h-3.5 text-cyan-400 mr-2" />
          <span>{currentTime}</span>
        </div>
      </div>
    </header>
  );
}
