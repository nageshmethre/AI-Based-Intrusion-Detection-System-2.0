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
  Crosshair,
  ChevronLeft,
  ChevronRight
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
  alertCount = 0
}) {
  const [isCollapsed, setIsCollapsed] = useState(false);

  return (
    <aside 
      className={`${
        isCollapsed ? 'w-16' : 'w-64'
      } bg-[#060A13] border-r border-cyan-900/30 flex flex-col h-full min-h-screen text-slate-200 select-none overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800 transition-all duration-300 relative flex-shrink-0 z-30`}
    >
      {/* Slide Toggle Bar Header */}
      <div className="p-3 border-b border-cyan-950/60 flex items-center justify-between">
        {!isCollapsed && (
          <div className="px-2 py-1 text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            <span>SOC OPERATIONS</span>
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
      <div className="p-2 flex-1">
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center ${
                  isCollapsed ? 'justify-center px-2 py-3' : 'justify-between px-3 py-2.5'
                } rounded-lg text-xs font-mono font-medium transition-all cursor-pointer relative ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-[0_0_15px_rgba(37,99,235,0.4)] border border-blue-400/50 font-bold'
                    : 'text-slate-400 hover:text-cyan-300 hover:bg-[#0A1224] border border-transparent'
                }`}
                title={isCollapsed ? item.label : undefined}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? 'text-white' : 'text-slate-400'}`} />
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
