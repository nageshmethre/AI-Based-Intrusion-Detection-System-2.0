import React from 'react';
import { 
  ShieldCheck, 
  Activity, 
  AlertTriangle, 
  Cpu, 
  FileText, 
  Settings,
  Radio,
  BookOpen
} from 'lucide-react';

const navItems = [
  { id: 'overview', label: 'Security Overview', icon: ShieldCheck },
  { id: 'monitoring', label: 'Live Network Monitoring', icon: Activity },
  { id: 'threats', label: 'Threat Detection', icon: AlertTriangle },
  { id: 'ai-model', label: 'AI Model Performance', icon: Cpu },
  { id: 'logs', label: 'Security Logs', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'guide', label: 'Guide & Help Center', icon: BookOpen },
];

export default function Sidebar({ activeTab, setActiveTab, alertCount = 0 }) {
  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen sticky top-0 select-none">
      {/* Brand */}
      <div className="p-5 border-b border-slate-800 flex items-center space-x-3">
        <div className="p-2 bg-blue-600/20 rounded-lg text-blue-400 border border-blue-500/30">
          <Radio className="w-6 h-6 animate-pulse" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-white tracking-wider uppercase">CyberSOC IDS</h1>
          <p className="text-xs text-blue-400 font-medium">Real-Time AI Defense</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1.5 overflow-y-auto">
        <div className="px-3 py-2 text-xs font-semibold uppercase text-slate-500 tracking-wider">
          SOC Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.id === 'threats' && alertCount > 0 && (
                <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-red-500 text-white animate-pulse">
                  {alertCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/40 text-xs text-slate-500">
        <div className="flex items-center justify-between mb-1">
          <span>Engine Status:</span>
          <span className="text-emerald-400 font-semibold flex items-center">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block mr-1.5 animate-ping"></span>
            ACTIVE
          </span>
        </div>
        <div>CIC-IDS2017 RF Core v1.0</div>
      </div>
    </aside>
  );
}
