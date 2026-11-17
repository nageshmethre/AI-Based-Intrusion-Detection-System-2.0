import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Layout, 
  Activity, 
  Network, 
  Cpu, 
  Database, 
  Radio, 
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  FolderOpen,
  ShieldCheck,
  Clock
} from 'lucide-react';
import { fetchSystemStatus } from '../services/api';

export default function ProjectStatus() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadStatus = async () => {
    try {
      const data = await fetchSystemStatus();
      setStatus(data);
    } catch (err) {
      console.error('Failed to load system status:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadStatus();
  };

  if (loading && !status) {
    return (
      <div className="p-8 text-center text-slate-400 flex items-center justify-center space-x-2">
        <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
        <span>Loading live system telemetry...</span>
      </div>
    );
  }

  const backend = status?.backend || {};
  const frontend = status?.frontend || {};
  const capture = status?.packet_capture || {};
  const model = status?.ai_detection_engine || {};
  const dataset = status?.dataset_provenance || {};
  const db = status?.database || {};
  const ws = status?.websocket || {};

  return (
    <div className="space-y-6">
      {/* Title & Refresh */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider flex items-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400 mr-2" />
            Live Project Runtime Telemetry & Health Audit
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time validation of all operational subsystems across Windows 11 host
          </p>
        </div>

        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Sync Diagnostics</span>
        </button>
      </div>

      {/* Grid of Subsystems */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* 1. Backend Service */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Server className="w-4 h-4 text-blue-400 mr-1.5" />
              Backend API Server
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              {backend.status || 'ONLINE'}
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Framework:</span> {backend.framework}</div>
            <div><span className="text-slate-500">Version:</span> {backend.version}</div>
            <div><span className="text-slate-500">Host OS:</span> {backend.environment}</div>
          </div>
        </div>

        {/* 2. Frontend Client */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Layout className="w-4 h-4 text-cyan-400 mr-1.5" />
              Frontend SOC Client
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              {frontend.status || 'READY'}
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Framework:</span> {frontend.framework}</div>
            <div><span className="text-slate-500">Build:</span> {frontend.build}</div>
            <div><span className="text-slate-500">WS Channel:</span> {frontend.websocket_url}</div>
          </div>
        </div>

        {/* 3. Packet Capture Daemon */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Activity className="w-4 h-4 text-emerald-400 mr-1.5" />
              Packet Capture Engine
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              capture.is_running
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}>
              {capture.is_running ? 'SNIFFING' : 'IDLE'}
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Total Packets:</span> {capture.total_packets?.toLocaleString()}</div>
            <div><span className="text-slate-500">TCP / UDP:</span> {capture.tcp_packets} / {capture.udp_packets}</div>
            <div><span className="text-slate-500">Active Flows:</span> {capture.active_flows}</div>
          </div>
        </div>

        {/* 4. Selected Network Interface */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Network className="w-4 h-4 text-purple-400 mr-1.5" />
              Selected Adapter
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">
              ACTIVE
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div className="truncate" title={capture.interface_display}>
              <span className="text-slate-500">NIC:</span> {capture.interface_display}
            </div>
            <div><span className="text-slate-500">Npcap ID:</span> {capture.interface_id}</div>
            <div className="text-[10px] text-slate-400">
              {capture.interface_id?.toLowerCase().includes('loopback') ? 'Target: 127.0.0.1 (Isolated Lab)' : 'Target: Physical Wi-Fi Host Network'}
            </div>
          </div>
        </div>

        {/* 5. AI Detection Model */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Cpu className="w-4 h-4 text-blue-400 mr-1.5" />
              AI Model Engine
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              {model.status}
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Type:</span> {model.model_type}</div>
            <div><span className="text-slate-500">Accuracy:</span> {((model.accuracy || 0) * 100).toFixed(2)}% (F1: {((model.macro_f1 || 0) * 100).toFixed(2)}%)</div>
            <div><span className="text-slate-500">FPR:</span> {((model.macro_fpr || 0) * 100).toFixed(3)}%</div>
            <div><span className="text-slate-500">Threshold:</span> conf &ge; {model.alert_confidence_threshold}, margin &ge; {model.margin_threshold}</div>
          </div>
        </div>

        {/* 6. Dataset Provenance */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <FolderOpen className="w-4 h-4 text-amber-400 mr-1.5" />
              Dataset Provenance
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              model.is_authentic_unb 
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
            }`}>
              {model.is_authentic_unb ? 'AUTHENTIC UNB' : 'AUGMENTED SCHEMA'}
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Active DS:</span> {model.dataset_trained_on}</div>
            <div><span className="text-slate-500">Raw Files Found:</span> {dataset.raw_files_detected} in backend/data/raw</div>
            <div><span className="text-slate-500">Processed File:</span> {dataset.has_processed_authentic ? 'Authentic Ready' : 'Augmented Active'}</div>
          </div>
        </div>

        {/* 7. SQLite Database */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Database className="w-4 h-4 text-emerald-400 mr-1.5" />
              SQLite Event Store
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              PERSISTENT
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Database Engine:</span> {db.engine}</div>
            <div><span className="text-slate-500">Database Size:</span> {db.size_mb} MB</div>
            <div><span className="text-slate-500">Events / Alerts:</span> {db.total_network_events?.toLocaleString()} / {db.total_threat_alerts}</div>
          </div>
        </div>

        {/* 8. WebSocket Live Feed */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Radio className="w-4 h-4 text-cyan-400 mr-1.5" />
              WebSocket Telemetry
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              {ws.status}
            </span>
          </div>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            <div><span className="text-slate-500">Endpoint:</span> {ws.endpoint}</div>
            <div><span className="text-slate-500">Subscribers:</span> {ws.active_connections} active client(s)</div>
            <div><span className="text-slate-500">Broadcast Rate:</span> 1.0s interval (Traffic Pulse)</div>
          </div>
        </div>
      </div>
    </div>
  );
}
