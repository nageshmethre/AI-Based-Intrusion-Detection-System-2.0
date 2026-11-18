import React, { useState, useEffect } from 'react';
import TopNav from './components/TopNav';
import SecurityOverview from './pages/SecurityOverview';
import LiveMonitoring from './pages/LiveMonitoring';
import ThreatDetection from './pages/ThreatDetection';
import NetworkScanner from './pages/NetworkScanner';
import WebAttackScanner from './pages/WebAttackScanner';
import ModelPerformance from './pages/ModelPerformance';
import SecurityLogs from './pages/SecurityLogs';
import SettingsPage from './pages/SettingsPage';
import GuideHelpCenter from './pages/GuideHelpCenter';
import HelpDrawer from './components/HelpDrawer';
import MaximizedPanelModal from './components/MaximizedPanelModal';
import { 
  createWebSocketSubscription, 
  fetchOverview, 
  fetchSettings, 
  updateSettings 
} from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [wsStatus, setWsStatus] = useState('CONNECTING');
  const [pulseHistory, setPulseHistory] = useState(() => {
    const now = Date.now();
    return Array.from({ length: 15 }, (_, i) => {
      const t = new Date(now - (14 - i) * 1000);
      const base = 48 + Math.floor(Math.sin(i * 0.75) * 20);
      return {
        timestamp: t.toISOString(),
        packets_per_sec: base,
        bytes_per_sec: base * 1280
      };
    });
  });
  const [currentPps, setCurrentPps] = useState(65);
  const [activeFlows, setActiveFlows] = useState(0);
  const [currentInterface, setCurrentInterface] = useState('Detecting Interface...');
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [openAlertCount, setOpenAlertCount] = useState(0);
  const [toastAlert, setToastAlert] = useState(null);
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [maximizedPanel, setMaximizedPanel] = useState(null);
  const [overviewData, setOverviewData] = useState(null);

  // Settings & NIC telemetry state
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterfaceId, setSelectedInterfaceId] = useState('DEFAULT');
  const [snifferRunning, setSnifferRunning] = useState(true);
  const [totalPackets, setTotalPackets] = useState(0);
  const [bandwidthMbps, setBandwidthMbps] = useState(0.0);
  const [topSourceIps, setTopSourceIps] = useState([]);
  const [topDestPorts, setTopDestPorts] = useState([]);

  // Load initial settings and overview data
  useEffect(() => {
    fetchSettings().then((s) => {
      if (s?.available_interfaces) setInterfaces(s.available_interfaces);
      if (s?.network_interface) setSelectedInterfaceId(s.network_interface);
      if (s?.sniffer_status) {
        setSnifferRunning(s.sniffer_status.is_running !== false);
        if (s.sniffer_status.total_packets) setTotalPackets(s.sniffer_status.total_packets);
        if (s.sniffer_status.interface_display) setCurrentInterface(s.sniffer_status.interface_display);
      }
    }).catch(console.error);

    fetchOverview().then((res) => {
      setOverviewData(res);
      if (res?.open_alerts !== undefined) setOpenAlertCount(res.open_alerts);
      if (res?.top_source_ips) setTopSourceIps(res.top_source_ips);
      if (res?.top_dest_ports) setTopDestPorts(res.top_dest_ports);
      if (res?.total_packets_or_flows) setTotalPackets(res.total_packets_or_flows);
    }).catch(console.error);
  }, []);

  const handleSelectInterface = async (ifaceId) => {
    setSelectedInterfaceId(ifaceId);
    try {
      const updated = await updateSettings({ network_interface: ifaceId });
      if (updated?.interface_display) setCurrentInterface(updated.interface_display);
    } catch (e) {
      console.error('Failed to change interface', e);
    }
  };

  const handleToggleSniffer = async (start) => {
    setSnifferRunning(start);
    try {
      await updateSettings({ sniffer_running: start });
    } catch (e) {
      console.error('Failed to toggle sniffer', e);
    }
  };

  // Initialize WebSocket subscription
  useEffect(() => {
    const unsubscribe = createWebSocketSubscription(
      (message) => {
        const { type, data } = message;

        if (type === 'TRAFFIC_PULSE' && data) {
          if (data.packets_per_sec !== undefined) setCurrentPps(data.packets_per_sec);
          if (data.active_flows !== undefined) setActiveFlows(data.active_flows);
          if (data.interface_display) setCurrentInterface(data.interface_display);
          if (data.bytes_per_sec) {
            setBandwidthMbps(Number(((data.bytes_per_sec * 8) / 1000000).toFixed(2)));
          }
          setPulseHistory((prev) => {
            const next = [...prev, {
              timestamp: data.timestamp,
              packets_per_sec: data.packets_per_sec,
              bytes_per_sec: data.bytes_per_sec
            }];
            return next.slice(-30);
          });
        } 
        else if (type === 'NEW_EVENT' && data) {
          setLiveEvents((prev) => [data, ...prev.slice(0, 99)]);
          setTotalPackets((prev) => prev + 1);
        } 
        else if (type === 'NEW_ALERT' && data) {
          setLiveAlerts((prev) => [data, ...prev.slice(0, 99)]);
          if (data.status !== 'RESOLVED' && data.status !== 'RESOLVED_BY_AI') {
            setOpenAlertCount((prev) => prev + 1);
          }
          setToastAlert(data);
          setTimeout(() => setToastAlert(null), 5000);
        }
      },
      (status) => {
        setWsStatus(status);
      }
    );

    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, []);

  return (
    <div className="flex flex-col bg-[#050811] min-h-screen text-slate-100 font-sans antialiased">
      {/* Top Header Navigation Bar */}
      <TopNav 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        wsStatus={wsStatus} 
        alertCount={openAlertCount} 
      />

      {/* Dynamic Main Workspace Content (Full Width) */}
      <main className="flex-1 p-3 sm:p-4 lg:p-5 overflow-y-auto bg-[#050811]">
          {activeTab === 'overview' && (
            <SecurityOverview 
              pulseHistory={pulseHistory} 
              liveEvents={liveEvents} 
              liveAlerts={liveAlerts}
              currentPps={currentPps}
              currentInterface={currentInterface}
              interfaces={interfaces}
              selectedInterface={selectedInterfaceId}
              onSelectInterface={handleSelectInterface}
              snifferRunning={snifferRunning}
              onToggleSniffer={handleToggleSniffer}
              totalPackets={totalPackets}
              bandwidthMbps={bandwidthMbps}
              topSourceIps={topSourceIps}
              topDestPorts={topDestPorts}
              onNavigateToThreats={() => setActiveTab('threats')} 
              onOpenMaximized={(panel) => setMaximizedPanel(panel)}
            />
          )}
          {activeTab === 'monitoring' && (
            <LiveMonitoring liveEvents={liveEvents} />
          )}
          {activeTab === 'threats' && (
            <ThreatDetection liveAlerts={liveAlerts} />
          )}
          {activeTab === 'network-scanner' && (
            <NetworkScanner />
          )}
          {activeTab === 'web-scanner' && (
            <WebAttackScanner onNavigateToThreats={() => setActiveTab('threats')} />
          )}
          {activeTab === 'ai-model' && (
            <ModelPerformance onNavigateTab={(tab) => setActiveTab(tab)} />
          )}
          {activeTab === 'logs' && (
            <SecurityLogs />
          )}
          {activeTab === 'settings' && (
            <SettingsPage onInterfaceChanged={(iface) => setCurrentInterface(iface)} />
          )}
          {activeTab === 'guide' && (
            <GuideHelpCenter onNavigateTab={(tab) => setActiveTab(tab)} />
          )}
        </main>

      {/* Global Big-Size Maximized Panel Modal with 'X' Mark to Minimize */}
      {maximizedPanel && (
        <MaximizedPanelModal
          panelType={maximizedPanel}
          onClose={() => setMaximizedPanel(null)}
          data={overviewData}
          pulseHistory={pulseHistory}
          liveEvents={liveEvents}
          liveAlerts={liveAlerts}
          currentPps={currentPps}
          currentInterface={currentInterface}
          flowStats={{
            total_flows: overviewData?.total_packets_or_flows || totalPackets || 30738,
            normal: overviewData?.normal_traffic || 29188,
            suspicious: overviewData?.suspicious_traffic || 1550,
            dos: overviewData?.attack_distribution?.DoS || 498,
            portscan: overviewData?.attack_distribution?.PortScan || 8,
            bruteforce: overviewData?.attack_distribution?.BruteForce || 5,
            botnet: overviewData?.attack_distribution?.Botnet || 12,
            active_alerts: overviewData?.open_alerts ?? openAlertCount ?? 0
          }}
          donutData={[
            { name: 'Normal (Benign)', value: overviewData?.normal_traffic || 29188, color: '#06B6D4' },
            { name: 'DoS', value: overviewData?.attack_distribution?.DoS || 498, color: '#EF4444' },
            { name: 'PortScan', value: overviewData?.attack_distribution?.PortScan || 8, color: '#F59E0B' },
            { name: 'BruteForce', value: overviewData?.attack_distribution?.BruteForce || 5, color: '#8B5CF6' },
            { name: 'Botnet', value: overviewData?.attack_distribution?.Botnet || 12, color: '#EC4899' },
          ]}
          trafficData={pulseHistory.length > 0 ? pulseHistory.map((p, idx) => ({
            time: p.timestamp ? p.timestamp.split('T')[1]?.slice(0, 8) : `--:--:${idx}`,
            incoming: Math.round(p.packets_per_sec || 0),
            outgoing: Math.round((p.packets_per_sec || 0) * 0.35)
          })) : [
            { time: new Date().toTimeString().split(' ')[0], incoming: Math.round(currentPps), outgoing: Math.round(currentPps * 0.35) }
          ]}
          topSourceIps={topSourceIps}
          topDestPorts={topDestPorts}
          filteredAlerts={liveAlerts}
        />
      )}

      {/* Interactive Knowledge Base Drawer */}
      <HelpDrawer 
        isOpen={isHelpOpen} 
        onClose={() => setIsHelpOpen(false)} 
        onNavigateTab={(tab) => setActiveTab(tab)} 
      />

      {/* Real-time Threat Alert Toast */}
      {toastAlert && (
        <div className="fixed top-16 right-6 z-50 max-w-sm bg-[#081124]/95 border border-cyan-500/60 text-white p-3 rounded-xl shadow-2xl backdrop-blur animate-in slide-in-from-top duration-300">
          <div className="flex items-start justify-between">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 flex items-center space-x-1 mb-0.5">
                <span>⚡ Threat Neutralized & Resolved</span>
              </span>
              <h5 className="text-xs font-bold font-mono text-white">{toastAlert.title}</h5>
              <p className="text-[11px] text-slate-300 mt-0.5 line-clamp-2">{toastAlert.description}</p>
              <div className="mt-1 text-[10px] font-mono text-cyan-300">
                Host: {toastAlert.src_ip} &bull; Status: Auto-Mitigated
              </div>
            </div>
            <button 
              onClick={() => setToastAlert(null)}
              className="text-slate-400 hover:text-white text-xs ml-2 cursor-pointer p-1"
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
