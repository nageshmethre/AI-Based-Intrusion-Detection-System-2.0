import React, { useState, useEffect } from 'react';
import TopNav from './components/TopNav';
import HackerSidebar from './components/HackerSidebar';
import SecurityOverview from './pages/SecurityOverview';
import LiveMonitoring from './pages/LiveMonitoring';
import ThreatDetection from './pages/ThreatDetection';
import WebAttackScanner from './pages/WebAttackScanner';
import ModelPerformance from './pages/ModelPerformance';
import SecurityLogs from './pages/SecurityLogs';
import SettingsPage from './pages/SettingsPage';
import GuideHelpCenter from './pages/GuideHelpCenter';
import HelpDrawer from './components/HelpDrawer';
import { 
  createWebSocketSubscription, 
  fetchOverview, 
  fetchSettings, 
  updateSettings 
} from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [wsStatus, setWsStatus] = useState('CONNECTING');
  const [pulseHistory, setPulseHistory] = useState([]);
  const [currentPps, setCurrentPps] = useState(243);
  const [activeFlows, setActiveFlows] = useState(13);
  const [currentInterface, setCurrentInterface] = useState('Intel(R) Wi-Fi 6 AX201');
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [openAlertCount, setOpenAlertCount] = useState(505);
  const [toastAlert, setToastAlert] = useState(null);
  const [isHelpOpen, setIsHelpOpen] = useState(false);

  // Settings & NIC telemetry state
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterfaceId, setSelectedInterfaceId] = useState('DEFAULT');
  const [snifferRunning, setSnifferRunning] = useState(true);
  const [totalPackets, setTotalPackets] = useState(17385);
  const [bandwidthMbps, setBandwidthMbps] = useState(9.42);
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
          setOpenAlertCount((prev) => prev + 1);
          setToastAlert(data);
          setTimeout(() => setToastAlert(null), 6000);
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

      {/* Main Container: Sidebar + Content Area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Hacker SOC Sidebar */}
        <HackerSidebar 
          activeTab={activeTab} 
          setActiveTab={setActiveTab} 
          alertCount={openAlertCount}
          interfaces={interfaces}
          selectedInterface={selectedInterfaceId}
          onSelectInterface={handleSelectInterface}
          snifferRunning={snifferRunning}
          onToggleSniffer={handleToggleSniffer}
          pps={currentPps}
          bandwidthMbps={bandwidthMbps}
          totalPackets={totalPackets}
          topSourceIps={topSourceIps}
          topDestPorts={topDestPorts}
        />

        {/* Dynamic Main Workspace Content */}
        <main className="flex-1 p-5 overflow-y-auto bg-[#050811]">
          {activeTab === 'overview' && (
            <SecurityOverview 
              pulseHistory={pulseHistory} 
              liveEvents={liveEvents} 
              liveAlerts={liveAlerts}
              currentPps={currentPps}
              currentInterface={currentInterface}
              onNavigateToThreats={() => setActiveTab('threats')} 
            />
          )}
          {activeTab === 'monitoring' && (
            <LiveMonitoring liveEvents={liveEvents} />
          )}
          {activeTab === 'threats' && (
            <ThreatDetection liveAlerts={liveAlerts} />
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
      </div>

      {/* Interactive Knowledge Base Drawer */}
      <HelpDrawer 
        isOpen={isHelpOpen} 
        onClose={() => setIsHelpOpen(false)} 
        onNavigateTab={(tab) => setActiveTab(tab)} 
      />

      {/* Real-time Threat Alert Toast */}
      {toastAlert && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md bg-red-950/90 border border-red-500 text-white p-4 rounded-xl shadow-2xl backdrop-blur animate-in slide-in-from-bottom duration-300">
          <div className="flex items-start justify-between">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-red-400 block mb-1">
                🚨 Critical SOC Threat Alert
              </span>
              <h5 className="text-sm font-bold font-mono">{toastAlert.title}</h5>
              <p className="text-xs text-slate-300 mt-1">{toastAlert.description}</p>
              <div className="mt-2 text-[11px] font-mono text-red-300">
                Host: {toastAlert.src_ip} | Engine: {toastAlert.detection_type}
              </div>
            </div>
            <button 
              onClick={() => setToastAlert(null)}
              className="text-slate-400 hover:text-white text-xs ml-3"
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
