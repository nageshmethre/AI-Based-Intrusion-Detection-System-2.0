import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import SecurityOverview from './pages/SecurityOverview';
import LiveMonitoring from './pages/LiveMonitoring';
import ThreatDetection from './pages/ThreatDetection';
import WebAttackScanner from './pages/WebAttackScanner';
import ModelPerformance from './pages/ModelPerformance';
import SecurityLogs from './pages/SecurityLogs';
import SettingsPage from './pages/SettingsPage';
import GuideHelpCenter from './pages/GuideHelpCenter';
import HelpDrawer from './components/HelpDrawer';
import { createWebSocketSubscription, fetchOverview } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [wsStatus, setWsStatus] = useState('CONNECTING');
  const [pulseHistory, setPulseHistory] = useState([]);
  const [currentPps, setCurrentPps] = useState(0);
  const [activeFlows, setActiveFlows] = useState(0);
  const [currentInterface, setCurrentInterface] = useState('');
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [openAlertCount, setOpenAlertCount] = useState(0);
  const [toastAlert, setToastAlert] = useState(null);
  const [isHelpOpen, setIsHelpOpen] = useState(false);

  // Sync initial stats
  useEffect(() => {
    fetchOverview().then((res) => {
      if (res?.open_alerts !== undefined) {
        setOpenAlertCount(res.open_alerts);
      }
    }).catch(console.error);
  }, []);

  // Initialize WebSocket subscription
  useEffect(() => {
    const unsubscribe = createWebSocketSubscription(
      (message) => {
        const { type, data } = message;

        if (type === 'TRAFFIC_PULSE' && data) {
          setCurrentPps(data.packets_per_sec || 0);
          setActiveFlows(data.active_flows || 0);
          if (data.interface_display) {
            setCurrentInterface(data.interface_display);
          }
          setPulseHistory((prev) => {
            const next = [...prev, {
              timestamp: data.timestamp,
              packets_per_sec: data.packets_per_sec,
              bytes_per_sec: data.bytes_per_sec
            }];
            return next.slice(-30); // Keep last 30 points
          });
        } 
        else if (type === 'NEW_EVENT' && data) {
          setLiveEvents((prev) => [data, ...prev.slice(0, 99)]);
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
    <div className="flex bg-[#0B0F19] min-h-screen text-slate-100 font-sans">
      {/* Sidebar */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        alertCount={openAlertCount} 
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header 
          wsStatus={wsStatus} 
          pps={currentPps} 
          activeFlows={activeFlows} 
          currentInterface={currentInterface}
          onOpenHelp={() => setIsHelpOpen(true)}
        />

        <main className="flex-1 p-6 overflow-y-auto">
          {activeTab === 'overview' && (
            <SecurityOverview 
              pulseHistory={pulseHistory} 
              liveEvents={liveEvents}
              liveAlerts={liveAlerts}
              currentPps={currentPps}
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
              <h5 className="text-sm font-bold">{toastAlert.title}</h5>
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
