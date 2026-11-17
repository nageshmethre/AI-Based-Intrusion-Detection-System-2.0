import React, { useState, useEffect } from 'react';
import { 
  Settings, 
  Save, 
  Play, 
  Square, 
  Shield, 
  CheckCircle, 
  Network, 
  Cpu, 
  Sliders, 
  RefreshCw,
  Info
} from 'lucide-react';
import { fetchSettings, updateSettings } from '../services/api';
import ContextHelp from '../components/ContextHelp';

export default function SettingsPage({ onInterfaceChanged }) {
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saveMsg, setSaveMsg] = useState('');
  const [switchingIface, setSwitchingIface] = useState(false);
  const [formData, setFormData] = useState({
    network_interface: 'DEFAULT',
    flow_timeout: 5.0,
    ml_alert_confidence_threshold: 0.80,
    ml_probability_margin_threshold: 0.25,
    anomaly_threshold: 0.65,
    port_scan_threshold: 15,
  });

  const loadSettings = async () => {
    try {
      const res = await fetchSettings();
      setSettings(res);
      setFormData({
        network_interface: res.network_interface || 'DEFAULT',
        flow_timeout: res.flow_timeout || 5.0,
        ml_alert_confidence_threshold: res.ml_alert_confidence_threshold || 0.80,
        ml_probability_margin_threshold: res.ml_probability_margin_threshold || 0.25,
        anomaly_threshold: res.anomaly_threshold || 0.65,
        port_scan_threshold: res.port_scan_threshold || 15,
      });
      if (onInterfaceChanged && res.interface_display) {
        onInterfaceChanged(res.interface_display);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSave = async (e) => {
    e?.preventDefault();
    try {
      await updateSettings(formData);
      setSaveMsg('Configuration updated successfully!');
      await loadSettings();
      setTimeout(() => setSaveMsg(''), 4000);
    } catch (err) {
      console.error(err);
      alert('Failed to update settings');
    }
  };

  const handleQuickSwitch = async (targetIfaceId) => {
    setSwitchingIface(true);
    try {
      await updateSettings({ network_interface: targetIfaceId });
      setSaveMsg(`Interface switched to ${targetIfaceId === 'DEFAULT' ? 'Default Adapter' : targetIfaceId}`);
      await loadSettings();
      setTimeout(() => setSaveMsg(''), 4000);
    } catch (err) {
      console.error(err);
      alert('Failed to switch interface');
    } finally {
      setSwitchingIface(false);
    }
  };

  const handleToggleSniffer = async (start) => {
    try {
      await updateSettings({ sniffer_running: start });
      await loadSettings();
    } catch (err) {
      console.error(err);
      alert('Failed to toggle sniffer');
    }
  };

  if (loading && !settings) {
    return <div className="p-8 text-center text-slate-400">Loading system settings...</div>;
  }

  const isSnifferRunning = settings?.sniffer_status?.is_running;
  const activeDisplay = settings?.interface_display || settings?.network_interface || 'DEFAULT';
  const availableInterfaces = settings?.available_interfaces || [];

  // Identify default and loopback adapters
  const loopbackIface = availableInterfaces.find(i => i.is_loopback || i.id?.toLowerCase().includes('loopback') || i.name?.toLowerCase().includes('loopback'));
  const defaultIface = availableInterfaces.find(i => i.is_default);

  return (
    <div className="max-w-4xl space-y-6">
      {/* Active Interface & Sniffer Control Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
              <Shield className="w-5 h-5 text-blue-400 mr-2" />
              Live Packet Capture Engine (Windows Npcap)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Active packet sniffing thread and bidirectional flow reassembly daemon.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <span className={`px-3 py-1 rounded-full text-xs font-bold ${
              isSnifferRunning 
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                : 'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}>
              {isSnifferRunning ? 'SNIFFER ACTIVE' : 'SNIFFER STOPPED'}
            </span>

            {isSnifferRunning ? (
              <button
                onClick={() => handleToggleSniffer(false)}
                className="flex items-center space-x-1 px-3.5 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold shadow transition-colors"
              >
                <Square className="w-3.5 h-3.5 mr-1" />
                Stop Sniffer
              </button>
            ) : (
              <button
                onClick={() => handleToggleSniffer(true)}
                className="flex items-center space-x-1 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow transition-colors"
              >
                <Play className="w-3.5 h-3.5 mr-1" />
                Start Sniffer
              </button>
            )}
          </div>
        </div>

        {/* Current Active Interface Status */}
        <div className="bg-slate-800/60 rounded-lg p-3.5 border border-slate-700 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-500/10 rounded-lg text-blue-400 border border-blue-500/20">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Currently Listening On Adapter
              </div>
              <div className="text-sm font-bold text-white font-mono mt-0.5">
                {activeDisplay}
              </div>
            </div>
          </div>

          {/* Quick Switch Buttons */}
          <div className="flex items-center space-x-2">
            <button
              type="button"
              disabled={switchingIface}
              onClick={() => handleQuickSwitch('DEFAULT')}
              className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-xs font-medium border border-slate-600 transition"
              title="Switch to default physical adapter (Wi-Fi/Ethernet)"
            >
              Default (Wi-Fi)
            </button>
            {loopbackIface && (
              <button
                type="button"
                disabled={switchingIface}
                onClick={() => handleQuickSwitch(loopbackIface.id)}
                className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded text-xs font-medium border border-amber-500/40 transition"
                title="Switch to Npcap Loopback for local test traffic (127.0.0.1)"
              >
                Npcap Loopback
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Configuration Form */}
      <form onSubmit={handleSave} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center">
            <Sliders className="w-4 h-4 text-cyan-400 mr-2" />
            Network Adapter & AI Threshold Configuration
          </h3>
          <span className="text-xs text-slate-400">Live Config</span>
        </div>

        {/* Network Interface Selection Dropdown */}
        <div className="space-y-2">
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Select Capture Network Interface
          </label>
          <select
            value={formData.network_interface}
            onChange={(e) => setFormData({ ...formData, network_interface: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3.5 py-2.5 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="DEFAULT">
              [DEFAULT] Primary Host Interface {defaultIface ? `(${defaultIface.name} - ${defaultIface.ip})` : ''}
            </option>
            {availableInterfaces.map((iface) => {
              const tag = iface.is_loopback ? '[LOOPBACK]' : iface.is_default ? '[DEFAULT]' : '';
              return (
                <option key={iface.id} value={iface.id}>
                  {tag} {iface.name} - {iface.description} {iface.ip !== '0.0.0.0' ? `(${iface.ip})` : ''}
                </option>
              );
            })}
          </select>
          <div className="text-[11px] text-slate-400 flex items-start space-x-1.5 mt-1">
            <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
            <span>
              <strong>Windows Npcap Note:</strong> Packets targeting <code>127.0.0.1</code> travel exclusively over <code>Npcap Loopback Adapter</code>. Physical traffic (browsing, YouTube, external APIs) travels over the <code>Wi-Fi / Ethernet</code> adapter.
            </span>
          </div>
        </div>

        {/* AI & Rule Sliders Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
          {/* ML Alert Confidence Threshold */}
          <div className="space-y-2 bg-slate-800/40 p-4 rounded-lg border border-slate-800">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200 flex items-center">
                ML Alert Confidence Threshold
                <ContextHelp
                  title="ML Alert Confidence"
                  description="Fraction of Random Forest trees that must agree on an attack class before generating a threat alert."
                  formula="Confidence = Trees(Predicted Class) / Total Trees"
                  example="Set to >= 0.80 to stop false alarms on normal HTTPS traffic."
                />
              </span>
              <span className="font-mono text-cyan-400 font-bold">{formData.ml_alert_confidence_threshold.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.50"
              max="0.99"
              step="0.05"
              value={formData.ml_alert_confidence_threshold}
              onChange={(e) => setFormData({ ...formData, ml_alert_confidence_threshold: parseFloat(e.target.value) })}
              className="w-full accent-blue-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-400">
              Minimum predicted attack probability to generate an incident alert. Set to <strong>&ge; 0.80</strong> to suppress HTTPS false positives.
            </p>
          </div>

          {/* ML Probability Margin Threshold */}
          <div className="space-y-2 bg-slate-800/40 p-4 rounded-lg border border-slate-800">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200 flex items-center">
                ML Probability Margin (vs BENIGN)
                <ContextHelp
                  title="Probability Margin"
                  description="Minimum difference between attack probability and benign probability."
                  formula="Margin = P(Attack) - P(BENIGN)"
                  example="Prevents marginal 51/49 splits from triggering critical alerts on web browsing."
                />
              </span>
              <span className="font-mono text-cyan-400 font-bold">{formData.ml_probability_margin_threshold.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.05"
              max="0.50"
              step="0.05"
              value={formData.ml_probability_margin_threshold}
              onChange={(e) => setFormData({ ...formData, ml_probability_margin_threshold: parseFloat(e.target.value) })}
              className="w-full accent-blue-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-400">
              Required margin between attack class probability and BENIGN. Prevents marginal 51/49 splits from triggering false alerts.
            </p>
          </div>

          {/* Flow Timeout */}
          <div className="space-y-2 bg-slate-800/40 p-4 rounded-lg border border-slate-800">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200 flex items-center">
                Flow Inactivity Timeout
                <ContextHelp
                  title="Flow Timeout"
                  description="Seconds of silence before an inactive connection flow is flushed and evaluated."
                  example="Shorter timeouts evaluate faster; longer timeouts capture long-lived sessions."
                />
              </span>
              <span className="font-mono text-cyan-400 font-bold">{formData.flow_timeout}s</span>
            </div>
            <input
              type="range"
              min="1.0"
              max="30.0"
              step="0.5"
              value={formData.flow_timeout}
              onChange={(e) => setFormData({ ...formData, flow_timeout: parseFloat(e.target.value) })}
              className="w-full accent-blue-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-400">
              Seconds of inactivity before an open network connection is aggregated and classified by AI.
            </p>
          </div>

          {/* Port Scan Threshold */}
          <div className="space-y-2 bg-slate-800/40 p-4 rounded-lg border border-slate-800">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200 flex items-center">
                Port Scan Target Ports Threshold
                <ContextHelp
                  title="Port Scan Threshold"
                  description="Number of distinct destination ports probed within a 5-second sliding window."
                  example="Default 15 ports. Triggers HIGH severity rule alert."
                />
              </span>
              <span className="font-mono text-cyan-400 font-bold">{formData.port_scan_threshold}</span>
            </div>
            <input
              type="range"
              min="5"
              max="50"
              step="1"
              value={formData.port_scan_threshold}
              onChange={(e) => setFormData({ ...formData, port_scan_threshold: parseInt(e.target.value) })}
              className="w-full accent-blue-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-400">
              Distinct destination ports probed within 5 seconds before the rule-based engine triggers a HIGH alert.
            </p>
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          {saveMsg && (
            <div className="flex items-center text-xs text-emerald-400 font-semibold">
              <CheckCircle className="w-4 h-4 mr-1.5" />
              <span>{saveMsg}</span>
            </div>
          )}
          <button
            type="submit"
            className="ml-auto flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition-colors"
          >
            <Save className="w-4 h-4 mr-1" />
            Apply Settings
          </button>
        </div>
      </form>
    </div>
  );
}
