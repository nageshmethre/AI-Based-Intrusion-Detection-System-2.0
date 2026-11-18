import React, { useState, useEffect } from 'react';
import { 
  Crosshair, 
  Search, 
  Server, 
  Activity, 
  Layers, 
  Play, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Clock, 
  Download, 
  RefreshCw,
  Terminal,
  Shield,
  Radio,
  FileText
} from 'lucide-react';
import { 
  runHostDiscovery, 
  runPortScan, 
  fetchScanHistory, 
  fetchDiscoveredHosts 
} from '../services/api';

const DEFAULT_TARGET_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
  1433, 1521, 3306, 3389, 5432, 8000, 8080, 8443
];

export default function NetworkScanner() {
  const [activeTab, setActiveTab] = useState('port-scan'); // 'port-scan', 'host-discovery', 'history'
  
  // Port scan state
  const [portTargetIp, setPortTargetIp] = useState('127.0.0.1');
  const [isScanningPorts, setIsScanningPorts] = useState(false);
  const [portScanResult, setPortScanResult] = useState(null);

  // Host discovery state
  const [subnetTarget, setSubnetTarget] = useState('172.20.10.0/28');
  const [isDiscoveringHosts, setIsDiscoveringHosts] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState(null);

  // History & Inventory
  const [scanHistory, setScanHistory] = useState([]);
  const [discoveredHosts, setDiscoveredHosts] = useState([]);
  const [errorMsg, setErrorMsg] = useState(null);

  const loadHistory = async () => {
    try {
      const hist = await fetchScanHistory(20);
      setScanHistory(hist);
      const hosts = await fetchDiscoveredHosts(30);
      setDiscoveredHosts(hosts);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleRunPortScan = async () => {
    if (!portTargetIp.trim()) return;
    setIsScanningPorts(true);
    setErrorMsg(null);
    setPortScanResult(null);

    try {
      const res = await runPortScan(portTargetIp.trim(), DEFAULT_TARGET_PORTS, 15);
      setPortScanResult(res);
      loadHistory();
    } catch (err) {
      setErrorMsg(err.message || 'Port scan failed');
    } finally {
      setIsScanningPorts(false);
    }
  };

  const handleRunHostDiscovery = async () => {
    if (!subnetTarget.trim()) return;
    setIsDiscoveringHosts(true);
    setErrorMsg(null);
    setDiscoveryResult(null);

    try {
      const res = await runHostDiscovery(subnetTarget.trim(), 20);
      setDiscoveryResult(res);
      loadHistory();
    } catch (err) {
      setErrorMsg(err.message || 'Subnet discovery failed');
    } finally {
      setIsDiscoveringHosts(false);
    }
  };

  return (
    <div className="space-y-5 font-mono">
      {/* Top Banner */}
      <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-[0_4px_25px_rgba(0,0,0,0.7)]">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-blue-600/20 text-cyan-400 border border-blue-500/40 rounded-lg">
            <Crosshair className="w-6 h-6 animate-spin-slow" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              Authorized Network Inventory & Port Scanner
              <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-500/40 px-2 py-0.5 rounded font-bold">
                AUDIT ENGINE
              </span>
            </h2>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Genuine TCP connect scanning, host ARP discovery, and service banner identification on authorized subnets
            </p>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center space-x-1.5 bg-[#050811] p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveTab('port-scan')}
            className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${
              activeTab === 'port-scan'
                ? 'bg-blue-600 text-white shadow-[0_0_12px_rgba(37,99,235,0.4)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            TCP Port Scan
          </button>
          <button
            onClick={() => setActiveTab('host-discovery')}
            className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${
              activeTab === 'host-discovery'
                ? 'bg-cyan-600 text-white shadow-[0_0_12px_rgba(6,182,212,0.4)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Subnet Host Sweep
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${
              activeTab === 'history'
                ? 'bg-purple-600 text-white shadow-[0_0_12px_rgba(147,51,234,0.4)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Scan Audit History ({scanHistory.length})
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="bg-red-950/40 border border-red-500/50 p-3 rounded-xl text-xs text-red-300 flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Tab 1: TCP Port Scan */}
      {activeTab === 'port-scan' && (
        <div className="space-y-4">
          <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Server className="w-4 h-4 mr-2 text-cyan-400" />
              Target Host Specification
            </h3>
            
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex-1">
                <input
                  type="text"
                  value={portTargetIp}
                  onChange={(e) => setPortTargetIp(e.target.value)}
                  placeholder="e.g. 127.0.0.1 or 172.20.10.2 (Authorized Private/Lab Target Only)"
                  className="w-full bg-[#050811] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-400"
                  disabled={isScanningPorts}
                />
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setPortTargetIp('127.0.0.1')}
                  className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 rounded border border-slate-700"
                >
                  Target: 127.0.0.1
                </button>
                <button
                  onClick={() => setPortTargetIp('172.20.10.2')}
                  className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 rounded border border-slate-700"
                >
                  Target: Wi-Fi IP
                </button>
                <button
                  onClick={handleRunPortScan}
                  disabled={isScanningPorts || !portTargetIp.trim()}
                  className={`px-5 py-2 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center shadow-lg transition-all ${
                    isScanningPorts
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                      : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-600/30'
                  }`}
                >
                  {isScanningPorts ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 mr-2 animate-spin text-cyan-300" />
                      Scanning Ports...
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 mr-2 fill-current" />
                      Launch Port Scan
                    </>
                  )}
                </button>
              </div>
            </div>

            <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span>Audited Ports: 20 Common Services ({DEFAULT_TARGET_PORTS.slice(0, 10).join(', ')}...)</span>
              <span className="text-emerald-400">Method: Genuine Socket TCP Connect (RFC 793)</span>
            </div>
          </div>

          {/* Port Scan Results */}
          {portScanResult && (
            <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl space-y-3 animate-in fade-in duration-300">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                    Scan Output: {portScanResult.target} ({portScanResult.resolved_ip})
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Probed {portScanResult.total_scanned} ports in {portScanResult.duration_seconds}s | Discovered: <strong className="text-emerald-400">{portScanResult.open_ports_count} OPEN</strong>, <span className="text-slate-400">{portScanResult.closed_ports_count} Closed</span>, <span className="text-amber-400">{portScanResult.filtered_ports_count} Filtered</span>
                  </p>
                </div>
                <div className="text-[11px] text-slate-400">
                  Scan ID: #{portScanResult.scan_id}
                </div>
              </div>

              {/* Open Ports Highlight */}
              {portScanResult.open_ports?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#050811] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                      <tr>
                        <th className="py-2 px-3">PORT</th>
                        <th className="py-2 px-3">STATE</th>
                        <th className="py-2 px-3">SERVICE NAME</th>
                        <th className="py-2 px-3">BANNER TELEMETRY</th>
                        <th className="py-2 px-3">ROUND-TRIP LATENCY</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/50">
                      {portScanResult.open_ports.map((p, idx) => (
                        <tr key={idx} className="bg-emerald-950/10 hover:bg-emerald-950/20">
                          <td className="py-2 px-3 font-bold text-cyan-300">{p.port}/TCP</td>
                          <td className="py-2 px-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                              OPEN
                            </span>
                          </td>
                          <td className="py-2 px-3 text-white font-semibold">{p.service}</td>
                          <td className="py-2 px-3 text-slate-300 truncate max-w-xs">{p.banner}</td>
                          <td className="py-2 px-3 text-emerald-400">{p.latency_ms} ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-[#050811] p-6 rounded-lg text-center text-xs text-slate-400">
                  <CheckCircle2 className="w-6 h-6 mx-auto mb-2 text-slate-500" />
                  No open ports discovered on {portScanResult.target}. Target closed or filtered by firewall.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Subnet Host Discovery */}
      {activeTab === 'host-discovery' && (
        <div className="space-y-4">
          <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Activity className="w-4 h-4 mr-2 text-cyan-400" />
              Subnet Active Host Sweep
            </h3>

            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex-1">
                <input
                  type="text"
                  value={subnetTarget}
                  onChange={(e) => setSubnetTarget(e.target.value)}
                  placeholder="e.g. 172.20.10.0/28 or 127.0.0.1/32 (Authorized CIDR)"
                  className="w-full bg-[#050811] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-400"
                  disabled={isDiscoveringHosts}
                />
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setSubnetTarget('127.0.0.1/32')}
                  className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 rounded border border-slate-700"
                >
                  Loopback /32
                </button>
                <button
                  onClick={() => setSubnetTarget('172.20.10.0/28')}
                  className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 rounded border border-slate-700"
                >
                  Wi-Fi Subnet /28
                </button>
                <button
                  onClick={handleRunHostDiscovery}
                  disabled={isDiscoveringHosts || !subnetTarget.trim()}
                  className={`px-5 py-2 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center shadow-lg transition-all ${
                    isDiscoveringHosts
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-600/30'
                  }`}
                >
                  {isDiscoveringHosts ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 mr-2 animate-spin text-cyan-300" />
                      Probing Subnet...
                    </>
                  ) : (
                    <>
                      <Search className="w-3.5 h-3.5 mr-2" />
                      Sweep Subnet
                    </>
                  )}
                </button>
              </div>
            </div>

            <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span>Host Discovery: TCP Echo + ICMP Ping Sweep + Windows ARP Cache Lookup</span>
              <span className="text-cyan-400">Strict Safety: Limited to max 64 hosts per sweep</span>
            </div>
          </div>

          {/* Discovery Output */}
          {discoveryResult && (
            <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl space-y-3 animate-in fade-in duration-300">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Discovered Active Hosts in {discoveryResult.target} ({discoveryResult.hosts_found} Active of {discoveryResult.probed_count} Probed)
                </h4>
                <div className="text-[11px] text-slate-400">
                  Elapsed: {discoveryResult.duration_seconds}s
                </div>
              </div>

              {discoveryResult.hosts?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#050811] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                      <tr>
                        <th className="py-2 px-3">IP ADDRESS</th>
                        <th className="py-2 px-3">STATUS</th>
                        <th className="py-2 px-3">MAC ADDRESS</th>
                        <th className="py-2 px-3">HOSTNAME</th>
                        <th className="py-2 px-3">LATENCY</th>
                        <th className="py-2 px-3">CONFIRMED BY</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/50">
                      {discoveryResult.hosts.map((h, idx) => (
                        <tr key={idx} className="hover:bg-slate-900/40">
                          <td className="py-2 px-3 font-bold text-cyan-300">{h.ip}</td>
                          <td className="py-2 px-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                              ACTIVE (ALIVE)
                            </span>
                          </td>
                          <td className="py-2 px-3 text-slate-300">{h.mac || 'N/A'}</td>
                          <td className="py-2 px-3 text-white">{h.hostname || 'None'}</td>
                          <td className="py-2 px-3 text-emerald-400">{h.latency_ms} ms</td>
                          <td className="py-2 px-3 text-slate-400">{h.confirmed_by}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-[#050811] p-6 rounded-lg text-center text-xs text-slate-400">
                  No active hosts responded to TCP echo or ICMP sweeps in {discoveryResult.target}.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Scan Audit History & Discovered Host Inventory */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          {/* Discovered Hosts Inventory Card */}
          <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white flex items-center justify-between">
              <span>Persistent Host Inventory ({discoveredHosts.length} Records)</span>
              <button onClick={loadHistory} className="text-cyan-400 hover:text-cyan-300 flex items-center text-[11px]">
                <RefreshCw className="w-3 h-3 mr-1" />
                Refresh
              </button>
            </h4>

            {discoveredHosts.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#050811] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">HOST IP</th>
                      <th className="py-2 px-3">MAC</th>
                      <th className="py-2 px-3">HOSTNAME</th>
                      <th className="py-2 px-3">OPEN PORTS FOUND</th>
                      <th className="py-2 px-3">LAST AUDITED</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {discoveredHosts.map((h) => (
                      <tr key={h.id} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 font-bold text-cyan-300">{h.ip}</td>
                        <td className="py-2 px-3 text-slate-400">{h.mac || 'N/A'}</td>
                        <td className="py-2 px-3 text-white">{h.hostname || 'None'}</td>
                        <td className="py-2 px-3">
                          {h.open_ports && h.open_ports.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {h.open_ports.map((op, i) => (
                                <span key={i} className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/30 text-[10px]">
                                  {op.port} ({op.service})
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-slate-500 text-[11px]">None detected</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-slate-400">{new Date(h.timestamp).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="bg-[#050811] p-6 rounded-lg text-center text-xs text-slate-500">
                No hosts discovered in database yet. Run a subnet sweep or port scan above.
              </div>
            )}
          </div>

          {/* Scan Execution History Card */}
          <div className="bg-[#070D1A] border border-cyan-900/40 p-4 rounded-xl space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white">
              Scan Execution Audit Trail (SQLite)
            </h4>

            {scanHistory.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#050811] text-slate-400 text-[10px] uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">ID</th>
                      <th className="py-2 px-3">TIMESTAMP</th>
                      <th className="py-2 px-3">TARGET</th>
                      <th className="py-2 px-3">SCAN TYPE</th>
                      <th className="py-2 px-3">HOSTS</th>
                      <th className="py-2 px-3">OPEN PORTS</th>
                      <th className="py-2 px-3">STATUS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {scanHistory.map((s) => (
                      <tr key={s.id} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-slate-500">#{s.id}</td>
                        <td className="py-2 px-3 text-slate-300">{new Date(s.timestamp).toLocaleString()}</td>
                        <td className="py-2 px-3 font-bold text-white">{s.target}</td>
                        <td className="py-2 px-3 text-cyan-400 font-semibold">{s.scan_type}</td>
                        <td className="py-2 px-3 text-slate-300">{s.hosts_found}</td>
                        <td className="py-2 px-3 text-emerald-400 font-bold">{s.open_ports_count}</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                            {s.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="bg-[#050811] p-6 rounded-lg text-center text-xs text-slate-500">
                No scan history recorded in SQLite yet.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
