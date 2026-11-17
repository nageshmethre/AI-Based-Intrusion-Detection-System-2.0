import React, { useState } from 'react';
import { 
  BookOpen, 
  Terminal, 
  Server, 
  Activity, 
  ShieldAlert, 
  Cpu, 
  Database, 
  AlertTriangle, 
  HelpCircle, 
  Copy, 
  Check, 
  CheckCircle,
  ExternalLink,
  ChevronRight,
  Layers,
  FileText,
  Sliders,
  Radio,
  Search,
  Code
} from 'lucide-react';
import ProjectStatus from '../components/ProjectStatus';

const CHAPTERS = [
  { id: 'status', label: '1. Live Project Diagnostics', icon: Radio },
  { id: 'getting-started', label: '2. Getting Started', icon: BookOpen },
  { id: 'architecture', label: '3. System Architecture', icon: Layers },
  { id: 'dashboard', label: '4. Dashboard Guide', icon: Activity },
  { id: 'monitoring', label: '5. Live Monitoring & Adapters', icon: Server },
  { id: 'ai-model', label: '6. AI Model & CIC-IDS2017', icon: Cpu },
  { id: 'threats', label: '7. Threat Detection Engine', icon: ShieldAlert },
  { id: 'testing', label: '8. Testing & Demo Guide', icon: Terminal },
  { id: 'database', label: '9. Database & Audit Logs', icon: Database },
  { id: 'troubleshooting', label: '10. Troubleshooting', icon: AlertTriangle },
  { id: 'faq', label: '11. MCA Evaluation FAQs', icon: HelpCircle },
];

export default function GuideHelpCenter({ onNavigateTab }) {
  const [activeChapter, setActiveChapter] = useState('status');
  const [copiedCode, setCopiedCode] = useState(null);
  const [searchFilter, setSearchFilter] = useState('');

  const handleCopy = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const CodeBlock = ({ code, id, title }) => (
    <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden my-3">
      {title && (
        <div className="px-3.5 py-1.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-mono text-cyan-400 font-semibold">{title}</span>
          <button
            onClick={() => handleCopy(code, id)}
            className="flex items-center space-x-1 text-slate-400 hover:text-white transition"
          >
            {copiedCode === id ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-bold text-[11px]">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span className="text-[11px]">Copy</span>
              </>
            )}
          </button>
        </div>
      )}
      <pre className="p-3.5 font-mono text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap break-all">
        {code}
      </pre>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1">
            <BookOpen className="w-4 h-4" />
            <span>CyberSOC Knowledge Base & Documentation</span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-wide">
            SOC Operations, Architecture & MCA Evaluation Guide
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Comprehensive technical manual covering real-time packet sniffing, flow reassembly, Random Forest ML, and threat response
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setActiveChapter('testing')}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition"
          >
            Jump to Demo Scripts
          </button>
        </div>
      </div>

      {/* Main Layout: Chapter Navigation & Content */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        {/* Navigation Sidebar */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-3 shadow-lg space-y-1 sticky top-20">
          <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-500 border-b border-slate-800 mb-2">
            Table of Contents
          </div>
          {CHAPTERS.map((chap) => {
            const Icon = chap.icon;
            const isActive = activeChapter === chap.id;
            return (
              <button
                key={chap.id}
                onClick={() => setActiveChapter(chap.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                <div className="flex items-center space-x-2.5 truncate">
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                  <span className="truncate">{chap.label}</span>
                </div>
                <ChevronRight className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-white' : 'text-slate-600'}`} />
              </button>
            );
          })}
        </div>

        {/* Chapter Content Panel */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-6 sm:p-8 shadow-lg text-slate-300 text-xs leading-relaxed space-y-6">
          {/* Chapter 1: Live Status */}
          {activeChapter === 'status' && (
            <div className="space-y-4">
              <ProjectStatus />
            </div>
          )}

          {/* Chapter 2: Getting Started */}
          {activeChapter === 'getting-started' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                2. Getting Started with CyberSOC IDS
              </h3>

              <h4 className="text-sm font-bold text-cyan-400 mt-3">What is this Application?</h4>
              <p>
                CyberSOC IDS is a full-stack, enterprise-grade Network Intrusion Detection System (NIDS) designed for real-time cyber defense. It captures live network packets traversing your Windows network adapter, reconstructs them into bidirectional connection flows, extracts 40 statistical flow features conforming strictly to the CIC-IDS2017 schema, and evaluates them using a dual-engine architecture:
              </p>
              <ul className="list-disc pl-5 space-y-1 text-slate-300">
                <li><strong>Machine Learning Engine:</strong> Random Forest Classifier trained on statistical flow behaviors (detecting DoS, PortScan, BruteForce, Botnet).</li>
                <li><strong>Rule-Based Engine:</strong> High-speed sliding-window detectors for port sweeping, SYN floods, and SSH authentication brute-force logs.</li>
              </ul>

              <h4 className="text-sm font-bold text-cyan-400 mt-4">How to Start the Application</h4>
              <p>
                To launch the complete application (FastAPI backend, background packet capture daemon, WebSocket broadcaster, and compiled React SOC console):
              </p>
              <CodeBlock 
                id="cmd-start"
                title="PowerShell (Run as Administrator for Raw Packet Sniffing)"
                code="python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000"
              />
              <p>
                Once started, open your web browser and navigate to:
                <br />
                <a href="http://127.0.0.1:8000" target="_blank" rel="noreferrer" className="text-cyan-400 font-bold underline font-mono">
                  http://127.0.0.1:8000
                </a>
              </p>

              <h4 className="text-sm font-bold text-cyan-400 mt-4">How to Stop the Application</h4>
              <p>
                Press <kbd className="px-1.5 py-0.5 bg-slate-800 rounded border border-slate-700 text-white font-mono">Ctrl + C</kbd> in your terminal window. The shutdown lifecycle hook gracefully terminates the Scapy packet capture thread, flushes active network flows to SQLite, and closes WebSocket client connections.
              </p>
            </div>
          )}

          {/* Chapter 3: System Architecture */}
          {activeChapter === 'architecture' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                3. System Architecture & End-to-End Pipeline
              </h3>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300">
                Network Traffic &rarr; Scapy Packet Capture &rarr; Flow Aggregator (5s Timeout) &rarr; Feature Extractor (40 Features) &rarr; AI & Rule Engines &rarr; SQLite Store &rarr; WebSocket Broadcast &rarr; React SOC Dashboard
              </div>

              <div className="space-y-3 pt-2">
                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-white text-xs mb-1">1. Packet Capture (Scapy Sniffer)</h5>
                  <p>Binds directly to the selected Windows Npcap adapter via <code>scapy.sendrecv.AsyncSniffer</code>. Each packet is timestamped, its TCP/UDP/ICMP headers parsed, and delivered to both the fast rule-engine and the flow aggregator.</p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-white text-xs mb-1">2. Bidirectional Flow Aggregation</h5>
                  <p>Packets are mapped to bidirectional flows using a normalized 5-tuple: <code>(min_ip, max_ip, min_port, max_port, protocol)</code>. Packets with TCP FIN or RST flags finalize the flow immediately; otherwise, inactive connections are flushed after a configurable timeout (default: 5.0 seconds).</p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-white text-xs mb-1">3. Statistical Feature Extraction (40 Features)</h5>
                  <p>Calculates packet counts, byte volumes, inter-arrival times (IAT mean, std, max, min), packet length statistics, TCP flag counters (SYN, FIN, RST, PSH, ACK, URG), and TCP initial window sizes conforming to the UNB CIC-IDS2017 dataset standard.</p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-white text-xs mb-1">4. Dual Detection Engine</h5>
                  <p><strong>Rule Engine:</strong> Detects horizontal/vertical port scans (&ge;15 distinct ports within 5s), SYN floods (&ge;50 half-open SYNs), and SSH brute force (&ge;5 failed auth attempts).<br /><strong>AI Engine:</strong> Random Forest Classifier scales features via RobustScaler and predicts malicious classes with confidence and probability margin filters.</p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-white text-xs mb-1">5. Persistence & Live Streaming</h5>
                  <p>Completed flows are archived in <code>network_events</code>. High-confidence threats are recorded in <code>threat_alerts</code>. An asynchronous WebSocket dispatcher broadcasts <code>TRAFFIC_PULSE</code>, <code>NEW_EVENT</code>, and <code>NEW_ALERT</code> to all connected React clients in real time.</p>
                </div>
              </div>
            </div>
          )}

          {/* Chapter 4: Dashboard Guide */}
          {activeChapter === 'dashboard' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                4. SOC Dashboard Metrics & Operations Guide
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-1">
                  <span className="font-bold text-cyan-400 block">Throughput (pkts/s)</span>
                  <p>Real-time packet arrival rate per second across the active network adapter, updated every 1,000 milliseconds via WebSocket pulses.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-1">
                  <span className="font-bold text-cyan-400 block">Active Flows</span>
                  <p>Current count of in-flight TCP/UDP conversations currently being reassembled in memory before reaching the inactivity timeout.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-1">
                  <span className="font-bold text-cyan-400 block">AI Confidence Score</span>
                  <p>The percentage of decision trees in the Random Forest ensemble that voted for the predicted attack class (e.g., 0.85 = 85 out of 100 trees).</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-1">
                  <span className="font-bold text-cyan-400 block">Probability Margin</span>
                  <p>Difference between predicted malicious probability and BENIGN: <code>P(Attack) - P(BENIGN)</code>. Must be &ge; 0.25 to prevent false alerts on HTTPS traffic.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-1">
                  <span className="font-bold text-cyan-400 block">Severity Levels</span>
                  <p><strong>CRITICAL:</strong> High confidence (&ge;0.90) DoS, DDoS, Botnet.<br /><strong>HIGH:</strong> Rule-based PortScan, SSH BruteForce.<br /><strong>MEDIUM / LOW:</strong> Sub-threshold candidate anomalies.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800 space-y-1">
                  <span className="font-bold text-cyan-400 block">Alert Statuses</span>
                  <p>Interactive incident response workflow: <code>OPEN</code> &rarr; <code>INVESTIGATING</code> &rarr; <code>RESOLVED</code> or <code>FALSE_POSITIVE</code>.</p>
                </div>
              </div>
            </div>
          )}

          {/* Chapter 5: Live Monitoring & Adapters */}
          {activeChapter === 'monitoring' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                5. Live Monitoring & Network Interface Selection
              </h3>

              <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <span className="font-bold text-amber-300 text-xs block mb-1">Windows Npcap Architecture Rule:</span>
                <p className="text-amber-200/90 text-[11px]">
                  Windows does not forward local loopback traffic (<code>127.0.0.1</code>) to physical network cards. Therefore, local tests run exclusively through Npcap's virtual loopback adapter.
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="text-sm font-bold text-cyan-400">Selecting Adapters in the SOC Console</h4>
                <ol className="list-decimal pl-5 space-y-2">
                  <li>Navigate to the <strong>Settings</strong> page from the left sidebar.</li>
                  <li>In the <strong>Live Packet Capture Engine</strong> card, view the currently active adapter.</li>
                  <li>Click <strong>Npcap Loopback</strong> when performing isolated local tests (e.g. port scan simulations against 127.0.0.1).</li>
                  <li>Click <strong>Default (Wi-Fi)</strong> when monitoring live physical internet browsing, YouTube, or external local subnet traffic.</li>
                  <li>Use the <strong>Start Sniffer / Stop Sniffer</strong> toggle to pause or resume packet capture at any time.</li>
                </ol>
              </div>
            </div>
          )}

          {/* Chapter 6: AI Model & CIC-IDS2017 */}
          {activeChapter === 'ai-model' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                6. AI Detection Model & Complete CIC-IDS2017 Dataset
              </h3>

              <h4 className="text-sm font-bold text-cyan-400">What is Random Forest?</h4>
              <p>
                Random Forest is an ensemble machine learning algorithm that builds multiple randomized decision trees during training and outputs the mode of the individual tree predictions. It resists overfitting on noisy network traffic and evaluates non-linear feature interactions without assuming Gaussian distributions.
              </p>

              <h4 className="text-sm font-bold text-cyan-400">Authentic CIC-IDS2017 Dataset Provenance</h4>
              <p>
                Created by the <strong>Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick (UNB)</strong>, CIC-IDS2017 contains 2.8 million labeled flow records generated from authentic network traffic captures spanning 5 days:
              </p>
              <ul className="list-disc pl-5 space-y-1">
                <li><code>Monday-WorkingHours.pcap_ISCX.csv</code>: Pure Benign baseline traffic</li>
                <li><code>Tuesday-WorkingHours.pcap_ISCX.csv</code>: FTP-Patator and SSH-Patator brute force</li>
                <li><code>Wednesday-workingHours.pcap_ISCX.csv</code>: DoS Slowloris, Slowhttptest, Hulk, GoldenEye, Heartbleed</li>
                <li><code>Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv</code>: Web attacks (Brute Force, XSS, SQLi)</li>
                <li><code>Friday-WorkingHours-Morning.pcap_ISCX.csv</code>: Botnet (ARES)</li>
                <li><code>Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv</code>: PortScan (Nmap)</li>
                <li><code>Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv</code>: DDoS (LOIC)</li>
              </ul>

              <h4 className="text-sm font-bold text-cyan-400">Official Download Resources</h4>
              <p>
                Download the complete raw dataset archive <code>GeneratedLabelledFlows.zip</code> from:
                <br />
                <a href="https://www.unb.ca/cic/datasets/ids-2017.html" target="_blank" rel="noreferrer" className="text-cyan-400 font-bold underline font-mono">
                  https://www.unb.ca/cic/datasets/ids-2017.html
                </a>
                <br />
                Or via the Kaggle Mirror:
                <br />
                <a href="https://www.kaggle.com/datasets/cicdataset/cicids2017" target="_blank" rel="noreferrer" className="text-cyan-400 font-bold underline font-mono">
                  https://www.kaggle.com/datasets/cicdataset/cicids2017
                </a>
              </p>

              <h4 className="text-sm font-bold text-cyan-400">Chunk-Based Ingestion & Preprocessing</h4>
              <p>
                To avoid Out-Of-Memory (OOM) crashes on 3+ GB datasets, our importer reads CSVs in 50,000-row chunks, removes whitespace in headers, strips infinities and nulls, enforces non-negativity, and performs stratified reservoir sampling to compile a balanced, authentic training set.
              </p>
            </div>
          )}

          {/* Chapter 7: Threat Detection Engine */}
          {activeChapter === 'threats' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                7. Threat Detection Engine & False Positive Mitigation
              </h3>

              <div className="space-y-3">
                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-white text-xs block mb-1">Port Scanning (Reconnaissance)</span>
                  <p>Detected by tracking unique destination ports probed by each source IP within a sliding 5.0-second window. If distinct ports hit &ge; 15, an immediate HIGH severity rule alert is fired.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-white text-xs block mb-1">Denial of Service (DoS / DDoS)</span>
                  <p>Characterized by massive request volume, abnormal forward/backward packet size ratios, and tiny inter-arrival times. Classified by Random Forest when prediction confidence &ge; 0.80.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-white text-xs block mb-1">SSH Authentication Brute Force</span>
                  <p>Correlates external syslog and Linux auth logs. If a host accumulates &ge; 5 failed logins within 60 seconds, an automated HIGH alert is recorded with attacker IP and targeted account.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-white text-xs block mb-1">Why Dual-Thresholds Stop False Positives</span>
                  <p>Ordinary HTTPS browsing flows (port 443 with TLS handshakes) can share boundary traits with slow DoS attacks. Requiring <code>confidence &ge; 0.80</code> and <code>P(Attack) - P(BENIGN) &ge; 0.25</code> eliminates HTTPS false alarms while maintaining 100% genuine attack detection.</p>
                </div>
              </div>
            </div>
          )}

          {/* Chapter 8: Testing & Demonstration Guide */}
          {activeChapter === 'testing' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                8. Step-by-Step Testing & Demonstration Guide (MCA Project)
              </h3>

              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-bold text-cyan-400">Step 1: Test Genuine Local Port Scan Detection</h4>
                  <p className="text-slate-300">
                    Switch the sniffer to <strong>Npcap Loopback Adapter</strong> in Settings (or run the switch command below), then trigger the port scan simulation:
                  </p>
                  <CodeBlock 
                    id="test-portscan"
                    title="1. Switch to Loopback and Run 20-Port SYN Sweep"
                    code={`# Switch sniffer to loopback:
python -c "import urllib.request, json; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/settings', data=json.dumps({'network_interface': r'\\\\Device\\\\NPF_Loopback'}).encode(), headers={'Content-Type': 'application/json'}))"

# Execute safe port scan simulation:
python test_traffic_generator.py --mode portscan`}
                  />
                  <p className="text-emerald-400 font-semibold">
                    &check; Expected Result: An orange HIGH severity "Port Scanning Activity Detected" alert appears in the SOC console within 2 seconds.
                  </p>
                </div>

                <div className="pt-2">
                  <h4 className="text-sm font-bold text-cyan-400">Step 2: Test SSH Brute Force Ingestion</h4>
                  <p className="text-slate-300">
                    Simulate 5 consecutive failed SSH authentication attempts from an external attacker IP:
                  </p>
                  <CodeBlock 
                    id="test-ssh"
                    title="2. Ingest 5 Failed Auth Log Lines"
                    code={`python -c "import urllib.request, json
for i in range(5):
    data = json.dumps({'log_line': 'Failed password for root from 198.51.100.44 port 42100 ssh2'}).encode()
    urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/logs/ingest', data=data, headers={'Content-Type': 'application/json'}))
print('5 SSH failure logs ingested successfully.')"`}
                  />
                  <p className="text-emerald-400 font-semibold">
                    &check; Expected Result: A HIGH severity "SSH Authentication Brute Force Attack Detected" alert is created for IP <code>198.51.100.44</code>.
                  </p>
                </div>

                <div className="pt-2">
                  <h4 className="text-sm font-bold text-cyan-400">Step 3: Test Normal HTTPS Traffic (Non-Alerting)</h4>
                  <p className="text-slate-300">
                    Switch back to Default (Wi-Fi) and browse regular web pages or run benign HTTPS requests:
                  </p>
                  <CodeBlock 
                    id="test-benign"
                    title="3. Switch to Wi-Fi and Generate Normal Web Traffic"
                    code={`# Switch back to physical Wi-Fi:
python -c "import urllib.request, json; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/settings', data=json.dumps({'network_interface': 'DEFAULT'}).encode(), headers={'Content-Type': 'application/json'}))"

# Generate normal requests:
python test_traffic_generator.py --mode benign`}
                  />
                  <p className="text-emerald-400 font-semibold">
                    &check; Expected Result: Network events increment in the Live Monitoring table, but zero false positive DoS alerts are added.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Chapter 9: Database & Logs */}
          {activeChapter === 'database' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                9. Database Architecture & Security Audit Logs
              </h3>

              <p>
                The backend utilizes <strong>SQLite 3 with Write-Ahead Logging (WAL)</strong> mode enabled. This allows concurrent read queries from REST endpoints while the Scapy capture thread continuously inserts live flow telemetry.
              </p>

              <div className="space-y-3">
                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-cyan-400 text-xs block mb-1">network_events Table</span>
                  <p>Stores completed connection flows: <code>id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, prediction, confidence, is_malicious, total_packets, total_bytes</code>.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-cyan-400 text-xs block mb-1">threat_alerts Table</span>
                  <p>Stores verified threat incidents: <code>id, timestamp, title, description, src_ip, dst_ip, dst_port, protocol, detection_type, threat_category, severity, confidence, status, details_json</code>.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-cyan-400 text-xs block mb-1">system_logs Table</span>
                  <p>Stores operational logs, SSH authentication failures, and system lifecycle events for compliance auditing.</p>
                </div>
              </div>

              <h4 className="text-sm font-bold text-cyan-400 mt-4">Inspect Database Directly via CLI</h4>
              <CodeBlock 
                id="cmd-sql"
                title="Inspect Alerts via Python SQLite"
                code={`python -c "import sqlite3; conn = sqlite3.connect('backend/data/soc_ids.db'); cur = conn.cursor(); cur.execute('SELECT id, timestamp, title, threat_category, severity FROM threat_alerts ORDER BY id DESC LIMIT 5'); print(cur.fetchall())"`}
              />
            </div>
          )}

          {/* Chapter 10: Troubleshooting */}
          {activeChapter === 'troubleshooting' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                10. SOC Troubleshooting & Problem Remediation
              </h3>

              <div className="space-y-3">
                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-amber-300 text-xs block mb-1">1. Scapy Error: WinPcap / Npcap Not Installed</span>
                  <p className="text-slate-300">
                    Install Npcap from <a href="https://npcap.com/#download" target="_blank" rel="noreferrer" className="text-cyan-400 underline">https://npcap.com</a>. Ensure the checkbox <em>"Install Npcap in WinPcap API-compatible Mode"</em> is checked during setup.
                  </p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-amber-300 text-xs block mb-1">2. Permission Denied / Raw Socket Error</span>
                  <p className="text-slate-300">
                    Open PowerShell or Windows Terminal as <strong>Administrator</strong> before running <code>python -m uvicorn backend.app.main:app</code>. Raw packet capture on Windows requires elevated privileges.
                  </p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-amber-300 text-xs block mb-1">3. Port Scan Alert Missing During Local Tests</span>
                  <p className="text-slate-300">
                    Verify the sniffer is listening on <code>\Device\NPF_Loopback</code>. If listening on Wi-Fi, loopback packets to <code>127.0.0.1</code> will never reach the sniffer.
                  </p>
                </div>

                <div className="p-3.5 bg-slate-800/40 rounded-lg border border-slate-800">
                  <span className="font-bold text-amber-300 text-xs block mb-1">4. WebSocket Reconnecting... in Dashboard Header</span>
                  <p className="text-slate-300">
                    Ensure Uvicorn is active on port 8000. If port 8000 is occupied, free it with: <code>Get-NetTCPConnection -LocalPort 8000 | Stop-Process</code>.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Chapter 11: MCA FAQs */}
          {activeChapter === 'faq' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-white uppercase tracking-wider border-b border-slate-800 pb-2">
                11. Frequently Asked Questions (MCA Project Defense)
              </h3>

              <div className="space-y-3">
                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-cyan-400 text-xs mb-1">Q1: How does this system differ from a traditional firewall?</h5>
                  <p>A firewall operates at the packet packet-filtering and port-blocking level using static rules. This AI-based IDS aggregates packets into bidirectional session flows, analyzes statistical flow dynamics (IAT, packet variance, window sizing), and classifies subtle malicious behaviors even when traffic uses legitimate open ports.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-cyan-400 text-xs mb-1">Q2: Why use Random Forest instead of Deep Learning (LSTM/CNN)?</h5>
                  <p>Random Forest excels on tabular network flow features, trains rapidly without requiring high-end GPUs, is robust to extreme statistical outliers, provides clear Gini feature importances for explainable AI, and executes microsecond inference suitable for high-throughput live network inspection.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-cyan-400 text-xs mb-1">Q3: How do you prevent data leakage during model training?</h5>
                  <p>The dataset is first deduplicated to prevent identical flow patterns from appearing in both training and test sets. Next, stratified splitting is performed. Finally, the RobustScaler is fitted strictly on the training partition and only transforms the holdout test set.</p>
                </div>

                <div className="p-3 bg-slate-800/40 rounded-lg border border-slate-800">
                  <h5 className="font-bold text-cyan-400 text-xs mb-1">Q4: Why is the F1-Score preferred over standard Accuracy in NIDS?</h5>
                  <p>Network traffic is severely imbalanced (95%+ of traffic is typically benign). A naive model that classifies everything as benign would achieve 95% accuracy while completely missing all cyberattacks. The F1-score balances precision and recall, ensuring genuine threats are captured without drowning operators in false positives.</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
