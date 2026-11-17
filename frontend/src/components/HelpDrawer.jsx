import React, { useState } from 'react';
import { 
  X, 
  Search, 
  Copy, 
  Check, 
  AlertTriangle, 
  BookOpen, 
  Terminal, 
  ExternalLink,
  Shield,
  Activity,
  Cpu,
  HelpCircle,
  ChevronRight
} from 'lucide-react';

const QUICK_COMMANDS = [
  {
    title: 'Run Server (Backend + Built Frontend)',
    command: 'python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000',
    description: 'Launches FastAPI server and serves React SOC dashboard at http://127.0.0.1:8000.'
  },
  {
    title: 'Recompile React Frontend (Vite)',
    command: 'cd frontend; npm run build; cd ..',
    description: 'Compiles production assets to frontend/dist.'
  },
  {
    title: 'Simulate Safe Port Scan (127.0.0.1)',
    command: 'python test_traffic_generator.py --mode portscan',
    description: 'Sends 20 distinct SYN packets to trigger the rule-based PortScan alert. (Requires Npcap Loopback selected).'
  },
  {
    title: 'Switch Interface to Npcap Loopback (CLI)',
    command: `python -c "import urllib.request, json; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/settings', data=json.dumps({'network_interface': r'\\\\Device\\\\NPF_Loopback'}).encode(), headers={'Content-Type': 'application/json'}))"`,
    description: 'Switches the Scapy sniffer to listen on the Windows Npcap loopback adapter.'
  },
  {
    title: 'Switch Interface to Default Wi-Fi (CLI)',
    command: `python -c "import urllib.request, json; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/settings', data=json.dumps({'network_interface': 'DEFAULT'}).encode(), headers={'Content-Type': 'application/json'}))"`,
    description: 'Switches the Scapy sniffer back to the host physical Wi-Fi adapter.'
  },
  {
    title: 'Ingest Sample SSH Failure Log (Rule Test)',
    command: `python -c "import urllib.request, json; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/logs/ingest', data=json.dumps({'log_line': 'Failed password for invalid user admin from 192.168.1.99 port 54321 ssh2'}).encode(), headers={'Content-Type': 'application/json'}))"`,
    description: 'Injects an auth log failure into the database to test the SSH brute force detector.'
  }
];

const GLOSSARY = [
  {
    term: 'Network Flow',
    def: 'A bidirectional sequence of IP packets sharing the same 5-tuple: (Source IP, Destination IP, Source Port, Destination Port, Transport Protocol).'
  },
  {
    term: 'Flow Duration',
    def: 'Total microseconds from the first packet to the last packet in a connection flow before inactivity timeout.'
  },
  {
    term: 'CIC-IDS2017',
    def: 'Benchmark intrusion detection evaluation dataset from the Canadian Institute for Cybersecurity (UNB), containing benign traffic and 14 attack profiles.'
  },
  {
    term: 'RobustScaler',
    def: 'Scikit-learn feature scaler that uses the median and interquartile range (IQR), making it resilient to extreme outliers common in network traffic bursts.'
  },
  {
    term: 'Probability Margin',
    def: 'The mathematical difference between the predicted attack category probability and the BENIGN probability: P(Attack) - P(BENIGN). Must be >= 0.25 to trigger an alert.'
  },
  {
    term: 'F1-Score',
    def: 'The harmonic mean of Precision and Recall: 2 * (Precision * Recall) / (Precision + Recall). Best metric for imbalanced cybersecurity datasets.'
  },
  {
    term: 'Npcap Loopback',
    def: 'Virtual NDIS adapter created by Npcap on Windows. All traffic targeting 127.0.0.1 travels strictly over this adapter rather than the physical Wi-Fi NIC.'
  }
];

export default function HelpDrawer({ isOpen, onClose, onNavigateTab }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedIndex, setCopiedIndex] = useState(null);

  if (!isOpen) return null;

  const handleCopy = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const filteredCommands = QUICK_COMMANDS.filter(c => 
    c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.command.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredGlossary = GLOSSARY.filter(g =>
    g.term.toLowerCase().includes(searchQuery.toLowerCase()) ||
    g.def.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-blue-500/10 text-cyan-400 rounded-lg border border-cyan-500/20">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Interactive SOC Knowledge Base
              </h3>
              <p className="text-xs text-slate-400">
                Documentation, live commands & technical reference
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Search Bar */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/50">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search guide, commands, or technical terms..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6 text-xs text-slate-300">
          {/* Important Security & Operational Warning */}
          <div className="p-3.5 bg-amber-500/10 border border-amber-500/30 rounded-xl space-y-2">
            <div className="flex items-center space-x-2 text-amber-300 font-bold uppercase tracking-wider text-[11px]">
              <AlertTriangle className="w-4 h-4" />
              <span>Important Windows Npcap Architecture Rule</span>
            </div>
            <p className="text-amber-200/90 leading-relaxed text-[11px]">
              On Windows 11, packets sent to <strong>127.0.0.1</strong> do <em>not</em> cross the physical Wi-Fi NIC. To detect local port scans or local test traffic, you must switch the sniffer to <strong>Npcap Loopback Adapter</strong> in Settings.
            </p>
          </div>

          {/* Quick Navigation Cards */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2.5 flex items-center">
              <ExternalLink className="w-3.5 h-3.5 text-cyan-400 mr-1.5" />
              Direct Dashboard Navigation
            </h4>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => { onNavigateTab('overview'); onClose(); }}
                className="p-2.5 bg-slate-800 hover:bg-slate-750 border border-slate-700 rounded-lg text-left transition flex items-center justify-between"
              >
                <div>
                  <span className="font-semibold text-white block">Security Overview</span>
                  <span className="text-[10px] text-slate-400">Live SOC telemetry</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
              </button>

              <button
                onClick={() => { onNavigateTab('threats'); onClose(); }}
                className="p-2.5 bg-slate-800 hover:bg-slate-750 border border-slate-700 rounded-lg text-left transition flex items-center justify-between"
              >
                <div>
                  <span className="font-semibold text-white block">Threat Detection</span>
                  <span className="text-[10px] text-slate-400">Manage incident alerts</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
              </button>

              <button
                onClick={() => { onNavigateTab('ai-model'); onClose(); }}
                className="p-2.5 bg-slate-800 hover:bg-slate-750 border border-slate-700 rounded-lg text-left transition flex items-center justify-between"
              >
                <div>
                  <span className="font-semibold text-white block">Model Performance</span>
                  <span className="text-[10px] text-slate-400">Metrics & CIC-IDS2017</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
              </button>

              <button
                onClick={() => { onNavigateTab('guide'); onClose(); }}
                className="p-2.5 bg-cyan-950/40 hover:bg-cyan-950/60 border border-cyan-500/30 rounded-lg text-left transition flex items-center justify-between"
              >
                <div>
                  <span className="font-semibold text-cyan-300 block">Full Guide & Center</span>
                  <span className="text-[10px] text-cyan-400/80">10 in-depth chapters</span>
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />
              </button>
            </div>
          </div>

          {/* Copyable Terminal Commands */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2.5 flex items-center">
              <Terminal className="w-3.5 h-3.5 text-blue-400 mr-1.5" />
              Testing & Execution Commands ({filteredCommands.length})
            </h4>
            <div className="space-y-3">
              {filteredCommands.map((item, idx) => (
                <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white text-[11px]">{item.title}</span>
                    <button
                      onClick={() => handleCopy(item.command, idx)}
                      className="flex items-center space-x-1 px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] transition"
                    >
                      {copiedIndex === idx ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400 font-bold">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-2 bg-slate-900 rounded font-mono text-[10px] text-cyan-300 overflow-x-auto whitespace-pre-wrap break-all border border-slate-800/80">
                    {item.command}
                  </pre>
                  <p className="text-[10px] text-slate-400 leading-relaxed">
                    {item.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Technical Glossary */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2.5 flex items-center">
              <HelpCircle className="w-3.5 h-3.5 text-purple-400 mr-1.5" />
              Cybersecurity Technical Glossary ({filteredGlossary.length})
            </h4>
            <div className="space-y-2">
              {filteredGlossary.map((item, idx) => (
                <div key={idx} className="p-2.5 bg-slate-800/50 rounded-lg border border-slate-800">
                  <span className="font-bold text-cyan-300 text-[11px] block">{item.term}</span>
                  <p className="text-[11px] text-slate-300 mt-0.5 leading-relaxed">{item.def}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <span className="text-[11px] text-slate-400">CyberSOC IDS MCA Project Guide v1.0</span>
          <button
            onClick={() => { onNavigateTab('guide'); onClose(); }}
            className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow transition"
          >
            Open Full Documentation
          </button>
        </div>
      </div>
    </div>
  );
}
