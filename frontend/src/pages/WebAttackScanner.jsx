import React, { useState } from 'react';
import { 
  Globe, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Lock, 
  Unlock, 
  Server, 
  Terminal, 
  Search, 
  Play, 
  CheckCircle2, 
  XCircle, 
  AlertCircle, 
  FileCode, 
  Code, 
  ExternalLink,
  Flame,
  ArrowRight,
  RefreshCw,
  Bug,
  Database,
  Layers
} from 'lucide-react';
import { runWebScan, recordWebScanAlert } from '../services/api';

const PRESET_TARGETS = [
  { label: 'Local SOC Backend (8000)', url: 'http://127.0.0.1:8000' },
  { label: 'Local Frontend Server (5173)', url: 'http://localhost:5173' },
  { label: 'Localhost (Port 80)', url: 'http://localhost:80' },
  { label: 'Authorized Custom Host', url: 'https://httpbin.org' }
];

export default function WebAttackScanner({ onNavigateToThreats }) {
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000');
  const [checkExposures, setCheckExposures] = useState(true);
  const [testWaf, setTestWaf] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [results, setResults] = useState(null);
  const [activeResultTab, setActiveResultTab] = useState('findings');
  const [findingFilter, setFindingFilter] = useState('ALL');
  const [recordingId, setRecordingId] = useState(null);
  const [recordedAlertIds, setRecordedAlertIds] = useState([]);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleLaunchScan = async () => {
    if (!targetUrl.trim()) return;
    setScanning(true);
    setErrorMsg(null);
    setResults(null);
    setScanStep('1/5: Connecting to target & fingerprinting HTTP server banner...');

    try {
      const stepTimer1 = setTimeout(() => {
        setScanStep('2/5: Auditing OWASP Recommended Security Headers (CSP, HSTS, X-Frame)...');
      }, 700);

      const stepTimer2 = setTimeout(() => {
        setScanStep('3/5: Probing sensitive paths for dangerous exposure (/.env, /.git, /config)...');
      }, 1500);

      const stepTimer3 = setTimeout(() => {
        setScanStep('4/5: Testing WAF resistance against simulated attack vectors (SQLi, XSS, LFI)...');
      }, 2300);

      const res = await runWebScan(targetUrl, checkExposures, testWaf);

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);

      setScanStep('5/5: Compiling audit report & calculating posture score...');
      setTimeout(() => {
        setResults(res);
        setScanning(false);
      }, 500);

    } catch (err) {
      setErrorMsg(err.message || 'Audit execution encountered an error.');
      setScanning(false);
    }
  };

  const handleRecordIncident = async (finding) => {
    setRecordingId(finding.id);
    try {
      const res = await recordWebScanAlert({
        title: `[Web Audit] ${finding.title}`,
        severity: finding.severity,
        description: finding.description,
        target_url: results?.target_url || targetUrl,
        category: finding.category,
        evidence: finding.evidence,
        remediation: finding.remediation
      });
      setRecordedAlertIds((prev) => [...prev, finding.id]);
      alert(`Success: ${res.message}! View it in Threat Detection.`);
    } catch (err) {
      alert(`Failed to record incident: ${err.message}`);
    } finally {
      setRecordingId(null);
    }
  };

  const filteredFindings = results?.findings?.filter((f) => {
    if (findingFilter === 'ALL') return true;
    return f.severity === findingFilter;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="p-2 bg-rose-600/20 text-rose-400 border border-rose-500/30 rounded-lg">
              <Globe className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-base font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Web Application Attack Scanner & Security Auditor
                <span className="text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40 px-2 py-0.5 rounded font-mono font-bold">
                  DEFENSIVE AUDIT
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Automated OWASP security header assessment, sensitive exposure discovery & WAF attack vector resistance testing
              </p>
            </div>
          </div>
        </div>

        {results && (
          <button
            onClick={() => {
              setResults(null);
              handleLaunchScan();
            }}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 flex items-center shadow transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-2" />
            Re-run Audit
          </button>
        )}
      </div>

      {/* Target Configuration Console */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-end gap-4">
          <div className="flex-1 space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center">
              <Search className="w-3.5 h-3.5 mr-1.5 text-blue-400" />
              Target Website / API Endpoint URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="e.g. http://127.0.0.1:8000 or https://target-app.internal"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
              disabled={scanning}
            />
          </div>

          <div className="flex flex-wrap items-center gap-4 text-xs text-slate-300 pb-2">
            <label className="flex items-center space-x-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={checkExposures}
                onChange={(e) => setCheckExposures(e.target.checked)}
                className="rounded bg-slate-800 border-slate-700 text-rose-600 focus:ring-0"
                disabled={scanning}
              />
              <span>Probing Sensitive Files (<code>.env</code>, <code>.git</code>)</span>
            </label>

            <label className="flex items-center space-x-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={testWaf}
                onChange={(e) => setTestWaf(e.target.checked)}
                className="rounded bg-slate-800 border-slate-700 text-rose-600 focus:ring-0"
                disabled={scanning}
              />
              <span>WAF Attack Simulation (SQLi, XSS)</span>
            </label>
          </div>

          <button
            onClick={handleLaunchScan}
            disabled={scanning || !targetUrl.trim()}
            className={`px-6 py-2.5 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center justify-center shadow-lg transition-all ${
              scanning
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30'
            }`}
          >
            {scanning ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin text-rose-300" />
                Scanning Attack Surface...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 mr-2 fill-current" />
                Launch Attack Scan
              </>
            )}
          </button>
        </div>

        {/* Quick Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-800/80">
          <span className="text-[11px] text-slate-500 font-medium">Quick Presets:</span>
          {PRESET_TARGETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => setTargetUrl(p.url)}
              disabled={scanning}
              className="px-2.5 py-1 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 text-[11px] rounded transition-colors font-mono"
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Scanning Terminal / Live Step Feed */}
        {scanning && (
          <div className="bg-slate-950 border border-rose-500/30 rounded-lg p-4 font-mono text-xs text-rose-400 flex items-center space-x-3 shadow-inner">
            <RefreshCw className="w-4 h-4 animate-spin text-rose-400 shrink-0" />
            <div className="flex-1">
              <span className="font-bold text-white block">Audit in progress:</span>
              <span className="text-slate-300">{scanStep}</span>
            </div>
          </div>
        )}

        {errorMsg && (
          <div className="bg-red-950/40 border border-red-500/50 rounded-lg p-4 font-mono text-xs text-red-300 flex items-center space-x-2">
            <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Results View */}
      {results && results.status === 'COMPLETED' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Posture Score & Metrics Header */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Score & Grade Card */}
            <div className={`p-5 rounded-xl border shadow-lg flex items-center justify-between ${
              results.grade === 'A' ? 'bg-gradient-to-br from-emerald-950/50 to-slate-900 border-emerald-500/40' :
              results.grade === 'B' ? 'bg-gradient-to-br from-blue-950/50 to-slate-900 border-blue-500/40' :
              results.grade === 'C' ? 'bg-gradient-to-br from-amber-950/50 to-slate-900 border-amber-500/40' :
              'bg-gradient-to-br from-red-950/50 to-slate-900 border-red-500/40'
            }`}>
              <div>
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                  Security Posture Score
                </span>
                <div className="flex items-baseline space-x-2">
                  <span className="text-3xl font-extrabold text-white font-mono">
                    {results.overall_score}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">/ 100</span>
                </div>
                <div className="mt-1 text-xs font-semibold text-slate-300">
                  Risk Level: <span className="font-bold text-white">{results.risk_level}</span>
                </div>
              </div>
              <div className={`w-14 h-14 rounded-full border-2 flex items-center justify-center font-black text-2xl font-mono ${
                results.grade === 'A' ? 'border-emerald-500 text-emerald-400 bg-emerald-500/10' :
                results.grade === 'B' ? 'border-blue-500 text-blue-400 bg-blue-500/10' :
                results.grade === 'C' ? 'border-amber-500 text-amber-400 bg-amber-500/10' :
                'border-red-500 text-red-400 bg-red-500/10'
              }`}>
                {results.grade}
              </div>
            </div>

            {/* Total Findings Card */}
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-lg">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Discovered Findings
              </span>
              <div className="text-3xl font-extrabold text-white font-mono">
                {results.total_findings}
              </div>
              <div className="mt-2 flex items-center gap-2 text-[11px] font-mono">
                <span className="text-red-400 font-bold">{results.summary.CRITICAL || 0} Critical</span>
                <span className="text-slate-600">•</span>
                <span className="text-orange-400 font-bold">{results.summary.HIGH || 0} High</span>
                <span className="text-slate-600">•</span>
                <span className="text-amber-400 font-bold">{results.summary.MEDIUM || 0} Med</span>
              </div>
            </div>

            {/* Server Fingerprint Card */}
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-lg">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Server Identity & Latency
              </span>
              <div className="text-sm font-bold text-white font-mono truncate">
                {results.server_info.server_banner || 'Hidden'}
              </div>
              <div className="mt-2 text-[11px] text-slate-400 font-mono space-y-0.5">
                <div>Latency: <span className="text-emerald-400 font-bold">{results.server_info.response_time_ms} ms</span></div>
                <div>Status: <span className="text-blue-400 font-bold">HTTP {results.server_info.status_code}</span></div>
              </div>
            </div>

            {/* Transport & SSL */}
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-lg">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Transport Layer Security
              </span>
              <div className="flex items-center space-x-2 mt-1">
                {results.server_info.is_https ? (
                  <>
                    <Lock className="w-5 h-5 text-emerald-400" />
                    <span className="text-sm font-bold text-emerald-400 font-mono">HTTPS Encrypted</span>
                  </>
                ) : (
                  <>
                    <Unlock className="w-5 h-5 text-rose-400" />
                    <span className="text-sm font-bold text-rose-400 font-mono">HTTP Cleartext</span>
                  </>
                )}
              </div>
              <div className="mt-2 text-[11px] text-slate-400 font-mono">
                Audit Duration: <span className="text-slate-300 font-bold">{results.duration_seconds}s</span>
              </div>
            </div>
          </div>

          {/* Results Navigation Tabs */}
          <div className="flex border-b border-slate-800 gap-2">
            <button
              onClick={() => setActiveResultTab('findings')}
              className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center border-b-2 transition-all ${
                activeResultTab === 'findings'
                  ? 'border-rose-500 text-rose-400 bg-rose-500/10'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <AlertTriangle className="w-4 h-4 mr-2" />
              Vulnerability Findings ({results.findings?.length || 0})
            </button>

            <button
              onClick={() => setActiveResultTab('headers')}
              className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center border-b-2 transition-all ${
                activeResultTab === 'headers'
                  ? 'border-blue-500 text-blue-400 bg-blue-500/10'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <FileCode className="w-4 h-4 mr-2" />
              Security Headers Audit
            </button>

            <button
              onClick={() => setActiveResultTab('exposures')}
              className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center border-b-2 transition-all ${
                activeResultTab === 'exposures'
                  ? 'border-amber-500 text-amber-400 bg-amber-500/10'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <Layers className="w-4 h-4 mr-2" />
              Sensitive Path Probing
            </button>

            <button
              onClick={() => setActiveResultTab('waf')}
              className={`px-4 py-2.5 text-xs font-bold uppercase tracking-wider flex items-center border-b-2 transition-all ${
                activeResultTab === 'waf'
                  ? 'border-purple-500 text-purple-400 bg-purple-500/10'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <Bug className="w-4 h-4 mr-2" />
              WAF Attack Resistance
            </button>
          </div>

          {/* Tab 1: Findings */}
          {activeResultTab === 'findings' && (
            <div className="space-y-4">
              {/* Filter pills */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-slate-400 font-semibold mr-1">Severity:</span>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setFindingFilter(sev)}
                    className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider transition-all ${
                      findingFilter === sev
                        ? 'bg-rose-600 text-white shadow'
                        : 'bg-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              {/* Findings List */}
              {filteredFindings.length > 0 ? (
                <div className="space-y-3">
                  {filteredFindings.map((finding) => {
                    const isRecorded = recordedAlertIds.includes(finding.id);
                    return (
                      <div
                        key={finding.id}
                        className={`bg-slate-900 border rounded-xl p-5 shadow-lg space-y-3 transition-all ${
                          finding.severity === 'CRITICAL' ? 'border-red-500/50 bg-red-950/10' :
                          finding.severity === 'HIGH' ? 'border-orange-500/40 bg-orange-950/10' :
                          finding.severity === 'MEDIUM' ? 'border-amber-500/30' :
                          'border-slate-800'
                        }`}
                      >
                        <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                          <div className="space-y-1 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider ${
                                finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                                finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                                finding.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                'bg-slate-800 text-slate-400'
                              }`}>
                                {finding.severity}
                              </span>

                              <span className="text-xs text-slate-400 font-mono">
                                Category: <span className="text-slate-200 font-semibold">{finding.category}</span>
                              </span>
                            </div>

                            <h4 className="text-base font-bold text-white tracking-wide pt-1">
                              {finding.title}
                            </h4>

                            <p className="text-xs text-slate-300 leading-relaxed">
                              {finding.description}
                            </p>
                          </div>

                          {/* Action Button: Record into SOC Incident DB */}
                          <div className="shrink-0 pt-1">
                            <button
                              onClick={() => handleRecordIncident(finding)}
                              disabled={isRecorded || recordingId === finding.id}
                              className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center transition-all ${
                                isRecorded
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40 cursor-default'
                                  : 'bg-rose-700 hover:bg-rose-600 text-white border border-rose-500/50 shadow-md'
                              }`}
                            >
                              <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />
                              {isRecorded ? 'Logged in SOC' : recordingId === finding.id ? 'Logging...' : 'Log as Threat Alert'}
                            </button>
                          </div>
                        </div>

                        {/* Evidence & Remediation Box */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs font-mono">
                          <div className="bg-slate-950/80 p-3 rounded border border-slate-800">
                            <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">
                              Evidence Telemetry:
                            </span>
                            <span className="text-slate-300 break-all">{finding.evidence}</span>
                          </div>

                          <div className="bg-slate-950/80 p-3 rounded border border-slate-800">
                            <span className="text-emerald-400 text-[10px] uppercase font-bold block mb-1">
                              Actionable Remediation:
                            </span>
                            <span className="text-emerald-300/90 break-words">{finding.remediation}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 font-medium text-xs">
                  <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-emerald-400" />
                  No security findings discovered under selected severity filter.
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Security Headers */}
          {activeResultTab === 'headers' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                OWASP ASVS Standard Security Headers Assessment
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(results.headers_analyzed || {}).map(([hdrKey, info]) => {
                  const isPresent = info.status === 'PRESENT';
                  return (
                    <div
                      key={hdrKey}
                      className={`p-4 rounded-lg border font-mono text-xs flex flex-col justify-between ${
                        isPresent
                          ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                          : 'bg-red-950/20 border-red-500/40 text-red-300'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-bold text-white text-sm">{info.name}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isPresent ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'
                        }`}>
                          {info.status}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        Header: <span className="text-slate-300">{hdrKey}</span>
                      </div>
                      {isPresent && (
                        <div className="mt-2 text-[10px] bg-slate-950 p-2 rounded border border-emerald-900/50 text-slate-300 break-all">
                          Value: {info.value}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tab 3: Sensitive Exposures */}
          {activeResultTab === 'exposures' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Sensitive File Probing Results
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-slate-950 text-slate-400 text-[11px] uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Resource Target</th>
                      <th className="py-2.5 px-3">Probe Path</th>
                      <th className="py-2.5 px-3">HTTP Status</th>
                      <th className="py-2.5 px-3">Exposure Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {(results.exposure_results || []).map((exp, idx) => (
                      <tr key={idx} className={exp.exposed ? 'bg-red-950/20' : 'hover:bg-slate-800/30'}>
                        <td className="py-2.5 px-3 text-white font-semibold">{exp.name}</td>
                        <td className="py-2.5 px-3 text-cyan-400">{exp.path}</td>
                        <td className="py-2.5 px-3">{exp.status_code || 'Err'}</td>
                        <td className="py-2.5 px-3">
                          {exp.exposed ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                              EXPOSED (DANGER)
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400">
                              PROTECTED (PASS)
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 4: WAF Attack Vectors */}
          {activeResultTab === 'waf' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                WAF Defense & Attack Vector Resistance Tests
              </h4>
              <div className="space-y-3">
                {(results.attack_test_results || []).map((atk, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-bold text-white">{atk.name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {atk.category}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Probe Payload: <code className="text-rose-400">{atk.payload}</code>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 shrink-0">
                      <div className="text-right">
                        <span className="text-[10px] text-slate-500 block uppercase">Server Response</span>
                        <span className="font-bold text-white">HTTP {atk.status_code}</span>
                      </div>

                      {atk.waf_blocked ? (
                        <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center">
                          <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                          WAF BLOCKED (PASS)
                        </span>
                      ) : (
                        <span className="px-2.5 py-1 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center">
                          <AlertTriangle className="w-3.5 h-3.5 mr-1" />
                          UNFILTERED (200 OK)
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
