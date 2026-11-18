/**
 * API service and WebSocket connection manager for SOC Dashboard
 */

const API_BASE = '/api';

export const fetchOverview = async () => {
  const res = await fetch(`${API_BASE}/overview`);
  if (!res.ok) throw new Error('Failed to fetch overview metrics');
  return res.json();
};

export const fetchMonitoringEvents = async (limit = 50, offset = 0, isMalicious = null, protocol = '') => {
  let url = `${API_BASE}/monitoring/events?limit=${limit}&offset=${offset}`;
  if (isMalicious !== null) url += `&is_malicious=${isMalicious}`;
  if (protocol) url += `&protocol=${protocol}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch monitoring events');
  return res.json();
};

export const fetchThreatAlerts = async (limit = 50, offset = 0, severity = '', status = '', detectionType = '') => {
  let url = `${API_BASE}/threats/alerts?limit=${limit}&offset=${offset}`;
  if (severity) url += `&severity=${severity}`;
  if (status) url += `&status=${status}`;
  if (detectionType) url += `&detection_type=${detectionType}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch threat alerts');
  return res.json();
};

export const updateAlertStatus = async (alertId, newStatus) => {
  const res = await fetch(`${API_BASE}/threats/alerts/${alertId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus }),
  });
  if (!res.ok) throw new Error('Failed to update alert status');
  return res.json();
};

export const fetchModelMetrics = async () => {
  const res = await fetch(`${API_BASE}/model/metrics`);
  if (!res.ok) throw new Error('Failed to fetch model metrics');
  return res.json();
};

export const retrainModel = async (options = { use_authentic: true }) => {
  const res = await fetch(`${API_BASE}/model/retrain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options),
  });
  if (!res.ok) throw new Error('Failed to trigger model retraining');
  return res.json();
};

export const fetchDatasetStatus = async () => {
  const res = await fetch(`${API_BASE}/dataset/status`);
  if (!res.ok) throw new Error('Failed to fetch dataset status');
  return res.json();
};

export const processDataset = async (params = {}) => {
  const res = await fetch(`${API_BASE}/dataset/process`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Failed to trigger dataset processing');
  return res.json();
};

export const fetchSystemStatus = async () => {
  const res = await fetch(`${API_BASE}/system/status`);
  if (!res.ok) throw new Error('Failed to fetch detailed system status');
  return res.json();
};

export const fetchBlockedIps = async () => {
  const res = await fetch(`${API_BASE}/defense/blocked-ips`);
  if (!res.ok) throw new Error('Failed to fetch blocked IPs');
  return res.json();
};

export const blockAttackerIp = async (data) => {
  const res = await fetch(`${API_BASE}/defense/block`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to block IP');
  return res.json();
};

export const unblockAttackerIp = async (ip) => {
  const res = await fetch(`${API_BASE}/defense/unblock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });
  if (!res.ok) throw new Error('Failed to unblock IP');
  return res.json();
};

export const toggleAutoBlock = async (enabled) => {
  const res = await fetch(`${API_BASE}/defense/toggle-auto-block?enabled=${enabled}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to toggle auto block');
  return res.json();
};

export const fetchIpIntel = async (ip) => {
  const res = await fetch(`${API_BASE}/intel/ip/${encodeURIComponent(ip)}`);
  if (!res.ok) throw new Error('Failed to fetch IP intelligence');
  return res.json();
};

export const fetchAlertExplanation = async (alertId) => {
  const res = await fetch(`${API_BASE}/ml/explain/${alertId}`);
  if (!res.ok) throw new Error('Failed to fetch AI decision explanation');
  return res.json();
};

export const getIncidentReportUrl = () => `${API_BASE}/reports/incident-summary`;
export const getLogsDownloadUrl = () => `${API_BASE}/logs/download`;

export const runHostDiscovery = async (targetSubnet, maxThreads = 20) => {
  const res = await fetch(`${API_BASE}/network-scan/host-discovery`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_subnet: targetSubnet, max_threads: maxThreads }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Host discovery failed');
  }
  return res.json();
};

export const runPortScan = async (targetIp, ports = null, maxThreads = 15) => {
  const res = await fetch(`${API_BASE}/network-scan/port-scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_ip: targetIp, ports, max_threads: maxThreads }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Port scan failed');
  }
  return res.json();
};

export const fetchScanHistory = async (limit = 30) => {
  const res = await fetch(`${API_BASE}/network-scan/history?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return res.json();
};

export const fetchDiscoveredHosts = async (limit = 50) => {
  const res = await fetch(`${API_BASE}/network-scan/hosts?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch discovered hosts');
  return res.json();
};

export const fetchDefenseActionsHistory = async (limit = 50) => {
  const res = await fetch(`${API_BASE}/defense/actions-history?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch defense actions history');
  return res.json();
};

export const triggerEmergencyUnblockAll = async () => {
  const res = await fetch(`${API_BASE}/defense/emergency-unblock-all`, { method: 'POST' });
  if (!res.ok) throw new Error('Emergency unblock failed');
  return res.json();
};

export const runWebScan = async (targetUrl, checkExposures = true, testWaf = true) => {
  const res = await fetch(`${API_BASE}/scanner/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_url: targetUrl,
      check_exposures: checkExposures,
      test_waf: testWaf,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Web security audit failed');
  }
  return res.json();
};

export const recordWebScanAlert = async (data) => {
  const res = await fetch(`${API_BASE}/scanner/record-alert`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to record web scan threat alert');
  return res.json();
};

export const testWebhook = async () => {
  const res = await fetch(`${API_BASE}/notifications/test`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to test webhook');
  return res.json();
};

export const configureWebhook = async (data) => {
  const res = await fetch(`${API_BASE}/notifications/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to configure webhook');
  return res.json();
};

export const fetchSystemLogs = async (limit = 100, level = '') => {
  let url = `${API_BASE}/logs?limit=${limit}`;
  if (level) url += `&level=${level}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch system logs');
  return res.json();
};

export const ingestAuthLog = async (logLine, source = 'AUTH_LOG') => {
  const res = await fetch(`${API_BASE}/logs/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_line: logLine, source }),
  });
  if (!res.ok) throw new Error('Failed to ingest auth log');
  return res.json();
};

export const fetchSettings = async () => {
  const res = await fetch(`${API_BASE}/settings`);
  if (!res.ok) throw new Error('Failed to fetch settings');
  return res.json();
};

export const updateSettings = async (settingsData) => {
  const res = await fetch(`${API_BASE}/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settingsData),
  });
  if (!res.ok) throw new Error('Failed to update settings');
  return res.json();
};

/**
 * Creates auto-reconnecting WebSocket subscription
 */
export const createWebSocketSubscription = (onMessage, onStatusChange) => {
  let ws = null;
  let isClosedByUser = false;
  let reconnectTimeout = null;

  const connect = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/soc`;

    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        if (onStatusChange) onStatusChange('CONNECTED');
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (onMessage) onMessage(parsed);
        } catch (e) {
          console.error('Failed to parse WebSocket message', e);
        }
      };

      ws.onclose = () => {
        if (onStatusChange) onStatusChange('DISCONNECTED');
        if (!isClosedByUser) {
          reconnectTimeout = setTimeout(connect, 2500);
        }
      };

      ws.onerror = (err) => {
        if (onStatusChange) onStatusChange('ERROR');
        ws.close();
      };
    } catch (err) {
      if (onStatusChange) onStatusChange('ERROR');
      if (!isClosedByUser) {
        reconnectTimeout = setTimeout(connect, 2500);
      }
    }
  };

  connect();

  return () => {
    isClosedByUser = true;
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
    if (ws) ws.close();
  };
};
