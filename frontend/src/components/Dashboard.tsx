import React, { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import SharinganLogo from './SharinganLogo';
import './Dashboard.css';

interface SummaryData {
  total_events: number;
  unique_source_ips: number;
  malicious_event_count: number;
  blocklist_count: number;
  by_attack_category: Record<string, number>;
  by_protocol: Record<string, number>;
  by_risk_level: Record<string, number>;
}

interface EventRecord {
  id?: number;
  _record_id: number;
  timestamp: string | null;
  event_type: string;
  source_ip: string | null;
  source_port: number | null;
  protocol: string | null;
  session_id: string | null;
  username: string | null;
  password: string | null;
  command: string | null;
  command_preview: string;
  url: string | null;
  classification?: {
    attack_category: string;
    severity: string;
    reason: string;
  };
  threat_intel?: {
    score?: {
      is_malicious: boolean;
      confidence: string;
    };
  };
}

interface Threat {
  ip: string;
  count: number;
}

interface FilterOptions {
  event_types: string[];
  attack_categories: string[];
  protocols: string[];
}

interface AttackSession {
  id: number;
  session_id: string;
  source_ip: string;
  honeypot: string;
  start_time: string | null;
  end_time: string | null;
  event_count: number;
  attack_categories: string[];
  severity_counts: Record<string, number>;
  is_malicious: number;
  first_seen: string;
  last_seen: string;
}

interface SessionTimelineData {
  events: EventRecord[];
  session_id: string;
  source_ip: string;
}

interface DeviceMetrics {
  hostname?: string;
  uptime_seconds?: number;
  ram_used_mb?: number;
  ram_total_mb?: number;
  ram_percent?: number;
  load_1m?: number;
  cpu_count?: number;
  disk_used_gb?: number;
  disk_total_gb?: number;
  disk_percent?: number;
  local_ip?: string;
}

interface Device {
  device_id: string;
  name: string;
  provider: string | null;
  hostname: string | null;
  last_seen: string | null;
  status: 'online' | 'stale' | 'offline';
  age_seconds: number | null;
  metrics: DeviceMetrics;
}

interface NewDeviceInfo {
  device: Device;
  agent_token: string;
  install_command: string;
}

interface AuthUser {
  user_id: string;
  email: string;
  first_name: string;
  last_name?: string | null;
  cloud_provider: string;
}

const REFRESH_INTERVAL = 3000;
const GRAFANA_DASHBOARD_UID = 'honeypot-monitoring';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [authUser, setAuthUser] = useState<AuthUser | null>(() => {
    const raw = localStorage.getItem('authUser');
    if (!raw) return null;
    try {
      return JSON.parse(raw) as AuthUser;
    } catch {
      return null;
    }
  });
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [filterOptions, setFilterOptions] = useState<FilterOptions>({ event_types: [], attack_categories: [], protocols: [] });
  const [activeNav, setActiveNav] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  // Filters
  const [filterIp, setFilterIp] = useState('');
  const [filterEventType, setFilterEventType] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [filterProtocol, setFilterProtocol] = useState('');
  const [filterMaliciousOnly, setFilterMaliciousOnly] = useState(false);

  // Sessions
  const [sessions, setSessions] = useState<AttackSession[]>([]);
  const [sessionsTotal, setSessionsTotal] = useState(0);
  const [sessionsMsg, setSessionsMsg] = useState<string | null>(null);
  const [sessionsMaliciousOnly, setSessionsMaliciousOnly] = useState(false);
  const [viewingSession, setViewingSession] = useState<AttackSession | null>(null);
  const [sessionTimeline, setSessionTimeline] = useState<SessionTimelineData | null>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);

  // Devices
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesMsg, setDevicesMsg] = useState<string | null>(null);
  const [newDeviceName, setNewDeviceName] = useState('');
  const [newDeviceProvider, setNewDeviceProvider] = useState('');
  const [creatingDevice, setCreatingDevice] = useState(false);
  const [createdDevice, setCreatedDevice] = useState<NewDeviceInfo | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterIp) params.set('source_ip', filterIp);
      if (filterEventType) params.set('event_type', filterEventType);
      if (filterCategory) params.set('attack_category', filterCategory);
      if (filterProtocol) params.set('protocol', filterProtocol);
      if (filterMaliciousOnly) params.set('malicious_only', '1');
      const qs = params.toString() ? `?${params.toString()}` : '';

      const [summaryRes, eventsRes, threatsRes] = await Promise.all([
        fetch('/api/summary'),
        fetch(`/api/events${qs}`),
        fetch('/api/top-threats'),
      ]);

      if (summaryRes.ok) setSummary(await summaryRes.json());
      if (eventsRes.ok) {
        const data = await eventsRes.json();
        setEvents(data.records || []);
        setFilterOptions(data.filter_options || { event_types: [], attack_categories: [], protocols: [] });
      }
      if (threatsRes.ok) {
        const data = await threatsRes.json();
        setThreats(data.threats || []);
      }

      setLastUpdate(new Date());
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch data:', err);
      setLoading(false);
    }
  }, [filterIp, filterEventType, filterCategory, filterProtocol, filterMaliciousOnly]);

  const fetchSessions = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterIp) params.set('source_ip', filterIp);
      if (sessionsMaliciousOnly) params.set('malicious_only', '1');
      const qs = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`/api/sessions${qs}`);
      if (res.ok) {
        const data = await res.json();
        setSessions(data.sessions || []);
        setSessionsTotal(data.total || 0);
        setSessionsMsg(data.message || null);
      }
    } catch (err) {
      console.error('Failed to fetch sessions:', err);
    }
  }, [filterIp, sessionsMaliciousOnly]);

  const fetchDevices = useCallback(async () => {
    const token = localStorage.getItem('authToken');
    if (!token) return;
    try {
      const res = await fetch('/api/devices', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setDevices(data.devices || []);
        setDevicesMsg(null);
      } else {
        const data = await res.json().catch(() => ({}));
        setDevicesMsg(data.error || 'Unable to load devices.');
      }
    } catch (err) {
      console.error('Failed to fetch devices:', err);
    }
  }, []);

  const createDevice = async () => {
    const token = localStorage.getItem('authToken');
    if (!token || !newDeviceName.trim()) return;
    setCreatingDevice(true);
    setDeviceError(null);
    try {
      const res = await fetch('/api/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: newDeviceName.trim(), provider: newDeviceProvider || null }),
      });
      const data = await res.json();
      if (res.ok) {
        setCreatedDevice(data);
        setCopied(false);
        setNewDeviceName('');
        setNewDeviceProvider('');
        fetchDevices();
      } else {
        setDeviceError(data.error || 'Unable to create device.');
      }
    } catch (err) {
      console.error('Failed to create device:', err);
      setDeviceError('Unable to create device.');
    }
    setCreatingDevice(false);
  };

  const deleteDevice = async (device: Device) => {
    const token = localStorage.getItem('authToken');
    if (!token) return;
    if (!window.confirm(`Remove device "${device.metrics.hostname || device.name}"?`)) return;
    try {
      const res = await fetch(`/api/devices/${encodeURIComponent(device.device_id)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        setDevices((prev) => prev.filter((d) => d.device_id !== device.device_id));
      }
    } catch (err) {
      console.error('Failed to delete device:', err);
    }
  };

  const copyCommand = async (text: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for non-secure contexts (plain HTTP over LAN IP).
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  };

  const fetchSessionTimeline = async (session: AttackSession) => {
    setTimelineLoading(true);
    setViewingSession(session);
    try {
      const res = await fetch(
        `/api/sessions/${encodeURIComponent(session.session_id)}/timeline?source_ip=${encodeURIComponent(session.source_ip)}`
      );
      if (res.ok) {
        setSessionTimeline(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch session timeline:', err);
    }
    setTimelineLoading(false);
  };

  const closeTimeline = () => {
    setViewingSession(null);
    setSessionTimeline(null);
  };

  const handleLogout = async () => {
    const token = localStorage.getItem('authToken');
    if (token) {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => undefined);
    }
    localStorage.removeItem('authToken');
    localStorage.removeItem('authUser');
    navigate('/login', { replace: true });
  };

  useEffect(() => {
    const timeout = window.setTimeout(fetchData, 0);
    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => {
      window.clearTimeout(timeout);
      clearInterval(interval);
    };
  }, [fetchData]);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (!token) return;
    fetch('/api/auth/me', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(async (res) => {
        if (!res.ok) throw new Error('session expired');
        return res.json();
      })
      .then((data) => {
        if (data.user) {
          setAuthUser(data.user);
          localStorage.setItem('authUser', JSON.stringify(data.user));
        }
      })
      .catch(() => {
        localStorage.removeItem('authToken');
        localStorage.removeItem('authUser');
        navigate('/login', { replace: true });
      });
  }, [navigate]);

  useEffect(() => {
    if (activeNav === 'sessions') {
      const timeout = window.setTimeout(fetchSessions, 0);
      return () => window.clearTimeout(timeout);
    }
  }, [activeNav, fetchSessions]);

  useEffect(() => {
    if (activeNav === 'devices') {
      const timeout = window.setTimeout(fetchDevices, 0);
      const interval = setInterval(fetchDevices, REFRESH_INTERVAL);
      return () => {
        window.clearTimeout(timeout);
        clearInterval(interval);
      };
    }
  }, [activeNav, fetchDevices]);

  const stats = [
    { label: 'Total Events', value: summary?.total_events ?? 0 },
    { label: 'Unique IPs', value: summary?.unique_source_ips ?? 0 },
    { label: 'Malicious', value: summary?.malicious_event_count ?? 0, critical: true },
    { label: 'Blocklist', value: summary?.blocklist_count ?? 0 },
  ];

  const severityClass = (severity?: string) => {
    if (!severity) return 'low';
    return severity.toLowerCase();
  };

  const formatTime = (ts: string | null) => {
    if (!ts) return '-';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  };

  const formatDateTime = (ts: string | null) => {
    if (!ts) return '-';
    try {
      const d = new Date(ts);
      return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  const formatUptime = (seconds?: number) => {
    if (!seconds || seconds < 0) return '-';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
  };

  const grafanaBaseUrl = `${window.location.protocol}//${window.location.hostname}:3000`;
  const grafanaPath = `/d/${GRAFANA_DASHBOARD_UID}/honeypot-monitoring`;
  const grafanaParams = new URLSearchParams({
    orgId: '1',
    from: 'now-24h',
    to: 'now',
    theme: 'dark',
  });
  if (authUser?.user_id) {
    grafanaParams.append('var-user_id', authUser.user_id);
  }
  // Grafana 11+ uses a bare `&kiosk` flag (the old `kiosk=tv` value was removed).
  const grafanaEmbedUrl = `${grafanaBaseUrl}${grafanaPath}?${grafanaParams.toString()}&kiosk`;
  const grafanaDashboardUrl = grafanaEmbedUrl;

  const resetFilters = () => {
    setFilterIp('');
    setFilterEventType('');
    setFilterCategory('');
    setFilterProtocol('');
    setFilterMaliciousOnly(false);
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <aside className="dashboard-sidebar">
          <div className="sidebar-header"><SharinganLogo /></div>
        </aside>
        <main className="dashboard-main">
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Initializing Sharingan...</p>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <aside className="dashboard-sidebar">
        <div className="sidebar-header">
          <SharinganLogo />
        </div>
        <nav className="sidebar-nav">
          <a href="#" className={activeNav === 'overview' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('overview'); closeTimeline(); }}>Overview</a>
          <a href="#" className={activeNav === 'events' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('events'); closeTimeline(); }}>Events</a>
          <a href="#" className={activeNav === 'sessions' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('sessions'); closeTimeline(); }}>Sessions</a>
          <a href="#" className={activeNav === 'intelligence' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('intelligence'); closeTimeline(); }}>Intelligence</a>
          <a href="#" className={activeNav === 'devices' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('devices'); closeTimeline(); }}>Devices</a>
          <a href="#" className={activeNav === 'monitoring' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('monitoring'); closeTimeline(); }}>Monitoring</a>
          <a href="/api/exports/blocklist.txt" target="_blank" rel="noopener noreferrer">↓ Blocklist</a>
          <a href="/api/exports/report.md" target="_blank" rel="noopener noreferrer">↓ Report</a>
        </nav>
        <div className="sidebar-footer">
          <button className="logout-btn" onClick={handleLogout}>Sign out</button>
        </div>
      </aside>
      
      <main className="dashboard-main">
        <header className="dashboard-header">
          <div className="header-search">
            {activeNav === 'monitoring' ? (
              <div className="monitoring-search-label">Grafana history and trends</div>
            ) : activeNav === 'sessions' ? (
              <input
                type="text"
                placeholder="Filter by source IP..."
                value={filterIp}
                onChange={(e) => setFilterIp(e.target.value)}
              />
            ) : (
              <input
                type="text"
                placeholder="Filter by source IP..."
                value={filterIp}
                onChange={(e) => setFilterIp(e.target.value)}
              />
            )}
          </div>
          <div className="header-actions">
            <span className="status-indicator">
              Live · {lastUpdate.toLocaleTimeString()}
            </span>
            <div className="user-chip">
              <div className="user-profile">{authUser?.first_name?.charAt(0).toUpperCase() || 'U'}</div>
              <div>
                <strong>{authUser?.first_name || 'Operator'}</strong>
                <span>{authUser?.cloud_provider?.replace(/_/g, ' ') || 'dashboard'}</span>
              </div>
            </div>
          </div>
        </header>

        <section className="dashboard-content">
          {/* Stats Row — shown on overview, events, sessions */}
          {activeNav !== 'intelligence' && activeNav !== 'devices' && activeNav !== 'monitoring' && !viewingSession && (
            <div className="stats-grid">
              {stats.map((stat, i) => (
                <div key={i} className="stat-card">
                  <span className="stat-label">{stat.label}</span>
                  <div className="stat-value-group">
                    <span className={`stat-value ${stat.critical ? 'text-red' : ''}`}>
                      {stat.value.toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Filters Bar (events view) */}
          {activeNav === 'events' && !viewingSession && (
            <div className="filters-bar">
              <select value={filterEventType} onChange={(e) => setFilterEventType(e.target.value)}>
                <option value="">All Event Types</option>
                {filterOptions.event_types.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}>
                <option value="">All Categories</option>
                {filterOptions.attack_categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select value={filterProtocol} onChange={(e) => setFilterProtocol(e.target.value)}>
                <option value="">All Protocols</option>
                {filterOptions.protocols.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={filterMaliciousOnly}
                  onChange={(e) => setFilterMaliciousOnly(e.target.checked)}
                />
                <span>Malicious only</span>
              </label>
              <button className="reset-btn" onClick={resetFilters}>Reset</button>
            </div>
          )}

          {/* Sessions Filters */}
          {activeNav === 'sessions' && !viewingSession && (
            <div className="filters-bar">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={sessionsMaliciousOnly}
                  onChange={(e) => setSessionsMaliciousOnly(e.target.checked)}
                />
                <span>Malicious only</span>
              </label>
              <span className="sessions-count">
                {sessionsTotal} session{sessionsTotal !== 1 ? 's' : ''}
              </span>
            </div>
          )}

          {/* ── Session Timeline View ─────────────────────────────── */}
          {viewingSession && sessionTimeline && (
            <div className="timeline-panel">
              <div className="panel-header">
                <div>
                  <h3>
                    Attack Timeline
                    <span className="timeline-badge">
                      {viewingSession.source_ip} / {viewingSession.session_id}
                    </span>
                  </h3>
                  <p className="text-muted" style={{ marginTop: 4, fontSize: '0.85rem' }}>
                    {formatDateTime(viewingSession.start_time)} → {formatDateTime(viewingSession.end_time)} · {viewingSession.event_count} events
                  </p>
                </div>
                <button className="reset-btn" onClick={closeTimeline}>← Back to Sessions</button>
              </div>

              {timelineLoading ? (
                <div className="loading-state" style={{ padding: 40 }}>
                  <div className="loading-spinner"></div>
                </div>
              ) : (
                <table className="event-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Event Type</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessionTimeline.events.map(event => (
                      <tr key={event._record_id || event.timestamp}>
                        <td className="text-muted">{formatTime(event.timestamp)}</td>
                        <td><span className="code-text">{event.event_type}</span></td>
                        <td>{event.classification?.attack_category || '-'}</td>
                        <td>
                          <span className={`severity-pill ${severityClass(event.classification?.severity)}`}>
                            {event.classification?.severity || 'unknown'}
                          </span>
                        </td>
                        <td>
                          <Link to={`/dashboard/events/${event.id ?? event._record_id}`} className="detail-link">
                            View
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── Sessions List ─────────────────────────────────────── */}
          {activeNav === 'sessions' && !viewingSession && (
            <div className="event-log-panel" style={{ gridColumn: '1 / -1' }}>
              <div className="panel-header">
                <h3>Attack Sessions</h3>
              </div>

              {sessionsMsg ? (
                <div className="empty-state">
                  <p>{sessionsMsg}</p>
                  <p style={{ marginTop: 8, fontSize: '0.85rem' }}>
                    Run the pipeline with <code className="code-text">--db data/honeypot.db</code> to enable session tracking.
                  </p>
                </div>
              ) : sessions.length === 0 ? (
                <div className="empty-state">
                  <p>No attack sessions recorded yet.</p>
                  <p style={{ marginTop: 8, fontSize: '0.85rem' }}>
                    Attack the honeypot to generate session data, or run the pipeline with the database enabled.
                  </p>
                </div>
              ) : (
                <table className="event-table">
                  <thead>
                    <tr>
                      <th>Session ID</th>
                      <th>Source IP</th>
                      <th>Events</th>
                      <th>Categories</th>
                      <th>Severity</th>
                      <th>Time</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map(session => (
                      <tr key={session.id}
                          className={session.is_malicious ? 'row-malicious' : ''}
                          style={session.is_malicious ? { background: 'rgba(225, 29, 72, 0.05)' } : undefined}>
                        <td><span className="code-text">{session.session_id.substring(0, 12)}...</span></td>
                        <td>
                          <strong>{session.source_ip}</strong>
                          {session.is_malicious === 1 && (
                            <span className="severity-pill high" style={{ marginLeft: 8, fontSize: '0.65rem' }}>MAL</span>
                          )}
                        </td>
                        <td>{session.event_count}</td>
                        <td>
                          <div className="category-pills">
                            {session.attack_categories.map((cat: string) => (
                              <span key={cat} className="cat-pill">{cat.replace(/_/g, ' ')}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          {Object.entries(session.severity_counts).map(([sev, count]) => (
                            <span key={sev} className={`severity-pill ${severityClass(sev)}`} style={{ marginRight: 4 }}>
                              {sev}:{count}
                            </span>
                          ))}
                        </td>
                        <td className="text-muted" style={{ fontSize: '0.8rem' }}>
                          {formatDateTime(session.start_time)}
                        </td>
                        <td>
                          <button
                            className="detail-link"
                            style={{ background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}
                            onClick={() => fetchSessionTimeline(session)}
                          >
                            Timeline →
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── Intelligence View ─────────────────────────────────── */}
          {activeNav === 'intelligence' && !viewingSession && (
            <div className="content-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
              <div className="event-log-panel">
                <div className="panel-header"><h3>Risk Level Distribution</h3></div>
                <div className="threat-list">
                  {summary?.by_risk_level && Object.keys(summary.by_risk_level).length > 0 ? (
                    Object.entries(summary.by_risk_level)
                      .sort((a, b) => b[1] - a[1])
                      .map(([level, count]) => (
                        <div key={level} className="threat-item">
                          <span className={`severity-pill ${level.toLowerCase()}`}>{level}</span>
                          <span className="threat-count">{count} events</span>
                        </div>
                      ))
                  ) : (
                    <div className="threat-item empty"><span className="text-muted">No risk data available</span></div>
                  )}
                </div>
              </div>

              <div className="event-log-panel">
                <div className="panel-header"><h3>Attack Categories</h3></div>
                <div className="threat-list">
                  {summary?.by_attack_category && Object.keys(summary.by_attack_category).length > 0 ? (
                    Object.entries(summary.by_attack_category)
                      .sort((a, b) => b[1] - a[1])
                      .map(([cat, count]) => (
                        <div key={cat} className="threat-item">
                          <span className="threat-ip">{cat.replace(/_/g, ' ')}</span>
                          <span className="threat-count">{count}</span>
                        </div>
                      ))
                  ) : (
                    <div className="threat-item empty"><span className="text-muted">No category data</span></div>
                  )}
                </div>
              </div>

              <div className="event-log-panel">
                <div className="panel-header"><h3>Protocol Breakdown</h3></div>
                <div className="threat-list">
                  {summary?.by_protocol && Object.keys(summary.by_protocol).length > 0 ? (
                    Object.entries(summary.by_protocol)
                      .sort((a, b) => b[1] - a[1])
                      .map(([proto, count]) => (
                        <div key={proto} className="threat-item">
                          <span className="threat-ip">{proto}</span>
                          <span className="threat-count">{count}</span>
                        </div>
                      ))
                  ) : (
                    <div className="threat-item empty"><span className="text-muted">No protocol data</span></div>
                  )}
                </div>
              </div>

              <div className="event-log-panel">
                <div className="panel-header"><h3>Top Threat IPs</h3></div>
                <div className="threat-list">
                  {threats.length > 0 ? (
                    threats.map((threat, i) => (
                      <div key={i} className="threat-item">
                        <span className="threat-ip">{threat.ip}</span>
                        <span className="threat-count">{threat.count} events</span>
                      </div>
                    ))
                  ) : (
                    <div className="threat-item empty"><span className="text-muted">No threats detected yet</span></div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ── Monitoring View ───────────────────────────────────── */}
          {activeNav === 'monitoring' && !viewingSession && (
            <div className="monitoring-view">
              <div className="monitoring-panel">
                <div className="panel-header">
                  <div>
                    <h3>Grafana Monitoring</h3>
                    <p className="monitoring-subtitle">
                      Historical device health and honeypot activity graphs filtered for your devices.
                    </p>
                  </div>
                  <a
                    className="monitoring-link"
                    href={grafanaDashboardUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open in Grafana
                  </a>
                </div>
                <div className="monitoring-frame-shell">
                  <iframe
                    key={authUser?.user_id || 'grafana'}
                    title="Honeypot Grafana Monitoring"
                    src={grafanaEmbedUrl}
                    className="monitoring-frame"
                  />
                </div>
                <div className="monitoring-notes">
                  <span>Grafana URL: {grafanaBaseUrl}</span>
                  <span>If the panel does not load, confirm `grafana` and `prometheus` are running.</span>
                </div>
              </div>
            </div>
          )}

          {/* ── Devices View ──────────────────────────────────────── */}
          {activeNav === 'devices' && !viewingSession && (
            <div className="devices-view">
              <div className="device-install-panel">
                <div className="panel-header"><h3>Enroll a Device</h3></div>
                <div className="device-install-form">
                  <input
                    type="text"
                    placeholder="Device name (e.g. edge-vm)"
                    value={newDeviceName}
                    onChange={(e) => setNewDeviceName(e.target.value)}
                  />
                  <select value={newDeviceProvider} onChange={(e) => setNewDeviceProvider(e.target.value)}>
                    <option value="">Provider (optional)</option>
                    <option value="aws">AWS</option>
                    <option value="azure">Azure</option>
                    <option value="google_cloud">Google Cloud</option>
                    <option value="digitalocean">DigitalOcean</option>
                    <option value="cloudflare">Cloudflare</option>
                    <option value="local_server">Local Server</option>
                    <option value="other">Other</option>
                  </select>
                  <button
                    className="reset-btn"
                    onClick={createDevice}
                    disabled={creatingDevice || !newDeviceName.trim()}
                  >
                    {creatingDevice ? 'Creating…' : 'Create device'}
                  </button>
                </div>
                {deviceError && <p className="text-red" style={{ marginTop: 8 }}>{deviceError}</p>}
                {createdDevice && (
                  <div className="device-token-box">
                    <p>
                      <strong>Device "{createdDevice.device.name}" created.</strong> Copy this
                      install command now — the agent token is shown only once.
                    </p>
                    <code className="install-command">{createdDevice.install_command}</code>
                    <button
                      className="reset-btn"
                      onClick={() => copyCommand(createdDevice.install_command)}
                    >
                      {copied ? '✓ Copied' : 'Copy command'}
                    </button>
                    <div className="device-run-steps">
                      <p><strong>Then, on the device you want to monitor:</strong></p>
                      <ol>
                        <li>Make sure Python 3 and <code>curl</code> are installed.</li>
                        <li>Paste the command above (any directory). It installs a <code>systemd</code> service that auto-starts on boot, restarts on failure, and keeps reporting — no terminal needed.</li>
                        <li>Check it with <code>systemctl status honeypot-agent</code>. The device appears below as <span className="device-status online">online</span> within a few seconds.</li>
                      </ol>
                    </div>
                  </div>
                )}
              </div>

              {devicesMsg ? (
                <div className="empty-state"><p>{devicesMsg}</p></div>
              ) : devices.length === 0 ? (
                <div className="empty-state">
                  <p>No devices registered yet.</p>
                  <p style={{ marginTop: 8, fontSize: '0.85rem' }}>
                    Enroll a device above, then run the generated agent command on that machine.
                  </p>
                </div>
              ) : (
                <div className={`device-grid${devices.length === 1 ? ' single' : ''}`}>
                  {devices.map((device) => (
                    <div key={device.device_id} className="device-card">
                      <div className="device-card-header">
                        <div>
                          <h4>{device.metrics.hostname || device.name}</h4>
                          <span className="text-muted">{device.name}</span>
                        </div>
                        <span className={`device-status ${device.status}`}>{device.status}</span>
                      </div>
                      <div className="device-meta">
                        <span>{device.metrics.local_ip || '—'}</span>
                        <span>{device.provider ? device.provider.replace(/_/g, ' ') : 'unknown'}</span>
                      </div>
                      <div className="device-metrics">
                        <div className="device-metric">
                          <span className="metric-label">Uptime</span>
                          <span className="metric-value">{formatUptime(device.metrics.uptime_seconds)}</span>
                        </div>
                        <div className="device-metric">
                          <span className="metric-label">RAM</span>
                          <span className="metric-value">
                            {device.metrics.ram_percent != null
                              ? `${device.metrics.ram_percent}% (${device.metrics.ram_used_mb}/${device.metrics.ram_total_mb} MB)`
                              : '—'}
                          </span>
                        </div>
                        <div className="device-metric">
                          <span className="metric-label">CPU load</span>
                          <span className="metric-value">
                            {device.metrics.load_1m != null
                              ? `${device.metrics.load_1m}${device.metrics.cpu_count ? ` / ${device.metrics.cpu_count} cores` : ''}`
                              : '—'}
                          </span>
                        </div>
                        <div className="device-metric">
                          <span className="metric-label">Disk</span>
                          <span className="metric-value">
                            {device.metrics.disk_percent != null
                              ? `${device.metrics.disk_percent}% (${device.metrics.disk_used_gb}/${device.metrics.disk_total_gb} GB)`
                              : '—'}
                          </span>
                        </div>
                      </div>
                      <div className="device-footer">
                        <span className="text-muted">Last seen: {formatDateTime(device.last_seen)}</span>
                        <button className="device-remove-btn" onClick={() => deleteDevice(device)}>
                          Remove
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── Overview / Events (existing views) ────────────────── */}
          {activeNav !== 'sessions' && activeNav !== 'intelligence' && activeNav !== 'devices' && activeNav !== 'monitoring' && !viewingSession && (
            <div className="content-grid">
              <div className="event-log-panel">
                <div className="panel-header">
                  <h3>{activeNav === 'events' ? 'Event Log' : 'Live Event Stream'}</h3>
                  {activeNav !== 'events' && (
                    <button className="view-all" onClick={() => setActiveNav('events')}>View All</button>
                  )}
                </div>
                <table className="event-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Event Type</th>
                      <th>Source IP</th>
                      <th>Category</th>
                      <th>Severity</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(activeNav === 'events' ? events : events.slice(0, 8)).map(event => (
                      <tr key={event._record_id}>
                        <td className="text-muted">{formatTime(event.timestamp)}</td>
                        <td><span className="code-text">{event.event_type}</span></td>
                        <td>{event.source_ip || '-'}</td>
                        <td>{event.classification?.attack_category || '-'}</td>
                        <td>
                          <span className={`severity-pill ${severityClass(event.classification?.severity)}`}>
                            {event.classification?.severity || 'unknown'}
                          </span>
                        </td>
                        <td>
                          <Link to={`/dashboard/events/${event.id ?? event._record_id}`} className="detail-link">
                            View
                          </Link>
                        </td>
                      </tr>
                    ))}
                    {events.length === 0 && (
                      <tr>
                        <td colSpan={6} className="empty-state">
                          No events yet. Attack the honeypot to generate data.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
                {activeNav === 'events' && (
                  <div className="event-count">Showing {events.length} events</div>
                )}
              </div>
              
              {activeNav !== 'events' && (
                <div className="side-panel">
                  <div className="panel-header">
                    <h3>Top Threats</h3>
                  </div>
                  <div className="threat-list">
                    {threats.map((threat, i) => (
                      <div key={i} className="threat-item">
                        <span className="threat-ip">{threat.ip}</span>
                        <span className="threat-count">{threat.count} events</span>
                      </div>
                    ))}
                    {threats.length === 0 && (
                      <div className="threat-item empty">
                        <span className="text-muted">No threats detected yet</span>
                      </div>
                    )}
                  </div>

                  {/* Attack Category Breakdown */}
                  {summary?.by_attack_category && Object.keys(summary.by_attack_category).length > 0 && (
                    <>
                      <div className="panel-header" style={{ marginTop: '24px' }}>
                        <h3>Attack Categories</h3>
                      </div>
                      <div className="threat-list">
                        {Object.entries(summary.by_attack_category).map(([cat, count]) => (
                          <div key={cat} className="threat-item">
                            <span className="threat-ip">{cat}</span>
                            <span className="threat-count">{count}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}

                  {/* Protocol Breakdown */}
                  {summary?.by_protocol && Object.keys(summary.by_protocol).length > 0 && (
                    <>
                      <div className="panel-header" style={{ marginTop: '24px' }}>
                        <h3>Protocols</h3>
                      </div>
                      <div className="threat-list">
                        {Object.entries(summary.by_protocol).map(([proto, count]) => (
                          <div key={proto} className="threat-item">
                            <span className="threat-ip">{proto}</span>
                            <span className="threat-count">{count}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}

                  {/* Export Buttons */}
                  <div className="export-section">
                    <div className="panel-header">
                      <h3>Exports</h3>
                    </div>
                    <div className="export-buttons">
                      <a href="/api/exports/blocklist.txt" className="export-btn" target="_blank" rel="noopener noreferrer">
                        ⬇ Blocklist
                      </a>
                      <a href="/api/exports/malicious.json" className="export-btn" target="_blank" rel="noopener noreferrer">
                        ⬇ Malicious JSON
                      </a>
                      <a href="/api/exports/report.md" className="export-btn" target="_blank" rel="noopener noreferrer">
                        ⬇ Report
                      </a>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default Dashboard;
