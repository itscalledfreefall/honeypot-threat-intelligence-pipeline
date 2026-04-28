import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import SharinganLogo from './SharinganLogo';
import './Dashboard.css';

interface SummaryData {
  total_events: number;
  unique_source_ips: number;
  malicious_event_count: number;
  blocklist_count: number;
  by_attack_category: Record<string, number>;
  by_protocol: Record<string, number>;
}

interface EventRecord {
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

const REFRESH_INTERVAL = 3000;

const Dashboard: React.FC = () => {
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

  const fetchData = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterIp) params.set('source_ip', filterIp);
      if (filterEventType) params.set('event_type', filterEventType);
      if (filterCategory) params.set('attack_category', filterCategory);
      if (filterProtocol) params.set('protocol', filterProtocol);
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
  }, [filterIp, filterEventType, filterCategory, filterProtocol]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

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

  const resetFilters = () => {
    setFilterIp('');
    setFilterEventType('');
    setFilterCategory('');
    setFilterProtocol('');
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
          <a href="#" className={activeNav === 'overview' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('overview'); }}>Overview</a>
          <a href="#" className={activeNav === 'events' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('events'); }}>Events</a>
          <a href="#" className={activeNav === 'intelligence' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setActiveNav('intelligence'); }}>Intelligence</a>
          <a href="/api/exports/blocklist.txt" target="_blank" rel="noopener noreferrer">↓ Blocklist</a>
          <a href="/api/exports/report.md" target="_blank" rel="noopener noreferrer">↓ Report</a>
        </nav>
        <div className="sidebar-footer">
          <Link to="/" className="logout-btn">Back to Home</Link>
        </div>
      </aside>
      
      <main className="dashboard-main">
        <header className="dashboard-header">
          <div className="header-search">
            <input
              type="text"
              placeholder="Filter by source IP..."
              value={filterIp}
              onChange={(e) => setFilterIp(e.target.value)}
            />
          </div>
          <div className="header-actions">
            <span className="status-indicator">
              Live · {lastUpdate.toLocaleTimeString()}
            </span>
            <div className="user-profile"></div>
          </div>
        </header>

        <section className="dashboard-content">
          {/* Stats Row */}
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

          {/* Filters Bar (visible in events view) */}
          {activeNav === 'events' && (
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
              <button className="reset-btn" onClick={resetFilters}>Reset</button>
            </div>
          )}

          {/* Main Content Grid */}
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
                        <Link to={`/dashboard/events/${event._record_id}`} className="detail-link">
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
        </section>
      </main>
    </div>
  );
};

export default Dashboard;
