import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import SharinganLogo from './SharinganLogo';
import './EventDetail.css';

interface EventRecord {
  id?: number;
  _record_id: number;
  timestamp: string | null;
  event_type: string;
  honeypot: string;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
  session_id: string | null;
  username: string | null;
  password: string | null;
  command: string | null;
  url: string | null;
  indicators?: {
    ip_addresses: string[];
    usernames: string[];
    passwords: string[];
    commands: string[];
    urls: string[];
  };
  classification?: {
    target_profile: string;
    service_type: string;
    attack_category: string;
    severity: string;
    reason: string;
  };
  threat_intel?: {
    score?: {
      is_malicious?: boolean;
      confidence?: string;
    };
    [key: string]: unknown;
  };
  raw_event?: Record<string, unknown>;
}

const EventDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [event, setEvent] = useState<EventRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchEvent = async () => {
      try {
        const res = await fetch(`/api/events/${id}`);
        if (!res.ok) {
          setError(res.status === 404 ? 'Event not found' : 'Failed to load event');
          setLoading(false);
          return;
        }
        setEvent(await res.json());
        setLoading(false);
      } catch {
        setError('Failed to connect to API');
        setLoading(false);
      }
    };
    fetchEvent();
  }, [id]);

  const severityClass = (severity?: string) => {
    if (!severity) return 'low';
    return severity.toLowerCase();
  };

  if (loading) {
    return (
      <div className="detail-container">
        <aside className="detail-sidebar">
          <SharinganLogo />
        </aside>
        <main className="detail-main">
          <div className="loading-state">
            <div className="loading-spinner"></div>
            <p>Loading event...</p>
          </div>
        </main>
      </div>
    );
  }

  if (error || !event) {
    return (
      <div className="detail-container">
        <aside className="detail-sidebar">
          <SharinganLogo />
        </aside>
        <main className="detail-main">
          <div className="loading-state">
            <p>{error || 'Event not found'}</p>
            <Link to="/dashboard" className="back-link">← Back to Dashboard</Link>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="detail-container">
      <aside className="detail-sidebar">
        <div className="sidebar-header">
          <SharinganLogo />
        </div>
        <nav className="sidebar-nav">
          <Link to="/dashboard">← Dashboard</Link>
        </nav>
      </aside>

      <main className="detail-main">
        {/* Event Header */}
        <section className="detail-hero">
          <div className="detail-hero-top">
            <Link to="/dashboard" className="back-link">← Back</Link>
            <span className="detail-id">Event #{event.id ?? event._record_id}</span>
          </div>
          <h1 className="detail-title">{event.event_type}</h1>
          <div className="detail-pills">
            <span className={`severity-pill ${severityClass(event.classification?.severity)}`}>
              {event.classification?.severity || 'unknown'}
            </span>
            <span className="category-pill">
              {event.classification?.attack_category || 'unclassified'}
            </span>
            {event.threat_intel?.score?.is_malicious && (
              <span className="severity-pill high">malicious</span>
            )}
          </div>
          <p className="detail-meta">
            {event.timestamp || 'No timestamp'} · {event.source_ip || 'unknown source'} · {event.protocol || 'unknown protocol'}
          </p>
        </section>

        {/* Detail Grid */}
        <div className="detail-grid">
          {/* Normalized Fields */}
          <section className="detail-panel">
            <h3>Normalized Fields</h3>
            <div className="kv-list">
              <div className="kv-row"><span>Session</span><strong>{event.session_id || '-'}</strong></div>
              <div className="kv-row"><span>Source IP</span><strong>{event.source_ip || '-'}</strong></div>
              <div className="kv-row"><span>Source Port</span><strong>{event.source_port ?? '-'}</strong></div>
              <div className="kv-row"><span>Protocol</span><strong>{event.protocol || '-'}</strong></div>
              <div className="kv-row"><span>Username</span><strong>{event.username || '-'}</strong></div>
              <div className="kv-row"><span>Password</span><strong>{event.password || '-'}</strong></div>
              <div className="kv-row"><span>Command</span><strong className="code-text">{event.command || '-'}</strong></div>
              <div className="kv-row"><span>URL</span><strong className="code-text">{event.url || '-'}</strong></div>
            </div>
          </section>

          {/* Indicators */}
          <section className="detail-panel">
            <h3>Extracted Indicators</h3>
            {event.indicators ? (
              <div className="kv-list">
                <div className="kv-row">
                  <span>IPs</span>
                  <strong>{event.indicators.ip_addresses?.join(', ') || 'none'}</strong>
                </div>
                <div className="kv-row">
                  <span>Usernames</span>
                  <strong>{event.indicators.usernames?.join(', ') || 'none'}</strong>
                </div>
                <div className="kv-row">
                  <span>Passwords</span>
                  <strong>{event.indicators.passwords?.join(', ') || 'none'}</strong>
                </div>
                <div className="kv-row">
                  <span>Commands</span>
                  <strong className="code-text">{event.indicators.commands?.join(', ') || 'none'}</strong>
                </div>
                <div className="kv-row">
                  <span>URLs</span>
                  <strong className="code-text">{event.indicators.urls?.join(', ') || 'none'}</strong>
                </div>
              </div>
            ) : (
              <p className="text-muted">No indicators extracted</p>
            )}
          </section>

          {/* Classification */}
          <section className="detail-panel">
            <h3>Classification</h3>
            {event.classification ? (
              <div className="kv-list">
                <div className="kv-row"><span>Category</span><strong>{event.classification.attack_category}</strong></div>
                <div className="kv-row"><span>Severity</span><strong>{event.classification.severity}</strong></div>
                <div className="kv-row"><span>Service</span><strong>{event.classification.service_type}</strong></div>
                <div className="kv-row"><span>Target</span><strong>{event.classification.target_profile}</strong></div>
                <div className="kv-row full"><span>Reason</span><strong>{event.classification.reason}</strong></div>
              </div>
            ) : (
              <p className="text-muted">Not classified</p>
            )}
          </section>

          {/* Threat Intel */}
          <section className="detail-panel">
            <h3>Threat Intelligence</h3>
            {event.threat_intel && Object.keys(event.threat_intel).length > 0 ? (
              <pre className="json-block">{JSON.stringify(event.threat_intel, null, 2)}</pre>
            ) : (
              <p className="text-muted">No enrichment data (pipeline ran without API keys or enrichment flags)</p>
            )}
          </section>
        </div>

        {/* Raw Event JSON */}
        <section className="detail-panel full-width">
          <h3>Raw Event</h3>
          <pre className="json-block">{JSON.stringify(event.raw_event || {}, null, 2)}</pre>
        </section>
      </main>
    </div>
  );
};

export default EventDetail;
