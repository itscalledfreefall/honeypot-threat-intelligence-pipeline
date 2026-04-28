import React from 'react';
import SharinganLogo from './SharinganLogo';
import './Dashboard.css';

const Dashboard: React.FC = () => {
  // Mock data inspired by the project's dashboard.py
  const stats = [
    { label: 'Total Events', value: '1,284', change: '+12%' },
    { label: 'Unique IPs', value: '342', change: '+5%' },
    { label: 'Malicious', value: '89', change: '+18%', critical: true },
    { label: 'Blocklist', value: '42', change: '+2' },
  ];

  const recentEvents = [
    { id: 1, type: 'ssh.login.success', ip: '192.168.1.45', category: 'Brute Force', severity: 'High', time: '2 mins ago' },
    { id: 2, type: 'ssh.command.input', ip: '45.12.33.102', category: 'Exploitation', severity: 'Medium', time: '5 mins ago' },
    { id: 3, type: 'ssh.login.failed', ip: '210.4.55.12', category: 'Brute Force', severity: 'Low', time: '12 mins ago' },
    { id: 4, type: 'ssh.login.failed', ip: '185.22.1.9', category: 'Brute Force', severity: 'Low', time: '15 mins ago' },
  ];

  return (
    <div className="dashboard-container">
      <aside className="dashboard-sidebar">
        <div className="sidebar-header">
          <SharinganLogo />
        </div>
        <nav className="sidebar-nav">
          <a href="#" className="active">Overview</a>
          <a href="#">Events</a>
          <a href="#">Intelligence</a>
          <a href="#">Blocklist</a>
          <a href="#">Settings</a>
        </nav>
        <div className="sidebar-footer">
          <button className="logout-btn">Log out</button>
        </div>
      </aside>
      
      <main className="dashboard-main">
        <header className="dashboard-header">
          <div className="header-search">
            <input type="text" placeholder="Search events, IPs, or categories..." />
          </div>
          <div className="header-actions">
            <span className="status-indicator">Live monitoring active</span>
            <div className="user-profile"></div>
          </div>
        </header>

        <section className="dashboard-content">
          <div className="stats-grid">
            {stats.map((stat, i) => (
              <div key={i} className="stat-card">
                <span className="stat-label">{stat.label}</span>
                <div className="stat-value-group">
                  <span className={`stat-value ${stat.critical ? 'text-red' : ''}`}>{stat.value}</span>
                  <span className="stat-change">{stat.change}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="content-grid">
            <div className="event-log-panel">
              <div className="panel-header">
                <h3>Live Event Stream</h3>
                <button className="view-all">View All</button>
              </div>
              <table className="event-table">
                <thead>
                  <tr>
                    <th>Event Type</th>
                    <th>Source IP</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recentEvents.map(event => (
                    <tr key={event.id}>
                      <td><span className="code-text">{event.type}</span></td>
                      <td>{event.ip}</td>
                      <td>{event.category}</td>
                      <td>
                        <span className={`severity-pill ${event.severity.toLowerCase()}`}>
                          {event.severity}
                        </span>
                      </td>
                      <td className="text-muted">{event.time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <div className="side-panel">
              <div className="panel-header">
                <h3>Top Threats</h3>
              </div>
              <div className="threat-list">
                <div className="threat-item">
                  <span className="threat-ip">192.168.1.45</span>
                  <span className="threat-count">452 attempts</span>
                </div>
                <div className="threat-item">
                  <span className="threat-ip">45.12.33.102</span>
                  <span className="threat-count">128 attempts</span>
                </div>
                <div className="threat-item">
                  <span className="threat-ip">210.4.55.12</span>
                  <span className="threat-count">89 attempts</span>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
};

export default Dashboard;
