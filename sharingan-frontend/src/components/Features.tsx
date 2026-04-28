import React from 'react';
import './Features.css';

const features = [
  {
    title: 'Instant Detection',
    description: 'Track and identify honeypot intrusions in real-time with millisecond precision.',
    icon: '⚡'
  },
  {
    title: 'Advanced Enrichment',
    description: 'Automatically pull threat intelligence from global databases for every interaction.',
    icon: '🔍'
  },
  {
    title: 'Pattern Analysis',
    description: 'Our system identifies behavioral signatures of automated bots and human attackers.',
    icon: '🧠'
  },
  {
    title: 'Automated Response',
    description: 'Generate blocklists and trigger firewall rules immediately upon detection.',
    icon: '🛡️'
  }
];

const Features: React.FC = () => {
  return (
    <section id="features" className="features-section">
      <div className="features-grid">
        {features.map((feature, index) => (
          <div key={index} className="feature-card">
            <div className="feature-icon">{feature.icon}</div>
            <h3 className="feature-title">{feature.title}</h3>
            <p className="feature-description">{feature.description}</p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Features;
