import React from 'react';
import './DashboardPreview.css';

const DashboardPreview: React.FC = () => {
  return (
    <section id="preview" className="preview-section">
      <div className="preview-container">
        <div className="preview-header">
          <div className="dots">
            <span></span>
            <span></span>
            <span></span>
          </div>
          <div className="address-bar">sharingan.security/dashboard</div>
        </div>
        <div className="preview-content">
          <div className="preview-sidebar"></div>
          <div className="preview-main">
            <div className="preview-stat-row">
              <div className="preview-stat"></div>
              <div className="preview-stat"></div>
              <div className="preview-stat"></div>
            </div>
            <div className="preview-chart"></div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default DashboardPreview;
