import React from 'react';
import './Footer.css';

const Footer: React.FC = () => {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-brand">
          <span className="footer-logo">Sharingan</span>
          <p className="footer-tagline">Ultimate Threat Intelligence Pipeline</p>
        </div>
        <div className="footer-links">
          <div className="footer-group">
            <h4>Product</h4>
            <a href="#">Features</a>
            <a href="#">Integrations</a>
            <a href="#">Pricing</a>
          </div>
          <div className="footer-group">
            <h4>Company</h4>
            <a href="#">About</a>
            <a href="#">Security</a>
            <a href="#">Privacy</a>
          </div>
        </div>
      </div>
      <div className="footer-bottom">
        <p>© 2026 Sharingan Project. All rights reserved.</p>
      </div>
    </footer>
  );
};

export default Footer;
