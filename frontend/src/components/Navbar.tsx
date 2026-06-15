import React from 'react';
import { Link } from 'react-router-dom';
import SharinganLogo from './SharinganLogo';
import './Navbar.css';

const Navbar: React.FC = () => {
  return (
    <nav className="navbar">
      <div className="navbar-content">
        <Link to="/"><SharinganLogo /></Link>
        <div className="nav-links">
          <a href="#features">Features</a>
          <a href="#preview">Preview</a>
          <a href="#preview">Demo</a>
        </div>
        <Link to="/login" className="cta-button">Get Started</Link>
      </div>
    </nav>
  );
};

export default Navbar;
