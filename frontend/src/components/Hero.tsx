import React from 'react';
import { Link } from 'react-router-dom';
import './Hero.css';

const Hero: React.FC = () => {
  return (
    <section className="hero-section">
      <div className="hero-content">
        <h1 className="hero-title">
          The Eye of <span className="text-gradient">Intelligence</span>
        </h1>
        <p className="hero-subtitle">
          Unlock supreme vision into your security landscape. Detect, analyze, and neutralize threats with unprecedented precision.
        </p>
        <div className="hero-actions">
          <Link to="/login" className="primary-btn">Initialize Pipeline</Link>
          <a href="#preview" className="secondary-btn">View Demo</a>
        </div>
      </div>
      <div className="hero-background-glow"></div>
    </section>
  );
};

export default Hero;
