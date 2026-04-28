import React from 'react';
import './SharinganLogo.css';

const SharinganLogo: React.FC = () => {
  return (
    <div className="sharingan-container">
      <svg
        width="40"
        height="40"
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="sharingan-svg"
      >
        {/* Outer Ring */}
        <circle cx="50" cy="50" r="48" stroke="currentColor" strokeWidth="2" />
        
        {/* Inner Ring (Visible in normal state) */}
        <circle cx="50" cy="50" r="30" stroke="currentColor" strokeWidth="1" className="inner-ring" />

        {/* Pupill */}
        <circle cx="50" cy="50" r="8" fill="currentColor" />

        {/* Tomoes / Mangekyo Blades */}
        <g className="blades">
          {/* Top Blade */}
          <path
            className="blade-path"
            d="M50 20 C60 20 65 30 50 40 C35 30 40 20 50 20" 
            fill="currentColor"
          />
          {/* Bottom Right Blade */}
          <path
            className="blade-path"
            d="M76 65 C81 56 72 47 63 57 C54 67 67 74 76 65"
            fill="currentColor"
            style={{ transform: 'rotate(120deg)', transformOrigin: '50px 50px' }}
          />
          {/* Bottom Left Blade */}
          <path
            className="blade-path"
            d="M24 65 C19 56 28 47 37 57 C46 67 33 74 24 65"
            fill="currentColor"
            style={{ transform: 'rotate(240deg)', transformOrigin: '50px 50px' }}
          />
        </g>
      </svg>
      <span className="brand-name">Sharingan</span>
    </div>
  );
};

export default SharinganLogo;
