import React from 'react';
import './SharinganLogo.css';

const SharinganLogo: React.FC = () => {
  return (
    <div className="sharingan-container">
      <svg
        width="44"
        height="44"
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="sharingan-svg"
      >
        {/* Outer Ring */}
        <circle cx="50" cy="50" r="48" fill="black" />
        
        {/* Main Iris (Red) */}
        <circle cx="50" cy="50" r="44" fill="#bb0000" className="iris-circle" />

        {/* Inner Ring (Normal state only) */}
        <circle cx="50" cy="50" r="28" stroke="black" strokeWidth="0.8" className="inner-ring" />

        {/* Pupil */}
        <circle cx="50" cy="50" r="8" fill="black" />

        {/* Tomoes / Mangekyo Blades */}
        <g className="blades">
          {/* Top Blade - Refined Tomoe Path */}
          <path
            className="blade-path"
            d="M50 22 C55 22 58 25 58 29 C58 33 55 36 51 36 C47 36 45 33 45 29 C45 27 46 24 49 22 C50 21 50 22 50 22" 
            fill="black"
          />
          {/* Bottom Right Blade */}
          <path
            className="blade-path"
            d="M50 22 C55 22 58 25 58 29 C58 33 55 36 51 36 C47 36 45 33 45 29 C45 27 46 24 49 22 C50 21 50 22 50 22" 
            fill="black"
            style={{ transform: 'rotate(120deg)', transformOrigin: '50px 50px' }}
          />
          {/* Bottom Left Blade */}
          <path
            className="blade-path"
            d="M50 22 C55 22 58 25 58 29 C58 33 55 36 51 36 C47 36 45 33 45 29 C45 27 46 24 49 22 C50 21 50 22 50 22" 
            fill="black"
            style={{ transform: 'rotate(240deg)', transformOrigin: '50px 50px' }}
          />
        </g>
      </svg>
      <span className="brand-name">Sharingan</span>
    </div>
  );
};

export default SharinganLogo;
