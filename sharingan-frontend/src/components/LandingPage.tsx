import React from 'react';
import Navbar from './Navbar';
import Hero from './Hero';
import Features from './Features';
import DashboardPreview from './DashboardPreview';
import Footer from './Footer';

const LandingPage: React.FC = () => {
  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <Features />
        <DashboardPreview />
      </main>
      <Footer />
    </>
  );
};

export default LandingPage;
