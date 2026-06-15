import type { ReactElement } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import LandingPage from './components/LandingPage';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import EventDetail from './components/EventDetail';
import './App.css';

const hasSession = () => Boolean(localStorage.getItem('authToken'));

const ProtectedRoute = ({ children }: { children: ReactElement }) => {
  return hasSession() ? children : <Navigate to="/login" replace />;
};

function App() {
  return (
    <Router>
      <div className="app-container">
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/dashboard/events/:id" element={<ProtectedRoute><EventDetail /></ProtectedRoute>} />
          {/* Redirect /events to /dashboard for backwards compat */}
          <Route path="/events" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
