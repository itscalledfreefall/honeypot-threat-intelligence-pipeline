import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import SharinganLogo from './SharinganLogo';
import './Login.css';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate login
    navigate('/dashboard');
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <SharinganLogo />
          <h2>Welcome Back</h2>
          <p>Enter your credentials to access the eye.</p>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <div className="input-group">
            <label>Email Address</label>
            <input 
              type="email" 
              placeholder="name@company.com" 
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required 
            />
          </div>
          <div className="input-group">
            <label>Password</label>
            <input 
              type="password" 
              placeholder="••••••••" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required 
            />
          </div>
          <button type="submit" className="login-button">Sign In</button>
        </form>
        <div className="login-footer">
          <a href="#">Forgot password?</a>
        </div>
      </div>
    </div>
  );
};

export default Login;
