import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import SharinganLogo from './SharinganLogo';
import './Login.css';

type AuthMode = 'login' | 'register' | 'reset-request' | 'reset-confirm';

interface AuthResponse {
  token?: string;
  reset_token?: string;
  user?: {
    user_id: string;
    email: string;
    first_name: string;
    last_name?: string | null;
    cloud_provider: string;
  };
  error?: string;
  message?: string;
}

const cloudOptions = [
  { value: 'aws', label: 'AWS' },
  { value: 'cloudflare', label: 'Cloudflare' },
  { value: 'bulutistan', label: 'Bulutistan' },
  { value: 'azure', label: 'Azure' },
  { value: 'google_cloud', label: 'Google Cloud' },
  { value: 'digitalocean', label: 'DigitalOcean' },
  { value: 'local_server', label: 'I use a local server' },
  { value: 'other', label: 'Other' },
];

const Login: React.FC = () => {
  const [mode, setMode] = useState<AuthMode>('login');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [cloudProvider, setCloudProvider] = useState('aws');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [generatedResetToken, setGeneratedResetToken] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const saveSession = (data: AuthResponse) => {
    if (!data.token || !data.user) return;
    localStorage.setItem('authToken', data.token);
    localStorage.setItem('authUser', JSON.stringify(data.user));
    navigate('/dashboard');
  };

  const requestJson = async (url: string, body: Record<string, unknown>) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({})) as AuthResponse;
    if (!response.ok) {
      throw new Error(data.error || 'Request failed. Please try again.');
    }
    return data;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setStatus('');
    setSubmitting(true);

    try {
      if (mode === 'login') {
        const data = await requestJson('/api/auth/login', { email, password });
        saveSession(data);
      }

      if (mode === 'register') {
        const data = await requestJson('/api/auth/register', {
          first_name: firstName,
          middle_name: lastName || null,
          cloud_provider: cloudProvider,
          email,
          password,
        });
        saveSession(data);
      }

      if (mode === 'reset-request') {
        const data = await requestJson('/api/auth/password-reset/request', { email });
        setStatus(data.message || 'Reset request created.');
        setGeneratedResetToken(data.reset_token || '');
        if (data.reset_token) {
          setResetToken(data.reset_token);
          setMode('reset-confirm');
        }
      }

      if (mode === 'reset-confirm') {
        await requestJson('/api/auth/password-reset/confirm', {
          token: resetToken,
          password,
        });
        setPassword('');
        setResetToken('');
        setGeneratedResetToken('');
        setMode('login');
        setStatus('Password reset complete. Sign in with your new password.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const switchMode = (nextMode: AuthMode) => {
    setMode(nextMode);
    setError('');
    setStatus('');
    setGeneratedResetToken('');
  };

  const title = {
    login: 'Welcome Back',
    register: 'Create Account',
    'reset-request': 'Reset Password',
    'reset-confirm': 'Set New Password',
  }[mode];

  const subtitle = {
    login: 'Sign in to monitor honeypot intelligence.',
    register: 'Create a unique operator account.',
    'reset-request': 'Generate a one-time reset token for this lab.',
    'reset-confirm': 'Use the token to set a new password.',
  }[mode];

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <SharinganLogo />
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>

        <div className="auth-tabs">
          <button className={mode === 'login' ? 'active' : ''} onClick={() => switchMode('login')} type="button">
            Sign in
          </button>
          <button className={mode === 'register' ? 'active' : ''} onClick={() => switchMode('register')} type="button">
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {mode === 'register' && (
            <>
              <div className="form-row">
                <div className="input-group">
                  <label>First Name</label>
                  <input
                    type="text"
                    placeholder="John"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    required
                  />
                </div>
                <div className="input-group">
                  <label>Last Name</label>
                  <input
                    type="text"
                    placeholder="Smith"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                  />
                </div>
              </div>
              <div className="input-group">
                <label>Cloud or Hosting</label>
                <select value={cloudProvider} onChange={(e) => setCloudProvider(e.target.value)}>
                  {cloudOptions.map(option => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </div>
            </>
          )}

          {(mode === 'login' || mode === 'register' || mode === 'reset-request') && (
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
          )}

          {mode === 'reset-confirm' && (
            <div className="input-group">
              <label>Reset Token</label>
              <input
                type="text"
                placeholder="Paste reset token"
                value={resetToken}
                onChange={(e) => setResetToken(e.target.value)}
                required
              />
            </div>
          )}

          {mode !== 'reset-request' && (
            <div className="input-group">
              <label>{mode === 'reset-confirm' ? 'New Password' : 'Password'}</label>
              <input
                type="password"
                placeholder="At least 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
              />
            </div>
          )}

          {error && <div className="auth-alert error">{error}</div>}
          {status && <div className="auth-alert success">{status}</div>}
          {generatedResetToken && (
            <div className="reset-token-box">
              <span>Local reset token</span>
              <code>{generatedResetToken}</code>
            </div>
          )}

          <button type="submit" className="login-button" disabled={submitting}>
            {submitting ? 'Working...' : (
              mode === 'login' ? 'Sign In' :
              mode === 'register' ? 'Create Account' :
              mode === 'reset-request' ? 'Generate Reset Token' :
              'Reset Password'
            )}
          </button>
        </form>

        <div className="login-footer">
          {mode === 'login' && (
            <button type="button" onClick={() => switchMode('reset-request')}>Forgot password?</button>
          )}
          {mode === 'reset-request' && (
            <button type="button" onClick={() => switchMode('reset-confirm')}>I already have a token</button>
          )}
          {(mode === 'reset-confirm' || mode === 'register') && (
            <button type="button" onClick={() => switchMode('login')}>Back to sign in</button>
          )}
        </div>
      </div>
    </div>
  );
};

export default Login;
