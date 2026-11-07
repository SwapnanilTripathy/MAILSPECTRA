import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Cpu,
  Lock,
  User,
  ArrowRight,
  AlertCircle,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, loading } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const res = await login(username, password);
    if (res.success) navigate('/');
    else
      setError(
        res.error || 'Authentication failed. Please verify credentials.',
      );
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <div className="brand-mark">
            <Cpu size={21} aria-hidden="true" />
          </div>
          <div>
            <div className="brand-name">
              MAIL<span>SPECTRA</span>
            </div>
            <div className="brand-caption">THREAT INTELLIGENCE</div>
          </div>
        </div>
        <div className="login-intro">
          <div className="eyebrow">
            <span className="eyebrow-line" /> ANALYST WORKSPACE
          </div>
          <h1>
            Welcome back<span className="heading-period">.</span>
          </h1>
          <p>Sign in to continue your investigations.</p>
        </div>
        {error && (
          <div role="alert" className="login-error">
            <AlertCircle size={17} aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
        <form onSubmit={handleSubmit} className="login-form">
          <div>
            <label htmlFor="username">Username</label>
            <div className="login-input">
              <User size={18} aria-hidden="true" />
              <input
                id="username"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="Enter your username"
              />
            </div>
          </div>
          <div>
            <label htmlFor="password">Password</label>
            <div className="login-input">
              <Lock size={18} aria-hidden="true" />
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="Enter your password"
              />
            </div>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="primary-action login-submit"
          >
            <span>{loading ? 'Signing in…' : 'Sign in to workspace'}</span>
            <ArrowRight size={17} aria-hidden="true" />
          </button>
        </form>

      </div>
      <p className="login-footer">
        MAILSPECTRA <span> / </span> EMAIL FORENSICS & THREAT INTELLIGENCE
      </p>
    </div>
  );
}
