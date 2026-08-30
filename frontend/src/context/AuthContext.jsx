import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('deeptrace_user');
    return saved ? JSON.parse(saved) : { username: 'analyst', full_name: 'Lead Forensic Analyst', role: 'Lead Investigator' };
  });
  const [token, setToken] = useState(() => localStorage.getItem('deeptrace_token') || 'deeptrace-demo-token');
  const [loading, setLoading] = useState(false);

  const login = async (username, password) => {
    setLoading(true);
    try {
      const res = await api.login(username, password);
      setToken(res.access_token);
      setUser(res.user);
      localStorage.setItem('deeptrace_token', res.access_token);
      localStorage.setItem('deeptrace_user', JSON.stringify(res.user));
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    api.logout().catch(() => {});
    setToken(null);
    setUser(null);
    localStorage.removeItem('deeptrace_token');
    localStorage.removeItem('deeptrace_user');
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: Boolean(token), login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
