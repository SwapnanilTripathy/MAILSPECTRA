import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = sessionStorage.getItem('deeptrace_user');
    try {
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState(
    () => sessionStorage.getItem('deeptrace_token') || null,
  );
  const [loading, setLoading] = useState(false);

  const login = async (username, password) => {
    setLoading(true);
    try {
      const res = await api.login(username, password);
      setToken(res.access_token);
      setUser(res.user);
      sessionStorage.setItem('deeptrace_token', res.access_token);
      sessionStorage.setItem('deeptrace_user', JSON.stringify(res.user));
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try { await api.logout(); } catch { /* Local logout still clears an expired session. */ }
    setToken(null);
    setUser(null);
    sessionStorage.removeItem('deeptrace_token');
    sessionStorage.removeItem('deeptrace_user');
  };

  useEffect(() => {
    localStorage.removeItem('deeptrace_token');
    localStorage.removeItem('deeptrace_user');
    if (token) api.getCurrentUser().then(setUser).catch(() => {
      setUser(null); setToken(null);
      sessionStorage.removeItem('deeptrace_token');
      sessionStorage.removeItem('deeptrace_user');
    });
    const expire = () => { setUser(null); setToken(null); };
    window.addEventListener('session-expired', expire);
    return () => window.removeEventListener('session-expired', expire);
  }, [token]);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(token),
        login,
        logout,
        loading,
      }}
    >
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
