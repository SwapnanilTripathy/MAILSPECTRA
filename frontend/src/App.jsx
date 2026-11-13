import React, { lazy, Suspense } from 'react';
import { PrivacyProvider } from './context/PrivacyContext';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import AppLayout from './components/layout/AppLayout';
import { ThemeProvider } from './context/ThemeContext';

// Pages
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const InvestigatePage = lazy(() => import('./pages/InvestigatePage'));
const CasesPage = lazy(() => import('./pages/CasesPage'));
const CaseDetailPage = lazy(() => import('./pages/CaseDetailPage'));
const CampaignsPage = lazy(() => import('./pages/CampaignsPage'));
const IntelligencePage = lazy(() => import('./pages/IntelligencePage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const LoginPage = lazy(() => import('./pages/LoginPage'));

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <PrivacyProvider>
          <BrowserRouter>
            <Suspense fallback={<p role="status" className="p-8">Loading workspace…</p>}>
              <Routes>
                {/* Public Auth Route */}
                <Route path="/login" element={<LoginPage />} />

                {/* Protected SOC Platform Workspace Routes */}
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <AppLayout />
                    </ProtectedRoute>
                  }
                >
                  <Route index element={<DashboardPage />} />
                  <Route path="investigate" element={<InvestigatePage />} />
                  <Route path="cases" element={<CasesPage />} />
                  <Route path="cases/:caseId" element={<CaseDetailPage />} />
                  <Route path="campaigns" element={<CampaignsPage />} />
                  <Route path="intelligence" element={<IntelligencePage />} />
                  <Route path="reports" element={<ReportsPage />} />
                  <Route path="settings" element={<SettingsPage />} />
                </Route>

                {/* Catch-all fallback */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </PrivacyProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}
