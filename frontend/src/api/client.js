import axios from 'axios';

const baseURL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const apiClient = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Interceptor for attaching auth token
apiClient.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('deeptrace_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      sessionStorage.removeItem('deeptrace_token');
      sessionStorage.removeItem('deeptrace_user');
      window.dispatchEvent(new Event('session-expired'));
    }
    const errorMsg = error.response?.data?.detail || error.message || 'API request failed';
    return Promise.reject(new Error(errorMsg));
  }
);

export const api = {
  // Authentication
  login: (username, password) => apiClient.post('/auth/login', { username, password }),
  getCurrentUser: () => apiClient.get('/auth/me'),
  logout: () => apiClient.post('/auth/logout'),

  // Email Analysis
  analyzeEmailFile: (file, maskPii = false) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post('/analyze/email', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      params: maskPii ? { mask_pii: true } : {},
    });
  },
  analyzeRawEmail: (raw_content, filename = 'raw_input.eml', maskPii = false) =>
    apiClient.post('/analyze/raw', { raw_content, filename, mask_pii: maskPii }),

  // Real-Time Threat Alerts
  getAlerts: (limit = 20) => apiClient.get('/alerts', { params: { limit } }),
  getAlertConfig: () => apiClient.get('/alerts/config'),

  // Dashboard Metrics
  getDashboardStats: () => apiClient.get('/dashboard/stats'),
  getDashboardRecent: () => apiClient.get('/dashboard/recent'),
  getDashboardDistribution: () => apiClient.get('/dashboard/distribution'),

  // Case Management
  listCases: (params = {}) => apiClient.get('/cases', { params }),
  getCaseDetail: (caseId) => apiClient.get(`/cases/${caseId}`),
  createCase: (payload) => apiClient.post('/cases', payload),
  updateCaseStatus: (caseId, payload) => apiClient.patch(`/cases/${caseId}/status`, payload),

  // Threat Campaigns
  listCampaigns: () => apiClient.get('/campaigns'),
  getCampaignDetail: (campaignId) => apiClient.get(`/campaigns/${campaignId}`),

  // Reports
  generateReport: (caseId) => apiClient.post(`/reports/generate/${caseId}`),
  verifyReport: (caseId) => apiClient.get(`/reports/${caseId}/verify`),
  listReports: () => apiClient.get('/reports'),
  downloadReport: async (caseId) => {
    const blob = await apiClient.get(`/reports/${caseId}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = `${caseId}.pdf`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
  getReportDownloadUrl: (caseId) => `${baseURL}/reports/${caseId}/download`,

  // System & Health
  getSystemStatus: () => apiClient.get('/system/status'),
  getSystemSettings: () => apiClient.get('/system/settings'),
  getHealth: () => apiClient.get('/health'),
};


export default api;
