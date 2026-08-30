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
  const token = localStorage.getItem('deeptrace_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
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
  analyzeEmailFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post('/analyze/email', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  analyzeRawEmail: (raw_content, filename = 'raw_input.eml') =>
    apiClient.post('/analyze/raw', { raw_content, filename }),

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
  getReportDownloadUrl: (caseId) => `${baseURL}/reports/${caseId}/download`,

  // System & Health
  getSystemStatus: () => apiClient.get('/system/status'),
  getSystemSettings: () => apiClient.get('/system/settings'),
  getHealth: () => apiClient.get('/health'),
};

export default api;
