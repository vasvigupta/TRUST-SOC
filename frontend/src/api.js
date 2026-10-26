import axios from 'axios';

const API_BASE_URL = window.location.origin;

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getHealth = () => api.get('/api/health');
export const getStats = () => api.get('/api/stats');
export const getAlerts = (params) => api.get('/api/alerts', { params });
export const getAlertById = (id) => api.get(`/api/alerts/${id}`);
export const updateAlertStatus = (id, status, note = '') =>
  api.post(`/api/alerts/${id}/status`, { status, note });

export const getPdfReportUrl = (alertId) => `/api/alerts/${alertId}/report/pdf`;
export const getJsonReportUrl = (alertId) => `/api/alerts/${alertId}/report/json`;

export const getReplayStatus = () => api.get('/api/replay/status');
export const controlReplay = (action, rate = null, n = 1) =>
  api.post('/api/replay/control', { action, rate, n });

export const getStreamUrl = () => `${API_BASE_URL}/api/replay/stream`;

export const postDetect = (payload) => {
  const body = payload && payload.features ? payload : { features: payload };
  return api.post('/api/detect', body);
};
export const getExamples = () => api.get('/api/detect/examples');
