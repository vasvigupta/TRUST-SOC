import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getHealth = () => api.get('/');
export const getMetrics = () => api.get('/metrics');
export const getAlerts = (params) => api.get('/alerts', { params });
export const getAlertSummary = () => api.get('/alerts/summary');
export const getAlertById = (id) => api.get(`/alerts/${id}`);
export const triggerReplay = (n = 20) => api.get('/replay', { params: { n } });
export const postDetect = (features) => api.post('/detect', { features });
export const getPdfReportUrl = (alertId) => `${API_BASE_URL}/reports/${alertId}/pdf`;
export const getShapPlotUrl = () => `${API_BASE_URL}/reports/shap-plot`;
export const getConfusionMatrixUrl = () => `${API_BASE_URL}/reports/confusion-matrix`;
