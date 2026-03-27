import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 10000,
});

export const getSummary = () => api.get('/api/dashboard/summary').then(r => r.data);
export const getDatasetStats = () => api.get('/api/dashboard/dataset-stats').then(r => r.data);
export const getIncidents = () => api.get('/api/dashboard/incidents').then(r => r.data);
export const getPlaybooks = () => api.get('/api/dashboard/playbooks').then(r => r.data);
export const getAudit = () => api.get('/api/dashboard/audit').then(r => r.data);
export const getSeverity = () => api.get('/api/dashboard/severity-distribution').then(r => r.data);
export const getDrift = () => api.get('/api/dashboard/drift').then(r => r.data);
export const getHealth = () => api.get('/health').then(r => r.data);
