import React, { useEffect, useState } from 'react';
import { getAlerts } from '../api';
import AlertCard from '../components/AlertCard';
import { RefreshCw, Filter } from 'lucide-react';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [filterClass, setFilterClass] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchAlerts = () => {
    setLoading(true);
    const params = { limit: 50 };
    if (filterClass) params.prediction = filterClass;

    getAlerts(params)
      .then((res) => setAlerts(res.data.alerts || []))
      .catch((err) => console.error('Error fetching alerts:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAlerts();
  }, [filterClass]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>Persisted Alert Feed (SQLite Data Store)</h2>
        <div style={{ display: 'flex', gap: '12px' }}>
          <select
            value={filterClass}
            onChange={(e) => setFilterClass(e.target.value)}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid var(--border-light)',
              background: '#ffffff',
            }}
          >
            <option value="">All Attack Classes</option>
            <option value="Benign">Benign</option>
            <option value="DoS/DDoS">DoS/DDoS</option>
            <option value="Port Scan">Port Scan</option>
            <option value="Brute Force">Brute Force</option>
            <option value="Web Attack">Web Attack</option>
            <option value="Botnet">Botnet</option>
          </select>
          <button className="btn-secondary" onClick={fetchAlerts} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div>Loading recorded alerts...</div>
      ) : alerts.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
          No alerts stored in database for the selected criteria.
        </div>
      ) : (
        alerts.map((alert) => <AlertCard key={alert.alert_id} alert={alert} />)
      )}
    </div>
  );
}
