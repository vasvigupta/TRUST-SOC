import React, { useState } from 'react';
import { triggerReplay } from '../api';
import AlertCard from '../components/AlertCard';
import { FastForward, CheckCircle2 } from 'lucide-react';

export default function Replay() {
  const [numRecords, setNumRecords] = useState(25);
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleStartReplay = async () => {
    setLoading(true);
    setStatus(null);
    try {
      const res = await triggerReplay(numRecords);
      setAlerts(res.data.alerts);
      setStatus(`Successfully replayed ${res.data.processed} records. ${res.data.stored} alerts committed to SQLite.`);
    } catch (err) {
      setStatus(`Replay failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: '10px' }}>Log Ingestion & Stream Replay Simulator</h2>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '20px', fontSize: '0.95rem' }}>
        Controlled-rate replay simulating real-time SOC log ingestion pipeline from CICIDS2017 historical records.
      </p>

      <div className="card" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div>
            <label style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
              Number of flows to stream:
            </label>
            <input
              type="number"
              min={1}
              max={100}
              value={numRecords}
              onChange={(e) => setNumRecords(Number(e.target.value))}
              style={{
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-light)',
                width: '120px',
              }}
            />
          </div>
          <button className="btn-primary" onClick={handleStartReplay} disabled={loading} style={{ marginTop: '18px' }}>
            <FastForward size={16} /> {loading ? 'Streaming...' : 'Start Replay Stream'}
          </button>
        </div>

        {status && (
          <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: '#16a34a', fontSize: '0.9rem' }}>
            <CheckCircle2 size={16} /> {status}
          </div>
        )}
      </div>

      {alerts.length > 0 && (
        <div>
          <h3 style={{ marginBottom: '16px', fontSize: '1.1rem' }}>Generated Live Stream Alerts ({alerts.length})</h3>
          {alerts.map((alert) => (
            <AlertCard key={alert.alert_id} alert={alert} />
          ))}
        </div>
      )}
    </div>
  );
}
