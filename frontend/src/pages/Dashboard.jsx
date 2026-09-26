import React, { useEffect, useState } from 'react';
import { getMetrics, getAlertSummary, getShapPlotUrl, getConfusionMatrixUrl } from '../api';
import MetricsBar from '../components/MetricsBar';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

export default function Dashboard() {
  const [metrics, setMetrics] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getMetrics(), getAlertSummary()])
      .then(([mRes, sRes]) => {
        setMetrics(mRes.data);
        setSummary(sRes.data);
      })
      .catch((err) => console.error('Error fetching dashboard data:', err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div>Loading SOC metrics & baseline...</div>;

  const chartData = summary && summary.by_class ? {
    labels: Object.keys(summary.by_class),
    datasets: [
      {
        data: Object.values(summary.by_class),
        backgroundColor: ['#22c55e', '#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4', '#ec4899'],
      },
    ],
  } : null;

  return (
    <div>
      <h2 style={{ marginBottom: '20px' }}>Security Operations Overview</h2>
      <MetricsBar metrics={metrics} />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '24px' }}>
        <div className="card">
          <h3 style={{ marginBottom: '16px', fontSize: '1.1rem' }}>Alerts by Classification (SQLite Store)</h3>
          {chartData && Object.keys(summary.by_class).length > 0 ? (
            <div style={{ maxHeight: '260px', display: 'flex', justifyContent: 'center' }}>
              <Doughnut data={chartData} options={{ maintainAspectRatio: false }} />
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px 0' }}>
              No alerts recorded yet. Go to the Replay or Detection tab!
            </div>
          )}
        </div>

        <div className="card">
          <h3 style={{ marginBottom: '16px', fontSize: '1.1rem' }}>Global SHAP Feature Importance</h3>
          <img
            src={getShapPlotUrl()}
            alt="SHAP Feature Importance"
            style={{ width: '100%', borderRadius: '6px', maxHeight: '260px', objectFit: 'contain' }}
            onError={(e) => { e.target.style.display = 'none'; }}
          />
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginBottom: '16px', fontSize: '1.1rem' }}>Confusion Matrix (Held-out Test Evaluation)</h3>
        <img
          src={getConfusionMatrixUrl()}
          alt="Confusion Matrix"
          style={{ width: '100%', maxHeight: '350px', objectFit: 'contain' }}
          onError={(e) => { e.target.style.display = 'none'; }}
        />
      </div>
    </div>
  );
}
