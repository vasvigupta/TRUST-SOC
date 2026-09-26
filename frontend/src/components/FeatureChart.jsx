import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

export default function FeatureChart({ features, title = 'Top Contributing Features (SHAP / Importance)' }) {
  if (!features || features.length === 0) {
    return <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No feature attributions available.</div>;
  }

  const sorted = [...features].sort((a, b) => {
    const valA = Math.abs(a.shap_value ?? a.importance ?? 0);
    const valB = Math.abs(b.shap_value ?? b.importance ?? 0);
    return valB - valA;
  }).slice(0, 8);

  const labels = sorted.map((f) => f.feature.length > 25 ? f.feature.substring(0, 22) + '...' : f.feature);
  const dataValues = sorted.map((f) => f.shap_value ?? f.importance ?? 0);

  const data = {
    labels,
    datasets: [
      {
        label: 'Attribution Score',
        data: dataValues,
        backgroundColor: dataValues.map(v => v < 0 ? '#ef4444' : '#2563eb'),
        borderRadius: 4,
      },
    ],
  };

  const options = {
    indexAxis: 'y',
    responsive: true,
    plugins: {
      legend: { display: false },
      title: { display: true, text: title, font: { size: 14, weight: 'bold' } },
    },
    scales: {
      x: { grid: { color: '#f1f5f9' } },
      y: { grid: { display: false } },
    },
  };

  return (
    <div style={{ height: '260px', width: '100%' }}>
      <Bar data={data} options={options} />
    </div>
  );
}
