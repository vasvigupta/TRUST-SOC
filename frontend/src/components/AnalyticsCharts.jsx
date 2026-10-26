import React from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export default function AnalyticsCharts({ stats }) {
  if (!stats) return null;

  const byBand = stats.by_band || {};
  const byDecision = stats.by_decision || {};
  const byClass = stats.by_class || {};

  // 1. Confidence Bands Doughnut
  const bandData = {
    labels: ['HIGH (C ≥ 0.80)', 'MEDIUM (0.50 ≤ C < 0.80)', 'LOW (C < 0.50)'],
    datasets: [
      {
        data: [byBand.HIGH || 0, byBand.MEDIUM || 0, byBand.LOW || 0],
        backgroundColor: ['#B42318', '#B54708', '#2E7D5B'],
        borderColor: '#FFFFFF',
        borderWidth: 2,
      },
    ],
  };

  const bandOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          boxWidth: 12,
          padding: 12,
          font: { size: 11, family: 'inherit' },
        },
      },
      tooltip: {
        callbacks: {
          label: (context) => {
            const val = context.raw || 0;
            const total = (byBand.HIGH || 0) + (byBand.MEDIUM || 0) + (byBand.LOW || 0);
            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0.0';
            return ` ${context.label}: ${val.toLocaleString()} (${pct}%)`;
          },
        },
      },
    },
    cutout: '68%',
  };

  // 2. Class Distribution & Verification Decisions
  const classLabels = ['DoS/DDoS', 'Port Scan', 'Brute Force', 'Web Attack', 'Botnet'];
  const totalConfirm = byDecision.CONFIRM || 0;
  const totalReduce = byDecision.REDUCE || 0;
  const totalReject = byDecision.REJECT || 0;

  // Approximate or exact class breakdown
  const barData = {
    labels: classLabels,
    datasets: [
      {
        label: 'CONFIRM (Validated)',
        data: classLabels.map((c) => Math.round((byClass[c] || 0) * (totalConfirm / Math.max(1, totalConfirm + totalReduce + totalReject)))),
        backgroundColor: '#1F6F43',
        borderRadius: 4,
      },
      {
        label: 'REDUCE (Needs Review)',
        data: classLabels.map((c) => Math.round((byClass[c] || 0) * (totalReduce / Math.max(1, totalConfirm + totalReduce + totalReject)))),
        backgroundColor: '#B54708',
        borderRadius: 4,
      },
      {
        label: 'REJECT (Filtered FP)',
        data: classLabels.map((c) => Math.round((byClass[c] || 0) * (totalReject / Math.max(1, totalConfirm + totalReduce + totalReject)))),
        backgroundColor: '#5B6676',
        borderRadius: 4,
      },
    ],
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          boxWidth: 12,
          padding: 12,
          font: { size: 11, family: 'inherit' },
        },
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { font: { size: 10 } },
      },
      y: {
        grid: { color: '#E5E7EB' },
        ticks: { font: { size: 10 } },
      },
    },
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px', marginBottom: '24px' }}>
      {/* Chart 1: Bands */}
      <div className="card">
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)', marginBottom: '4px' }}>
          Alerts by Composite Confidence Band
        </h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
          Fused formula: C = 0.40 p_d + 0.40 p_v + 0.20 r_corr
        </p>
        <div style={{ height: '220px', position: 'relative' }}>
          <Doughnut data={bandData} options={bandOptions} />
        </div>
      </div>

      {/* Chart 2: Decisions by Class */}
      <div className="card">
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)', marginBottom: '4px' }}>
          Verification Decisions by Threat Category
        </h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
          Corroborated alerts vs. filtered false alarms per MITRE attack vector
        </p>
        <div style={{ height: '220px' }}>
          <Bar data={barData} options={barOptions} />
        </div>
      </div>

      {/* Card 3: Prioritisation Matrix Visual */}
      <div className="card" style={{ gridColumn: 'span 1' }}>
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)', marginBottom: '4px' }}>
          Operational Prioritisation Matrix (3 × 3)
        </h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
          Triaging logic based on Confidence Band × Asset Criticality
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr 1fr 1fr', gap: '6px', fontSize: '0.72rem' }}>
          <div />
          <div style={{ fontWeight: 700, textAlign: 'center', color: 'var(--text-muted)' }}>CRITICAL ASSET</div>
          <div style={{ fontWeight: 700, textAlign: 'center', color: 'var(--text-muted)' }}>HIGH ASSET</div>
          <div style={{ fontWeight: 700, textAlign: 'center', color: 'var(--text-muted)' }}>NORMAL ASSET</div>

          <div style={{ fontWeight: 700, color: 'var(--high)', display: 'flex', alignItems: 'center' }}>HIGH CONF</div>
          <div style={{ backgroundColor: '#FEE4E2', color: '#B42318', padding: '8px', borderRadius: '4px', textAlign: 'center', fontWeight: 700 }}>
            P1: Page On-Call
          </div>
          <div style={{ backgroundColor: '#FEE4E2', color: '#B42318', padding: '8px', borderRadius: '4px', textAlign: 'center', fontWeight: 700 }}>
            P1: Urgent Triage
          </div>
          <div style={{ backgroundColor: '#FEF0C7', color: '#B54708', padding: '8px', borderRadius: '4px', textAlign: 'center', fontWeight: 600 }}>
            P2: Standard Queue
          </div>

          <div style={{ fontWeight: 700, color: 'var(--medium)', display: 'flex', alignItems: 'center' }}>MED CONF</div>
          <div style={{ backgroundColor: '#FEE4E2', color: '#B42318', padding: '8px', borderRadius: '4px', textAlign: 'center', fontWeight: 700 }}>
            P1: Urgent Review
          </div>
          <div style={{ backgroundColor: '#FEF0C7', color: '#B54708', padding: '8px', borderRadius: '4px', textAlign: 'center', fontWeight: 600 }}>
            P2: Analyst Queue
          </div>
          <div style={{ backgroundColor: '#F2F4F7', color: '#5B6676', padding: '8px', borderRadius: '4px', textAlign: 'center' }}>
            P3: Daily Batch
          </div>

          <div style={{ fontWeight: 700, color: 'var(--low)', display: 'flex', alignItems: 'center' }}>LOW CONF</div>
          <div style={{ backgroundColor: '#FEF0C7', color: '#B54708', padding: '8px', borderRadius: '4px', textAlign: 'center', fontWeight: 600 }}>
            P2: Context Enrich
          </div>
          <div style={{ backgroundColor: '#F2F4F7', color: '#5B6676', padding: '8px', borderRadius: '4px', textAlign: 'center' }}>
            P3: Auto-Audit
          </div>
          <div style={{ backgroundColor: '#EDFDF2', color: '#1F6F43', padding: '8px', borderRadius: '4px', textAlign: 'center' }}>
            P4: Suppressed
          </div>
        </div>
      </div>
    </div>
  );
}
