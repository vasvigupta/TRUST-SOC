import React from 'react';
import { Download, AlertCircle, CheckCircle2 } from 'lucide-react';
import { getPdfReportUrl } from '../api';

export default function AlertCard({ alert }) {
  const isBenign = alert.prediction === 'Benign';
  const prob = (alert.probability * 100).toFixed(1);

  return (
    <div className="card" style={{ marginBottom: '12px', borderLeft: `5px solid ${isBenign ? '#16a34a' : '#dc2626'}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {isBenign ? <CheckCircle2 color="#16a34a" size={18} /> : <AlertCircle color="#dc2626" size={18} />}
          <span style={{ fontWeight: 600 }}>{alert.alert_id}</span>
          <span className={`badge ${isBenign ? 'badge-benign' : 'badge-attack'}`}>{alert.prediction}</span>
        </div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {alert.timestamp || alert.created_at}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
        <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
          Confidence: <strong>{prob}%</strong> | Ground Truth: <strong>{alert.true_label || 'Unknown'}</strong> | Verification: <span style={{ color: 'var(--text-muted)' }}>{alert.verification_result}</span>
        </div>
        <a
          href={getPdfReportUrl(alert.alert_id)}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-secondary"
          style={{ fontSize: '0.8rem', padding: '6px 12px', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <Download size={14} /> PDF Report
        </a>
      </div>
    </div>
  );
}
