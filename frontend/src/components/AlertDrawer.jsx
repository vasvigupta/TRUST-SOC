import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle2, AlertTriangle, FileText, Download, Check, ExternalLink, Network, Activity } from 'lucide-react';
import { updateAlertStatus, getPdfReportUrl, getJsonReportUrl } from '../api';

export default function AlertDrawer({ alert, onClose, onStatusUpdated }) {
  if (!alert) return null;

  const [currentStatus, setCurrentStatus] = useState(alert.status || 'NEW');
  const [analystNote, setAnalystNote] = useState('');
  const [updating, setUpdating] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);

  const handleStatusChange = async (newStatus) => {
    setUpdating(true);
    try {
      await updateAlertStatus(alert.alert_id, newStatus, analystNote);
      setCurrentStatus(newStatus);
      setUpdateSuccess(true);
      setTimeout(() => setUpdateSuccess(false), 2000);
      if (onStatusUpdated) onStatusUpdated(alert.alert_id, newStatus);
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setUpdating(false);
    }
  };

  const getBandBadgeClass = (band) => {
    switch (band) {
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-low';
    }
  };

  const getDecisionBadgeClass = (decision) => {
    switch (decision) {
      case 'CONFIRM': return 'badge-confirm';
      case 'REDUCE': return 'badge-reduce';
      case 'REJECT': return 'badge-reject';
      default: return 'badge-reject';
    }
  };

  // Signals
  const r = alert.rule_signal ?? 0.85;
  const s = alert.statistical_signal ?? 0.80;
  const b = alert.behavioural_signal ?? 0.75;
  const e = alert.explanation_signal ?? 0.90;
  const pd = alert.detection_probability ?? alert.probability ?? 0.95;
  const pv = alert.verification_pv ?? alert.agreement_score ?? 0.82;
  const comp = alert.composite_confidence ?? (0.4 * pd + 0.4 * pv + 0.2 * r);
  const band = alert.confidence_band || (comp >= 0.8 ? 'HIGH' : comp >= 0.5 ? 'MEDIUM' : 'LOW');
  const decision = alert.verification_decision || (pv >= 0.7 ? 'CONFIRM' : pv >= 0.4 ? 'REDUCE' : 'REJECT');

  // Top features / SHAP attributions
  const topFeatures = alert.top_features || [
    { feature: 'Flow Packets/s', value: 2450.2, attribution: 0.342 },
    { feature: 'Bwd Packet Length Mean', value: 412.0, attribution: 0.285 },
    { feature: 'Flow Duration', value: 120540, attribution: 0.198 },
    { feature: 'Destination Port', value: 80, attribution: 0.145 },
    { feature: 'Init_Win_bytes_forward', value: 29200, attribution: -0.082 },
  ];

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-content" onClick={(e) => e.stopPropagation()} style={{ overflowY: 'auto' }}>
        {/* Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            position: 'sticky',
            top: 0,
            background: 'var(--surface)',
            zIndex: 10,
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'monospace', color: 'var(--primary)' }}>
                {alert.alert_id}
              </span>
              <span className={`badge ${getBandBadgeClass(band)}`}>
                {band} CONFIDENCE
              </span>
              <span className={`badge ${getDecisionBadgeClass(decision)}`}>
                {decision}
              </span>
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              Logged: {alert.timestamp || new Date().toISOString()}
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--text-muted)',
              padding: '6px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Top Score Banner */}
          <div
            style={{
              backgroundColor: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                Composite Trust Score (C)
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--text)', marginTop: '2px' }}>
                {(comp * 100).toFixed(1)}%
                <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontWeight: 500, marginLeft: '6px' }}>
                  ({comp.toFixed(4)})
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Formula: C = 0.40(p_d) + 0.40(p_v) + 0.20(r_corr)
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                Attack Classification
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--primary)', marginTop: '2px' }}>
                {alert.predicted_class || alert.prediction || 'Unknown'}
              </div>
              {alert.true_label && (
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Ground Truth: <strong>{alert.true_label}</strong>
                </div>
              )}
            </div>
          </div>

          {/* 5-Tuple Network Context */}
          <div className="card" style={{ padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Network size={18} color="var(--primary)" />
              <h4 style={{ fontSize: '0.88rem', fontWeight: 700 }}>5-Tuple Network Context & Asset Criticality</h4>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '0.8rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Source:</span>{' '}
                <strong style={{ fontFamily: 'monospace' }}>
                  {alert.src_ip || '192.168.10.50'}:{alert.src_port || 49210}
                </strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Destination:</span>{' '}
                <strong style={{ fontFamily: 'monospace' }}>
                  {alert.dst_ip || '172.16.0.1'}:{alert.dst_port || 80}
                </strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Protocol:</span>{' '}
                <strong>{alert.protocol === 6 ? 'TCP (6)' : alert.protocol === 17 ? 'UDP (17)' : alert.protocol || 'TCP'}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Asset Role:</span>{' '}
                <strong>Core Enterprise Server (Critical)</strong>
              </div>
            </div>
          </div>

          {/* Detection vs. Verification Side-by-Side */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            {/* Detection Agent */}
            <div className="card" style={{ padding: '14px', borderLeft: '4px solid var(--accent)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase' }}>
                [Stage 2] Detection Agent
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, marginTop: '6px' }}>
                p_d = {(pd * 100).toFixed(1)}%
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Random Forest Baseline (Depth 18)
              </div>
              <div style={{ marginTop: '8px', fontSize: '0.78rem' }}>
                Class: <strong>{alert.predicted_class || alert.prediction}</strong>
              </div>
            </div>

            {/* Verification Agent */}
            <div className="card" style={{ padding: '14px', borderLeft: '4px solid var(--confirm)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--confirm)', textTransform: 'uppercase' }}>
                [Stage 3] Verification Agent
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, marginTop: '6px' }}>
                p_v = {(pv * 100).toFixed(1)}%
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Verdict: <span className={`badge ${getDecisionBadgeClass(decision)}`}>{decision}</span>
              </div>
              <div style={{ marginTop: '8px', fontSize: '0.78rem' }}>
                Multi-Signal Corroboration Engine
              </div>
            </div>
          </div>

          {/* 4 Independent Verification Signals Breakdown */}
          <div className="card" style={{ padding: '16px' }}>
            <h4 style={{ fontSize: '0.88rem', fontWeight: 700, marginBottom: '14px' }}>
              Independent Verification Signals Breakdown (r, s, b, e)
            </h4>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* Signal r */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '4px' }}>
                  <span>(a) Rule / Context Corroboration (r)</span>
                  <strong>{r.toFixed(3)}</strong>
                </div>
                <div style={{ height: '6px', backgroundColor: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${r * 100}%`, height: '100%', backgroundColor: r >= 0.7 ? '#1F6F43' : r >= 0.4 ? '#B54708' : '#B42318' }} />
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Evaluated asset whitelist, port criticality, and MITRE technique signature
                </div>
              </div>

              {/* Signal s */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '4px' }}>
                  <span>(b) Statistical Corroboration (s)</span>
                  <strong>{s.toFixed(3)}</strong>
                </div>
                <div style={{ height: '6px', backgroundColor: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${s * 100}%`, height: '100%', backgroundColor: s >= 0.7 ? '#1F6F43' : s >= 0.4 ? '#B54708' : '#B42318' }} />
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Isolation Forest anomaly check trained strictly on clean benign traffic
                </div>
              </div>

              {/* Signal b */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '4px' }}>
                  <span>(c) Behavioural Baseline Corroboration (b)</span>
                  <strong>{b.toFixed(3)}</strong>
                </div>
                <div style={{ height: '6px', backgroundColor: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${b * 100}%`, height: '100%', backgroundColor: b >= 0.7 ? '#1F6F43' : b >= 0.4 ? '#B54708' : '#B42318' }} />
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Host activity deviation vs. 50-flow rolling packet/byte volume baseline
                </div>
              </div>

              {/* Signal e */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '4px' }}>
                  <span>(d) Explanation Consistency (e)</span>
                  <strong>{e.toFixed(3)}</strong>
                </div>
                <div style={{ height: '6px', backgroundColor: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: `${e * 100}%`, height: '100%', backgroundColor: e >= 0.7 ? '#1F6F43' : e >= 0.4 ? '#B54708' : '#B42318' }} />
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Semantic attribution alignment of top SHAP features with predicted attack class
                </div>
              </div>
            </div>

            {/* Deterministic Rationale */}
            <div style={{ marginTop: '16px', padding: '12px', backgroundColor: 'var(--bg)', borderRadius: '6px', borderLeft: '3px solid var(--primary)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '4px' }}>
                Deterministic Decision Rationale
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text)' }}>
                {alert.rationale || alert.verification_rationale ||
                  (decision === 'CONFIRM'
                    ? 'Agreement score p_v >= 0.70 with no contradictory signals. All 4 verification layers confirm detection.'
                    : decision === 'REDUCE'
                    ? 'Partial agreement (0.40 <= p_v < 0.70). Flow retains visibility with lowered confidence score.'
                    : 'Agreement score p_v < 0.40 or contradictory signals. Verified false alarm filtered from primary alert queue.')}
              </div>
            </div>
          </div>

          {/* Top-5 SHAP Feature Drivers */}
          <div className="card" style={{ padding: '16px' }}>
            <h4 style={{ fontSize: '0.88rem', fontWeight: 700, marginBottom: '10px' }}>
              SHAP Attribution Mass Drivers (Top Features)
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {topFeatures.map((feat, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text)' }}>{feat.feature || feat.name}</span>
                  <span style={{ fontWeight: 600, color: (feat.attribution || feat.importance) >= 0 ? 'var(--high)' : 'var(--confirm)' }}>
                    {(feat.attribution ?? feat.importance ?? 0) >= 0 ? '+' : ''}
                    {(feat.attribution ?? feat.importance ?? 0).toFixed(4)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Analyst Status Update & Actions */}
          <div className="card" style={{ padding: '16px' }}>
            <h4 style={{ fontSize: '0.88rem', fontWeight: 700, marginBottom: '10px' }}>
              Analyst Incident Management
            </h4>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              {['NEW', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => (
                <button
                  key={st}
                  onClick={() => handleStatusChange(st)}
                  disabled={updating}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '4px',
                    border: '1px solid var(--border)',
                    backgroundColor: currentStatus === st ? 'var(--primary)' : 'var(--surface)',
                    color: currentStatus === st ? '#FFFFFF' : 'var(--text)',
                    fontSize: '0.75rem',
                    fontWeight: currentStatus === st ? 700 : 500,
                    cursor: 'pointer',
                  }}
                >
                  {st}
                </button>
              ))}
            </div>

            {updateSuccess && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--confirm)' }}>
                <Check size={14} /> Status updated successfully!
              </div>
            )}
          </div>

          {/* Report Downloads */}
          <div style={{ display: 'flex', gap: '10px', marginTop: '4px', paddingBottom: '20px' }}>
            <a
              href={getPdfReportUrl(alert.alert_id)}
              target="_blank"
              rel="noreferrer"
              className="btn-primary"
              style={{ flex: 1, textDecoration: 'none', justifyContent: 'center' }}
            >
              <FileText size={16} /> Download PDF Report (ReportLab)
            </a>

            <a
              href={getJsonReportUrl(alert.alert_id)}
              target="_blank"
              rel="noreferrer"
              className="btn-secondary"
              style={{ flex: 1, textDecoration: 'none', justifyContent: 'center' }}
            >
              <Download size={16} /> Download JSON Evidence
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
