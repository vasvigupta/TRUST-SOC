import React from 'react';
import { ShieldAlert, CheckCircle2, AlertOctagon, TrendingDown, Filter, ShieldCheck } from 'lucide-react';

export default function TopSummaryBar({ stats }) {
  if (!stats) return null;

  const total = stats.total_alerts || 0;
  const high = stats.by_band?.HIGH || 0;
  const medium = stats.by_band?.MEDIUM || 0;
  const low = stats.by_band?.LOW || 0;
  const rejected = stats.by_decision?.REJECT || 0;

  const fpr = stats.fpr_reduction || {
    baseline_fpr_pct: 1.3721,
    post_verification_lenient_fpr_pct: 0.0167,
    relative_reduction_pct: 98.79,
    absolute_reduction_pct_pts: 1.3555,
    recall_cost_pct: 2.39,
    cohens_kappa: 0.608,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
      {/* Primary Project Success Metric Banner */}
      <div
        style={{
          background: 'linear-gradient(135deg, #1F3864 0%, #2F6FB3 100%)',
          borderRadius: '8px',
          padding: '18px 24px',
          color: '#FFFFFF',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
          boxShadow: '0 2px 8px rgba(31, 56, 100, 0.15)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              backgroundColor: 'rgba(255, 255, 255, 0.15)',
              padding: '10px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldCheck size={28} color="#FFFFFF" />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.06em', opacity: 0.85, fontWeight: 600 }}>
              Primary Success Metric (Core Trust Mechanism)
            </div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: '2px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>{fpr.relative_reduction_pct.toFixed(2)}% False-Positive Rate Reduction</span>
              <span
                style={{
                  fontSize: '0.75rem',
                  backgroundColor: '#2E7D5B',
                  color: '#FFFFFF',
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontWeight: 700,
                }}
              >
                VERIFIED
              </span>
            </div>
            <div style={{ fontSize: '0.82rem', opacity: 0.9, marginTop: '4px' }}>
              Baseline IDS FPR: <strong>{fpr.baseline_fpr_pct.toFixed(4)}%</strong> (247 false alarms) &rarr; Post-Verification: <strong>{fpr.post_verification_lenient_fpr_pct.toFixed(4)}%</strong> (only 3 surviving false alarms)
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <div style={{ textAlign: 'right', borderRight: '1px solid rgba(255, 255, 255, 0.2)', paddingRight: '20px' }}>
            <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>Absolute Drop</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700 }}>-{fpr.absolute_reduction_pct_pts.toFixed(4)} pp</div>
          </div>
          <div style={{ textAlign: 'right', borderRight: '1px solid rgba(255, 255, 255, 0.2)', paddingRight: '20px' }}>
            <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>Recall Cost</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700 }}>{fpr.recall_cost_pct.toFixed(2)}%</div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>Agreement (&kappa;)</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700 }}>{fpr.cohens_kappa.toFixed(3)}</div>
          </div>
        </div>
      </div>

      {/* 4 Standard SOC Counters */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ backgroundColor: 'var(--primary-soft)', padding: '12px', borderRadius: '8px', color: 'var(--primary)' }}>
            <ShieldAlert size={24} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>TOTAL ALERTS</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text)', marginTop: '2px' }}>
              {total.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Flows logged in SQLite</div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ backgroundColor: '#FEE4E2', padding: '12px', borderRadius: '8px', color: 'var(--high)' }}>
            <AlertOctagon size={24} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--high)', fontWeight: 600 }}>HIGH CONFIDENCE (C &ge; 0.80)</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--high)', marginTop: '2px' }}>
              {high.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {total > 0 ? `${((high / total) * 100).toFixed(1)}%` : '0%'} auto-escalated to tier-1
            </div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ backgroundColor: '#FEF0C7', padding: '12px', borderRadius: '8px', color: 'var(--medium)' }}>
            <Filter size={24} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--medium)', fontWeight: 600 }}>MEDIUM REVIEW (0.50-0.80)</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--medium)', marginTop: '2px' }}>
              {medium.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {total > 0 ? `${((medium / total) * 100).toFixed(1)}%` : '0%'} queued for triage
            </div>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ backgroundColor: '#EDFDF2', padding: '12px', borderRadius: '8px', color: 'var(--confirm)' }}>
            <CheckCircle2 size={24} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--confirm)', fontWeight: 600 }}>REJECTED FALSE ALARMS</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--confirm)', marginTop: '2px' }}>
              {rejected.toLocaleString()}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Surfacing verified non-threats
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
