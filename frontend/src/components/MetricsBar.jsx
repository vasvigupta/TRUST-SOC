import React from 'react';
import { ShieldCheck, Activity, AlertTriangle, Layers, Percent } from 'lucide-react';

export default function MetricsBar({ metrics }) {
  if (!metrics) return null;

  const items = [
    { label: 'Accuracy', val: `${(metrics.accuracy * 100).toFixed(2)}%`, icon: ShieldCheck, color: '#16a34a' },
    { label: 'Weighted F1', val: metrics.f1_weighted?.toFixed(4), icon: Activity, color: '#1d4ed8' },
    { label: 'FPR (Macro Avg)', val: metrics.fpr_macro?.toFixed(4), icon: Percent, color: '#d97706' },
    { label: 'Baseline Model', val: metrics.model || 'Random Forest', icon: Layers, color: '#475569' },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
      {items.map((it, i) => {
        const Icon = it.icon;
        return (
          <div key={i} className="card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ backgroundColor: `${it.color}15`, padding: '12px', borderRadius: '8px', color: it.color }}>
              <Icon size={24} />
            </div>
            <div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{it.label}</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                {it.val}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
