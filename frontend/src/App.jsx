import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import Detection from './pages/Detection';
import { Shield, LayoutDashboard, Search, ExternalLink, GitBranch } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const navItems = [
    { id: 'dashboard', label: 'SOC Live Operations', icon: LayoutDashboard },
    { id: 'detection', label: 'Single Flow Pipeline', icon: Search },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg)' }}>
      {/* Sidebar */}
      <aside
        style={{
          width: '270px',
          backgroundColor: 'var(--surface)',
          borderRight: '1px solid var(--border)',
          padding: '24px 16px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        <div>
          {/* Brand */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '32px', paddingLeft: '8px' }}>
            <div
              style={{
                backgroundColor: 'var(--primary)',
                padding: '9px',
                borderRadius: '8px',
                color: '#FFFFFF',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield size={22} />
            </div>
            <div>
              <h1 style={{ fontSize: '1.15rem', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--primary)' }}>
                TRUST-SOC
              </h1>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>
                Verification-Driven IDS
              </span>
            </div>
          </div>

          {/* Navigation */}
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    padding: '11px 14px',
                    borderRadius: '6px',
                    border: 'none',
                    backgroundColor: active ? 'var(--primary-soft)' : 'transparent',
                    color: active ? 'var(--primary)' : 'var(--text-muted)',
                    fontWeight: active ? 700 : 500,
                    fontSize: '0.88rem',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <Icon size={18} color={active ? 'var(--primary)' : 'var(--text-muted)'} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Academic / Project Attribution Footer */}
        <div
          style={{
            borderTop: '1px solid var(--border)',
            paddingTop: '16px',
            paddingLeft: '8px',
            fontSize: '0.72rem',
            color: 'var(--text-muted)',
            lineHeight: 1.5,
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--primary)', marginBottom: '4px' }}>
            BTech CSE Micro-Project
          </div>
          <div>BVCOE, New Delhi</div>
          <div style={{ marginTop: '4px' }}>
            <strong>Team:</strong> TRUST-SOC Project Team
          </div>
          <div>
            <strong>Guide:</strong> Faculty Guide, BVCOE
          </div>
          <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '4px', opacity: 0.8 }}>
            <GitBranch size={12} />
            <span>v1.0.0 (Light Theme)</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '32px', overflowY: 'auto' }}>
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'detection' && <Detection />}
      </main>
    </div>
  );
}
