import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import Detection from './pages/Detection';
import Alerts from './pages/Alerts';
import Replay from './pages/Replay';
import { Shield, LayoutDashboard, Search, Bell, RotateCcw } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'detection', label: 'Single Detection', icon: Search },
    { id: 'alerts', label: 'Alert Feed', icon: Bell },
    { id: 'replay', label: 'Log Replay', icon: RotateCcw },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      <aside style={{
        width: '260px',
        backgroundColor: '#ffffff',
        borderRight: '1px solid var(--border-light)',
        padding: '24px 16px',
        display: 'flex',
        flexDirection: 'column',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '32px', paddingLeft: '8px' }}>
          <div style={{ backgroundColor: 'var(--primary-blue)', padding: '8px', borderRadius: '8px', color: '#ffffff' }}>
            <Shield size={22} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.1rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#0f172a' }}>TRUST-SOC</h1>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SOC Verification Pipeline</span>
          </div>
        </div>

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
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: 'none',
                  backgroundColor: active ? 'var(--bg-subtle)' : 'transparent',
                  color: active ? 'var(--primary-blue)' : 'var(--text-secondary)',
                  fontWeight: active ? 600 : 500,
                  fontSize: '0.9rem',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease',
                }}
              >
                <Icon size={18} />
                {item.label}
              </button>
            );
          })}
        </nav>

        <div style={{ marginTop: 'auto', padding: '16px 8px', borderTop: '1px solid var(--border-light)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <div><strong>Prototype Stage:</strong> Phase 1</div>
          <div style={{ marginTop: '4px' }}>Tech: React + Chart.js + FastAPI + SQLite</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '32px', overflowY: 'auto' }}>
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'detection' && <Detection />}
        {activeTab === 'alerts' && <Alerts />}
        {activeTab === 'replay' && <Replay />}
      </main>
    </div>
  );
}
