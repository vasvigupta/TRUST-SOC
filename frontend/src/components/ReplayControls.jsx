import React, { useState } from 'react';
import { Play, Pause, FastForward, StepForward, Square, Radio, Activity } from 'lucide-react';
import { controlReplay } from '../api';

export default function ReplayControls({ status, isStreaming, onRefresh }) {
  const [targetRate, setTargetRate] = useState(10);
  const [loadingAction, setLoadingAction] = useState(false);

  const isRunning = status?.is_running || false;
  const isPaused = status?.is_paused || false;
  const currentIndex = status?.current_index || 0;
  const totalRecords = status?.total_records || 1;
  const currentRate = status?.rate || targetRate;
  const progressPct = Math.min(100, Math.max(0, (currentIndex / totalRecords) * 100));

  const handleAction = async (action, rate = null, n = 1) => {
    setLoadingAction(true);
    try {
      await controlReplay(action, rate, n);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Replay control failed:', err);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleRateChange = (newRate) => {
    setTargetRate(newRate);
    handleAction('set_rate', newRate);
  };

  return (
    <div className="card" style={{ marginBottom: '24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Activity size={20} color="var(--primary)" />
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text)' }}>
            Log Ingestion / Controlled-Rate Replay Simulator
          </h3>
          <span
            style={{
              fontSize: '0.72rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '10px',
              backgroundColor: isRunning ? (isPaused ? '#FEF0C7' : '#D1FADF') : '#EAECF0',
              color: isRunning ? (isPaused ? 'var(--medium)' : 'var(--confirm)') : 'var(--text-muted)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: isRunning ? (isPaused ? 'var(--medium)' : 'var(--confirm)') : 'var(--text-muted)',
              }}
            />
            {isRunning ? (isPaused ? 'PAUSED' : 'STREAMING LIVE') : 'IDLE / STOPPED'}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              fontSize: '0.75rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              color: isStreaming ? 'var(--confirm)' : 'var(--text-muted)',
              fontWeight: 600,
            }}
          >
            <Radio size={14} className={isStreaming ? 'animate-pulse' : ''} />
            {isStreaming ? 'SSE Stream Connected' : 'SSE Disconnected'}
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
          <span>Replay Buffer Progress: <strong>{currentIndex.toLocaleString()}</strong> / {totalRecords.toLocaleString()} flows</span>
          <span><strong>{progressPct.toFixed(1)}%</strong> complete</span>
        </div>
        <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--border)', borderRadius: '4px', overflow: 'hidden' }}>
          <div
            style={{
              width: `${progressPct}%`,
              height: '100%',
              backgroundColor: 'var(--accent)',
              transition: 'width 0.25s ease',
            }}
          />
        </div>
      </div>

      {/* Controls & Speed Selector */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {!isRunning || isPaused ? (
            <button
              className="btn-primary"
              disabled={loadingAction}
              onClick={() => handleAction(isPaused ? 'resume' : 'start', targetRate)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <Play size={16} />
              {isPaused ? 'Resume Replay' : 'Start Replay'}
            </button>
          ) : (
            <button
              className="btn-secondary"
              disabled={loadingAction}
              onClick={() => handleAction('pause')}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <Pause size={16} />
              Pause
            </button>
          )}

          <button
            className="btn-secondary"
            disabled={loadingAction || (isRunning && !isPaused)}
            onClick={() => handleAction('step', null, 1)}
            title="Ingest single next flow through verification pipeline"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
          >
            <StepForward size={15} />
            Step 1
          </button>

          <button
            className="btn-secondary"
            disabled={loadingAction || (isRunning && !isPaused)}
            onClick={() => handleAction('step', null, 10)}
            title="Step next 10 flows"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
          >
            <FastForward size={15} />
            Step 10
          </button>

          <button
            className="btn-secondary"
            disabled={loadingAction || !isRunning}
            onClick={() => handleAction('stop')}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--high)' }}
          >
            <Square size={14} />
            Stop
          </button>
        </div>

        {/* Speed Adjustment */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Replay Rate:</span>
          <div style={{ display: 'flex', gap: '4px' }}>
            {[1, 5, 10, 25, 50].map((rate) => (
              <button
                key={rate}
                onClick={() => handleRateChange(rate)}
                style={{
                  padding: '4px 10px',
                  borderRadius: '4px',
                  border: '1px solid var(--border)',
                  backgroundColor: currentRate === rate ? 'var(--primary)' : 'var(--surface)',
                  color: currentRate === rate ? '#FFFFFF' : 'var(--text)',
                  fontSize: '0.75rem',
                  fontWeight: currentRate === rate ? 700 : 500,
                  cursor: 'pointer',
                }}
              >
                {rate}/s
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
