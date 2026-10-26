import React, { useEffect, useState, useCallback, useRef } from 'react';
import { getStats, getAlerts, getReplayStatus, getStreamUrl } from '../api';
import TopSummaryBar from '../components/TopSummaryBar';
import ReplayControls from '../components/ReplayControls';
import AnalyticsCharts from '../components/AnalyticsCharts';
import AlertsTable from '../components/AlertsTable';
import AlertDrawer from '../components/AlertDrawer';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [replayStatus, setReplayStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [loading, setLoading] = useState(true);

  const eventSourceRef = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, alertsRes, replayRes] = await Promise.all([
        getStats(),
        getAlerts({ limit: 100 }),
        getReplayStatus(),
      ]);
      setStats(statsRes.data);
      setAlerts(alertsRes.data.alerts || []);
      setTotalAlerts(alertsRes.data.total || 0);
      setReplayStatus(replayRes.data);
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Real-time SSE Stream listener
  useEffect(() => {
    const streamUrl = getStreamUrl();
    const es = new EventSource(streamUrl);
    eventSourceRef.current = es;

    es.onopen = () => {
      setIsStreaming(true);
    };

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'alert' && data.data) {
          const newAlert = data.data;
          setAlerts((prev) => [newAlert, ...prev.slice(0, 199)]);
          setTotalAlerts((prev) => prev + 1);
        } else if (data.type === 'status' && data.data) {
          setReplayStatus(data.data);
        }
      } catch (e) {
        console.error('SSE JSON parse error:', e);
      }
    };

    es.onerror = () => {
      setIsStreaming(false);
    };

    return () => {
      if (es) {
        es.close();
      }
    };
  }, []);

  // Poll replay status periodically if running
  useEffect(() => {
    const timer = setInterval(() => {
      getReplayStatus()
        .then((res) => setReplayStatus(res.data))
        .catch(() => {});
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  const handleStatusUpdated = (alertId, newStatus) => {
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === alertId ? { ...a, status: newStatus } : a))
    );
    if (selectedAlert && selectedAlert.alert_id === alertId) {
      setSelectedAlert((prev) => ({ ...prev, status: newStatus }));
    }
  };

  return (
    <div>
      {/* Page Title */}
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--primary)', letterSpacing: '-0.02em' }}>
          Security Operations Center (SOC) Live Monitoring
        </h2>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginTop: '2px' }}>
          Trust-Aware, Multi-Signal Verification Pipeline & Alert Prioritisation Engine
        </p>
      </div>

      {/* Top Metrics & FPR Reduction Summary */}
      <TopSummaryBar stats={stats} />

      {/* Controlled-Rate Replay Simulator */}
      <ReplayControls
        status={replayStatus}
        isStreaming={isStreaming}
        onRefresh={fetchData}
      />

      {/* Analytic Charts & Prioritisation Matrix */}
      <AnalyticsCharts stats={stats} />

      {/* Live Alerts Feed Table */}
      <AlertsTable
        alerts={alerts}
        totalAlerts={totalAlerts}
        onSelectAlert={(alert) => setSelectedAlert(alert)}
        onRefresh={fetchData}
        loading={loading}
      />

      {/* Forensic Drill-Down Evidence Drawer */}
      {selectedAlert && (
        <AlertDrawer
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusUpdated={handleStatusUpdated}
        />
      )}
    </div>
  );
}
