import React, { useState } from 'react';
import { Search, Filter, RefreshCw, Eye, Download, Check, FileText } from 'lucide-react';
import { getPdfReportUrl } from '../api';

export default function AlertsTable({ alerts, totalAlerts, onSelectAlert, onRefresh, loading }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [bandFilter, setBandFilter] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('');
  const [classFilter, setClassFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const [page, setPage] = useState(1);
  const pageSize = 15;

  // Filter alerts locally if provided as a list, or display filtered view
  const filtered = alerts.filter((a) => {
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchId = (a.alert_id || '').toLowerCase().includes(term);
      const matchSrc = (a.src_ip || '').toLowerCase().includes(term);
      const matchDst = (a.dst_ip || '').toLowerCase().includes(term);
      const matchClass = (a.predicted_class || a.prediction || '').toLowerCase().includes(term);
      if (!matchId && !matchSrc && !matchDst && !matchClass) return false;
    }
    if (bandFilter && (a.confidence_band || '').toUpperCase() !== bandFilter.toUpperCase()) return false;
    if (decisionFilter && (a.verification_decision || '').toUpperCase() !== decisionFilter.toUpperCase()) return false;
    if (classFilter && (a.predicted_class || a.prediction || '') !== classFilter) return false;
    if (statusFilter && (a.status || '').toUpperCase() !== statusFilter.toUpperCase()) return false;
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageAlerts = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const getBandBadge = (band) => {
    switch (band) {
      case 'HIGH': return <span className="badge badge-high">HIGH</span>;
      case 'MEDIUM': return <span className="badge badge-medium">MED</span>;
      case 'LOW': return <span className="badge badge-low">LOW</span>;
      default: return <span className="badge badge-low">{band || 'LOW'}</span>;
    }
  };

  const getDecisionBadge = (decision) => {
    switch (decision) {
      case 'CONFIRM': return <span className="badge badge-confirm">CONFIRM</span>;
      case 'REDUCE': return <span className="badge badge-reduce">REDUCE</span>;
      case 'REJECT': return <span className="badge badge-reject">REJECT</span>;
      default: return <span className="badge badge-reject">{decision || 'NONE'}</span>;
    }
  };

  return (
    <div className="card" style={{ padding: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text)' }}>
            Live Security Alerts Feed
          </h3>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Fused confidence scoring with independent verification verdicts
          </p>
        </div>

        <button
          className="btn-secondary"
          onClick={onRefresh}
          disabled={loading}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Filters Bar */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '10px',
          marginBottom: '16px',
          padding: '12px',
          backgroundColor: 'var(--bg)',
          borderRadius: '6px',
          border: '1px solid var(--border)',
        }}
      >
        {/* Search */}
        <div style={{ position: 'relative', gridColumn: 'span 2' }}>
          <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search by Alert ID, IP, or Class..."
            value={searchTerm}
            onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
            style={{
              width: '100%',
              padding: '6px 10px 6px 32px',
              borderRadius: '4px',
              border: '1px solid var(--border)',
              fontSize: '0.8rem',
              backgroundColor: 'var(--surface)',
            }}
          />
        </div>

        {/* Confidence Band Filter */}
        <select
          value={bandFilter}
          onChange={(e) => { setBandFilter(e.target.value); setPage(1); }}
          style={{
            padding: '6px 8px',
            borderRadius: '4px',
            border: '1px solid var(--border)',
            fontSize: '0.8rem',
            backgroundColor: 'var(--surface)',
          }}
        >
          <option value="">All Bands</option>
          <option value="HIGH">HIGH Band (≥ 0.80)</option>
          <option value="MEDIUM">MEDIUM Band (0.50-0.80)</option>
          <option value="LOW">LOW Band (&lt; 0.50)</option>
        </select>

        {/* Verification Decision Filter */}
        <select
          value={decisionFilter}
          onChange={(e) => { setDecisionFilter(e.target.value); setPage(1); }}
          style={{
            padding: '6px 8px',
            borderRadius: '4px',
            border: '1px solid var(--border)',
            fontSize: '0.8rem',
            backgroundColor: 'var(--surface)',
          }}
        >
          <option value="">All Decisions</option>
          <option value="CONFIRM">CONFIRM</option>
          <option value="REDUCE">REDUCE</option>
          <option value="REJECT">REJECT</option>
        </select>

        {/* Attack Class Filter */}
        <select
          value={classFilter}
          onChange={(e) => { setClassFilter(e.target.value); setPage(1); }}
          style={{
            padding: '6px 8px',
            borderRadius: '4px',
            border: '1px solid var(--border)',
            fontSize: '0.8rem',
            backgroundColor: 'var(--surface)',
          }}
        >
          <option value="">All Threat Classes</option>
          <option value="DoS/DDoS">DoS/DDoS</option>
          <option value="Port Scan">Port Scan</option>
          <option value="Brute Force">Brute Force</option>
          <option value="Web Attack">Web Attack</option>
          <option value="Botnet">Botnet</option>
          <option value="Benign">Benign</option>
        </select>

        {/* Incident Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          style={{
            padding: '6px 8px',
            borderRadius: '4px',
            border: '1px solid var(--border)',
            fontSize: '0.8rem',
            backgroundColor: 'var(--surface)',
          }}
        >
          <option value="">All Statuses</option>
          <option value="NEW">NEW</option>
          <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
          <option value="RESOLVED">RESOLVED</option>
          <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
        </select>
      </div>

      {/* Alerts Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Alert ID</th>
              <th>5-Tuple (Src &rarr; Dst)</th>
              <th>Predicted Class</th>
              <th>Detection (p_d)</th>
              <th>Verification</th>
              <th>Agreement (p_v)</th>
              <th>Confidence (C)</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {pageAlerts.length > 0 ? (
              pageAlerts.map((a) => {
                const pd = a.detection_probability ?? a.probability ?? 0.0;
                const pv = a.verification_pv ?? 0.0;
                const comp = a.composite_confidence ?? 0.0;
                const band = a.confidence_band || (comp >= 0.8 ? 'HIGH' : comp >= 0.5 ? 'MEDIUM' : 'LOW');
                const decision = a.verification_decision || (pv >= 0.7 ? 'CONFIRM' : pv >= 0.4 ? 'REDUCE' : 'REJECT');

                return (
                  <tr
                    key={a.alert_id}
                    onClick={() => onSelectAlert(a)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {a.timestamp ? a.timestamp.split('T')[1]?.substring(0, 8) || a.timestamp : '—'}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--primary)', whiteSpace: 'nowrap' }}>
                      {a.alert_id}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                      {a.src_ip || '192.168.10.50'} &rarr; {a.dst_ip || '172.16.0.1'}:{a.dst_port || 80}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text)' }}>
                      {a.predicted_class || a.prediction}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>{(pd * 100).toFixed(0)}%</span>
                        <div style={{ width: '40px', height: '4px', backgroundColor: 'var(--border)', borderRadius: '2px' }}>
                          <div style={{ width: `${pd * 100}%`, height: '100%', backgroundColor: 'var(--accent)' }} />
                        </div>
                      </div>
                    </td>
                    <td>{getDecisionBadge(decision)}</td>
                    <td style={{ fontWeight: 600, fontSize: '0.75rem' }}>{(pv * 100).toFixed(0)}%</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.78rem' }}>{(comp * 100).toFixed(1)}%</span>
                        {getBandBadge(band)}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
                        {a.status || 'NEW'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button
                        className="btn-secondary"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(a);
                        }}
                        style={{ padding: '3px 8px', fontSize: '0.72rem', marginRight: '4px' }}
                      >
                        <Eye size={12} /> Inspect
                      </button>

                      <a
                        href={getPdfReportUrl(a.alert_id)}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '3px 8px',
                          borderRadius: '4px',
                          border: '1px solid var(--border)',
                          backgroundColor: 'var(--surface)',
                          color: 'var(--primary)',
                          textDecoration: 'none',
                          fontSize: '0.72rem',
                          fontWeight: 600,
                        }}
                      >
                        <FileText size={12} /> PDF
                      </a>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={10} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {loading ? 'Loading alerts feed from SQLite store...' : 'No alerts match the selected filters.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '16px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
        <div>
          Showing {pageAlerts.length} of {filtered.length} alerts ({totalAlerts.toLocaleString()} total in database)
        </div>

        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            className="btn-secondary"
            disabled={currentPage <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            style={{ padding: '4px 10px', fontSize: '0.75rem' }}
          >
            Previous
          </button>
          <span style={{ display: 'flex', alignItems: 'center', padding: '0 8px', fontWeight: 600 }}>
            Page {currentPage} of {totalPages}
          </span>
          <button
            className="btn-secondary"
            disabled={currentPage >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            style={{ padding: '4px 10px', fontSize: '0.75rem' }}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
