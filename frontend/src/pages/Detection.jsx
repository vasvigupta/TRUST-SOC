import React, { useState } from 'react';
import { postDetect, getPdfReportUrl } from '../api';
import FeatureChart from '../components/FeatureChart';
import { Play, Download } from 'lucide-react';

const SAMPLE_PAYLOAD = {
  "Flow Duration": 120,
  "Total Fwd Packets": 2,
  "Total Backward Packets": 0,
  "Flow Packets/s": 16666.6,
  "Packet Length Variance": 24.5,
  "Fwd Packet Length Min": 40.0,
  "act_data_pkt_fwd": 1.0,
  "Down/Up Ratio": 0.0,
};

export default function Detection() {
  const [inputJson, setInputJson] = useState(JSON.stringify(SAMPLE_PAYLOAD, null, 2));
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleDetect = async () => {
    setLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(inputJson);
      const res = await postDetect(parsed);
      setResult(res.data);
    } catch (err) {
      setError(err.message || 'Failed to detect flow record');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: '20px' }}>Flow-by-Flow Live Detection Agent</h2>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div className="card">
          <h3 style={{ marginBottom: '12px', fontSize: '1.1rem' }}>Input Network Flow Features (JSON)</h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
            Provide flow record attributes to test inference, classification, and real-time SHAP attributions.
          </p>
          <textarea
            value={inputJson}
            onChange={(e) => setInputJson(e.target.value)}
            rows={12}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '6px',
              border: '1px solid var(--border-light)',
              fontFamily: 'monospace',
              fontSize: '0.9rem',
              marginBottom: '16px',
            }}
          />
          <button className="btn-primary" onClick={handleDetect} disabled={loading}>
            <Play size={16} /> {loading ? 'Analyzing...' : 'Run Detection'}
          </button>
          {error && <div style={{ color: 'var(--danger)', marginTop: '10px' }}>{error}</div>}
        </div>

        <div>
          {result ? (
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '1.1rem' }}>Inference & Attribution Verdict</h3>
                <a
                  href={getPdfReportUrl(result.alert_id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem' }}
                >
                  <Download size={15} /> Export PDF
                </a>
              </div>

              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '20px' }}>
                <span className={`badge ${result.prediction === 'Benign' ? 'badge-benign' : 'badge-attack'}`} style={{ fontSize: '1rem', padding: '6px 14px' }}>
                  {result.prediction}
                </span>
                <span style={{ fontSize: '1.1rem', fontWeight: 600 }}>
                  Confidence: {(result.probability * 100).toFixed(1)}%
                </span>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <FeatureChart features={result.top_features} title="Instance SHAP Explanation" />
              </div>

              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                Alert ID: {result.alert_id} | Status: {result.status} | Verification: {result.verification_result}
              </div>
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '300px', color: 'var(--text-muted)' }}>
              Run detection to view predictions, probabilities, and SHAP explainability.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
