import React, { useState, useEffect } from 'react';
import { postDetect, getPdfReportUrl, getExamples } from '../api';
import FeatureChart from '../components/FeatureChart';
import { Play, Download, Copy, Check, FileText } from 'lucide-react';

const FALLBACK_NEUTRAL_EXAMPLES = {
  "Sample Flow 1": {
    "Flow Duration": -0.4305,
    "Total Fwd Packets": -0.3067,
    "Total Length of Fwd Packets": -0.924,
    "Flow Packets/s": 0.9399,
    "Packet Length Variance": -0.7645,
    "act_data_pkt_fwd": 0.229,
    "Down/Up Ratio": -0.8308,
    "Fwd Packet Length Min": 0.113
  },
  "Sample Flow 2": {
    "Flow Duration": 1.372,
    "Total Fwd Packets": -0.3013,
    "Total Length of Fwd Packets": -0.8249,
    "Flow Packets/s": -0.4021,
    "Packet Length Variance": 0.1602,
    "act_data_pkt_fwd": 0.0459,
    "Down/Up Ratio": -0.834,
    "Fwd Packet Length Min": 2.4884
  },
  "Sample Flow 3": {
    "Flow Duration": 0.4271,
    "Total Fwd Packets": -0.3017,
    "Total Length of Fwd Packets": 1.7331,
    "Flow Packets/s": -0.3874,
    "Packet Length Variance": 0.409,
    "act_data_pkt_fwd": -0.4289,
    "Down/Up Ratio": 0.2201,
    "Fwd Packet Length Min": -0.3131
  },
  "Sample Flow 4": {
    "Flow Duration": -0.4188,
    "Total Fwd Packets": 0.5878,
    "Total Length of Fwd Packets": 0.1335,
    "Flow Packets/s": -0.3971,
    "Packet Length Variance": -0.7611,
    "act_data_pkt_fwd": 0.189,
    "Down/Up Ratio": -0.4248,
    "Fwd Packet Length Min": 3.9174
  },
  "Sample Flow 5": {
    "Flow Duration": -0.1284,
    "Total Fwd Packets": -0.0863,
    "Total Length of Fwd Packets": -0.2733,
    "Flow Packets/s": -0.4022,
    "Packet Length Variance": -0.7685,
    "act_data_pkt_fwd": -0.3765,
    "Down/Up Ratio": 0.347,
    "Fwd Packet Length Min": 0.2694
  },
  "Sample Flow 6": {
    "Flow Duration": 0.1108,
    "Total Fwd Packets": -0.2864,
    "Total Length of Fwd Packets": -0.7925,
    "Flow Packets/s": -0.4009,
    "Packet Length Variance": -0.0045,
    "act_data_pkt_fwd": -0.3428,
    "Down/Up Ratio": -0.0292,
    "Fwd Packet Length Min": 0.4258
  }
};

export default function Detection() {
  const [examples, setExamples] = useState(FALLBACK_NEUTRAL_EXAMPLES);
  const [activeSampleKey, setActiveSampleKey] = useState(null);
  const [inputJson, setInputJson] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    getExamples()
      .then((res) => {
        if (res.data && Object.keys(res.data).length > 0) {
          // Re-key as neutral Sample Flow 1, 2, ...
          const neutralMap = {};
          let idx = 1;
          Object.values(res.data).forEach((val) => {
            neutralMap[`Sample Flow ${idx}`] = val;
            idx += 1;
          });
          setExamples(neutralMap);
        }
      })
      .catch(() => {
        // Fallback remains
      });
  }, []);

  const handleLoadSample = (sampleKey) => {
    setActiveSampleKey(sampleKey);
    setInputJson(JSON.stringify(examples[sampleKey], null, 2));
    setResult(null);
    setError(null);
  };

  const handleCopy = () => {
    if (!inputJson) return;
    navigator.clipboard.writeText(inputJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleDetect = async () => {
    if (!inputJson.trim()) return;
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
      <h2 style={{ marginBottom: '8px' }}>Flow-by-Flow Live Detection Agent</h2>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '24px', fontSize: '0.92rem' }}>
        Input or paste network flow record features (JSON) to evaluate real-time classification, confidence probabilities, and SHAP explainability.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Left Column: Input JSON Card and Examples */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Main Input JSON Card */}
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600 }}>Input Network Flow Features (JSON)</h3>
              {inputJson && (
                <button
                  onClick={handleCopy}
                  className="btn-secondary"
                  style={{ fontSize: '0.75rem', padding: '4px 8px', display: 'flex', alignItems: 'center', gap: '4px' }}
                >
                  {copied ? <Check size={13} color="#16a34a" /> : <Copy size={13} />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              )}
            </div>

            <textarea
              value={inputJson}
              onChange={(e) => {
                setInputJson(e.target.value);
                setActiveSampleKey(null);
              }}
              placeholder='Paste network flow JSON features here... e.g.&#10;{&#10;  "Flow Duration": 120,&#10;  "Total Fwd Packets": 2,&#10;  "Flow Packets/s": 1666.6,&#10;  "Packet Length Variance": 24.5&#10;}'
              rows={13}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '6px',
                border: '1px solid var(--border-light)',
                fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                fontSize: '0.86rem',
                lineHeight: 1.45,
                marginBottom: '16px',
                backgroundColor: '#fafafa',
                color: '#1e293b',
              }}
            />

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="btn-primary" onClick={handleDetect} disabled={loading || !inputJson.trim()}>
                  <Play size={16} /> {loading ? 'Analyzing with Agent...' : 'Run Detection'}
                </button>
                {inputJson && (
                  <button
                    className="btn-secondary"
                    onClick={() => {
                      setInputJson("");
                      setActiveSampleKey(null);
                      setResult(null);
                      setError(null);
                    }}
                    style={{ fontSize: '0.85rem' }}
                  >
                    Clear
                  </button>
                )}
              </div>
              {activeSampleKey && (
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Loaded: <strong>{activeSampleKey}</strong>
                </span>
              )}
            </div>

            {error && (
              <div style={{ color: 'var(--danger)', marginTop: '12px', fontSize: '0.85rem' }}>
                ⚠️ {error}
              </div>
            )}
          </div>

          {/* Test Examples Box Below the Text Input Box */}
          <div className="card" style={{ padding: '16px 20px', backgroundColor: '#ffffff' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '0.9rem' }}>
              <FileText size={16} color="var(--primary-blue)" />
              <span>Load Test Flow Examples (Unlabeled):</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              Click any sample below to load its raw feature values into the input box and let the Detection Agent analyze and identify the attack class:
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {Object.keys(examples).map((sKey) => {
                const isSelected = activeSampleKey === sKey;
                return (
                  <button
                    key={sKey}
                    onClick={() => handleLoadSample(sKey)}
                    style={{
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '0.82rem',
                      fontWeight: 500,
                      cursor: 'pointer',
                      border: isSelected ? '1px solid var(--primary-blue)' : '1px solid var(--border-light)',
                      backgroundColor: isSelected ? 'var(--bg-subtle)' : '#ffffff',
                      color: isSelected ? 'var(--primary-blue)' : 'var(--text-primary)',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {sKey}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Prediction Results & Explanation Card */}
        <div>
          {result ? (
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 600 }}>Inference & SHAP Attribution Verdict</h3>
                <a
                  href={getPdfReportUrl(result.alert_id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem', padding: '6px 12px' }}
                >
                  <Download size={15} /> Export PDF Report
                </a>
              </div>

              <div style={{ display: 'flex', gap: '14px', alignItems: 'center', marginBottom: '20px' }}>
                <span
                  className={`badge ${result.prediction === 'Benign' ? 'badge-benign' : 'badge-attack'}`}
                  style={{ fontSize: '1rem', padding: '6px 16px', letterSpacing: '0.02em' }}
                >
                  {result.prediction}
                </span>
                <span style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Confidence: {(result.probability * 100).toFixed(1)}%
                </span>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <FeatureChart features={result.top_features} title="Instance SHAP Feature Contributions" />
              </div>

              <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '12px', fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                <span>Alert ID: <strong>{result.alert_id}</strong></span>
                <span>Verification: <strong>{result.verification_result}</strong></span>
              </div>
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '340px', color: 'var(--text-muted)', textAlign: 'center', gap: '8px' }}>
              <div style={{ fontSize: '1.8rem' }}>🛡️</div>
              <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Ready for Flow Record Inference</div>
              <div style={{ fontSize: '0.85rem', maxWidth: '320px' }}>
                Paste custom network flow features or pick one of the unlabeled test samples below the input box, then click <strong>Run Detection</strong>.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
