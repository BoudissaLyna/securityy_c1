import { useState, useMemo } from 'react';
import './AnalysisPanel.css';

export default function AnalysisPanel({ packet, packets, onAction }) {
  const [actionFeedback, setActionFeedback] = useState(null);
  const [showInspection, setShowInspection] = useState(false);

  // Frequency histogram: queries/min per top domains (last 60 packets)
  const freqData = useMemo(() => {
    const recent = packets.slice(-80);
    const domMap = {};
    recent.forEach(p => {
      const base = p.domain.split('.').slice(-2).join('.');
      domMap[base] = (domMap[base] || 0) + 1;
    });
    return Object.entries(domMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
  }, [packets]);

  const maxFreq = Math.max(...freqData.map(d => d[1]), 1);

  // Query length histogram bins
  const lengthBins = useMemo(() => {
    const bins = [0, 0, 0, 0, 0]; // 0-20, 21-40, 41-60, 61-80, 80+
    packets.slice(-100).forEach(p => {
      const len = p.domain.length;
      if (len <= 20) bins[0]++;
      else if (len <= 40) bins[1]++;
      else if (len <= 60) bins[2]++;
      else if (len <= 80) bins[3]++;
      else bins[4]++;
    });
    return bins;
  }, [packets]);
  const maxBin = Math.max(...lengthBins, 1);
  const binLabels = ['0-20', '21-40', '41-60', '61-80', '80+'];

  function handleAction(action) {
    if (action === 'INSPECT') {
      setShowInspection(!showInspection);
      return;
    }
    setActionFeedback(action);
    if (onAction) onAction(action, packet);
    setTimeout(() => setActionFeedback(null), 1800);
  }

  // Generate a human-friendly explanation
  const getExplanation = (p) => {
    if (p.status === 'CLEAN') {
      return "Traffic pattern matches normal browsing behavior. No anomalies detected.";
    }
    if (p.detectionRule?.includes('ML:')) {
      const conf = p.confidence || 0;
      if (conf > 90) return `XGBoost Model is highly confident (${conf}%) that this packet carries a malicious DNS tunnel payload based on 38 analyzed features.`;
      return `XGBoost Model detected unusual DNS activity. Multiple feature triggers (entropy, length, and timing) suggest possible tunneling.`;
    }
    if (p.detectionRule === 'HIGH ENTROPY SUBDOMAIN') {
      return "The subdomain contains random-looking characters. This is a common indicator of data being exfiltrated via DNS queries.";
    }
    if (p.detectionRule === 'BEACONING PATTERN') {
      return "Detected repeated check-ins to this domain at fixed intervals, typical of Malware Command & Control communication.";
    }
    return p.detectionRule || "Unusual traffic pattern detected.";
  };

  if (!packet) {
    return (
      <section className="hud-panel analysis-panel analysis-panel--empty" id="panel-analysis">
        <div className="corner-tr" /><div className="corner-bl" />
        <div className="panel-header">
          <span className="status-dot cyan" />
          <span className="panel-title">THREAT ANALYSIS ENGINE</span>
        </div>
        <div className="analysis-empty">
          <div className="analysis-empty-icon" />
          <p>SELECT A PACKET TO ANALYZE</p>
          <p className="analysis-empty-sub">Click any row in the live feed to inspect it</p>
        </div>
      </section>
    );
  }

  const entropyPct = Math.min((packet.entropy / 4.5) * 100, 100);
  const entropyColor = entropyPct > 70 ? 'var(--red)' : entropyPct > 40 ? 'var(--amber)' : 'var(--green)';

  return (
    <section className={`hud-panel analysis-panel ${showInspection ? 'analysis-panel--inspecting' : ''}`} id="panel-analysis">
      <div className="corner-tr" /><div className="corner-bl" />
      <div className="panel-header">
        <span className={`status-dot ${packet.status === 'BLOCKED' ? 'red' : packet.status === 'SUSPICIOUS' ? 'amber' : 'green'}`} />
        <span className="panel-title">THREAT ANALYSIS ENGINE</span>
        <div className="panel-badges">
          <span className={`badge ${packet.queryType === 'ML' ? 'badge-ml' : 'badge-rule'}`}>
            {packet.queryType === 'ML' ? 'ML ENGINE' : 'RULE ENGINE'}
          </span>
          <span className={`badge ${packet.status === 'BLOCKED' ? 'badge-blocked' : packet.status === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-clean'}`}>
            {packet.status}
          </span>
        </div>
      </div>

      <div className="analysis-body">
        {!showInspection ? (
          <>
            {/* Verdict Explanation */}
            <div className={`verdict-box ${packet.status.toLowerCase()}`}>
              <div className="verdict-label">THREAT ASSESSMENT</div>
              <div className="verdict-text">{getExplanation(packet)}</div>
              {packet.confidence && (
                <div className="confidence-meter">
                  <div className="cm-label">MODEL CONFIDENCE</div>
                  <div className="cm-bar-track">
                    <div className="cm-bar-fill" style={{ width: `${packet.confidence}%` }} />
                    <span className="cm-val">{packet.confidence}%</span>
                  </div>
                </div>
              )}
            </div>

            {/* Meta info */}
            <div className="analysis-meta">
              <div className="meta-item">
                <span className="meta-label">DOMAIN</span>
                <span className="meta-value meta-domain">{packet.domain}</span>
              </div>
              <div className="meta-item">
                <span className="meta-label">SOURCE</span>
                <span className="meta-value">{packet.sourceIp}</span>
              </div>
              <div className="meta-item">
                <span className="meta-label">QUERY TYPE</span>
                <span className="meta-value">{packet.features?.rr_type_has_TXT ? 'TXT (Covert)' : 'Standard'}</span>
              </div>
              <div className="meta-item">
                <span className="meta-label">PACKET SIZE</span>
                <span className="meta-value">{packet.byteSize} BYTES</span>
              </div>
            </div>

            {/* Charts row */}
            <div className="analysis-charts">
              <div className="chart-block">
                <span className="chart-label">SUBDOMAIN ENTROPY (RANDOMNESS)</span>
                <div className="entropy-bar-track">
                  <div
                    className="entropy-bar-fill"
                    style={{ width: `${entropyPct}%`, background: entropyColor, boxShadow: `0 0 10px ${entropyColor}` }}
                  />
                  <span className="entropy-val" style={{ color: entropyColor }}>{packet.entropy.toFixed(2)} bits</span>
                </div>
                <div className="entropy-scale">
                  <span>BENIGN</span><span>SUSPICIOUS</span><span>MALICIOUS</span>
                </div>
              </div>

              <div className="chart-block chart-block--freq">
                <span className="chart-label">QUERY FREQUENCY (BEACONING)</span>
                <div className="freq-chart">
                  {freqData.slice(0, 4).map(([dom, cnt], i) => (
                    <div className="freq-row" key={i}>
                      <span className="freq-dom">{dom}</span>
                      <div className="freq-bar-track">
                        <div className="freq-bar" style={{ width: `${(cnt / maxFreq) * 100}%` }} />
                      </div>
                      <span className="freq-cnt">{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        ) : (
          /* Feature Inspection Mode */
          <div className="inspection-grid">
            <div className="inspection-header">
              <span>ML FEATURE BREAKDOWN (38 INPUTS)</span>
              <button className="close-inspect" onClick={() => setShowInspection(false)}>BACK</button>
            </div>
            <div className="feature-list">
              {packet.features && Object.entries(packet.features)
                .filter(([k]) => !k.startsWith('_'))
                .map(([key, val]) => (
                  <div className="feature-item" key={key}>
                    <span className="f-name">{key.replace(/_/g, ' ')}</span>
                    <span className="f-val">{typeof val === 'number' ? val.toFixed(4) : String(val)}</span>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Defensive Explanation */}
        <div className="mitigation-guide">
          <div className="mg-header">DEFENSIVE MITIGATION</div>
          <p className="mg-text">
            Clicking <b>BLOCK IP</b> simulates a firewall trigger. The system adds the source IP to a 
            Local Blocklist in the Python kernel. All future packets from this host will be 
            instantly dropped, neutralizing the DNS tunnel.
          </p>
        </div>

        {/* Action buttons */}
        <div className="analysis-actions">
          <button className="tac-btn red-btn" id="btn-block-ip" onClick={() => handleAction('BLOCK')}>
            BLOCK IP
          </button>
          <button className="tac-btn" id="btn-inspect" onClick={() => handleAction('INSPECT')}>
            {showInspection ? 'CLOSE INSPECT' : 'INSPECT FEATURES'}
          </button>
          {actionFeedback && (
            <span className="action-feedback">{actionFeedback} — SENT</span>
          )}
        </div>
      </div>
    </section>
  );
}
