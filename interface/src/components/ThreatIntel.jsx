import { useMemo } from 'react';
import { GEO_DOTS } from '../data/mockData';
import './ThreatIntel.css';

function AnimatedCounter({ value, label, color }) {
  return (
    <div className="ti-counter">
      <span className="ti-counter-val tick-anim" style={{ color, textShadow: `0 0 8px ${color}` }} key={value}>
        {value.toLocaleString()}
      </span>
      <span className="ti-counter-label">{label}</span>
    </div>
  );
}

export default function ThreatIntel({ packets, blockedItems }) {
  const stats = useMemo(() => {
    let clean = 0, suspicious = 0, blocked = 0;
    packets.forEach(p => {
      if (p.status === 'CLEAN') clean++;
      else if (p.status === 'SUSPICIOUS') suspicious++;
      else blocked++;
    });
    return { total: packets.length, clean, suspicious, blocked };
  }, [packets]);

  // Top flagged domains
  const topFlagged = useMemo(() => {
    const map = {};
    packets.filter(p => p.status !== 'CLEAN').forEach(p => {
      const base = p.domain.split('.').slice(-2).join('.');
      map[base] = (map[base] || 0) + 1;
    });
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7);
  }, [packets]);

  const maxFlagged = Math.max(...topFlagged.map(d => d[1]), 1);

  return (
    <section className="hud-panel threat-intel" id="panel-threat-intel" aria-label="Threat Intelligence">
      <div className="corner-tr" /><div className="corner-bl" />
      <div className="panel-header">
        <span className="status-dot cyan" />
        <span className="panel-title">THREAT INTELLIGENCE</span>
      </div>

      <div className="ti-body">
        {/* ---- Counters ---- */}
        <div className="ti-counters" id="live-counters">
          <AnimatedCounter value={stats.total}      label="TOTAL CAPTURED" color="var(--cyan)" />
          <AnimatedCounter value={stats.suspicious} label="SUSPICIOUS"     color="var(--amber)" />
          <AnimatedCounter value={stats.blocked}    label="BLOCKED"        color="var(--red)" />
          <AnimatedCounter value={stats.clean}      label="CLEAN"          color="var(--green)" />
        </div>

        {/* ---- Top flagged domains ---- */}
        <div className="ti-section">
          <span className="ti-section-title">TOP FLAGGED DOMAINS</span>
          <div className="ti-bar-chart">
            {topFlagged.map(([dom, cnt], i) => (
              <div className="ti-bar-row" key={i}>
                <span className="ti-bar-dom">{dom}</span>
                <div className="ti-bar-track">
                  <div
                    className="ti-bar-fill"
                    style={{ width: `${(cnt / maxFlagged) * 100}%` }}
                  />
                </div>
                <span className="ti-bar-cnt">{cnt}</span>
              </div>
            ))}
            {topFlagged.length === 0 && (
              <span className="ti-no-data">AWAITING DATA...</span>
            )}
          </div>
        </div>

        {/* ---- Threat map ---- */}
        <div className="ti-section">
          <span className="ti-section-title">SOURCE IP GEOLOCATIONS</span>
          <div className="ti-map" id="threat-map">
            {/* Simple world map outline as SVG background */}
            <svg className="ti-map-bg" viewBox="0 0 200 100" xmlns="http://www.w3.org/2000/svg">
              {/* Simplified continents */}
              <ellipse cx="55" cy="40" rx="24" ry="22" fill="none" stroke="rgba(0,245,255,0.08)" strokeWidth="0.5" />
              <ellipse cx="120" cy="35" rx="30" ry="25" fill="none" stroke="rgba(0,245,255,0.08)" strokeWidth="0.5" />
              <ellipse cx="170" cy="50" rx="18" ry="20" fill="none" stroke="rgba(0,245,255,0.08)" strokeWidth="0.5" />
              <ellipse cx="65" cy="70" rx="12" ry="16" fill="none" stroke="rgba(0,245,255,0.08)" strokeWidth="0.5" />
              <ellipse cx="130" cy="72" rx="8" ry="10" fill="none" stroke="rgba(0,245,255,0.08)" strokeWidth="0.5" />
              {/* Grid */}
              {Array.from({ length: 5 }, (_, i) => (
                <line key={`h${i}`} x1="0" y1={i * 25} x2="200" y2={i * 25} stroke="rgba(0,245,255,0.04)" strokeWidth="0.3" />
              ))}
              {Array.from({ length: 9 }, (_, i) => (
                <line key={`v${i}`} x1={i * 25} y1="0" x2={i * 25} y2="100" stroke="rgba(0,245,255,0.04)" strokeWidth="0.3" />
              ))}
            </svg>
            {/* Dots */}
            {GEO_DOTS.map((dot, i) => (
              <div
                key={i}
                className={`ti-dot ${dot.threat ? 'ti-dot--threat' : ''}`}
                style={{ left: `${dot.x}%`, top: `${dot.y}%` }}
                title={dot.ip}
              />
            ))}
          </div>
        </div>

        {/* ---- Firewall Active Blocks ---- */}
        <div className="ti-section ti-blocks-block">
          <span className="ti-section-title red">FIREWALL ACTIVE BLOCKS</span>
          <div className="ti-block-list">
            {blockedItems && blockedItems.length > 0 ? (
              blockedItems.map((item, i) => (
                <div className="ti-block-item" key={i}>
                  <div className="ti-block-meta">
                    <span className="ti-block-ip">{item.ip}</span>
                    <span className="ti-block-time">{item.time}</span>
                  </div>
                  <span className="ti-block-status">DROPPING TRAFFIC</span>
                </div>
              ))
            ) : (
              <span className="ti-no-data">NO ACTIVE BLOCKS</span>
            )}
          </div>
        </div>

        {/* ---- System status ---- */}
        <div className="ti-section ti-status-block">
          <span className="ti-section-title">SYSTEM STATUS</span>
          <div className="ti-status-list">
            <div className="ti-status-item">
              <span className="status-dot green" />
              <span className="ti-status-label">Capture Engine</span>
              <span className="ti-status-val active">ACTIVE</span>
            </div>
            <div className="ti-status-item">
              <span className="status-dot green" />
              <span className="ti-status-label">ML Model</span>
              <span className="ti-status-val active">LOADED</span>
            </div>
            <div className="ti-status-item">
              <span className="status-dot green" />
              <span className="ti-status-label">Firewall Hook</span>
              <span className="ti-status-val active">CONNECTED</span>
            </div>
            <div className="ti-status-item">
              <span className="status-dot cyan" />
              <span className="ti-status-label">Entropy Analyzer</span>
              <span className="ti-status-val">RUNNING</span>
            </div>
            <div className="ti-status-item">
              <span className="status-dot cyan" />
              <span className="ti-status-label">Pattern Matcher</span>
              <span className="ti-status-val">SCANNING</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
