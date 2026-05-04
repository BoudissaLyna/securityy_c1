import { useState, useEffect, useRef } from 'react';
import './TopBar.css';

export default function TopBar({ mode, onModeChange, packetCount, connectionStatus }) {
  const [time, setTime] = useState(new Date());
  const [uptime, setUptime] = useState(0);
  const startRef = useRef(Date.now());

  useEffect(() => {
    const t = setInterval(() => {
      setTime(new Date());
      setUptime(Math.floor((Date.now() - startRef.current) / 1000));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  const fmt = (n) => String(n).padStart(2, '0');
  const timeStr = `${fmt(time.getHours())}:${fmt(time.getMinutes())}:${fmt(time.getSeconds())}`;
  const dateStr = time.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase();
  const uptimeStr = `${fmt(Math.floor(uptime / 3600))}:${fmt(Math.floor((uptime % 3600) / 60))}:${fmt(uptime % 60)}`;

  const connLabel = connectionStatus === 'live' ? 'LIVE CAPTURE' : connectionStatus === 'connecting' ? 'CONNECTING' : 'SIMULATION';
  const connColor = connectionStatus === 'live' ? 'var(--green)' : connectionStatus === 'connecting' ? 'var(--amber)' : 'var(--cyan)';
  const connDot = connectionStatus === 'live' ? 'green' : connectionStatus === 'connecting' ? 'amber' : 'cyan';

  function openGuide() {
    const guideUrl = window.location.origin.startsWith('file')
      ? 'dns_tunnel_detection.html'
      : '/dns_tunnel_detection.html';
    window.open(guideUrl, '_blank', 'noopener');
  }

  function openPhishing() {
    window.open('http://localhost:5000', '_blank', 'noopener');
  }

  return (
    <header className="top-bar" id="top-bar">
      {/* Logo */}
      <div className="top-bar__logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="shield-icon">
          <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
          <path d="M11 14H9l3-6v4h2l-3 6v-4z" fill="#000"/>
        </svg>
        <div className="logo-text">
          <span className="logo-main">DNS SENTINEL</span>
          <span className="logo-sub">TUNNEL DETECTION SYSTEM v2.4.1</span>
        </div>
      </div>

      {/* Center — clock + uptime */}
      <div className="top-bar__center">
        <div className="clock-block">
          <span className="clock-label">SYS TIME</span>
          <span className="clock-time">{timeStr}</span>
          <span className="clock-date">{dateStr}</span>
        </div>
        <div className="divider-v" />
        <div className="clock-block">
          <span className="clock-label">UPTIME</span>
          <span className="clock-time uptime">{uptimeStr}</span>
          <span className="clock-date">{packetCount.toLocaleString()} PKT CAPTURED</span>
        </div>
        <div className="divider-v" />
        <div className="conn-status" id="connection-status">
          <span className={`status-dot ${mode === 'ACTIVE DEFENSE' ? 'red' : connDot}`} />
          <span className="conn-label" style={{ 
            color: mode === 'ACTIVE DEFENSE' ? 'var(--red)' : connColor, 
            textShadow: `0 0 8px ${mode === 'ACTIVE DEFENSE' ? 'var(--red)' : connColor}` 
          }}>
            {mode === 'ACTIVE DEFENSE' ? 'THREAT LOCK — ACTIVE' : connLabel}
          </span>
        </div>
      </div>

      {/* Right — utilities + mode toggle */}
      <div className="top-bar__right">
        <div className="utility-buttons">
          <button className="util-btn guide-btn" onClick={openGuide}>GUIDE</button>
          <button className="util-btn phishing-btn" onClick={openPhishing}>PHISHING</button>
        </div>
        <div className="top-bar__right-bottom">
          <span className="mode-label">INTERFACE MODE</span>
          <div className="mode-toggle" id="mode-toggle" role="group">
            <button
              className={`mode-btn ${mode === 'MONITOR' ? 'active' : ''}`}
              onClick={() => onModeChange('MONITOR')}
            >MONITOR</button>
            <button
              className={`mode-btn mode-btn--defense ${mode === 'ACTIVE DEFENSE' ? 'active' : ''}`}
              onClick={() => onModeChange('ACTIVE DEFENSE')}
            >ACTIVE DEFENSE</button>
          </div>
        </div>
      </div>
    </header>
  );
}
