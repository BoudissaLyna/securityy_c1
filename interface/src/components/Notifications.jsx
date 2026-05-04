import { useState, useEffect, useCallback, useRef } from 'react';
import './Notifications.css';

let _nid = 0;

export default function Notifications({ packets }) {
  const [toasts, setToasts] = useState([]);
  const prevLen = useRef(packets.length);

  // Watch for new BLOCKED / SUSPICIOUS packets
  useEffect(() => {
    if (packets.length <= prevLen.current) {
      prevLen.current = packets.length;
      return;
    }

    const newPkts = packets.slice(prevLen.current);
    prevLen.current = packets.length;

    const alerts = newPkts.filter(p => p.status === 'BLOCKED' || p.status === 'SUSPICIOUS');
    if (alerts.length === 0) return;

    // Only show the latest alert to avoid flooding
    const pkt = alerts[alerts.length - 1];
    const id = ++_nid;

    const toast = {
      id,
      status: pkt.status,
      domain: pkt.domain,
      rule: pkt.detectionRule || 'ANOMALY DETECTED',
      ip: pkt.sourceIp,
      ts: pkt.timestamp,
    };

    setToasts(prev => [...prev.slice(-4), toast]); // Keep max 5

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4500);
  }, [packets]);

  if (toasts.length === 0) return null;

  return (
    <div className="notif-container" id="notification-area" aria-live="assertive">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`notif-toast notif-toast--${t.status.toLowerCase()}`}
        >
          <div className="notif-header">
            <span className={`notif-status-badge notif-status-badge--${t.status.toLowerCase()}`}>{t.status}</span>
            <span className="notif-ts">{t.ts}</span>
          </div>
          <div className="notif-rule">{t.rule}</div>
          <div className="notif-details">
            <span className="notif-domain" title={t.domain}>
              {t.domain.length > 36 ? t.domain.slice(0, 34) + '…' : t.domain}
            </span>
            <span className="notif-ip">{t.ip}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
