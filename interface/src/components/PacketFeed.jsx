import { useEffect, useRef } from 'react';
import './PacketFeed.css';

const STATUS_CLASS = {
  CLEAN: 'badge-clean',
  SUSPICIOUS: 'badge-suspicious',
  BLOCKED: 'badge-blocked',
};

export default function PacketFeed({ packets, onSelect, selectedId, pps }) {
  const listRef = useRef(null);
  const prevLenRef = useRef(packets.length);

  // Auto-scroll to bottom when new packets arrive
  useEffect(() => {
    if (packets.length !== prevLenRef.current) {
      prevLenRef.current = packets.length;
      if (listRef.current) {
        listRef.current.scrollTop = listRef.current.scrollHeight;
      }
    }
  }, [packets.length]);

  return (
    <section className="hud-panel packet-feed" id="panel-packet-feed" aria-label="Live Packet Feed">
      <div className="corner-tr" /><div className="corner-bl" />

      <div className="panel-header">
        <div className="pf-dot">
          <span className="status-dot cyan" />
        </div>
        <span className="panel-title">LIVE PACKET FEED</span>
        <div className="pps-badge" id="pps-counter" aria-live="polite">
          <span className="pps-val">{pps}</span>
          <span className="pps-unit">PKT/S</span>
        </div>
      </div>

      {/* Column headers */}
      <div className="pf-cols">
        <span>TIMESTAMP</span>
        <span>SRC IP</span>
        <span>DOMAIN</span>
        <span>TYPE</span>
        <span>BYTES</span>
        <span>STATUS</span>
      </div>

      {/* Scrolling list */}
      <div className="pf-list" ref={listRef}>
        {packets.slice(-200).map((pkt, idx) => (
          <button
            key={pkt.id}
            className={`pf-row${pkt.status === 'BLOCKED' ? ' pf-row--blocked' : ''}${pkt.status === 'SUSPICIOUS' ? ' pf-row--suspicious' : ''}${selectedId === pkt.id ? ' pf-row--selected' : ''} pf-row--new`}
            style={{ '--delay': `${Math.min(idx * 0.01, 0.4)}s` }}
            onClick={() => onSelect(pkt)}
            id={`pkt-${pkt.id}`}
            aria-pressed={selectedId === pkt.id}
          >
            <span className="pf-ts">{pkt.timestamp}</span>
            <span className="pf-ip">{pkt.sourceIp}</span>
            <span className="pf-domain" title={pkt.domain}>{pkt.domain.length > 30 ? pkt.domain.slice(0, 28) + '…' : pkt.domain}</span>
            <span className={`pf-type type-${pkt.queryType.toLowerCase()}`}>{pkt.queryType}</span>
            <span className="pf-bytes">{pkt.byteSize}B</span>
            <span className={`badge ${STATUS_CLASS[pkt.status]}`}>{pkt.status}</span>
          </button>
        ))}
      </div>

      {/* Footer summary */}
      <div className="pf-footer">
        <span>TOTAL: {packets.length.toLocaleString()}</span>
        <span className="pf-footer--blocked">BLOCKED: {packets.filter(p => p.status === 'BLOCKED').length}</span>
        <span className="pf-footer--suspicious">SUSPICIOUS: {packets.filter(p => p.status === 'SUSPICIOUS').length}</span>
      </div>
    </section>
  );
}
