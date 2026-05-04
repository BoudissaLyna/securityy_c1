import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import TopBar from './components/TopBar';
import PacketFeed from './components/PacketFeed';
import ThreatRadar from './components/ThreatRadar';
import AnalysisPanel from './components/AnalysisPanel';
import ThreatIntel from './components/ThreatIntel';
import Notifications from './components/Notifications';
import { usePacketStream } from './hooks/usePacketStream';
import './App.css';

export default function App() {
  const { packets, connectionStatus, pps, sendCommand } = usePacketStream();
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [mode, setMode] = useState('MONITOR');
  const [blockedItems, setBlockedItems] = useState([]); // Real-time blocklist for the HUD
  const selectedIdRef = useRef(null);

  // Keep ref in sync with state (no extra render)
  selectedIdRef.current = selectedPacket?.id ?? null;

  // Calculate threat score based on recent packet ratios
  const threatScore = useMemo(() => {
    const recent = packets.slice(-60);
    if (recent.length === 0) return 0;
    const blocked = recent.filter(p => p.status === 'BLOCKED').length;
    const suspicious = recent.filter(p => p.status === 'SUSPICIOUS').length;
    return Math.min(100, Math.round(((blocked * 3 + suspicious) / recent.length) * 100));
  }, [packets]);

  const handleSelect = useCallback((pkt) => {
    setSelectedPacket(pkt);
  }, []);

  const handleAction = useCallback((action, pkt) => {
    console.log(`[SENTINEL] ${action} → ${pkt.sourceIp} | ${pkt.domain}`);
    
    // Send command to Python backend for real blocking simulation
    if (action === 'BLOCK') {
      sendCommand({ action: 'block_ip', ip: pkt.sourceIp });
      sendCommand({ action: 'block_domain', domain: pkt.domain.split('.').slice(-2).join('.') });
      
      // Add to UI blocklist for the teacher to see
      setBlockedItems(prev => {
        if (prev.find(i => i.ip === pkt.sourceIp)) return prev;
        return [...prev, { ip: pkt.sourceIp, domain: pkt.domain, time: new Date().toLocaleTimeString() }];
      });
    }

    if (window.sentinel) {
      window.sentinel.showNotification({
        title: `DNS SENTINEL — ${action}`,
        body: `${action} executed for ${pkt.sourceIp}\nDomain: ${pkt.domain}`,
        urgency: 'normal',
      });
    }
  }, [sendCommand]);

  // Auto-select latest blocked packet in ACTIVE DEFENSE mode
  // Uses a ref so the effect only depends on [packets, mode] — no loop
  useEffect(() => {
    if (mode !== 'ACTIVE DEFENSE') return;
    const latestBlocked = packets.filter(p => p.status === 'BLOCKED').slice(-1)[0];
    if (latestBlocked && latestBlocked.id !== selectedIdRef.current) {
      setSelectedPacket(latestBlocked);
    }
  }, [packets, mode]);

  return (
    <div className={`sentinel-app ${mode === 'ACTIVE DEFENSE' ? 'mode--defense' : ''}`} id="sentinel-app">
      <div className="scanline"></div>
      {/* ⑤ TOP BAR */}
      <TopBar
        mode={mode}
        onModeChange={setMode}
        packetCount={packets.length}
        connectionStatus={connectionStatus}
      />

      {/* Main grid */}
      <main className="sentinel-grid">
        {/* ① LEFT — Live Packet Feed */}
        <div className="grid-left">
          <PacketFeed
            packets={packets}
            onSelect={handleSelect}
            selectedId={selectedPacket?.id}
            pps={pps}
          />
        </div>

        {/* Center column */}
        <div className="grid-center">
          {/* ② CENTER-TOP — Threat Radar / Arc Reactor */}
          <div className="grid-center-top">
            <ThreatRadar threatScore={threatScore} />
          </div>
          {/* ③ CENTER-BOTTOM — Analysis Engine */}
          <div className="grid-center-bottom">
            <AnalysisPanel
              packet={selectedPacket}
              packets={packets}
              onAction={handleAction}
            />
          </div>
        </div>

        {/* ④ RIGHT — Threat Intelligence */}
        <div className="grid-right">
          <ThreatIntel packets={packets} blockedItems={blockedItems} />
        </div>
      </main>

      {/* In-app HUD notifications */}
      <Notifications packets={packets} />

      {/* Mode overlay indicator */}
      {mode === 'ACTIVE DEFENSE' && (
        <div className="defense-overlay" aria-live="polite">
          <span className="defense-badge">ACTIVE DEFENSE ENABLED</span>
        </div>
      )}
    </div>
  );
}
