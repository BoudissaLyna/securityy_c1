// ============================================================
//  DNS TUNNEL SENTINEL — WebSocket Packet Stream Hook
//  Connects to Python capture engine; falls back to mock data.
// ============================================================
import { useState, useEffect, useRef, useCallback } from 'react';
import { getInitialPackets, getNewPacket } from '../data/mockData';

const WS_URL = 'ws://127.0.0.1:8765';
const MAX_PACKETS = 500;
const TRIM_TO = 400;

// Global client-side ID for WS packets (avoids collision with mock IDs)
let _wsPacketId = Date.now();

export function usePacketStream() {
  const [packets, setPackets] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [pps, setPps] = useState(0);
  const wsRef = useRef(null);
  const ppsCounter = useRef(0);
  const reconnectTimer = useRef(null);
  const mockTimer = useRef(null);
  const mountedRef = useRef(true);
  const isLiveRef = useRef(false); // true when WS is connected

  // PPS counter — ticks every second
  useEffect(() => {
    const interval = setInterval(() => {
      setPps(ppsCounter.current);
      ppsCounter.current = 0;
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Add packets helper (trims buffer)
  const addPackets = useCallback((newPkts) => {
    setPackets(prev => {
      const merged = [...prev, ...newPkts];
      return merged.length > MAX_PACKETS ? merged.slice(-TRIM_TO) : merged;
    });
    ppsCounter.current += newPkts.length;
  }, []);

  // ── Stop simulation ──
  const stopSimulation = useCallback(() => {
    if (mockTimer.current) {
      clearTimeout(mockTimer.current);
      mockTimer.current = null;
    }
  }, []);

  // ── Start mock/simulation mode ──
  const startSimulation = useCallback(() => {
    if (mockTimer.current || isLiveRef.current) return; // don't start if live

    setConnectionStatus('simulation');
    // Seed with initial data only if empty
    setPackets(prev => {
      if (prev.length === 0) return getInitialPackets(25);
      return prev;
    });

    function scheduleNext() {
      const delay = 200 + Math.random() * 600;
      mockTimer.current = setTimeout(() => {
        if (!mountedRef.current || isLiveRef.current) return;
        addPackets([getNewPacket()]);
        scheduleNext();
      }, delay);
    }
    scheduleNext();
  }, [addPackets]);

  // ── WebSocket connection ──
  const connectWs = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    setConnectionStatus('connecting');

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[SENTINEL] WebSocket connected to capture engine');
        isLiveRef.current = true;
        setConnectionStatus('live');
        stopSimulation();
        // Clear mock packets and start fresh with live data
        setPackets([]);
        ws.send(JSON.stringify({ action: 'ping' }));
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          if (msg.type === 'packets' && Array.isArray(msg.data)) {
            // Stamp with unique client-side IDs to avoid any collision
            const stamped = msg.data.map(p => ({ ...p, id: _wsPacketId++ }));
            addPackets(stamped);

            // Show OS notification for blocked packets (via Electron)
            if (window.sentinel) {
              stamped
                .filter(p => p.status === 'BLOCKED')
                .forEach(p => {
                  window.sentinel.showNotification({
                    title: '⚠ DNS THREAT BLOCKED',
                    body: `${p.domain}\nRule: ${p.detectionRule || 'UNKNOWN'}\nSource: ${p.sourceIp}`,
                    urgency: 'critical',
                  });
                });
            }
          }
        } catch (e) {
          console.warn('[SENTINEL] Failed to parse WS message:', e);
        }
      };

      ws.onclose = () => {
        console.log('[SENTINEL] WebSocket disconnected');
        isLiveRef.current = false;
        wsRef.current = null;
        if (mountedRef.current) {
          // Fall back to simulation
          reconnectTimer.current = setTimeout(() => {
            if (mountedRef.current && !isLiveRef.current) {
              startSimulation();
              // Retry WS in background
              reconnectTimer.current = setTimeout(connectWs, 9000);
            }
          }, 1500);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      startSimulation();
    }
  }, [addPackets, startSimulation, stopSimulation]);

  // ── Lifecycle ──
  useEffect(() => {
    mountedRef.current = true;
    connectWs();

    // Fall back to simulation after 2s if WS hasn't connected
    const fallbackTimer = setTimeout(() => {
      if (mountedRef.current && !isLiveRef.current) {
        startSimulation();
      }
    }, 2000);

    return () => {
      mountedRef.current = false;
      clearTimeout(fallbackTimer);
      clearTimeout(reconnectTimer.current);
      stopSimulation();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sendCommand = useCallback((cmd) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(cmd));
      return true;
    }
    return false;
  }, []);

  return { packets, connectionStatus, pps, sendCommand };
}
