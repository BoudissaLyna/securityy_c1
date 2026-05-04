import { useEffect, useRef } from 'react';
import './ThreatRadar.css';

export default function ThreatRadar({ threatScore }) {
  const canvasRef = useRef(null);
  const frameRef = useRef(0);
  const scoreRef = useRef(threatScore);

  // Smoothly animate towards new score
  useEffect(() => {
    scoreRef.current = threatScore;
  }, [threatScore]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let raf;
    let displayScore = scoreRef.current;

    function resize() {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.parentElement.getBoundingClientRect();
      const size = Math.min(rect.width, rect.height);
      canvas.width = size * dpr;
      canvas.height = size * dpr;
      canvas.style.width = size + 'px';
      canvas.style.height = size + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resize();
    window.addEventListener('resize', resize);

    function draw(t) {
      const W = parseFloat(canvas.style.width);
      const H = parseFloat(canvas.style.height);
      const cx = W / 2, cy = H / 2;
      const R = Math.min(cx, cy) - 8;
      ctx.clearRect(0, 0, W, H);

      // Smoothly interpolate display score
      displayScore += (scoreRef.current - displayScore) * 0.04;

      const isHigh = displayScore > 65;
      const primary = isHigh ? '#ff1744' : '#00f5ff';
      const primaryDim = isHigh ? 'rgba(255,23,68,0.25)' : 'rgba(0,245,255,0.25)';
      const primaryGlow = isHigh ? 'rgba(255,23,68,0.5)' : 'rgba(0,245,255,0.5)';

      // ── Outer ring 1 — slow rotation ──
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(t * 0.0003);
      ctx.strokeStyle = primaryDim;
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(0, 0, R, 0, Math.PI * 2); ctx.stroke();
      // Tick marks
      for (let i = 0; i < 60; i++) {
        const a = (Math.PI * 2 * i) / 60;
        const inner = i % 5 === 0 ? R - 10 : R - 5;
        ctx.strokeStyle = i % 5 === 0 ? primary : primaryDim;
        ctx.lineWidth = i % 5 === 0 ? 1.8 : 0.8;
        ctx.beginPath();
        ctx.moveTo(Math.cos(a) * inner, Math.sin(a) * inner);
        ctx.lineTo(Math.cos(a) * R, Math.sin(a) * R);
        ctx.stroke();
      }
      ctx.restore();

      // ── Ring 2 — medium speed, dashed ──
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-t * 0.0005);
      ctx.strokeStyle = primaryDim;
      ctx.lineWidth = 1;
      ctx.setLineDash([8, 12]);
      ctx.beginPath(); ctx.arc(0, 0, R * 0.82, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
      ctx.restore();

      // ── Ring 3 — fast, dotted ──
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(t * 0.001);
      ctx.strokeStyle = primaryDim;
      ctx.lineWidth = 0.8;
      ctx.setLineDash([2, 8]);
      ctx.beginPath(); ctx.arc(0, 0, R * 0.68, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
      ctx.restore();

      // ── Rotating arcs (sweeping segments) ──
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(t * 0.0007);
      ctx.strokeStyle = primary;
      ctx.lineWidth = 2.5;
      ctx.shadowColor = primary;
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(0, 0, R * 0.75, -0.3, 0.6);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(0, 0, R * 0.75, Math.PI - 0.3, Math.PI + 0.6);
      ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.restore();

      // ── Inner ring 4 ──
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-t * 0.0012);
      ctx.strokeStyle = primaryDim;
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 6]);
      ctx.beginPath(); ctx.arc(0, 0, R * 0.52, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
      ctx.restore();

      // ── Gauge arc (score) ──
      const gaugeR = R * 0.45;
      const startAngle = Math.PI * 0.75;
      const endAngle = Math.PI * 2.25;
      const scoreAngle = startAngle + ((endAngle - startAngle) * displayScore) / 100;

      // Track
      ctx.save();
      ctx.translate(cx, cy);
      ctx.strokeStyle = 'rgba(255,255,255,0.06)';
      ctx.lineWidth = 6;
      ctx.lineCap = 'round';
      ctx.beginPath(); ctx.arc(0, 0, gaugeR, startAngle, endAngle); ctx.stroke();

      // Filled arc
      const grad = ctx.createLinearGradient(-gaugeR, 0, gaugeR, 0);
      grad.addColorStop(0, '#00e676');
      grad.addColorStop(0.5, '#ffb300');
      grad.addColorStop(1, '#ff1744');
      ctx.strokeStyle = grad;
      ctx.lineWidth = 6;
      ctx.shadowColor = primaryGlow;
      ctx.shadowBlur = 14;
      ctx.beginPath(); ctx.arc(0, 0, gaugeR, startAngle, scoreAngle); ctx.stroke();
      ctx.shadowBlur = 0;

      // Needle dot
      const nx = Math.cos(scoreAngle) * gaugeR;
      const ny = Math.sin(scoreAngle) * gaugeR;
      ctx.fillStyle = '#fff';
      ctx.shadowColor = primary;
      ctx.shadowBlur = 12;
      ctx.beginPath(); ctx.arc(nx, ny, 4, 0, Math.PI * 2); ctx.fill();
      ctx.shadowBlur = 0;
      ctx.restore();

      // ── Central score text ──
      const ds = Math.round(displayScore);
      ctx.save();
      ctx.translate(cx, cy);
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      ctx.font = `900 ${R * 0.28}px Orbitron`;
      ctx.fillStyle = primary;
      ctx.shadowColor = primary;
      ctx.shadowBlur = 20;
      ctx.fillText(String(ds), 0, -4);
      ctx.shadowBlur = 0;

      ctx.font = `500 ${R * 0.08}px "Share Tech Mono"`;
      ctx.fillStyle = 'rgba(176,234,245,0.6)';
      ctx.fillText('THREAT LEVEL', 0, R * 0.18);

      const label = ds > 75 ? 'CRITICAL' : ds > 50 ? 'HIGH' : ds > 25 ? 'MODERATE' : 'LOW';
      const labelColor = ds > 75 ? '#ff1744' : ds > 50 ? '#ffb300' : ds > 25 ? '#00bcd4' : '#00e676';
      ctx.font = `700 ${R * 0.1}px Orbitron`;
      ctx.fillStyle = labelColor;
      ctx.shadowColor = labelColor;
      ctx.shadowBlur = 10;
      ctx.fillText(label, 0, R * 0.32);
      ctx.shadowBlur = 0;
      ctx.restore();

      // ── Pulsing core glow ──
      const pulse = Math.sin(t * 0.003) * 0.3 + 0.7;
      ctx.save();
      ctx.translate(cx, cy);
      const coreGrad = ctx.createRadialGradient(0, 0, 0, 0, 0, R * 0.25);
      coreGrad.addColorStop(0, isHigh ? `rgba(255,23,68,${0.12 * pulse})` : `rgba(0,245,255,${0.12 * pulse})`);
      coreGrad.addColorStop(1, 'transparent');
      ctx.fillStyle = coreGrad;
      ctx.beginPath(); ctx.arc(0, 0, R * 0.25, 0, Math.PI * 2); ctx.fill();
      ctx.restore();

      // Small orbiting dots
      for (let i = 0; i < 3; i++) {
        const angle = t * 0.001 * (i + 1) + (Math.PI * 2 * i) / 3;
        const orbitR = R * (0.58 + i * 0.1);
        const dx = cx + Math.cos(angle) * orbitR;
        const dy = cy + Math.sin(angle) * orbitR;
        ctx.fillStyle = primary;
        ctx.shadowColor = primary;
        ctx.shadowBlur = 8;
        ctx.beginPath(); ctx.arc(dx, dy, 2, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      }

      raf = requestAnimationFrame(draw);
    }

    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  const isHigh = threatScore > 65;

  return (
    <section className={`hud-panel threat-radar ${isHigh ? 'high-threat-pulse' : ''}`} id="panel-threat-radar" aria-label="Threat Radar">
      <div className="corner-tr" /><div className="corner-bl" />
      <div className="panel-header">
        <span className={`status-dot ${isHigh ? 'red' : 'cyan'}`} />
        <span className="panel-title">THREAT RADAR</span>
        <span className="radar-status" style={{ color: isHigh ? 'var(--red)' : 'var(--green)' }}>
          {isHigh ? 'ELEVATED' : 'NOMINAL'}
        </span>
      </div>
      <div className="radar-canvas-wrap">
        <canvas ref={canvasRef} id="radar-canvas" />
      </div>
    </section>
  );
}
