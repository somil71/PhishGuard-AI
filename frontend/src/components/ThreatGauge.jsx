import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Shield } from 'lucide-react';

export default function ThreatGauge({ score = 0, riskLevel = 'SAFE', confidence = 0, isPhishing = false }) {
  // Normalize score between 0 and 100
  const normalizedScore = Math.max(0, Math.min(100, Number(score) || 0));
  
  // Calculate SVG arc: 220 degree sweep (-110 deg to +110 deg)
  // Radius = 85, Center = (120, 110)
  const radius = 80;
  const cx = 110;
  const cy = 110;
  const startAngle = -120;
  const endAngle = 120;
  const totalAngle = endAngle - startAngle; // 240 degrees
  
  // Convert polar to cartesian
  const polarToCartesian = (centerX, centerY, r, angleInDegrees) => {
    const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180.0;
    return {
      x: centerX + r * Math.cos(angleInRadians),
      y: centerY + r * Math.sin(angleInRadians),
    };
  };

  const describeArc = (x, y, r, startA, endA) => {
    const start = polarToCartesian(x, y, r, endA);
    const end = polarToCartesian(x, y, r, startA);
    const largeArcFlag = endA - startA <= 180 ? '0' : '1';
    return ['M', start.x, start.y, 'A', r, r, 0, largeArcFlag, 0, end.x, end.y].join(' ');
  };

  const currentAngle = startAngle + (normalizedScore / 100) * totalAngle;
  const backgroundPath = describeArc(cx, cy, radius, startAngle, endAngle);
  const activePath = describeArc(cx, cy, radius, startAngle, currentAngle);

  // Dynamic color configuration based on risk level and score
  const getColorMeta = () => {
    if (normalizedScore >= 75 || riskLevel === 'CRITICAL_PHISHING' || riskLevel === 'HIGH_RISK') {
      return {
        stroke: '#f43f5e', // rose-500
        text: 'text-rose-400',
        bg: 'bg-rose-500/10',
        border: 'border-rose-500/30',
        glow: 'glow-danger',
        label: 'CRITICAL PHISHING',
        icon: ShieldAlert,
        desc: 'Immediate blocking recommended'
      };
    }
    if (normalizedScore >= 40 || riskLevel === 'SUSPICIOUS') {
      return {
        stroke: '#f59e0b', // amber-500
        text: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/30',
        glow: 'shadow-amber-500/20',
        label: 'SUSPICIOUS LURE',
        icon: AlertTriangle,
        desc: 'Manual SOC triage advised'
      };
    }
    return {
      stroke: '#10b981', // emerald-500
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      glow: 'glow-safe',
      label: 'BENIGN / SAFE',
      icon: ShieldCheck,
      desc: 'No phishing signatures detected'
    };
  };

  const meta = getColorMeta();
  const Icon = meta.icon;

  return (
    <div className={`relative flex flex-col items-center justify-center p-6 rounded-2xl bg-slate-900/90 border border-slate-800 ${meta.border} ${meta.glow} transition-all duration-300`}>
      {/* Risk Badge Header */}
      <div className="flex items-center justify-between w-full mb-3">
        <span className="text-xs font-mono tracking-wider uppercase text-slate-400 flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          Threat Index
        </span>
        <span className={`px-2.5 py-0.5 text-xs font-bold font-mono tracking-wide rounded-full border ${meta.bg} ${meta.text} ${meta.border}`}>
          {meta.label}
        </span>
      </div>

      {/* Speedometer Gauge Visualizer */}
      <div className="relative flex items-center justify-center w-[220px] h-[160px]">
        <svg className="w-full h-full overflow-visible" viewBox="0 0 220 180">
          {/* Subtle Defs for glow */}
          <defs>
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10b981" />
              <stop offset="50%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#f43f5e" />
            </linearGradient>
            <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background Track Arc */}
          <path
            d={backgroundPath}
            fill="none"
            stroke="#1e293b"
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* Dynamic Fill Arc */}
          {normalizedScore > 0 && (
            <path
              d={activePath}
              fill="none"
              stroke={meta.stroke}
              strokeWidth="14"
              strokeLinecap="round"
              filter="url(#gaugeGlow)"
              className="transition-all duration-700 ease-out"
            />
          )}

          {/* Scale Labels */}
          <text x="32" y="172" fill="#64748b" fontSize="11" fontFamily="monospace" textAnchor="middle">0</text>
          <text x="110" y="32" fill="#64748b" fontSize="11" fontFamily="monospace" textAnchor="middle">50</text>
          <text x="188" y="172" fill="#64748b" fontSize="11" fontFamily="monospace" textAnchor="middle">100</text>
        </svg>

        {/* Center Digital Readout */}
        <div className="absolute inset-x-0 bottom-4 flex flex-col items-center justify-center pointer-events-none">
          <div className="flex items-baseline space-x-1">
            <span className={`text-5xl font-extrabold font-mono tracking-tight ${meta.text}`}>
              {normalizedScore.toFixed(1)}
            </span>
            <span className="text-slate-500 text-sm font-mono font-medium">/ 100</span>
          </div>
          <span className="text-[11px] font-medium text-slate-400 mt-0.5">
            Phish Threat Probability
          </span>
        </div>
      </div>

      {/* Summary Footer */}
      <div className="w-full mt-2 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
        <div className="flex items-center space-x-1.5 text-slate-400">
          <Icon className={`w-4 h-4 ${meta.text}`} />
          <span className="font-mono text-slate-300 font-semibold">{confidence > 0 ? `${confidence.toFixed(1)}%` : `${normalizedScore.toFixed(1)}%`}</span>
          <span className="text-slate-500">Confidence</span>
        </div>
        <div className="text-[11px] font-mono text-slate-400">
          Ensemble Consensus
        </div>
      </div>
    </div>
  );
}
