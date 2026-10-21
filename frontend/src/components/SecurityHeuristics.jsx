import React from 'react';
import { 
  Server, 
  Globe2, 
  Lock, 
  KeyRound, 
  Binary, 
  Languages, 
  Layers2, 
  Link2,
  CheckCircle2, 
  AlertOctagon, 
  AlertTriangle,
  Info
} from 'lucide-react';

export default function SecurityHeuristics({ heuristics = [] }) {
  // Mapping heuristic IDs to contextual icons
  const getHeuristicIcon = (id) => {
    switch (id) {
      case 'ip_host':
        return Server;
      case 'suspicious_tld':
        return Globe2;
      case 'transport_security':
        return Lock;
      case 'sensitive_keywords':
        return KeyRound;
      case 'entropy_obfuscation':
        return Binary;
      case 'idn_punycode':
        return Languages;
      case 'tld_in_subdomain':
        return Layers2;
      case 'url_shortener':
        return Link2;
      default:
        return Info;
    }
  };

  const getSeverityBadge = (severity, detected) => {
    if (!detected) {
      return (
        <span className="px-2 py-0.5 text-[10px] font-mono font-medium rounded-full bg-slate-800 text-slate-400">
          Clean
        </span>
      );
    }
    switch (severity) {
      case 'critical':
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded-full bg-rose-950/80 text-rose-300 border border-rose-800/60 animate-pulse">
            CRITICAL
          </span>
        );
      case 'warning':
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded-full bg-amber-950/80 text-amber-300 border border-amber-800/60">
            WARNING
          </span>
        );
      case 'info':
      default:
        return (
          <span className="px-2 py-0.5 text-[10px] font-mono font-medium rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
            DETECTED
          </span>
        );
    }
  };

  if (!heuristics || heuristics.length === 0) {
    return null;
  }

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            Automated SOC Heuristics Matrix
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time rule-based telemetry checks executing concurrently with ML inference.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400">
          {heuristics.filter(h => h.detected).length} of {heuristics.length} Triggered
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {heuristics.map((h) => {
          const Icon = getHeuristicIcon(h.id);
          const isTriggered = h.detected;
          const isCritical = isTriggered && h.severity === 'critical';
          const isWarning = isTriggered && h.severity === 'warning';

          let borderClass = 'border-slate-800 bg-slate-950/50 hover:border-slate-700';
          let iconBg = 'bg-slate-800/80 text-slate-400';
          if (isCritical) {
            borderClass = 'border-rose-900/50 bg-rose-950/20 hover:border-rose-700/60';
            iconBg = 'bg-rose-900/40 text-rose-400';
          } else if (isWarning) {
            borderClass = 'border-amber-900/50 bg-amber-950/20 hover:border-amber-700/60';
            iconBg = 'bg-amber-900/40 text-amber-400';
          } else if (isTriggered) {
            borderClass = 'border-cyan-900/50 bg-cyan-950/20 hover:border-cyan-700/60';
            iconBg = 'bg-cyan-900/40 text-cyan-400';
          }

          return (
            <div
              key={h.id}
              className={`p-3.5 rounded-xl border transition-all flex flex-col justify-between ${borderClass}`}
            >
              <div>
                <div className="flex items-start justify-between mb-2">
                  <div className={`p-2 rounded-lg ${iconBg}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  {getSeverityBadge(h.severity, h.detected)}
                </div>

                <div className="text-sm font-semibold text-slate-200 line-clamp-1">
                  {h.name}
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  {h.details}
                </p>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-500 uppercase">{h.id.replace(/_/g, ' ')}</span>
                <span className={`flex items-center gap-1 font-semibold ${
                  isTriggered ? (isCritical ? 'text-rose-400' : isWarning ? 'text-amber-400' : 'text-cyan-400') : 'text-emerald-400'
                }`}>
                  {isTriggered ? (
                    <>
                      <AlertTriangle className="w-3 h-3" /> Triggered
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-3 h-3" /> Pass
                    </>
                  )}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
