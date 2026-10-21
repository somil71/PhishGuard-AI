import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Trash2, 
  Globe, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  ArrowRight, 
  CheckCircle, 
  Lock, 
  Unlock, 
  Cpu, 
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Zap,
  Copy,
  Check
} from 'lucide-react';
import ThreatGauge from './ThreatGauge';
import ExplainabilityView from './ExplainabilityView';
import SecurityHeuristics from './SecurityHeuristics';
import { analyzeUrl, getSampleUrls } from '../services/api';

export default function UrlScanner() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [samples, setSamples] = useState([]);
  const [samplesLoading, setSamplesLoading] = useState(false);
  const [featuresOpen, setFeaturesOpen] = useState(false);
  const [featureSearch, setFeatureSearch] = useState('');
  const [copiedFeature, setCopiedFeature] = useState(null);

  // Fetch sample URLs on component mount
  useEffect(() => {
    async function loadSamples() {
      try {
        setSamplesLoading(true);
        const data = await getSampleUrls();
        if (Array.isArray(data)) {
          setSamples(data);
        } else if (data && data.samples) {
          setSamples(data.samples);
        }
      } catch (err) {
        console.warn('Failed to fetch samples:', err);
      } finally {
        setSamplesLoading(false);
      }
    }
    loadSamples();
  }, []);

  const handleScan = async (targetUrl = urlInput) => {
    const trimmed = (targetUrl || '').trim();
    if (!trimmed) {
      setError('Please provide a valid URL to analyze.');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const data = await analyzeUrl(trimmed, true);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Analysis failed. Check backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleSampleClick = (sampleUrl) => {
    setUrlInput(sampleUrl);
    handleScan(sampleUrl);
  };

  const handleClear = () => {
    setUrlInput('');
    setResult(null);
    setError(null);
  };

  const handleCopyFeature = (key, val) => {
    navigator.clipboard.writeText(`${key}: ${val}`);
    setCopiedFeature(key);
    setTimeout(() => setCopiedFeature(null), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Search Bar & Fast Scanner */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl shadow-cyan-950/20">
        <div className="max-w-4xl mx-auto">
          <div className="text-center sm:text-left mb-4">
            <h2 className="text-xl sm:text-2xl font-bold text-white flex items-center justify-center sm:justify-start gap-2.5">
              <Zap className="w-6 h-6 text-cyan-400" />
              Real-Time URL Threat Hunter & Forensic Scanner
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Extract 34 structural, entropy, and brand indicators evaluated by a LightGBM, XGBoost & RF Ensemble.
            </p>
          </div>

          {/* Input Box */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
            className="relative flex items-center"
          >
            <div className="absolute left-4 pointer-events-none text-slate-400">
              <Globe className="w-5 h-5 text-cyan-400" />
            </div>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Enter suspicious URL or domain (e.g. http://paypa1-security-verification.xyz/login.php)..."
              className="w-full pl-12 pr-32 py-3.5 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all shadow-inner"
            />
            <div className="absolute right-2 flex items-center space-x-1.5">
              {urlInput && (
                <button
                  type="button"
                  onClick={handleClear}
                  className="p-2 text-slate-400 hover:text-slate-200 transition-colors"
                  title="Clear input"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs sm:text-sm rounded-lg flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></span>
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Scan Threat</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Quick-load Sample Pills */}
          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <span className="text-xs font-mono uppercase text-slate-400 tracking-wider block mb-2">
              ⚡ Quick Lure Telemetry Samples:
            </span>
            <div className="flex flex-wrap gap-2">
              {samples.map((s, idx) => {
                const isPhish = s.expected === 'CRITICAL_PHISHING';
                return (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleSampleClick(s.url)}
                    className={`px-3 py-1 rounded-lg text-xs font-mono transition-all border ${
                      isPhish
                        ? 'bg-rose-950/40 text-rose-300 border-rose-800/40 hover:border-rose-600'
                        : 'bg-emerald-950/40 text-emerald-300 border-emerald-800/40 hover:border-emerald-600'
                    }`}
                  >
                    <span className="font-semibold">{s.category}:</span> {s.label}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/50 border border-rose-800 text-rose-200 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
            <span className="text-sm">{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-xs text-rose-300 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Analysis Results Display */}
      {result && (
        <div className="space-y-6">
          {/* Top Threat Overview Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Speedometer Threat Gauge */}
            <div className="lg:col-span-1">
              <ThreatGauge
                score={result.risk_score}
                riskLevel={result.risk_level}
                confidence={result.confidence}
                isPhishing={result.is_phishing}
              />
            </div>

            {/* Target Breakdown & Domain Telemetry */}
            <div className="lg:col-span-2 flex flex-col justify-between p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono tracking-wider uppercase text-slate-400">
                      Evaluated Target
                    </span>
                    <span className={`px-2 py-0.5 text-xs font-bold font-mono rounded ${
                      result.is_phishing ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {result.status_text}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-slate-500">
                    {new Date(result.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                {/* Analyzed URL */}
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 break-all font-mono text-sm text-cyan-300 flex items-center justify-between">
                  <span className="truncate">{result.url}</span>
                  <a
                    href={result.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="ml-2 text-slate-500 hover:text-slate-300 flex-shrink-0"
                    title="Open destination (Caution!)"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>

                {/* Domain & Transport Pills */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Domain Host</span>
                    <span className="text-xs font-mono font-semibold text-slate-200 truncate block">
                      {result.domain || 'N/A'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Registered Root</span>
                    <span className="text-xs font-mono font-semibold text-slate-200 truncate block">
                      {result.registered_domain || 'N/A'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Top Level Domain</span>
                    <span className="text-xs font-mono font-semibold text-cyan-300 block">
                      .{result.tld || 'unknown'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                    <span className="text-[10px] font-mono uppercase text-slate-500 block">Transport Security</span>
                    <span className={`text-xs font-mono font-semibold flex items-center gap-1 ${
                      result.extracted_features?.is_https ? 'text-emerald-400' : 'text-rose-400'
                    }`}>
                      {result.extracted_features?.is_https ? (
                        <>
                          <Lock className="w-3.5 h-3.5" /> HTTPS / TLS
                        </>
                      ) : (
                        <>
                          <Unlock className="w-3.5 h-3.5" /> Insecure HTTP
                        </>
                      )}
                    </span>
                  </div>
                </div>
              </div>

              {/* Actionable SOC Recommendation Banner */}
              <div className={`mt-4 p-4 rounded-xl border flex items-start space-x-3 ${
                result.is_phishing 
                  ? 'bg-rose-950/30 border-rose-800/60 text-rose-200' 
                  : 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
              }`}>
                {result.is_phishing ? (
                  <ShieldAlert className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                )}
                <div className="text-xs leading-relaxed">
                  <div className="font-bold uppercase tracking-wider text-[11px] mb-0.5">
                    {result.is_phishing ? 'CRITICAL SOC ACTION REQUIRED' : 'SOC ASSESSMENT'}
                  </div>
                  {result.recommended_action}
                </div>
              </div>
            </div>
          </div>

          {/* Brand Spoofing Alert Card (if detected or tested) */}
          {result.brand_analysis && (
            <div className={`p-4 rounded-xl border flex items-center justify-between ${
              result.brand_analysis.is_spoofed 
                ? 'bg-amber-950/30 border-amber-800/80 text-amber-200' 
                : 'bg-slate-900/60 border-slate-800 text-slate-300'
            }`}>
              <div className="flex items-center space-x-3">
                <div className={`p-2 rounded-lg ${result.brand_analysis.is_spoofed ? 'bg-amber-900/50 text-amber-300' : 'bg-slate-800 text-slate-400'}`}>
                  <AlertTriangle className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider font-mono">
                    Brand Protection Engine: {result.brand_analysis.target_brand ? `Targeted: ${result.brand_analysis.target_brand}` : 'No Impersonation Signature'}
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {result.brand_analysis.assessment} (Technique: {result.brand_analysis.technique})
                  </p>
                </div>
              </div>

              {result.brand_analysis.similarity_distance !== null && (
                <div className="text-right font-mono text-xs hidden sm:block">
                  <span className="text-slate-500 block">Levenshtein Dist</span>
                  <span className="text-cyan-300 font-bold">{result.brand_analysis.similarity_distance} chars</span>
                </div>
              )}
            </div>
          )}

          {/* Model Consensus Breakdown */}
          {result.model_breakdown && (
            <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-mono mb-4 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                Sub-Model Probability Consensus
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {Object.entries(result.model_breakdown).map(([modelKey, prob]) => {
                  const pct = (prob * 100).toFixed(1);
                  const isHigh = prob >= 0.7;
                  return (
                    <div key={modelKey} className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                      <div className="flex items-center justify-between text-xs mb-1.5">
                        <span className="font-mono uppercase text-slate-300">{modelKey.replace(/_/g, ' ')}</span>
                        <span className={`font-mono font-bold ${isHigh ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {pct}%
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            isHigh ? 'bg-gradient-to-r from-rose-500 to-red-600' : 'bg-gradient-to-r from-emerald-500 to-cyan-500'
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Explainable AI (SHAP) View */}
          <ExplainabilityView attributions={result.top_shap_attributions} />

          {/* Security Heuristics Grid */}
          <SecurityHeuristics heuristics={result.heuristics} />

          {/* Collapsible 34-Feature Inspector Table */}
          {result.extracted_features && (
            <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
              <div className="flex items-center justify-between cursor-pointer" onClick={() => setFeaturesOpen(!featuresOpen)}>
                <div>
                  <h3 className="text-base font-semibold text-white flex items-center gap-2">
                    <span>34-Dimensional Extracted Feature Vector</span>
                    <span className="px-2 py-0.5 text-xs font-mono bg-slate-800 text-cyan-300 rounded">
                      {Object.keys(result.extracted_features).length} Features
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Explore granular numeric indicators fed directly to the ML models.
                  </p>
                </div>
                <button className="p-2 text-slate-400 hover:text-white transition-colors">
                  {featuresOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                </button>
              </div>

              {featuresOpen && (
                <div className="mt-4 pt-4 border-t border-slate-800">
                  {/* Search input for features */}
                  <div className="mb-3 max-w-sm">
                    <input
                      type="text"
                      placeholder="Filter features (e.g. entropy, length, dots)..."
                      value={featureSearch}
                      onChange={(e) => setFeatureSearch(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5 max-h-96 overflow-y-auto pr-1 custom-scrollbar">
                    {Object.entries(result.extracted_features)
                      .filter(([k]) => k.toLowerCase().includes(featureSearch.toLowerCase()))
                      .map(([key, value]) => (
                        <div
                          key={key}
                          onClick={() => handleCopyFeature(key, value)}
                          className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-colors flex items-center justify-between"
                          title="Click to copy"
                        >
                          <div className="truncate pr-2">
                            <span className="text-[11px] font-mono text-slate-400 block truncate">{key}</span>
                            <span className="text-xs font-mono font-bold text-cyan-300">{value}</span>
                          </div>
                          {copiedFeature === key ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                          ) : (
                            <Copy className="w-3.5 h-3.5 text-slate-600 hover:text-slate-400 flex-shrink-0" />
                          )}
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
