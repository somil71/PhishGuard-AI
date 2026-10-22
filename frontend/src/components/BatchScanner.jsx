import React, { useState } from 'react';
import { 
  ListFilter, 
  Play, 
  FileDown, 
  RefreshCw, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Download, 
  Filter,
  CheckCircle,
  Clock,
  Layers
} from 'lucide-react';
import { batchAnalyzeUrls } from '../services/api';

const SAMPLE_BATCH_URLS = [
  "http://paypa1-security-verification.xyz/login.php?user=victim",
  "http://appleid.apple.com.verify-account-security.cfd/signin",
  "http://192.168.1.105:8080/chase/webscr/login.php",
  "https://github.com/torvalds/linux",
  "https://en.wikipedia.org/wiki/Phishing",
  "https://www.chase.com/personal/banking",
  "http://wellsfargo-update-client-portal.top/auth/login",
  "https://google.com/search?q=cybersecurity",
  "http://netflix-billing-reactivation.cf/login",
  "https://microsoft.com/en-us"
];

export default function BatchScanner() {
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [batchData, setBatchData] = useState(null);
  const [filterRisk, setFilterRisk] = useState('ALL'); // ALL, SAFE, SUSPICIOUS, PHISHING
  const [searchTerm, setSearchTerm] = useState('');

  const handleRunBatch = async (urlsToRun = null) => {
    let urls = [];
    if (urlsToRun) {
      urls = urlsToRun;
    } else {
      urls = inputText
        .split('\n')
        .map(u => u.trim())
        .filter(u => u.length > 0);
    }

    if (urls.length === 0) {
      setError('Please enter at least one URL (one per line).');
      return;
    }

    if (urls.length > 100) {
      setError('Batch limit is 100 URLs per scan.');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const data = await batchAnalyzeUrls(urls);
      setBatchData(data);
    } catch (err) {
      setError(err.message || 'Batch triage failed. Check backend service.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSampleBatch = () => {
    const text = SAMPLE_BATCH_URLS.join('\n');
    setInputText(text);
    handleRunBatch(SAMPLE_BATCH_URLS);
  };

  const handleExportCSV = () => {
    if (!batchData || !batchData.results) return;

    const headers = ['URL', 'Domain', 'TLD', 'Risk Score', 'Risk Level', 'Is Phishing', 'Confidence', 'Recommended Action'];
    const rows = batchData.results.map(r => [
      `"${r.url.replace(/"/g, '""')}"`,
      `"${r.domain}"`,
      `"${r.tld}"`,
      r.risk_score,
      `"${r.risk_level}"`,
      r.is_phishing,
      r.confidence,
      `"${r.recommended_action.replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_batch_triage_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Filtered results
  const filteredResults = (batchData?.results || []).filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          item.domain.toLowerCase().includes(searchTerm.toLowerCase());
    if (!matchesSearch) return false;

    if (filterRisk === 'ALL') return true;
    if (filterRisk === 'PHISHING') return item.risk_level === 'CRITICAL_PHISHING' || item.risk_level === 'HIGH_RISK';
    if (filterRisk === 'SUSPICIOUS') return item.risk_level === 'SUSPICIOUS';
    if (filterRisk === 'SAFE') return item.risk_level === 'SAFE' || item.risk_level === 'LOW_RISK';
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Batch Input Form */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <ListFilter className="w-5 h-5 text-cyan-400" />
              SOC Bulk Triage & Threat Stream Pipeline
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Analyze batches of suspected URLs extracted from email gateways, SIEM, or web proxy logs.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={handleLoadSampleBatch}
              className="px-3 py-1.5 text-xs font-mono rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition-colors"
            >
              Load Sample Batch
            </button>
            <button
              onClick={() => {
                setInputText('');
                setBatchData(null);
                setError(null);
              }}
              className="px-3 py-1.5 text-xs rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
            >
              Clear
            </button>
          </div>
        </div>

        <div className="relative">
          <textarea
            rows={5}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder={`Enter one URL per line (up to 100 URLs)...\nExample:\nhttp://paypa1-security-verification.xyz/login.php\nhttps://github.com\nhttp://appleid.apple.com.verify-account-security.cfd`}
            className="w-full p-4 bg-slate-950/90 border border-slate-700/80 rounded-xl text-slate-200 placeholder-slate-500 font-mono text-xs leading-relaxed focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 custom-scrollbar"
          />
        </div>

        {error && (
          <div className="mt-3 p-3 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
            {error}
          </div>
        )}

        <div className="mt-4 flex items-center justify-between">
          <span className="text-xs font-mono text-slate-500">
            {inputText.split('\n').filter(u => u.trim()).length} URL(s) queued
          </span>
          <button
            onClick={() => handleRunBatch()}
            disabled={loading}
            className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs rounded-xl flex items-center space-x-2 transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Running Batch Triage...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Batch Pipeline</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Batch Results & Summaries */}
      {batchData && (
        <div className="space-y-6">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <span className="text-xs font-mono uppercase text-slate-400 block mb-1">Total Scanned</span>
              <div className="text-2xl font-bold font-mono text-white">
                {batchData.summary?.total_scanned || 0}
              </div>
              <span className="text-[11px] text-slate-500">URLs processed</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-900/40 bg-emerald-950/10">
              <span className="text-xs font-mono uppercase text-emerald-400 block mb-1">Clean / Safe</span>
              <div className="text-2xl font-bold font-mono text-emerald-400">
                {batchData.summary?.safe_count || 0}
              </div>
              <span className="text-[11px] text-slate-500">Benign verified</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-900/40 bg-amber-950/10">
              <span className="text-xs font-mono uppercase text-amber-400 block mb-1">Suspicious Lures</span>
              <div className="text-2xl font-bold font-mono text-amber-400">
                {batchData.summary?.suspicious_count || 0}
              </div>
              <span className="text-[11px] text-slate-500">Require investigation</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-900/40 bg-rose-950/10">
              <span className="text-xs font-mono uppercase text-rose-400 block mb-1">Critical Phishing</span>
              <div className="text-2xl font-bold font-mono text-rose-400">
                {batchData.summary?.phishing_count || 0}
              </div>
              <span className="text-[11px] text-slate-500">Blocklist candidates</span>
            </div>
          </div>

          {/* Table Controls & Filter */}
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div className="flex items-center space-x-2">
                <Filter className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-mono">
                  Batch Threat Ledger ({filteredResults.length})
                </h3>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {/* Search bar */}
                <input
                  type="text"
                  placeholder="Filter domain or URL..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />

                {/* Filter buttons */}
                <div className="flex items-center space-x-1 p-0.5 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                  {['ALL', 'PHISHING', 'SUSPICIOUS', 'SAFE'].map((lvl) => (
                    <button
                      key={lvl}
                      onClick={() => setFilterRisk(lvl)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors ${
                        filterRisk === lvl ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>

                {/* CSV Export */}
                <button
                  onClick={handleExportCSV}
                  className="px-3 py-1.5 text-xs font-mono rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center space-x-1.5 transition-colors"
                >
                  <FileDown className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Export CSV</span>
                </button>
              </div>
            </div>

            {/* Results Table */}
            <div className="overflow-x-auto custom-scrollbar">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                    <th className="py-3 px-3">Target URL</th>
                    <th className="py-3 px-3">Domain</th>
                    <th className="py-3 px-3">Risk Score</th>
                    <th className="py-3 px-3">Verdict</th>
                    <th className="py-3 px-3">Confidence</th>
                    <th className="py-3 px-3">Recommended Triage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredResults.map((item, idx) => {
                    const isPhish = item.risk_level === 'CRITICAL_PHISHING' || item.risk_level === 'HIGH_RISK';
                    const isSusp = item.risk_level === 'SUSPICIOUS';
                    return (
                      <tr key={idx} className="hover:bg-slate-850/50 transition-colors">
                        <td className="py-3 px-3 max-w-xs truncate text-slate-200 font-mono" title={item.url}>
                          {item.url}
                        </td>
                        <td className="py-3 px-3 text-cyan-300">
                          {item.domain}
                        </td>
                        <td className="py-3 px-3">
                          <span className={`font-bold ${
                            isPhish ? 'text-rose-400' : isSusp ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {item.risk_score.toFixed(1)}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isPhish
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800/80'
                              : isSusp
                              ? 'bg-amber-950/80 text-amber-300 border border-amber-800/80'
                              : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80'
                          }`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-300">
                          {item.confidence.toFixed(1)}%
                        </td>
                        <td className="py-3 px-3 max-w-xs truncate text-slate-400 text-[11px]" title={item.recommended_action}>
                          {item.recommended_action}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {filteredResults.length === 0 && (
                <div className="py-8 text-center text-slate-500 font-mono">
                  No URLs match the selected filter criteria.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
