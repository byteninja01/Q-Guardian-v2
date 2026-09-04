import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileCode, FolderSearch, Zap, CheckCircle2, AlertTriangle, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import axios from 'axios';
import { API_BASE, TOKEN_KEY } from '../lib/api.js';

const RISK_COLOR = (score) =>
  score < 30 ? 'text-red-400' : score < 60 ? 'text-amber-400' : 'text-emerald-400';

const RISK_BG = (score) =>
  score < 30 ? 'bg-red-900/30 border-red-700/40' : score < 60 ? 'bg-amber-900/30 border-amber-700/40' : 'bg-emerald-900/30 border-emerald-700/40';

const FindingCard = ({ finding }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className={`rounded-lg border ${RISK_BG(finding.qtri_score)} p-3 transition-all`}>
      <button
        className="w-full text-left flex items-center justify-between gap-2"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2 min-w-0">
          <AlertTriangle size={12} className={RISK_COLOR(finding.qtri_score)} />
          <span className="font-black text-slate-200 text-xs font-mono truncate">{finding.algorithm}</span>
          <span className="text-[9px] text-slate-500 font-mono shrink-0">
            {finding.file?.split(/[\\/]/).pop()}:{finding.line}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-[10px] font-black font-mono ${RISK_COLOR(finding.qtri_score)}`}>
            QTRI {finding.qtri_score}
          </span>
          {open ? <ChevronUp size={12} className="text-slate-500" /> : <ChevronDown size={12} className="text-slate-500" />}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden"
          >
            <div className="mt-3 pt-3 border-t border-slate-700/50 space-y-1.5">
              <div className="text-[10px] text-slate-400 font-mono">
                <span className="text-slate-500">Rule: </span>{finding.rule_id || '—'}
              </div>
              <div className="text-[10px] text-slate-400 font-mono truncate" title={finding.file}>
                <span className="text-slate-500">File: </span>{finding.file}
              </div>
              {finding.recommendation && (
                <div className="text-[10px] text-cyan-400 font-mono mt-1 bg-cyan-900/20 border border-cyan-800/30 rounded px-2 py-1">
                  {'\u2192'} {finding.recommendation}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const SourceScanner = ({ onScanComplete }) => {
  const token = localStorage.getItem(TOKEN_KEY);
  const [path, setPath] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const runScan = async () => {
    if (!path.trim()) { setError('Enter a file or directory path.'); return; }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await axios.post(
        `${API_BASE}/scan/source`,
        { target_path: path },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setResult(res.data);
      if (onScanComplete) onScanComplete();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const criticalCount = result?.findings_summary?.filter(f => f.qtri_score < 30).length ?? 0;
  const warnCount    = result?.findings_summary?.filter(f => f.qtri_score >= 30 && f.qtri_score < 60).length ?? 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card border border-slate-800/80 overflow-hidden"
    >
      {/* Header */}
      <div className="bg-slate-950/80 border-b border-slate-800 px-5 py-4 flex items-center gap-3">
        <FileCode size={16} className="text-violet-400" />
        <div>
          <h3 className="text-violet-400 font-black text-xs tracking-widest font-mono">STATIC SOURCE SCANNER</h3>
          <p className="text-[10px] text-slate-500 mt-0.5">AST-based cryptographic primitive detection in Python / JS source files</p>
        </div>
      </div>

      {/* Input */}
      <div className="p-5 space-y-3">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <FolderSearch size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              id="source-scan-path"
              type="text"
              value={path}
              onChange={e => setPath(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runScan()}
              placeholder="e.g. /app/src  or  ./crypto_module.py"
              className="w-full bg-slate-900/80 border border-slate-700 rounded-lg pl-9 pr-4 py-2.5 text-[11px] font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-violet-600/70 transition-colors"
            />
          </div>
          <button
            id="source-scan-run-btn"
            onClick={runScan}
            disabled={loading}
            className="flex items-center gap-2 bg-violet-700 hover:bg-violet-600 disabled:bg-slate-700 text-white font-black text-[10px] tracking-widest px-5 py-2.5 rounded-lg transition-all active:scale-95 font-mono whitespace-nowrap"
          >
            {loading
              ? <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Zap size={12} />
            }
            {loading ? 'SCANNING…' : 'SCAN'}
          </button>
        </div>

        {error && (
          <div className="text-[11px] text-red-400 font-mono bg-red-900/20 border border-red-700/30 rounded px-3 py-2">
            {'\u26a0'} {error}
          </div>
        )}
      </div>

      {/* Results */}
      <AnimatePresence>
        {result && (
          <motion.div
            key="results"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="px-5 pb-5 space-y-4"
          >
            {/* Summary bar */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">Assets Found</span>
                <span className="text-xl font-black text-slate-100 font-mono">{result.assets_found}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">Critical</span>
                <span className="text-xl font-black text-red-400 font-mono">{criticalCount}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">Warning</span>
                <span className="text-xl font-black text-amber-400 font-mono">{warnCount}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">CBOM Spec</span>
                <span className="text-sm font-black text-cyan-400 font-mono flex items-center gap-1">
                  <CheckCircle2 size={12} /> {result.cbom_spec_version}
                </span>
              </div>
            </div>

            {/* Findings list */}
            {result.findings_summary?.length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1 scrollbar-thin">
                <div className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-1 flex items-center gap-2">
                  <ExternalLink size={9} /> Findings — click to expand
                </div>
                {result.findings_summary.map((f, i) => (
                  <FindingCard key={i} finding={f} />
                ))}
              </div>
            ) : (
              <div className="text-center py-6 text-slate-500 text-xs font-mono">
                <CheckCircle2 size={24} className="mx-auto mb-2 text-emerald-500" />
                No weak cryptographic primitives detected.
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default SourceScanner;
