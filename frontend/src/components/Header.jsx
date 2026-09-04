import { Activity, Search, ShieldCheck } from 'lucide-react';

const Header = ({ onScan, scanning, polling, domain, setDomain, progress, statusMessage }) => {
  return (
    <div className="fixed top-0 left-0 right-0 z-40">
      <div className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex h-20 w-full max-w-[1500px] items-center justify-between gap-4 px-4 sm:px-6">
          {/* Brand */}
          <div className="flex min-w-0 items-center gap-3">
            <img
              src="/brand/q-guardian-logo.png"
              alt="Q-Guardian"
              className="h-10 w-auto shrink-0 object-contain drop-shadow-[0_1px_2px_rgba(11,31,58,0.25)]"
              draggable="false"
            />
            <div className="min-w-0 leading-tight">
              <div className="font-display text-[17px] tracking-wide text-navy">
                Q-GUARDIAN
              </div>
              <div className="hidden text-[9px] font-semibold uppercase tracking-[0.18em] text-slate-400 md:block">
                Post-Quantum CBOM · Risk Audit Platform
              </div>
            </div>
            <span className="hidden rounded border border-cobalt-100 bg-cobalt-50 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-cobalt-700 md:inline-flex items-center gap-1">
              v2.0 · CycloneDX 1.6
            </span>
          </div>

          {/* Scan controls */}
          <div className="flex items-center gap-2.5">
            {polling && (
              <span className="hidden items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500 xl:flex">
                <span className="h-1.5 w-1.5 rounded-full bg-success qg-live-dot" />
                Live monitoring
              </span>
            )}

            <div className="relative hidden sm:block">
              <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Target domain, e.g. example.com"
                className="w-64 rounded-lg border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 font-mono text-xs text-navy placeholder:font-sans placeholder:text-slate-400 transition-colors focus:border-cobalt-500 focus:bg-white focus:outline-none focus:ring-1 focus:ring-cobalt-200 lg:w-80"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !scanning && onScan?.()}
              />
            </div>

            <button
              onClick={onScan}
              disabled={scanning || !domain}
              className="qg-button whitespace-nowrap"
            >
              {scanning ? (
                <>
                  <Activity size={14} className="animate-spin" /> Scanning…
                </>
              ) : (
                <>
                  <ShieldCheck size={14} /> Trigger network scan
                </>
              )}
            </button>
          </div>
        </div>

        {/* Scan progress */}
        {scanning && (
          <div className="border-t border-slate-100">
            <div className="mx-auto flex w-full max-w-[1500px] items-center gap-3 px-6 py-2">
              <div className="h-1 w-full max-w-sm overflow-hidden rounded-full bg-slate-100">
                <div
                  className="h-full rounded-full bg-cobalt-600 transition-all duration-500 ease-out"
                  style={{ width: `${Math.max(progress || 0, 4)}%` }}
                />
              </div>
              <span className="truncate font-mono text-[11px] text-slate-500">
                {statusMessage || 'Initializing engines…'}
              </span>
              <span className="ml-auto shrink-0 font-mono text-[11px] font-semibold text-cobalt-700">
                {Math.round(progress || 0)}%
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Header;
