import { ShieldCheck, Activity, Terminal, Cpu } from 'lucide-react';

const Header = ({ onScan, scanning, polling, domain, setDomain, progress, statusMessage }) => {
  return (
    <div className="fixed top-0 left-0 right-0 z-40 shadow-2xl">
      <div className="bg-slate-950 h-10 flex items-center justify-between px-6 text-white text-sm font-bold tracking-wider relative overflow-hidden border-b border-slate-800">
        <div className="absolute inset-0 opacity-10 bg-[linear-gradient(rgba(255,255,255,0.2)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.2)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
        
        <div className="flex items-center gap-4 relative z-10">
          <span className="flex items-center gap-1.5 text-indigo-400 font-extrabold"><ShieldCheck size={18} /> Q-GUARDIAN ENTERPRISE</span>
          <span className="opacity-70 px-4 border-l border-slate-700 hidden sm:block text-slate-300 text-xs">POST-QUANTUM CBOM & RISK AUDIT PLATFORM</span>
        </div>
        <div className="hidden md:flex gap-4 relative z-10 items-center text-xs">
            {polling && <span className="flex items-center gap-2 text-cyan-400 font-mono text-[10px] animate-pulse"><Activity size={14}/> LIVE RUNTIME MONITORING</span>}
            <span className="text-slate-400 font-mono">v2.0 CYCLONEDX-NATIVE</span>
        </div>
      </div>
      <div className="bg-slate-900/95 backdrop-blur-md h-16 flex items-center justify-between px-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-600/20 border border-indigo-500/30 text-cyan-400 shadow-inner">
                <Cpu size={22} className="animate-pulse" />
            </div>
            <span className="text-white font-black text-2xl tracking-tighter flex items-center gap-2 font-mono">
                Q-GUARDIAN<span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block animate-pulse shadow-[0_0_12px_#06B6D4]"></span>
            </span>
        </div>
        <div className="flex items-center gap-3">
          <input 
            type="text" 
            placeholder="Enter Target Asset / Domain (e.g. app.corp.internal)" 
            className="px-4 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 w-64 sm:w-80 transition-all font-mono placeholder:text-slate-500 placeholder:font-sans"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <button 
            onClick={onScan}
            disabled={scanning || !domain}
            className={`qg-button text-xs py-2 px-6 flex items-center gap-2 ${scanning ? 'opacity-70 cursor-not-allowed' : ''}`}
          >
            {scanning ? (
                <><Activity size={14} className="animate-spin" /> SCANNING...</>
            ) : (
                <><ShieldCheck size={14} /> TRIGGER NETWORK SCAN</>
            )}
          </button>
        </div>
      </div>
      
      {/* Scan Progress Bar */}
      {scanning && (
          <div className="h-2 w-full bg-slate-950 overflow-hidden relative border-t border-slate-800 flex items-center">
              <div 
                className="absolute top-0 bottom-0 left-0 bg-gradient-to-r from-indigo-600 via-cyan-500 to-emerald-400 transition-all duration-500 ease-out z-10" 
                style={{width: `${progress || 0}%`}}
              >
                  <div className="absolute inset-0 bg-[linear-gradient(45deg,rgba(255,255,255,0.2)_25%,transparent_25%,transparent_50%,rgba(255,255,255,0.2)_50%,rgba(255,255,255,0.2)_75%,transparent_75%,transparent)] bg-[size:20px_20px] animate-[progress_2s_linear_infinite]"></div>
              </div>
              <div className="truncate text-[9px] font-black uppercase tracking-widest text-slate-300 px-6 z-20 flex items-center gap-2">
                  <Activity size={10} className="animate-spin text-cyan-400" />
                  {statusMessage || "Initializing Engine..."} ({progress || 0}%)
              </div>
          </div>
      )}
    </div>
  );
};

export default Header;
