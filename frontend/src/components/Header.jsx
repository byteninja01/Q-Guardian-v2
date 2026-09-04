import { ShieldCheck, Activity, Terminal, Database } from 'lucide-react';
import pnbLogo from '../assets/pnb_logo_secure.png';

const Header = ({ onScan, scanning, polling, domain, setDomain, progress, statusMessage }) => {
  return (
    <div className="fixed top-0 left-0 right-0 z-40 shadow-[0_4px_20px_rgba(162,12,57,0.1)]">
      <div className="bg-pnb-maroon h-10 flex items-center justify-between px-6 text-white text-sm font-bold tracking-wider relative overflow-hidden">
        {/* Animated grid background for header */}
        <div className="absolute inset-0 opacity-10 bg-[linear-gradient(rgba(255,255,255,0.2)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.2)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
        
        <div className="flex items-center gap-4 relative z-10">
          <span className="flex items-center gap-1"><ShieldCheck size={18} /> PNB CYBERSECURITY PLATFORM</span>
          <span className="opacity-70 px-4 border-l border-white/30 hidden sm:block">QUANTUM RISK OPERATIONS CONSOLE</span>
        </div>
        <div className="hidden md:flex gap-4 relative z-10 items-center">
            {polling && <span className="flex items-center gap-2 text-pnb-gold text-[10px] animate-pulse"><Activity size={14}/> LIVE DATA STREAM</span>}
            <span>Q-GUARDIAN v2.0 FINAL</span>
        </div>
      </div>
      <div className="bg-white h-14 flex items-center justify-between px-6 border-b border-pnb-maroon/10">
        <div className="flex items-center gap-3">
            <img src={pnbLogo} alt="PNB Logo" className="h-10 w-auto drop-shadow-md" />
            <span className="text-pnb-maroon font-black text-2xl tracking-tighter flex items-center gap-2">
                Q-GUARDIAN<span className="w-2.5 h-2.5 rounded-full bg-pnb-gold inline-block animate-pulse shadow-[0_0_8px_#FBBC09]"></span>
            </span>
        </div>
        <div className="flex items-center gap-3">
          <input 
            type="text" 
            placeholder="Enter Internal Domain (e.g. pnb.bank.in)" 
            className="px-4 py-1.5 rounded bg-slate-50 border border-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-pnb-maroon/50 focus:border-pnb-maroon/50 w-48 sm:w-64 transition-all"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <button 
            onClick={onScan}
            disabled={scanning || !domain}
            className={`pnb-button text-xs py-2 px-6 flex items-center gap-2 ${scanning ? 'opacity-70 cursor-not-allowed' : ''}`}
          >
            {scanning ? (
                <><Activity size={14} className="animate-spin" /> SCANNING...</>
            ) : (
                <><ShieldCheck size={14} /> TRIGGER FULL SCAN</>
            )}
          </button>
        </div>
      </div>
      
      {/* Scan Progress Bar */}
      {scanning && (
          <div className="h-2 w-full bg-slate-100 overflow-hidden relative border-t border-pnb-maroon/5 flex items-center">
              <div 
                className="absolute top-0 bottom-0 left-0 bg-gradient-to-r from-pnb-maroon to-[#d4114b] transition-all duration-500 ease-out z-10" 
                style={{width: `${progress || 0}%`}}
              >
                  <div className="absolute inset-0 bg-[linear-gradient(45deg,rgba(255,255,255,0.2)_25%,transparent_25%,transparent_50%,rgba(255,255,255,0.2)_50%,rgba(255,255,255,0.2)_75%,transparent_75%,transparent)] bg-[size:20px_20px] animate-[progress_2s_linear_infinite]"></div>
              </div>
              <div className="truncate text-[9px] font-black uppercase tracking-widest text-slate-800 px-6 z-20 flex items-center gap-2">
                  <Activity size={10} className="animate-spin text-pnb-maroon" />
                  {statusMessage || "Initializing Secure Protocol..."} ({progress || 0}%)
              </div>
          </div>
      )}
    </div>
  );
};

export default Header;
