import React, { useState } from 'react';
import { ShieldCheck, Lock, User, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const LoginPage = () => {
  const { login, loggingIn, authError } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await login(username, password);
  };

  return (
    <div className="min-h-screen bg-[#f8fafc] flex flex-col items-center justify-center relative overflow-hidden">

      {/* Background grid pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(162,12,57,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(162,12,57,0.03)_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />

      {/* Top accent bar */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-pnb-maroon via-pnb-gold to-pnb-maroon" />

      <div className="w-full max-w-md px-4 relative z-10">

        {/* Logo block */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-pnb-maroon shadow-2xl shadow-pnb-maroon/30 mb-4 rotate-3 hover:rotate-0 transition-transform duration-500">
            <ShieldCheck size={34} className="text-pnb-gold" />
          </div>
          <h1 className="text-3xl font-black text-pnb-maroon tracking-tighter flex items-center justify-center gap-2">
            Q-GUARDIAN
            <span className="w-2.5 h-2.5 rounded-full bg-pnb-gold inline-block animate-pulse shadow-[0_0_8px_#FBBC09]" />
          </h1>
          <p className="text-slate-500 text-xs font-bold tracking-widest uppercase mt-1">
            Quantum Transition Intelligence Platform
          </p>
          <div className="mt-3 inline-block bg-slate-100 px-4 py-1 rounded-full text-[10px] font-black text-slate-500 uppercase tracking-widest">
            Punjab National Bank · Restricted Access
          </div>
        </div>

        {/* Login card */}
        <div className="bg-white rounded-2xl shadow-2xl shadow-slate-200 border border-slate-100 overflow-hidden">
          <div className="bg-pnb-maroon px-8 py-5 border-b-4 border-pnb-gold">
            <h2 className="text-white font-black text-sm tracking-widest uppercase flex items-center gap-2">
              <Lock size={16} className="text-pnb-gold" />
              SECURE AUTHENTICATION REQUIRED
            </h2>
            <p className="text-white/60 text-[10px] mt-1 font-bold">
              Access is restricted to authorised PNB security personnel only.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="px-8 py-8 space-y-5">

            {/* Error alert */}
            {authError && (
              <div className="flex items-start gap-3 bg-red-50 border border-red-200 rounded-lg p-4 animate-in slide-in-from-top-2 duration-300">
                <AlertCircle size={16} className="text-red-500 mt-0.5 shrink-0" />
                <p className="text-red-700 text-xs font-bold">{authError}</p>
              </div>
            )}

            {/* Username */}
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
                <User size={12} /> Username
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                className="w-full px-4 py-3 rounded-lg border-2 border-slate-200 bg-slate-50 text-slate-800 text-sm font-semibold focus:outline-none focus:border-pnb-maroon focus:bg-white transition-all placeholder:font-normal placeholder:text-slate-400"
              />
            </div>

            {/* Password */}
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
                <Lock size={12} /> Password
              </label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full px-4 py-3 pr-12 rounded-lg border-2 border-slate-200 bg-slate-50 text-slate-800 text-sm font-semibold focus:outline-none focus:border-pnb-maroon focus:bg-white transition-all placeholder:font-normal placeholder:text-slate-400"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-pnb-maroon transition-colors"
                >
                  {showPw ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              id="login-submit"
              type="submit"
              disabled={loggingIn || !username || !password}
              className="w-full py-3.5 rounded-lg bg-pnb-maroon text-white font-black text-sm uppercase tracking-widest hover:bg-[#8a0a30] active:scale-[0.98] transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-pnb-maroon/30"
            >
              {loggingIn ? (
                <>
                  <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  AUTHENTICATING...
                </>
              ) : (
                <>
                  <ShieldCheck size={16} />
                  ACCESS PLATFORM
                </>
              )}
            </button>
          </form>

          <div className="px-8 pb-6">
            <div className="border-t border-slate-100 pt-4 flex items-center justify-between">
              <div className="text-[9px] text-slate-400 font-bold uppercase tracking-widest">Quantum Risk Operations Console</div>
              <div className="text-[9px] text-slate-400 font-bold uppercase tracking-widest">Q-GUARDIAN v2.0</div>
            </div>
          </div>
        </div>

        {/* Trial Credentials Hint */}
        <div className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-lg text-center animate-in fade-in slide-in-from-bottom-2 duration-700">
          <p className="text-[10px] font-black text-amber-700 uppercase tracking-widest mb-1">Trial Credentials</p>
          <p className="text-[11px] text-amber-800 font-bold">
            User: <span className="font-mono bg-amber-100 px-1 rounded">qguardian_admin</span> · 
            Pass: <span className="font-mono bg-amber-100 px-1 rounded">QGuardian@2026</span>
          </p>
        </div>
      </div>

      {/* Bottom accent bar */}
      <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-pnb-maroon via-pnb-gold to-pnb-maroon" />
    </div>
  );
};

export default LoginPage;
