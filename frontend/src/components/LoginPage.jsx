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
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center relative overflow-hidden text-slate-100">

      {/* Background grid pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(99,102,241,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(99,102,241,0.05)_1px,transparent_1px)] bg-[size:40px_40px] pointer-events-none" />

      {/* Top accent bar */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 via-cyan-400 to-indigo-500" />

      <div className="w-full max-w-md px-4 relative z-10">

        {/* Logo block */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 text-cyan-400 shadow-2xl shadow-indigo-500/20 mb-4 rotate-3 hover:rotate-0 transition-transform duration-500">
            <ShieldCheck size={36} />
          </div>
          <h1 className="text-3xl font-black text-white tracking-tighter flex items-center justify-center gap-2 font-mono">
            Q-GUARDIAN
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block animate-pulse shadow-[0_0_10px_#06B6D4]" />
          </h1>
          <p className="text-slate-400 text-xs font-bold tracking-widest uppercase mt-1">
            Post-Quantum CBOM & Cyber Risk Platform
          </p>
          <div className="mt-3 inline-block bg-slate-900 border border-slate-800 px-4 py-1 rounded-full text-[10px] font-black text-cyan-400 uppercase tracking-widest font-mono">
            Critical Infrastructure · Level 4 Authorization
          </div>
        </div>

        {/* Login card */}
        <div className="bg-slate-900/90 rounded-2xl shadow-2xl border border-slate-800 overflow-hidden backdrop-blur-xl">
          <div className="bg-indigo-950/60 px-8 py-5 border-b border-indigo-500/20">
            <h2 className="text-indigo-200 font-black text-sm tracking-widest uppercase flex items-center gap-2 font-mono">
              <Lock size={16} className="text-cyan-400" />
              SECURE AUTHENTICATION REQUIRED
            </h2>
            <p className="text-slate-400 text-[10px] mt-1 font-semibold">
              Authorized security analysts and compliance officers only.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="px-8 py-8 space-y-5">

            {/* Error alert */}
            {authError && (
              <div className="flex items-start gap-3 bg-red-950/50 border border-red-500/30 rounded-lg p-4 animate-in slide-in-from-top-2 duration-300">
                <AlertCircle size={16} className="text-red-400 mt-0.5 shrink-0" />
                <p className="text-red-300 text-xs font-semibold">{authError}</p>
              </div>
            )}

            {/* Username */}
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1.5 font-mono">
                <User size={12} /> Username
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full px-4 py-3 rounded-lg border border-slate-800 bg-slate-950 text-slate-100 text-sm font-semibold focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono placeholder:text-slate-600"
              />
            </div>

            {/* Password */}
            <div className="space-y-2">
              <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-1.5 font-mono">
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
                  placeholder="Enter password"
                  className="w-full px-4 py-3 pr-12 rounded-lg border border-slate-800 bg-slate-950 text-slate-100 text-sm font-semibold focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono placeholder:text-slate-600"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
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
              className="w-full py-3.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-black text-sm uppercase tracking-widest transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30"
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
            <div className="border-t border-slate-800 pt-4 flex items-center justify-between font-mono">
              <div className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Quantum Risk Operations Console</div>
              <div className="text-[9px] text-indigo-400 font-bold uppercase tracking-widest">Q-GUARDIAN v2.0</div>
            </div>
          </div>
        </div>

        {/* Trial Credentials Hint */}
        <div className="mt-4 p-3 bg-slate-900 border border-slate-800 rounded-lg text-center font-mono">
          <p className="text-[10px] font-black text-cyan-400 uppercase tracking-widest mb-1">Demo Credentials</p>
          <p className="text-[11px] text-slate-300 font-semibold">
            User: <span className="text-white bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">qguardian_admin</span> · 
            Pass: <span className="text-white bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">QGuardian@2026</span>
          </p>
        </div>
      </div>

      {/* Bottom accent bar */}
      <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 via-cyan-400 to-indigo-500" />
    </div>
  );
};

export default LoginPage;
