import React from 'react';
import { Activity, ShieldAlert, Cpu, Radio, Terminal, Database } from 'lucide-react';

export default function Header({
  isConnected,
  activeClients,
  totalPackets,
  onOpenMetrics,
}) {
  return (
    <header className="border-b border-[#1b253b] bg-[#0c1220]/90 backdrop-blur sticky top-0 z-30 px-6 py-3.5">
      <div className="flex items-center justify-between">
        {/* Brand & Pipeline Flow */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Activity className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="font-bold text-base tracking-wide text-white">
                  CYBER-DEFENSE PACKET ANALYZER
                </h1>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                  v2.0 Pipeline
                </span>
              </div>
              <p className="text-xs text-gray-400 flex items-center space-x-1.5">
                <span>Capture (Scapy)</span>
                <span>→</span>
                <span>Stream (FastAPI/Redis)</span>
                <span>→</span>
                <span>SOC (Antigravity AI)</span>
                <span>→</span>
                <span className="text-cyan-400 font-medium">Dashboard</span>
              </p>
            </div>
          </div>
        </div>

        {/* Live Status Indicators & Actions */}
        <div className="flex items-center space-x-4 text-xs font-mono">
          {/* WebSocket Status */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#11192e] border border-[#1b253b]">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected
                  ? 'bg-emerald-400 shadow-[0_0_8px_#10b981]'
                  : 'bg-rose-500 animate-ping'
              }`}
            />
            <span className={isConnected ? 'text-emerald-400' : 'text-rose-400'}>
              {isConnected ? 'LIVE FEED CONNECTED' : 'RECONNECTING...'}
            </span>
          </div>

          {/* Active Clients */}
          <div className="hidden sm:flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#11192e] border border-[#1b253b] text-gray-300">
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            <span>Clients: {activeClients}</span>
          </div>

          {/* Prometheus Metrics Button */}
          <button
            onClick={onOpenMetrics}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-colors"
          >
            <Database className="w-3.5 h-3.5" />
            <span>/metrics</span>
          </button>
        </div>
      </div>
    </header>
  );
}
