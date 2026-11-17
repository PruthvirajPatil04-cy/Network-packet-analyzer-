import React from 'react';
import { Layers, Zap, HardDrive, ShieldAlert } from 'lucide-react';

export default function MetricCards({ stats, alertCount }) {
  const pps = stats?.pps || 0;
  const bps = stats?.bps || 0;
  const kbps = (bps / 1024).toFixed(1);
  const totalPackets = stats?.total_packets || 0;
  const totalMB = ((stats?.total_bytes || 0) / (1024 * 1024)).toFixed(2);
  const queueDepth = stats?.queue_depth || 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Total Packets */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
        <div>
          <p className="text-[11px] font-mono uppercase text-gray-400">Total Ingested</p>
          <h3 className="text-2xl font-bold text-white mt-1 font-mono">
            {totalPackets.toLocaleString()}
          </h3>
          <p className="text-[11px] text-gray-500 mt-0.5">{totalMB} MB total volume</p>
        </div>
        <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
          <Layers className="w-5 h-5" />
        </div>
      </div>

      {/* Real-time PPS */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
        <div>
          <p className="text-[11px] font-mono uppercase text-gray-400">Throughput (PPS)</p>
          <div className="flex items-baseline space-x-1.5 mt-1">
            <h3 className="text-2xl font-bold text-cyan-400 font-mono">{pps}</h3>
            <span className="text-xs text-gray-400 font-mono">pkts/sec</span>
          </div>
          <p className="text-[11px] text-gray-500 mt-0.5">Buffer depth: {queueDepth}</p>
        </div>
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
          <Zap className="w-5 h-5" />
        </div>
      </div>

      {/* Network Bandwidth */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
        <div>
          <p className="text-[11px] font-mono uppercase text-gray-400">Bandwidth</p>
          <div className="flex items-baseline space-x-1.5 mt-1">
            <h3 className="text-2xl font-bold text-emerald-400 font-mono">{kbps}</h3>
            <span className="text-xs text-gray-400 font-mono">KB/sec</span>
          </div>
          <p className="text-[11px] text-gray-500 mt-0.5">10s rolling rate</p>
        </div>
        <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <HardDrive className="w-5 h-5" />
        </div>
      </div>

      {/* Security Threat Alerts */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
        <div>
          <p className="text-[11px] font-mono uppercase text-gray-400">SOC Threat Alerts</p>
          <div className="flex items-baseline space-x-2 mt-1">
            <h3 className={`text-2xl font-bold font-mono ${alertCount > 0 ? 'text-rose-400' : 'text-gray-200'}`}>
              {alertCount}
            </h3>
            {alertCount > 0 && (
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">
                Action Req.
              </span>
            )}
          </div>
          <p className="text-[11px] text-gray-500 mt-0.5">Antigravity SOC Agent</p>
        </div>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
          alertCount > 0 
            ? 'bg-rose-500/10 border border-rose-500/30 text-rose-400'
            : 'bg-gray-800/40 border border-gray-700/40 text-gray-400'
        }`}>
          <ShieldAlert className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}
