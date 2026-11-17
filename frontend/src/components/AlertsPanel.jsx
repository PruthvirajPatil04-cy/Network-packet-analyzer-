import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, Sparkles, Clock } from 'lucide-react';

export default function AlertsPanel({ alerts }) {
  return (
    <div className="bg-[#101728] border border-[#1e2a44] rounded-xl overflow-hidden flex flex-col h-[520px]">
      <div className="px-4 py-3 border-b border-[#1e2a44] bg-[#0d1424] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <h3 className="text-xs font-mono uppercase text-gray-200 font-semibold tracking-wider">
            SOC Threat Intelligence
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
          {alerts.length} Incidents
        </span>
      </div>

      <div className="flex-1 overflow-auto p-3 space-y-2.5">
        {alerts.length > 0 ? (
          alerts.slice().reverse().map((alert) => (
            <div
              key={alert.id || `${alert.time}-${alert.ip}`}
              className="bg-[#131b2e] border border-rose-500/20 rounded-lg p-3 hover:border-rose-500/40 transition-colors"
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] font-mono font-bold text-rose-400 tracking-wide flex items-center space-x-1">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>{alert.type}</span>
                </span>
                <span className="text-[10px] font-mono text-gray-400 flex items-center space-x-1">
                  <Clock className="w-3 h-3 text-gray-500" />
                  <span>{alert.time}</span>
                </span>
              </div>

              <div className="text-xs font-mono text-gray-200 mb-1.5">
                Target IP: <span className="text-white font-semibold">{alert.ip}</span>
              </div>

              <p className="text-[11px] font-mono text-gray-400 bg-[#0d1322] p-2 rounded border border-[#1d273d] mb-2">
                {alert.detail}
              </p>

              {alert.recommendation && (
                <div className="flex items-start space-x-1.5 text-[11px] font-mono text-cyan-300 bg-cyan-950/30 border border-cyan-800/40 p-2 rounded">
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-cyan-400 block text-[10px] uppercase">
                      AI SOC Recommendation:
                    </span>
                    <span>{alert.recommendation}</span>
                  </div>
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center p-6 text-gray-500 font-mono">
            <ShieldCheck className="w-10 h-10 text-emerald-500/50 mb-2" />
            <p className="text-xs text-gray-300 font-semibold">Clean Network Traffic</p>
            <p className="text-[11px] text-gray-500 mt-1 max-w-xs">
              Autonomous SOC Agent is actively monitoring ingress packets. No intrusive anomalies detected.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
