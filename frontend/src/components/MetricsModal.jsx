import React, { useState, useEffect } from 'react';
import { X, RefreshCw, Copy, Check } from 'lucide-react';

export default function MetricsModal({ isOpen, onClose }) {
  const [metricsText, setMetricsText] = useState('Loading metrics...');
  const [copied, setCopied] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchMetrics = async () => {
    setIsRefreshing(true);
    try {
      const resp = await fetch('/metrics');
      if (resp.ok) {
        const text = await resp.text();
        setMetricsText(text);
      } else {
        setMetricsText(`Error loading metrics: HTTP ${resp.status}`);
      }
    } catch (e) {
      setMetricsText(`Failed to connect to /metrics: ${e.message}`);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchMetrics();
    }
  }, [isOpen]);

  const handleCopy = () => {
    navigator.clipboard.writeText(metricsText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-[#0e1526] border border-[#23314f] rounded-xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col h-[550px]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-[#1e2a44] bg-[#0c1220] flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h3 className="text-xs font-mono font-bold uppercase text-white tracking-wider">
              Prometheus Observability (/metrics)
            </h3>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={fetchMetrics}
              disabled={isRefreshing}
              className="p-1.5 rounded-lg bg-[#151f33] text-gray-400 hover:text-white transition-colors"
              title="Refresh metrics"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={handleCopy}
              className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs font-mono hover:bg-cyan-500/20 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-[#151f33] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 p-4 overflow-auto font-mono text-[11px] text-gray-300 bg-[#090d17]">
          <pre className="whitespace-pre leading-relaxed select-text">{metricsText}</pre>
        </div>

        {/* Footer */}
        <div className="px-5 py-2.5 border-t border-[#1e2a44] bg-[#0c1220] text-[11px] font-mono text-gray-500 flex justify-between items-center">
          <span>Scraped by Prometheus server at :8000/metrics</span>
          <span className="text-cyan-400">P99 Latency / Drop Counter active</span>
        </div>
      </div>
    </div>
  );
}
