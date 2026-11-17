import React, { useState, useMemo } from 'react';
import { Search, Filter, Play, Pause, ArrowDown, ChevronRight, X } from 'lucide-react';

const PROTO_CLASSES = {
  TCP: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  UDP: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  ICMP: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  OTHER: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
};

export default function PacketTable({ packets, isPaused, onTogglePause }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [selectedPacket, setSelectedPacket] = useState(null);

  // Filtered packets
  const filtered = useMemo(() => {
    return packets.filter((p) => {
      if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) {
        return false;
      }
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchSrc = p.source?.toLowerCase().includes(term);
        const matchDst = p.destination?.toLowerCase().includes(term);
        const matchPort = String(p.port).includes(term) || String(p.dst_port).includes(term);
        return matchSrc || matchDst || matchPort;
      }
      return true;
    });
  }, [packets, protocolFilter, searchTerm]);

  return (
    <div className="bg-[#101728] border border-[#1e2a44] rounded-xl overflow-hidden flex flex-col h-[520px]">
      {/* Table Toolbar */}
      <div className="px-4 py-3 border-b border-[#1e2a44] bg-[#0d1424] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-2">
          <h3 className="text-xs font-mono uppercase text-gray-200 font-semibold tracking-wider flex items-center space-x-1.5">
            <span>Live Capture Feed</span>
            <span className="text-[10px] text-gray-500 font-normal">
              ({filtered.length} visible / {packets.length} buffered)
            </span>
          </h3>
        </div>

        {/* Filters & Controls */}
        <div className="flex items-center space-x-2.5">
          {/* Text Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter IP or port..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#151f33] border border-[#23314f] text-xs font-mono rounded-lg pl-8 pr-3 py-1 text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 w-36 sm:w-48"
            />
          </div>

          {/* Protocol Dropdown */}
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="bg-[#151f33] border border-[#23314f] text-xs font-mono rounded-lg px-2.5 py-1 text-gray-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="OTHER">OTHER</option>
          </select>

          {/* Pause / Resume Button */}
          <button
            onClick={onTogglePause}
            className={`flex items-center space-x-1 px-3 py-1 rounded-lg text-xs font-mono border transition-colors ${
              isPaused
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
                : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/20'
            }`}
          >
            {isPaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {/* Table Content */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left font-mono text-xs">
          <thead className="bg-[#0b101c] text-gray-400 uppercase text-[10px] sticky top-0 z-10 border-b border-[#1b253b]">
            <tr>
              <th className="px-4 py-2.5">Time</th>
              <th className="px-4 py-2.5">Source IP</th>
              <th className="px-4 py-2.5">Destination IP</th>
              <th className="px-4 py-2.5">Proto</th>
              <th className="px-4 py-2.5">Port</th>
              <th className="px-4 py-2.5">Bytes</th>
              <th className="px-4 py-2.5">Flags</th>
              <th className="px-4 py-2.5 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#182339]">
            {filtered.length > 0 ? (
              filtered.map((pkt, idx) => (
                <tr
                  key={`${pkt.timestamp}-${idx}`}
                  onClick={() => setSelectedPacket(pkt)}
                  className="hover:bg-cyan-950/20 cursor-pointer transition-colors group"
                >
                  <td className="px-4 py-2 text-gray-400 text-[11px] whitespace-nowrap">
                    {pkt.timestamp}
                  </td>
                  <td className="px-4 py-2 text-gray-200 font-medium whitespace-nowrap">
                    {pkt.source}
                  </td>
                  <td className="px-4 py-2 text-gray-300 whitespace-nowrap">
                    {pkt.destination}
                  </td>
                  <td className="px-4 py-2 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        PROTO_CLASSES[pkt.protocol] || PROTO_CLASSES.OTHER
                      }`}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-400 whitespace-nowrap">
                    {pkt.dst_port || pkt.port || '-'}
                  </td>
                  <td className="px-4 py-2 text-gray-300 whitespace-nowrap">
                    {pkt.size} B
                  </td>
                  <td className="px-4 py-2 text-gray-400 text-[11px] whitespace-nowrap">
                    {pkt.flags || '-'}
                  </td>
                  <td className="px-4 py-2 text-right whitespace-nowrap text-gray-500 group-hover:text-cyan-400">
                    <ChevronRight className="w-3.5 h-3.5 inline" />
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={8} className="py-12 text-center text-gray-500 font-mono">
                  No packets match the filter criteria.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Packet Inspector Drawer */}
      {selectedPacket && (
        <div className="border-t border-[#23314f] bg-[#0c1322] p-4 text-xs font-mono">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <span className="text-cyan-400 font-bold uppercase">Packet Inspector</span>
              <span className="text-gray-500">|</span>
              <span className="text-gray-300">{selectedPacket.timestamp}</span>
            </div>
            <button
              onClick={() => setSelectedPacket(null)}
              className="text-gray-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#11192e] p-3 rounded-lg border border-[#1b253b]">
            <div>
              <span className="text-[10px] uppercase text-gray-500 block">Source IP:Port</span>
              <span className="text-white font-medium">
                {selectedPacket.source}:{selectedPacket.src_port || '-'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase text-gray-500 block">Destination IP:Port</span>
              <span className="text-white font-medium">
                {selectedPacket.destination}:{selectedPacket.dst_port || selectedPacket.port || '-'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase text-gray-500 block">Protocol & Size</span>
              <span className="text-cyan-400 font-medium">
                {selectedPacket.protocol} ({selectedPacket.size} bytes)
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase text-gray-500 block">TCP Flags</span>
              <span className="text-emerald-400 font-medium">
                {selectedPacket.flags || 'None'}
              </span>
            </div>
          </div>
          <p className="text-[10px] text-gray-500 mt-2 italic">
            * Payload data excluded: Platform strictly processes L3/L4 metadata in compliance with privacy guidelines.
          </p>
        </div>
      )}
    </div>
  );
}
