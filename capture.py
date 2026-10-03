"""Packet capture interface."""

import datetime
from typing import List, Dict, Any, Optional
from scapy.all import sniff, IP, TCP, UDP, ICMP
from packet_buffer import PacketSink

def _parse_packet(pkt: Any) -> Dict[str, Any]:
    """Parses a Scapy packet into a dictionary with 7 required keys."""
    # Ensure it's an IP packet to extract src/dst
    if IP not in pkt:
        return {}
        
    protocol = "OTHER"
    if TCP in pkt:
        protocol = "TCP"
    elif UDP in pkt:
        protocol = "UDP"
    elif ICMP in pkt:
        protocol = "ICMP"
        
    flags = str(pkt[TCP].flags) if TCP in pkt else "-"
    port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else "-")
    
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    return {
        "timestamp": timestamp,
        "source": pkt[IP].src,
        "destination": pkt[IP].dst,
        "protocol": protocol,
        "size": len(pkt),
        "flags": flags,
        "port": port
    }

def start_capture(buffer: PacketSink, interface: Optional[str] = None, bpf_filter: str = "ip") -> None:
    """Starts a live packet capture and appends parsed packets to the buffer."""
    def callback(pkt: Any) -> None:
        entry = _parse_packet(pkt)
        if entry:
            # INVARIANT: callers must read via buffer.snapshot(), never index
            # the raw container. See packet_buffer.py.
            buffer.append(entry)
            
    kwargs = {"prn": callback, "store": False, "filter": bpf_filter}
    if interface:
        kwargs["iface"] = interface
        
    try:
        sniff(**kwargs)
    except (PermissionError, OSError, RuntimeError) as e:
        print(f"Capture error ({e}). Please use simulator.py instead if you lack capture privileges.")

if __name__ == "__main__":
    test_buffer: List[Dict[str, Any]] = []
    
    def callback(pkt: Any) -> None:
        entry = _parse_packet(pkt)
        if entry:
            test_buffer.append(entry)
            
    print("Testing capture (listening for up to 5 packets or 10 seconds)...")
    try:
        sniff(prn=callback, store=False, filter="ip", count=5, timeout=10)
        print("Capture finished. Buffer contents:")
        for item in test_buffer:
            print(item)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except (PermissionError, OSError, RuntimeError) as e:
        print(f"Capture error ({e}). Please use simulator.py instead if you lack capture privileges.")
