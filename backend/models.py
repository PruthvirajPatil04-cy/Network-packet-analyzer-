"""Pydantic data models for the Network Packet Analyzer platform."""

from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PacketMetadata(BaseModel):
    """
    L3/L4 packet metadata schema.
    Strictly excludes payload data for privacy and security compliance.
    """
    timestamp: str = Field(description="Capture timestamp in HH:MM:SS.mmm format")
    source: str = Field(description="Source IPv4/IPv6 address")
    destination: str = Field(description="Destination IPv4/IPv6 address")
    src_port: Optional[int] = Field(default=None, description="Source port number")
    dst_port: Optional[int] = Field(default=None, description="Destination port number")
    port: Any = Field(default="-", description="Primary destination port or dash for display")
    protocol: str = Field(default="OTHER", description="L4 protocol name: TCP, UDP, ICMP, OTHER")
    size: int = Field(default=0, ge=0, description="Packet size in bytes")
    flags: str = Field(default="-", description="TCP flags summary, e.g. 'S', 'PA', 'FPU'")


class PacketBatch(BaseModel):
    """Batch of packet metadata produced by capture agents."""
    agent_id: str = Field(default="agent-default", description="Identifier of the capture agent")
    sent_at: float = Field(description="Epoch timestamp when the batch was dispatched")
    packets: List[PacketMetadata] = Field(default_factory=list, description="Array of packet records")


class TopTalker(BaseModel):
    """Traffic statistics for a single host."""
    ip: str
    packet_count: int
    byte_count: int


class StatsResponse(BaseModel):
    """Rolling statistical aggregates computed over a sliding time window."""
    pps: float = Field(default=0.0, description="Packets per second over window")
    bps: float = Field(default=0.0, description="Bytes per second over window")
    total_packets: int = Field(default=0, description="Total packets ingested since boot")
    total_bytes: int = Field(default=0, description="Total bytes ingested since boot")
    protocol_distribution: Dict[str, int] = Field(
        default_factory=lambda: {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
    )
    top_sources: List[TopTalker] = Field(default_factory=list)
    top_destinations: List[TopTalker] = Field(default_factory=list)
    queue_depth: int = Field(default=0, description="Current buffered packets in memory")
    packets_dropped: int = Field(default=0, description="Total packets dropped by backpressure")
    window_seconds: float = Field(default=10.0, description="Aggregation window in seconds")


class AlertModel(BaseModel):
    """Security alert emitted by SOC detection rules or AI Agent."""
    id: str = Field(description="Unique alert identifier")
    time: str = Field(description="Timestamp formatted string")
    type: str = Field(description="Attack categorization, e.g. 'DoS / FLOOD', 'PORT SCAN'")
    ip: str = Field(description="Offending source IP address")
    detail: str = Field(description="Detailed forensic observation")
    severity: str = Field(default="HIGH", description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: Optional[int] = Field(default=85, description="Confidence percentage 0-100")
    timestamp_ms: float = Field(description="Epoch millisecond timestamp")
    recommendation: Optional[str] = Field(default=None, description="Suggested mitigation action")


class HealthResponse(BaseModel):
    """Health and readiness diagnostic payload."""
    status: str = Field(default="healthy")
    uptime_seconds: float
    queue_depth: int
    active_ws_clients: int
    redis_connected: bool
    version: str = "2.0.0"
