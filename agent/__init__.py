"""
Agent package for Network Packet Analyzer.
Includes PacketCaptureAgent (Capture Service) and SOCAgentConsumer (SOC Analysis Service).
Maintains full backward compatibility with root agent.py exports.
"""

from agent.capture import (
    PacketCaptureAgent,
    BoundedPacketQueue,
    extract_metadata,
    start_capture,
)
from agent.soc_agent import (
    SOCAgentConsumer,
    PLAYBOOKS,
)
from agent.service import (
    AGENT,
    start_agent,
    AgentService,
    THREAT_INTEL_DB,
    MEMORY_FILE,
    generate_attack_narrative,
)

__all__ = [
    "PacketCaptureAgent",
    "BoundedPacketQueue",
    "extract_metadata",
    "start_capture",
    "SOCAgentConsumer",
    "PLAYBOOKS",
    "AGENT",
    "start_agent",
    "AgentService",
    "THREAT_INTEL_DB",
    "MEMORY_FILE",
    "generate_attack_narrative",
]
