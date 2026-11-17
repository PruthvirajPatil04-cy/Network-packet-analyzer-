"""
Tests for Pydantic data schemas.
"""

import pytest
from pydantic import ValidationError
from backend.models import (
    PacketMetadata, PacketBatch, StatsResponse, AlertModel, HealthResponse, TopTalker
)


def test_packet_metadata_valid():
    pkt = PacketMetadata(
        timestamp="12:00:00.123",
        source="192.168.1.10",
        destination="10.0.0.1",
        src_port=54321,
        dst_port=443,
        port=443,
        protocol="TCP",
        size=1500,
        flags="PA",
    )
    assert pkt.protocol == "TCP"
    assert pkt.size == 1500
    assert pkt.source == "192.168.1.10"


def test_packet_metadata_size_negative_rejected():
    with pytest.raises(ValidationError):
        PacketMetadata(
            timestamp="12:00:00.000",
            source="1.1.1.1",
            destination="2.2.2.2",
            size=-1,  # Negative size must fail ge=0 validation
        )


def test_packet_batch_serialization():
    batch = PacketBatch(
        agent_id="test-agent",
        sent_at=1700000000.0,
        packets=[
            PacketMetadata(
                timestamp="12:00:00.100",
                source="192.168.1.5",
                destination="10.0.0.1",
                protocol="UDP",
                size=128,
            )
        ]
    )
    data = batch.model_dump()
    assert data["agent_id"] == "test-agent"
    assert len(data["packets"]) == 1
    assert data["packets"][0]["protocol"] == "UDP"


def test_stats_response_defaults():
    stats = StatsResponse(
        pps=100.5,
        bps=50000.0,
        total_packets=1000,
        total_bytes=500000,
        top_sources=[TopTalker(ip="10.0.0.1", packet_count=500, byte_count=250000)],
    )
    assert stats.pps == 100.5
    assert stats.protocol_distribution["TCP"] == 0
    assert len(stats.top_sources) == 1


def test_alert_model():
    alert = AlertModel(
        id="alert-123",
        time="14:30:00",
        type="PORT SCAN",
        ip="192.168.1.99",
        detail="Scanned 25 ports in 3 seconds",
        severity="HIGH",
        timestamp_ms=1700000000000.0,
    )
    assert alert.type == "PORT SCAN"
    assert alert.severity == "HIGH"
