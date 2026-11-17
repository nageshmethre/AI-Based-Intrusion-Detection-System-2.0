"""Phase 3 Network Packet Capture & Flow Aggregation Verification Test."""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.capture.flow import FlowAggregator, NetworkFlow
from backend.app.capture.sniffer import PacketSniffer
from backend.app.ml.schema import FLOW_FEATURES
from scapy.all import IP, TCP, UDP, ICMP


def test_flow_aggregation_and_features():
    print("Testing bidirectional flow aggregation and CIC-IDS2017 feature extraction...")
    completed_flows = []
    
    def on_complete(flow_dict):
        completed_flows.append(flow_dict)

    aggregator = FlowAggregator(flow_timeout=2.0, on_flow_complete=on_complete)
    
    base_time = time.time()

    # Simulate Forward Packet 1 (SYN)
    aggregator.process_packet(
        src_ip="192.168.1.100",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        pkt_len=60,
        header_len=32,
        tcp_flags={"S": True},
        window_size=29200,
        timestamp=base_time
    )

    # Simulate Backward Packet 1 (SYN-ACK)
    aggregator.process_packet(
        src_ip="10.0.0.1",
        src_port=80,
        dst_ip="192.168.1.100",
        dst_port=54321,
        protocol="TCP",
        pkt_len=60,
        header_len=32,
        tcp_flags={"S": True, "A": True},
        window_size=28960,
        timestamp=base_time + 0.015
    )

    # Simulate Forward Packet 2 (ACK + Data GET)
    aggregator.process_packet(
        src_ip="192.168.1.100",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        pkt_len=450,
        header_len=32,
        tcp_flags={"A": True, "P": True},
        window_size=29200,
        timestamp=base_time + 0.025
    )

    # Simulate Backward Packet 2 (HTTP Response)
    aggregator.process_packet(
        src_ip="10.0.0.1",
        src_port=80,
        dst_ip="192.168.1.100",
        dst_port=54321,
        protocol="TCP",
        pkt_len=1460,
        header_len=32,
        tcp_flags={"A": True, "P": True},
        window_size=28960,
        timestamp=base_time + 0.040
    )

    # Simulate Forward Packet 3 (FIN) -> should close and emit flow
    aggregator.process_packet(
        src_ip="192.168.1.100",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        pkt_len=54,
        header_len=32,
        tcp_flags={"F": True, "A": True},
        window_size=29200,
        timestamp=base_time + 0.050
    )

    assert len(completed_flows) == 1, f"Expected 1 completed flow, got {len(completed_flows)}"
    flow = completed_flows[0]

    # Verify flow identity
    assert flow["src_ip"] == "192.168.1.100"
    assert flow["dst_ip"] == "10.0.0.1"
    assert flow["src_port"] == 54321
    assert flow["destination_port"] == 80.0
    assert flow["protocol"] == "TCP"

    # Verify flow counters
    assert flow["total_fwd_packets"] == 3.0
    assert flow["total_bwd_packets"] == 2.0
    assert flow["total_fwd_len"] == 564.0  # 60 + 450 + 54
    assert flow["total_bwd_len"] == 1520.0 # 60 + 1460

    # Verify that all 40 FLOW_FEATURES exist and are non-null floats
    for feature in FLOW_FEATURES:
        assert feature in flow, f"Missing feature in flow extraction: {feature}"
        assert isinstance(flow[feature], (int, float)), f"Feature {feature} is not numeric: {type(flow[feature])}"

    print("✓ Flow aggregation and 40-feature schema extraction validated successfully!")


def test_packet_sniffer_pipeline():
    print("Testing PacketSniffer ingestion with Scapy synthetic packets...")
    captured_packets = []

    def on_packet(pkt_dict):
        captured_packets.append(pkt_dict)

    sniffer = PacketSniffer(packet_callback=on_packet)

    # Create synthetic Scapy packets
    p_tcp = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=12345, dport=80, flags="S", window=65535)
    p_udp = IP(src="127.0.0.1", dst="1.1.1.1") / UDP(sport=5353, dport=53)
    p_icmp = IP(src="192.168.1.1", dst="192.168.1.254") / ICMP()

    # Parse through sniffer
    res1 = sniffer.parse_packet(p_tcp)
    res2 = sniffer.parse_packet(p_udp)
    res3 = sniffer.parse_packet(p_icmp)

    assert res1["protocol"] == "TCP"
    assert res1["dst_port"] == 80
    assert res1["tcp_flags"]["S"] is True
    assert res1["window_size"] == 65535

    assert res2["protocol"] == "UDP"
    assert res2["dst_port"] == 53

    assert res3["protocol"] == "ICMP"
    assert res3["src_ip"] == "192.168.1.1"

    assert len(captured_packets) == 3
    print("✓ Packet parsing for TCP, UDP, ICMP verified successfully!")


if __name__ == "__main__":
    test_flow_aggregation_and_features()
    test_packet_sniffer_pipeline()
    print("\n--- Phase 3 Verification Passed Successfully! ---")
