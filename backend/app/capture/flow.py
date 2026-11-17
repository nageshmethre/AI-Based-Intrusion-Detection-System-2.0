"""Bidirectional Network Flow Aggregation & Feature Computation Engine.

Aggregates individual Scapy packets into network flows and extracts the exact 40
statistical flow features required by the CIC-IDS2017 machine learning model.
"""

import time
import math
import threading
from typing import Dict, Tuple, Optional, List, Callable, Any
from dataclasses import dataclass, field
from backend.app.ml.schema import FLOW_FEATURES


def get_canonical_flow_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
) -> Tuple[Tuple[str, int, str, int, str], bool]:
    """
    Returns canonical bidirectional 5-tuple key and is_forward boolean.
    Forward is defined by the originator of the first packet in the flow.
    """
    forward_tuple = (src_ip, src_port, dst_ip, dst_port, protocol)
    reverse_tuple = (dst_ip, dst_port, src_ip, src_port, protocol)
    return forward_tuple, reverse_tuple


class NetworkFlow:
    """Represents a single active bidirectional network flow between two endpoints."""

    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str, start_time: float):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time: float = start_time
        self.last_seen: float = start_time

        # Packet and byte counters
        self.fwd_packets: int = 0
        self.bwd_packets: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0

        # Packet lengths
        self.fwd_pkt_lens: List[int] = []
        self.bwd_pkt_lens: List[int] = []

        # Timestamps for IAT (Inter-arrival time in microseconds)
        self.timestamps: List[float] = []
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []

        # Header lengths
        self.fwd_header_len: int = 0
        self.bwd_header_len: int = 0

        # TCP Flags
        self.fin_cnt: int = 0
        self.syn_cnt: int = 0
        self.rst_cnt: int = 0
        self.psh_cnt: int = 0
        self.ack_cnt: int = 0
        self.urg_cnt: int = 0

        # TCP Window sizes
        self.init_win_bytes_fwd: float = -1.0
        self.init_win_bytes_bwd: float = -1.0

        self.is_closed: bool = False

    def add_packet(
        self,
        is_forward: bool,
        pkt_len: int,
        header_len: int,
        tcp_flags: Dict[str, bool],
        window_size: Optional[int],
        timestamp: float
    ):
        """Update flow metrics with a new packet."""
        self.last_seen = timestamp
        self.timestamps.append(timestamp)

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_lens.append(pkt_len)
            self.fwd_header_len += header_len
            self.fwd_timestamps.append(timestamp)
            if self.init_win_bytes_fwd == -1.0 and window_size is not None:
                self.init_win_bytes_fwd = float(window_size)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_pkt_lens.append(pkt_len)
            self.bwd_header_len += header_len
            self.bwd_timestamps.append(timestamp)
            if self.init_win_bytes_bwd == -1.0 and window_size is not None:
                self.init_win_bytes_bwd = float(window_size)

        # Flag accumulation
        if tcp_flags:
            if tcp_flags.get("F"):
                self.fin_cnt += 1
                self.is_closed = True
            if tcp_flags.get("S"):
                self.syn_cnt += 1
            if tcp_flags.get("R"):
                self.rst_cnt += 1
                self.is_closed = True
            if tcp_flags.get("P"):
                self.psh_cnt += 1
            if tcp_flags.get("A"):
                self.ack_cnt += 1
            if tcp_flags.get("U"):
                self.urg_cnt += 1

    def _calc_stats(self, values: List[float]) -> Tuple[float, float, float, float]:
        """Compute min, max, mean, standard deviation safely."""
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        v_min = float(min(values))
        v_max = float(max(values))
        v_mean = float(sum(values) / len(values))
        if len(values) > 1:
            variance = sum((x - v_mean) ** 2 for x in values) / (len(values) - 1)
            v_std = float(math.sqrt(max(0.0, variance)))
        else:
            v_std = 0.0
        return v_min, v_max, v_mean, v_std

    def _calc_iats(self, ts_list: List[float]) -> List[float]:
        """Calculate inter-arrival times in microseconds."""
        if len(ts_list) < 2:
            return []
        return [(ts_list[i] - ts_list[i - 1]) * 1e6 for i in range(1, len(ts_list))]

    def to_feature_dict(self) -> Dict[str, Any]:
        """
        Calculates all 40 statistical flow features matching CIC-IDS2017 schema.
        Also returns metadata (IPs, ports, protocol, timestamps).
        """
        # Duration in microseconds
        duration_us = max(0.0, (self.last_seen - self.start_time) * 1e6)
        dur_sec = max(duration_us / 1e6, 0.000001)

        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        fwd_min, fwd_max, fwd_mean, fwd_std = self._calc_stats(self.fwd_pkt_lens)
        bwd_min, bwd_max, bwd_mean, bwd_std = self._calc_stats(self.bwd_pkt_lens)
        all_min, all_max, all_mean, all_std = self._calc_stats(self.fwd_pkt_lens + self.bwd_pkt_lens)

        # IATs
        flow_iats = self._calc_iats(self.timestamps)
        iat_min, iat_max, iat_mean, iat_std = self._calc_stats(flow_iats)

        fwd_iats = self._calc_iats(self.fwd_timestamps)
        fwd_iat_total = sum(fwd_iats) if fwd_iats else 0.0
        fwd_iat_mean = (fwd_iat_total / len(fwd_iats)) if fwd_iats else 0.0

        bwd_iats = self._calc_iats(self.bwd_timestamps)
        bwd_iat_total = sum(bwd_iats) if bwd_iats else 0.0
        bwd_iat_mean = (bwd_iat_total / len(bwd_iats)) if bwd_iats else 0.0

        down_up_ratio = self.bwd_packets / max(self.fwd_packets, 1)
        avg_pkt_size = total_bytes / max(total_pkts, 1)

        features = {
            "destination_port": float(self.dst_port),
            "flow_duration": float(duration_us),
            "total_fwd_packets": float(self.fwd_packets),
            "total_bwd_packets": float(self.bwd_packets),
            "total_fwd_len": float(self.fwd_bytes),
            "total_bwd_len": float(self.bwd_bytes),
            "fwd_pkt_len_max": fwd_max,
            "fwd_pkt_len_min": fwd_min,
            "fwd_pkt_len_mean": fwd_mean,
            "fwd_pkt_len_std": fwd_std,
            "bwd_pkt_len_max": bwd_max,
            "bwd_pkt_len_min": bwd_min,
            "bwd_pkt_len_mean": bwd_mean,
            "bwd_pkt_len_std": bwd_std,
            "flow_bytes_per_sec": float(total_bytes / dur_sec),
            "flow_pkts_per_sec": float(total_pkts / dur_sec),
            "flow_iat_mean": iat_mean,
            "flow_iat_std": iat_std,
            "flow_iat_max": iat_max,
            "flow_iat_min": iat_min,
            "fwd_iat_total": fwd_iat_total,
            "fwd_iat_mean": fwd_iat_mean,
            "bwd_iat_total": bwd_iat_total,
            "bwd_iat_mean": bwd_iat_mean,
            "fwd_header_len": float(self.fwd_header_len),
            "bwd_header_len": float(self.bwd_header_len),
            "fwd_pkts_per_sec": float(self.fwd_packets / dur_sec),
            "bwd_pkts_per_sec": float(self.bwd_packets / dur_sec),
            "pkt_len_min": all_min,
            "pkt_len_max": all_max,
            "pkt_len_mean": all_mean,
            "pkt_len_std": all_std,
            "fin_flag_cnt": float(self.fin_cnt),
            "syn_flag_cnt": float(self.syn_cnt),
            "rst_flag_cnt": float(self.rst_cnt),
            "psh_flag_cnt": float(self.psh_cnt),
            "ack_flag_cnt": float(self.ack_cnt),
            "urg_flag_cnt": float(self.urg_cnt),
            "down_up_ratio": float(down_up_ratio),
            "avg_pkt_size": float(avg_pkt_size),
            "init_win_bytes_fwd": float(self.init_win_bytes_fwd),
            "init_win_bytes_bwd": float(self.init_win_bytes_bwd),
            # Metadata
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "total_packets": total_pkts,
            "total_bytes": total_bytes
        }
        return features


class FlowAggregator:
    """Thread-safe flow aggregator for live packet capture."""

    def __init__(self, flow_timeout: float = 5.0, on_flow_complete: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.flow_timeout = flow_timeout
        self.on_flow_complete = on_flow_complete
        self.active_flows: Dict[Tuple[str, int, str, int, str], NetworkFlow] = {}
        self.lock = threading.Lock()
        self.total_packets_seen: int = 0
        self.total_flows_completed: int = 0

    def process_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        pkt_len: int,
        header_len: int,
        tcp_flags: Dict[str, bool],
        window_size: Optional[int],
        timestamp: Optional[float] = None
    ):
        """Ingest a packet and update or create its flow."""
        now = timestamp if timestamp is not None else time.time()
        fwd_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        bwd_key = (dst_ip, dst_port, src_ip, src_port, protocol)

        completed_flow_data = None

        with self.lock:
            self.total_packets_seen += 1
            if fwd_key in self.active_flows:
                flow = self.active_flows[fwd_key]
                flow.add_packet(True, pkt_len, header_len, tcp_flags, window_size, now)
                if flow.is_closed:
                    completed_flow_data = flow.to_feature_dict()
                    del self.active_flows[fwd_key]
                    self.total_flows_completed += 1

            elif bwd_key in self.active_flows:
                flow = self.active_flows[bwd_key]
                flow.add_packet(False, pkt_len, header_len, tcp_flags, window_size, now)
                if flow.is_closed:
                    completed_flow_data = flow.to_feature_dict()
                    del self.active_flows[bwd_key]
                    self.total_flows_completed += 1

            else:
                flow = NetworkFlow(src_ip, src_port, dst_ip, dst_port, protocol, now)
                flow.add_packet(True, pkt_len, header_len, tcp_flags, window_size, now)
                if flow.is_closed:
                    completed_flow_data = flow.to_feature_dict()
                    self.total_flows_completed += 1
                else:
                    self.active_flows[fwd_key] = flow

        if completed_flow_data and self.on_flow_complete:
            self.on_flow_complete(completed_flow_data)

    def sweep_expired(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Flush flows that have exceeded flow_timeout."""
        now = current_time if current_time is not None else time.time()
        expired_flows: List[Dict[str, Any]] = []

        with self.lock:
            keys_to_remove = []
            for key, flow in self.active_flows.items():
                if (now - flow.last_seen) >= self.flow_timeout:
                    keys_to_remove.append(key)
                    expired_flows.append(flow.to_feature_dict())

            for key in keys_to_remove:
                del self.active_flows[key]
                self.total_flows_completed += 1

        if self.on_flow_complete:
            for flow_data in expired_flows:
                self.on_flow_complete(flow_data)

        return expired_flows

    def get_stats(self) -> Dict[str, Any]:
        """Current summary stats."""
        with self.lock:
            return {
                "active_flows_count": len(self.active_flows),
                "total_packets_seen": self.total_packets_seen,
                "total_flows_completed": self.total_flows_completed
            }
