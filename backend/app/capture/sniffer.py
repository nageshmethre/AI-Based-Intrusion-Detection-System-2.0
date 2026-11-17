"""Live Network Packet Capture Engine with Scapy.

Sniffs packets from the selected network interface or loopback,
parses IP/TCP/UDP/ICMP layers, and dispatches them into the FlowAggregator.
"""

import time
import logging
import threading
from typing import Optional, Callable, Dict, Any, List
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, get_if_list, conf

from backend.app.config import settings
from backend.app.capture.flow import FlowAggregator

logger = logging.getLogger("SOC_Sniffer")
logging.basicConfig(level=logging.INFO)


class PacketSniffer:
    """Live Scapy sniffer running in a background worker thread."""

    def __init__(
        self,
        interface: Optional[str] = None,
        flow_aggregator: Optional[FlowAggregator] = None,
        packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.interface = interface or settings.NETWORK_INTERFACE
        self.flow_aggregator = flow_aggregator or FlowAggregator(flow_timeout=settings.FLOW_TIMEOUT)
        self.packet_callback = packet_callback
        
        self.is_running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._sweep_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self.packet_count: int = 0
        self.tcp_count: int = 0
        self.udp_count: int = 0
        self.icmp_count: int = 0
        self.other_count: int = 0
        self.total_bytes: int = 0

    def parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Parse raw Scapy packet into normalized dictionary."""
        timestamp = float(packet.time) if hasattr(packet, "time") else time.time()
        pkt_len = len(packet)
        self.total_bytes += pkt_len
        self.packet_count += 1

        src_ip = None
        dst_ip = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            self.other_count += 1
            return None

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        header_len = 20
        tcp_flags = {}
        window_size = None

        if TCP in packet:
            protocol = "TCP"
            self.tcp_count += 1
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            header_len = int(packet[TCP].dataofs or 5) * 4
            raw_flags = str(packet[TCP].flags)
            tcp_flags = {
                "F": "F" in raw_flags,
                "S": "S" in raw_flags,
                "R": "R" in raw_flags,
                "P": "P" in raw_flags,
                "A": "A" in raw_flags,
                "U": "U" in raw_flags
            }
            window_size = int(packet[TCP].window)

        elif UDP in packet:
            protocol = "UDP"
            self.udp_count += 1
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            header_len = 8

        elif ICMP in packet:
            protocol = "ICMP"
            self.icmp_count += 1
            header_len = 8

        parsed = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "pkt_len": pkt_len,
            "header_len": header_len,
            "tcp_flags": tcp_flags,
            "window_size": window_size,
            "timestamp": timestamp
        }

        # Dispatch to flow aggregator
        self.flow_aggregator.process_packet(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            pkt_len=pkt_len,
            header_len=header_len,
            tcp_flags=tcp_flags,
            window_size=window_size,
            timestamp=timestamp
        )

        if self.packet_callback:
            self.packet_callback(parsed)

        return parsed

    def _sweep_loop(self):
        """Periodically sweeps and flushes expired inactive flows."""
        while not self._stop_event.is_set():
            time.sleep(settings.FLOW_SWEEP_INTERVAL)
            try:
                self.flow_aggregator.sweep_expired()
            except Exception as e:
                logger.error(f"Error sweeping expired flows: {e}")

    def _sniff_loop(self):
        """Scapy sniffing execution loop."""
        logger.info(f"Starting Scapy sniffing on interface: {self.interface or 'DEFAULT'}")
        try:
            sniff(
                iface=self.interface,
                prn=self.parse_packet,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False
            )
        except Exception as e:
            logger.error(f"Sniffing error occurred: {e}")
            # Fallback to loopback or default interface if specific adapter fails
            if not self._stop_event.is_set():
                try:
                    logger.warning("Attempting fallback sniffing on all available interfaces...")
                    sniff(
                        prn=self.parse_packet,
                        stop_filter=lambda p: self._stop_event.is_set(),
                        store=False
                    )
                except Exception as ex:
                    logger.error(f"Critical sniffer failure: {ex}")

    def start(self):
        """Start packet sniffer and sweep threads."""
        if self.is_running:
            return
        self.is_running = True
        self._stop_event.clear()

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="PacketSnifferThread")
        self._sweep_thread = threading.Thread(target=self._sweep_loop, daemon=True, name="FlowSweepThread")

        self._thread.start()
        self._sweep_thread.start()
        logger.info("PacketSniffer background service initiated.")

    def stop(self):
        """Stop packet sniffer."""
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        logger.info("Stopping PacketSniffer service...")
        # Flush remaining flows
        self.flow_aggregator.sweep_expired(current_time=time.time() + 1000)

    def switch_interface(self, new_iface: Optional[str]):
        """Cleanly switches packet sniffing to a new network interface."""
        logger.info(f"Switching sniffer interface from {self.interface} to {new_iface}")
        was_running = self.is_running
        if was_running:
            self.stop()
            time.sleep(0.5)

        self.interface = new_iface if new_iface and new_iface != "DEFAULT" else None
        if was_running:
            self.start()

    def get_metrics(self) -> Dict[str, Any]:
        """Telemetry metrics for dashboard."""
        flow_stats = self.flow_aggregator.get_stats()
        
        # Determine human-friendly display name
        display_name = "Default (Auto)"
        try:
            if self.interface:
                for iface in list_available_interfaces():
                    if iface["id"] == self.interface:
                        display_name = f"{iface['name']} ({iface['ip'] or iface['description']})"
                        break
                else:
                    display_name = self.interface
            else:
                for iface in list_available_interfaces():
                    if iface["is_default"]:
                        display_name = f"{iface['name']} ({iface['ip'] or iface['description']}) [Default]"
                        break
        except Exception:
            display_name = self.interface or "DEFAULT"

        return {
            "is_running": self.is_running,
            "interface": self.interface or "DEFAULT",
            "interface_display": display_name,
            "total_packets": self.packet_count,
            "total_bytes": self.total_bytes,
            "tcp_packets": self.tcp_count,
            "udp_packets": self.udp_count,
            "icmp_packets": self.icmp_count,
            "other_packets": self.other_count,
            "active_flows": flow_stats["active_flows_count"],
            "completed_flows": flow_stats["total_flows_completed"]
        }


def list_available_interfaces() -> List[Dict[str, Any]]:
    """Retrieve detailed metadata for all network interfaces discovered via Scapy/Npcap."""
    discovered = []
    try:
        default_iface_id = getattr(conf.iface, "name", None) or str(conf.iface)
        
        for iface_id, iface in conf.ifaces.items():
            name = getattr(iface, "name", str(iface_id))
            desc = getattr(iface, "description", "") or name
            ip = getattr(iface, "ip", "") or ""
            
            is_loopback = (
                "loopback" in str(iface_id).lower() or 
                "loopback" in str(name).lower() or 
                "loopback" in str(desc).lower() or 
                ip == "127.0.0.1"
            )
            is_default = (iface_id == default_iface_id)
            
            discovered.append({
                "id": str(iface_id),
                "name": str(name),
                "description": str(desc),
                "ip": str(ip),
                "is_loopback": is_loopback,
                "is_default": is_default
            })
    except Exception as e:
        logger.error(f"Error discovering interfaces via conf.ifaces: {e}")
        try:
            for iface in get_if_list():
                discovered.append({
                    "id": str(iface),
                    "name": str(iface),
                    "description": str(iface),
                    "ip": "",
                    "is_loopback": "loopback" in str(iface).lower(),
                    "is_default": False
                })
        except Exception:
            pass
            
    return discovered
