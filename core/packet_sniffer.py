"""
Packet Sniffer Module
Captures and processes network packets
"""

from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
from scapy.layers.inet import IP
import threading
import logging
from datetime import datetime
from queue import Queue
from config.settings import (
    PACKET_CAPTURE_INTERFACE,
    PACKET_TIMEOUT,
    PACKET_BUFFER_SIZE,
    PACKET_PROCESSING_THREADS,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Captures network packets and queues them for analysis
    """

    def __init__(self, interface=None, packet_count=0, timeout=PACKET_TIMEOUT):
        """
        Initialize the packet sniffer
        
        Args:
            interface: Network interface to sniff on (auto-detect if None)
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds
        """
        self.interface = interface or self._get_default_interface()
        self.packet_count = packet_count
        self.timeout = timeout
        self.packet_queue = Queue(maxsize=PACKET_BUFFER_SIZE)
        self.is_running = False
        self.packet_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
        }
        self.sniffer_thread = None

        logger.info(f"PacketSniffer initialized on interface: {self.interface}")

    def _get_default_interface(self):
        """
        Get the default network interface
        """
        interfaces = get_if_list()
        if not interfaces:
            raise RuntimeError("No network interfaces found!")
        
        # Prefer non-loopback interface
        for iface in interfaces:
            if iface not in ['lo', 'lo0', 'localhost']:
                logger.info(f"Auto-detected interface: {iface}")
                return iface
        
        logger.warning("Using loopback interface as fallback")
        return interfaces[0]

    def _packet_callback(self, packet):
        """
        Callback function for each captured packet
        """
        try:
            # Add timestamp
            packet.captured_at = datetime.now()
            
            # Update statistics
            self.packet_stats['total_packets'] += 1
            
            if TCP in packet:
                self.packet_stats['tcp_packets'] += 1
            elif UDP in packet:
                self.packet_stats['udp_packets'] += 1
            elif ICMP in packet:
                self.packet_stats['icmp_packets'] += 1
            else:
                self.packet_stats['other_packets'] += 1
            
            # Queue the packet for processing
            if not self.packet_queue.full():
                self.packet_queue.put(packet)
            else:
                logger.warning("Packet queue is full, dropping packet")

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start(self):
        """
        Start packet sniffing in a separate thread
        """
        if self.is_running:
            logger.warning("Sniffer is already running!")
            return

        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        logger.info("PacketSniffer started")

    def _sniff_packets(self):
        """
        Internal method to perform packet sniffing
        """
        try:
            logger.info(f"Starting packet capture on {self.interface}")
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                count=self.packet_count,
                timeout=self.timeout,
                stop_filter=lambda x: not self.is_running,
            )
        except PermissionError:
            logger.error("Permission denied! Please run with sudo/admin privileges")
            self.is_running = False
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            self.is_running = False

    def stop(self):
        """
        Stop packet sniffing
        """
        self.is_running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        logger.info("PacketSniffer stopped")

    def get_next_packet(self, timeout=1):
        """
        Get the next packet from the queue
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Packet or None if timeout
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except:
            return None

    def get_statistics(self):
        """
        Get packet capture statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'interface': self.interface,
            'is_running': self.is_running,
            'queue_size': self.packet_queue.qsize(),
            'stats': self.packet_stats.copy(),
        }

    def print_statistics(self):
        """
        Print statistics to console
        """
        stats = self.get_statistics()
        print("\n" + "="*50)
        print("PACKET SNIFFER STATISTICS")
        print("="*50)
        print(f"Interface: {stats['interface']}")
        print(f"Status: {'Running' if stats['is_running'] else 'Stopped'}")
        print(f"Queue Size: {stats['queue_size']}")
        print("\nPacket Counts:")
        for key, value in stats['stats'].items():
            print(f"  {key}: {value}")
        print("="*50 + "\n")


if __name__ == "__main__":
    import time
    logger.info("Starting CyberShield-IDS Packet Sniffer Test")
    sniffer = PacketSniffer()
    sniffer.start()
    try:
        for i in range(60):
            packet = sniffer.get_next_packet(timeout=1)
            if i % 10 == 0:
                sniffer.print_statistics()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        sniffer.stop()
