"""
Protocol Analyzer Module
Analyzes captured packets and extracts relevant information
"""

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.http import HTTPRequest
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ProtocolAnalyzer:
    """
    Analyzes network protocols and extracts packet information
    """

    def __init__(self):
        """Initialize the protocol analyzer"""
        self.packet_data_cache = {}
        logger.info("ProtocolAnalyzer initialized")

    def analyze_packet(self, packet):
        """
        Analyze a captured packet and extract information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet analysis
        """
        analysis = {
            'timestamp': getattr(packet, 'captured_at', datetime.now()),
            'layers': [],
            'ip_layer': None,
            'transport_layer': None,
            'application_layer': None,
            'flags': {},
            'payload': None,
        }

        try:
            # Analyze IP layer
            if IP in packet:
                analysis['ip_layer'] = self._analyze_ip(packet)
                analysis['layers'].append('IP')

            # Analyze Transport layer
            if TCP in packet:
                analysis['transport_layer'] = self._analyze_tcp(packet)
                analysis['layers'].append('TCP')
            elif UDP in packet:
                analysis['transport_layer'] = self._analyze_udp(packet)
                analysis['layers'].append('UDP')
            elif ICMP in packet:
                analysis['transport_layer'] = self._analyze_icmp(packet)
                analysis['layers'].append('ICMP')

            # Analyze Application layer
            if DNS in packet:
                analysis['application_layer'] = self._analyze_dns(packet)
                analysis['layers'].append('DNS')
            elif HTTPRequest in packet:
                analysis['application_layer'] = self._analyze_http(packet)
                analysis['layers'].append('HTTP')

            # Extract raw payload
            if Raw in packet:
                payload = packet[Raw].load
                analysis['payload'] = {
                    'size': len(payload),
                    'hex': payload[:100].hex(),
                }

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")

        return analysis

    def _analyze_ip(self, packet):
        """Analyze IP layer"""
        ip_layer = packet[IP]
        return {
            'version': ip_layer.version,
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'protocol': ip_layer.proto,
            'ttl': ip_layer.ttl,
            'length': ip_layer.len,
            'flags': ip_layer.flags,
            'fragment_offset': ip_layer.frag,
            'checksum': ip_layer.chksum,
        }

    def _analyze_tcp(self, packet):
        """Analyze TCP layer"""
        tcp_layer = packet[TCP]
        return {
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'sequence': tcp_layer.seq,
            'acknowledgement': tcp_layer.ack,
            'flags': {
                'SYN': bool(tcp_layer.flags.S),
                'ACK': bool(tcp_layer.flags.A),
                'FIN': bool(tcp_layer.flags.F),
                'RST': bool(tcp_layer.flags.R),
                'PSH': bool(tcp_layer.flags.P),
                'URG': bool(tcp_layer.flags.U),
            },
            'window_size': tcp_layer.window,
            'checksum': tcp_layer.chksum,
        }

    def _analyze_udp(self, packet):
        """Analyze UDP layer"""
        udp_layer = packet[UDP]
        return {
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'length': udp_layer.len,
            'checksum': udp_layer.chksum,
        }

    def _analyze_icmp(self, packet):
        """Analyze ICMP layer"""
        icmp_layer = packet[ICMP]
        return {
            'type': icmp_layer.type,
            'code': icmp_layer.code,
            'checksum': icmp_layer.chksum,
            'seq': getattr(icmp_layer, 'seq', None),
            'id': getattr(icmp_layer, 'id', None),
        }

    def _analyze_dns(self, packet):
        """Analyze DNS layer"""
        dns_layer = packet[DNS]
        dns_info = {
            'id': dns_layer.id,
            'opcode': dns_layer.opcode,
            'response': dns_layer.qr,
            'questions': [],
            'answers': [],
        }

        # Extract DNS questions
        if DNSQR in packet:
            for question in packet[DNSQR]:
                dns_info['questions'].append({
                    'name': question.qname.decode() if isinstance(question.qname, bytes) else str(question.qname),
                    'type': question.qtype,
                    'class': question.qclass,
                })

        # Extract DNS answers
        if DNSRR in packet:
            for answer in packet[DNSRR]:
                dns_info['answers'].append({
                    'name': answer.rrname.decode() if isinstance(answer.rrname, bytes) else str(answer.rrname),
                    'type': answer.type,
                    'ttl': answer.ttl,
                    'rdata': str(answer.rdata),
                })

        return dns_info

    def _analyze_http(self, packet):
        """Analyze HTTP layer"""
        http_layer = packet[HTTPRequest]
        return {
            'method': http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else str(http_layer.Method),
            'path': http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else str(http_layer.Path),
            'version': http_layer.Http_Version.decode() if isinstance(http_layer.Http_Version, bytes) else str(http_layer.Http_Version),
            'host': http_layer.Host.decode() if hasattr(http_layer, 'Host') and isinstance(http_layer.Host, bytes) else getattr(http_layer, 'Host', None),
        }

    def get_packet_summary(self, packet):
        """
        Get a simple summary of packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Simple string summary
        """
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [TCP]"
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [UDP]"
                else:
                    return f"{src_ip} -> {dst_ip} [Other]"
            else:
                return "Non-IP packet"
        except Exception as e:
            logger.error(f"Error getting packet summary: {e}")
            return "Unknown packet"

    def detect_anomalies(self, analysis):
        """
        Detect potential anomalies in packet
        
        Args:
            analysis: Packet analysis dictionary
            
        Returns:
            List of detected anomalies
        """
        anomalies = []

        try:
            # Check for suspicious TTL
            if analysis['ip_layer'] and analysis['ip_layer']['ttl'] == 0:
                anomalies.append("Suspicious TTL (0)")

            # Check for large packets
            if analysis['ip_layer'] and analysis['ip_layer']['length'] > 65000:
                anomalies.append("Unusually large packet")

            # Check for TCP flags
            if analysis['transport_layer'] and 'flags' in analysis['transport_layer']:
                flags = analysis['transport_layer']['flags']
                if flags.get('SYN') and flags.get('FIN'):
                    anomalies.append("Suspicious TCP flags (SYN+FIN)")
                if flags.get('SYN') and flags.get('RST'):
                    anomalies.append("Suspicious TCP flags (SYN+RST)")

            # Check for suspicious payload
            if analysis['payload'] and analysis['payload']['size'] > 0:
                if analysis['payload']['size'] > 100000:
                    anomalies.append("Large payload detected")

        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")

        return anomalies
