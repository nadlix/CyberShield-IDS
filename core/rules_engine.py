"""
Rules Engine Module
Manages and applies detection rules to packets
"""

import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from config.settings import (
    SIGNATURE_RULES_FILE,
    ATTACK_CATEGORIES,
    MONITORED_PORTS,
)

logger = logging.getLogger(__name__)


class RulesEngine:
    """
    Evaluates packets against detection rules
    """

    def __init__(self):
        """
        Initialize the rules engine
        """
        self.rules = self._load_rules()
        self.traffic_history = defaultdict(lambda: deque(maxlen=10000))
        self.port_scan_tracker = defaultdict(set)
        self.brute_force_tracker = defaultdict(int)
        self.ddos_tracker = defaultdict(int)
        logger.info(f"RulesEngine initialized with {len(self.rules)} rules")

    def _load_rules(self):
        """
        Load detection rules from file
        
        Returns:
            List of rules
        """
        try:
            with open(SIGNATURE_RULES_FILE, 'r') as f:
                rules = json.load(f)
            logger.info(f"Loaded {len(rules)} detection rules")
            return rules
        except FileNotFoundError:
            logger.warning(f"Rules file not found: {SIGNATURE_RULES_FILE}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing rules file: {e}")
            return []

    def check_packet(self, packet_analysis):
        """
        Check packet against all rules
        
        Args:
            packet_analysis: Packet analysis dictionary from ProtocolAnalyzer
            
        Returns:
            List of matched rules/alerts
        """
        alerts = []

        try:
            # Check signature-based rules
            alerts.extend(self._check_signatures(packet_analysis))
            
            # Check for DDoS
            alerts.extend(self._check_ddos(packet_analysis))
            
            # Check for port scanning
            alerts.extend(self._check_port_scan(packet_analysis))
            
            # Check for brute force
            alerts.extend(self._check_brute_force(packet_analysis))
            
            # Check for suspicious flags
            alerts.extend(self._check_suspicious_flags(packet_analysis))
            
            # Check for large payload
            alerts.extend(self._check_large_payload(packet_analysis))

        except Exception as e:
            logger.error(f"Error checking packet: {e}")

        return alerts

    def _check_signatures(self, packet_analysis):
        """
        Check packet against signature rules
        """
        alerts = []
        ip_layer = packet_analysis.get('ip_layer')
        transport_layer = packet_analysis.get('transport_layer')
        payload = packet_analysis.get('payload')

        if not ip_layer or not transport_layer:
            return alerts

        try:
            src_ip = ip_layer.get('src')
            dst_port = transport_layer.get('dst_port')

            # Check SQL injection patterns
            if payload:
                payload_hex = payload.get('hex', '')
                sql_keywords = ['union', 'select', 'insert', 'delete', 'drop', 'exec']
                
                for keyword in sql_keywords:
                    if keyword.encode().hex() in payload_hex.lower():
                        alerts.append({
                            'type': 'SQL_INJECTION',
                            'severity': 'HIGH',
                            'source': src_ip,
                            'destination_port': dst_port,
                            'pattern': keyword,
                            'timestamp': datetime.now(),
                        })
                        break

            # Check monitored ports
            if dst_port in MONITORED_PORTS:
                alerts.append({
                    'type': 'MONITORED_PORT_ACCESS',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'destination_port': dst_port,
                    'timestamp': datetime.now(),
                })

        except Exception as e:
            logger.error(f"Error in signature check: {e}")

        return alerts

    def _check_ddos(self, packet_analysis):
        """
        Detect DDoS attacks
        """
        alerts = []
        ip_layer = packet_analysis.get('ip_layer')

        if not ip_layer:
            return alerts

        try:
            src_ip = ip_layer.get('src')
            timestamp = packet_analysis.get('timestamp', datetime.now())
            
            # Track packets per source
            self.ddos_tracker[src_ip] = self.ddos_tracker.get(src_ip, 0) + 1
            
            # Check threshold
            ddos_config = ATTACK_CATEGORIES.get('ddos', {})
            threshold = ddos_config.get('threshold', 1000)
            
            if self.ddos_tracker[src_ip] > threshold:
                alerts.append({
                    'type': 'DDOS_ATTACK',
                    'severity': 'CRITICAL',
                    'source': src_ip,
                    'packet_count': self.ddos_tracker[src_ip],
                    'threshold': threshold,
                    'timestamp': timestamp,
                })
                # Reset counter
                self.ddos_tracker[src_ip] = 0

        except Exception as e:
            logger.error(f"Error in DDoS check: {e}")

        return alerts

    def _check_port_scan(self, packet_analysis):
        """
        Detect port scanning activities
        """
        alerts = []
        ip_layer = packet_analysis.get('ip_layer')
        transport_layer = packet_analysis.get('transport_layer')

        if not ip_layer or not transport_layer:
            return alerts

        try:
            src_ip = ip_layer.get('src')
            dst_port = transport_layer.get('dst_port')
            
            # Track unique ports from source
            self.port_scan_tracker[src_ip].add(dst_port)
            
            # Check threshold
            port_scan_config = ATTACK_CATEGORIES.get('port_scan', {})
            threshold = port_scan_config.get('threshold', 50)
            
            if len(self.port_scan_tracker[src_ip]) > threshold:
                alerts.append({
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'unique_ports': len(self.port_scan_tracker[src_ip]),
                    'threshold': threshold,
                    'timestamp': datetime.now(),
                })
                # Reset tracker
                self.port_scan_tracker[src_ip].clear()

        except Exception as e:
            logger.error(f"Error in port scan check: {e}")

        return alerts

    def _check_brute_force(self, packet_analysis):
        """
        Detect brute force attempts
        """
        alerts = []
        transport_layer = packet_analysis.get('transport_layer')
        ip_layer = packet_analysis.get('ip_layer')

        if not transport_layer or not ip_layer:
            return alerts

        try:
            src_ip = ip_layer.get('src')
            dst_port = transport_layer.get('dst_port')
            
            # SSH brute force (port 22)
            if dst_port == 22:
                key = f"{src_ip}:22"
                self.brute_force_tracker[key] = self.brute_force_tracker.get(key, 0) + 1
                
                brute_force_config = ATTACK_CATEGORIES.get('brute_force', {})
                threshold = brute_force_config.get('threshold', 10)
                
                if self.brute_force_tracker[key] > threshold:
                    alerts.append({
                        'type': 'BRUTE_FORCE',
                        'severity': 'HIGH',
                        'source': src_ip,
                        'target_port': dst_port,
                        'attempts': self.brute_force_tracker[key],
                        'threshold': threshold,
                        'timestamp': datetime.now(),
                    })
                    # Reset counter
                    self.brute_force_tracker[key] = 0

        except Exception as e:
            logger.error(f"Error in brute force check: {e}")

        return alerts

    def _check_suspicious_flags(self, packet_analysis):
        """
        Detect suspicious TCP flags
        """
        alerts = []
        transport_layer = packet_analysis.get('transport_layer')
        ip_layer = packet_analysis.get('ip_layer')

        if not transport_layer or not ip_layer or 'flags' not in transport_layer:
            return alerts

        try:
            flags = transport_layer.get('flags', {})
            src_ip = ip_layer.get('src')
            dst_port = transport_layer.get('dst_port')
            
            # Check for SYN+FIN (port scan attempt)
            if flags.get('SYN') and flags.get('FIN'):
                alerts.append({
                    'type': 'SUSPICIOUS_FLAGS',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'destination_port': dst_port,
                    'flags': 'SYN+FIN',
                    'timestamp': datetime.now(),
                })
            
            # Check for SYN+RST
            elif flags.get('SYN') and flags.get('RST'):
                alerts.append({
                    'type': 'SUSPICIOUS_FLAGS',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'destination_port': dst_port,
                    'flags': 'SYN+RST',
                    'timestamp': datetime.now(),
                })

        except Exception as e:
            logger.error(f"Error in suspicious flags check: {e}")

        return alerts

    def _check_large_payload(self, packet_analysis):
        """
        Detect unusually large payloads (potential data exfiltration)
        """
        alerts = []
        payload = packet_analysis.get('payload')
        ip_layer = packet_analysis.get('ip_layer')

        if not payload or not ip_layer:
            return alerts

        try:
            payload_size = payload.get('size', 0)
            src_ip = ip_layer.get('src')
            
            # Flag if payload > 100KB
            if payload_size > 100000:
                alerts.append({
                    'type': 'LARGE_PAYLOAD',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'payload_size': payload_size,
                    'timestamp': datetime.now(),
                })

        except Exception as e:
            logger.error(f"Error in large payload check: {e}")

        return alerts

    def get_statistics(self):
        """
        Get rule engine statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_rules': len(self.rules),
            'ddos_trackers': len(self.ddos_tracker),
            'port_scan_trackers': len(self.port_scan_tracker),
            'brute_force_trackers': len(self.brute_force_tracker),
        }
