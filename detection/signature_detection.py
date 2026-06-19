"""
Signature Detection Module
Detects known attack signatures
"""

import json
import logging
from datetime import datetime
from config.settings import SIGNATURE_RULES_FILE

logger = logging.getLogger(__name__)


class SignatureDetector:
    """
    Detects attacks using known signatures
    """

    def __init__(self):
        """
        Initialize signature detector
        """
        self.signatures = self._load_signatures()
        self.detection_count = 0
        logger.info(f"SignatureDetector initialized with {len(self.signatures)} signatures")

    def _load_signatures(self):
        """
        Load attack signatures from file
        
        Returns:
            Dictionary of signatures
        """
        try:
            with open(SIGNATURE_RULES_FILE, 'r') as f:
                signatures = json.load(f)
            return signatures
        except FileNotFoundError:
            logger.warning(f"Signature file not found: {SIGNATURE_RULES_FILE}")
            return {}
        except Exception as e:
            logger.error(f"Error loading signatures: {e}")
            return {}

    def detect(self, packet_analysis):
        """
        Detect known attack signatures in packet
        
        Args:
            packet_analysis: Packet analysis from ProtocolAnalyzer
            
        Returns:
            List of detected signatures
        """
        detections = []
        
        try:
            # Check payload for malicious content
            if packet_analysis.get('payload'):
                payload_detections = self._check_payload_signatures(
                    packet_analysis.get('payload')
                )
                detections.extend(payload_detections)
            
            # Check protocol behaviors
            protocol_detections = self._check_protocol_signatures(packet_analysis)
            detections.extend(protocol_detections)
            
            # Update detection count
            self.detection_count += len(detections)
        
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
        
        return detections

    def _check_payload_signatures(self, payload):
        """
        Check payload for known malicious patterns
        
        Args:
            payload: Payload data
            
        Returns:
            List of detections
        """
        detections = []
        
        try:
            payload_hex = payload.get('hex', '').lower()
            
            # Common SQL injection signatures
            sql_signatures = [
                'union select',
                'union all select',
                'or 1=1',
                'drop table',
                'exec xp_',
            ]
            
            for sig in sql_signatures:
                if sig.encode().hex().lower() in payload_hex:
                    detections.append({
                        'type': 'SQL_INJECTION',
                        'signature': sig,
                        'confidence': 0.95,
                        'timestamp': datetime.now(),
                    })
            
            # XSS signatures
            xss_signatures = [
                '<script',
                'javascript:',
                'onerror=',
                'onload=',
            ]
            
            for sig in xss_signatures:
                if sig.encode().hex().lower() in payload_hex:
                    detections.append({
                        'type': 'XSS_ATTACK',
                        'signature': sig,
                        'confidence': 0.90,
                        'timestamp': datetime.now(),
                    })
        
        except Exception as e:
            logger.error(f"Error in payload signature check: {e}")
        
        return detections

    def _check_protocol_signatures(self, packet_analysis):
        """
        Check protocol-level signatures
        
        Args:
            packet_analysis: Packet analysis
            
        Returns:
            List of detections
        """
        detections = []
        
        try:
            transport = packet_analysis.get('transport_layer')
            if not transport:
                return detections
            
            # Check for suspicious TCP flag combinations
            flags = transport.get('flags', {})
            
            # SYN+FIN: Port scanning
            if flags.get('SYN') and flags.get('FIN'):
                detections.append({
                    'type': 'PORT_SCAN',
                    'signature': 'TCP_SYN_FIN',
                    'confidence': 0.85,
                    'timestamp': datetime.now(),
                })
            
            # All flags set (XMAS scan)
            if all(flags.values()):
                detections.append({
                    'type': 'PORT_SCAN',
                    'signature': 'TCP_XMAS_SCAN',
                    'confidence': 0.80,
                    'timestamp': datetime.now(),
                })
        
        except Exception as e:
            logger.error(f"Error in protocol signature check: {e}")
        
        return detections

    def get_statistics(self):
        """
        Get detector statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_signatures': len(self.signatures),
            'detections': self.detection_count,
        }
