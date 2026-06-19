"""
Anomaly Detection Module
Detects suspicious behavior patterns
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
from config.settings import ANOMALY_SENSITIVITY

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detects anomalous network behavior
    """

    def __init__(self, sensitivity=ANOMALY_SENSITIVITY):
        """
        Initialize anomaly detector
        
        Args:
            sensitivity: Detection sensitivity (0-1)
        """
        self.sensitivity = sensitivity
        self.baseline = {}
        self.traffic_stats = defaultdict(lambda: deque(maxlen=1000))
        self.learning_phase = True
        self.learning_samples = 0
        self.learning_threshold = 1000
        logger.info(f"AnomalyDetector initialized (sensitivity: {sensitivity})")

    def analyze_packet(self, packet_analysis):
        """
        Analyze packet for anomalies
        
        Args:
            packet_analysis: Packet analysis from ProtocolAnalyzer
            
        Returns:
            List of anomalies detected
        """
        anomalies = []
        
        try:
            if self.learning_phase:
                self._learn_baseline(packet_analysis)
            else:
                anomalies = self._detect_anomalies(packet_analysis)
        
        except Exception as e:
            logger.error(f"Error in anomaly analysis: {e}")
        
        return anomalies

    def _learn_baseline(self, packet_analysis):
        """
        Learn normal traffic patterns
        
        Args:
            packet_analysis: Packet to learn from
        """
        try:
            ip_layer = packet_analysis.get('ip_layer')
            transport_layer = packet_analysis.get('transport_layer')
            
            if not ip_layer or not transport_layer:
                return
            
            src_ip = ip_layer.get('src')
            dst_port = transport_layer.get('dst_port')
            packet_size = ip_layer.get('length', 0)
            
            # Store traffic patterns
            key = f"{src_ip}:{dst_port}"
            self.traffic_stats[key].append(packet_size)
            
            self.learning_samples += 1
            
            if self.learning_samples >= self.learning_threshold:
                self._compute_baseline()
                self.learning_phase = False
                logger.info("Baseline learning complete. Anomaly detection enabled.")
        
        except Exception as e:
            logger.error(f"Error in baseline learning: {e}")

    def _compute_baseline(self):
        """
        Compute baseline statistics from collected data
        """
        try:
            for key, sizes in self.traffic_stats.items():
                if len(sizes) > 0:
                    sizes_array = np.array(list(sizes))
                    self.baseline[key] = {
                        'mean': float(np.mean(sizes_array)),
                        'std': float(np.std(sizes_array)),
                        'min': float(np.min(sizes_array)),
                        'max': float(np.max(sizes_array)),
                    }
            
            logger.info(f"Baseline computed for {len(self.baseline)} traffic patterns")
        
        except Exception as e:
            logger.error(f"Error computing baseline: {e}")

    def _detect_anomalies(self, packet_analysis):
        """
        Detect anomalies based on baseline
        
        Args:
            packet_analysis: Packet to check
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        try:
            ip_layer = packet_analysis.get('ip_layer')
            transport_layer = packet_analysis.get('transport_layer')
            
            if not ip_layer or not transport_layer:
                return anomalies
            
            src_ip = ip_layer.get('src')
            dst_port = transport_layer.get('dst_port')
            packet_size = ip_layer.get('length', 0)
            
            key = f"{src_ip}:{dst_port}"
            
            # Check if this is a known pattern
            if key in self.baseline:
                baseline_stats = self.baseline[key]
                
                # Calculate Z-score
                z_score = self._calculate_z_score(
                    packet_size,
                    baseline_stats['mean'],
                    baseline_stats['std']
                )
                
                # Threshold based on sensitivity
                threshold = 3 - (self.sensitivity * 2)
                
                if abs(z_score) > threshold:
                    anomalies.append({
                        'type': 'ANOMALOUS_TRAFFIC_SIZE',
                        'severity': 'MEDIUM',
                        'source': src_ip,
                        'destination_port': dst_port,
                        'packet_size': packet_size,
                        'baseline_mean': baseline_stats['mean'],
                        'z_score': z_score,
                        'timestamp': datetime.now(),
                    })
            
            # Check for new traffic patterns
            if key not in self.baseline:
                anomalies.append({
                    'type': 'NEW_TRAFFIC_PATTERN',
                    'severity': 'LOW',
                    'source': src_ip,
                    'destination_port': dst_port,
                    'packet_size': packet_size,
                    'timestamp': datetime.now(),
                })
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
        
        return anomalies

    def _calculate_z_score(self, value, mean, std):
        """
        Calculate Z-score for value
        
        Args:
            value: Value to calculate Z-score for
            mean: Mean of distribution
            std: Standard deviation
            
        Returns:
            Z-score
        """
        if std == 0:
            return 0
        return (value - mean) / std

    def reset_learning(self):
        """
        Reset baseline learning
        """
        self.baseline = {}
        self.traffic_stats.clear()
        self.learning_phase = True
        self.learning_samples = 0
        logger.info("Anomaly detector reset for relearning")

    def get_statistics(self):
        """
        Get detector statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'learning_phase': self.learning_phase,
            'learning_progress': min(100, (self.learning_samples / self.learning_threshold) * 100),
            'baseline_patterns': len(self.baseline),
            'sensitivity': self.sensitivity,
        }
