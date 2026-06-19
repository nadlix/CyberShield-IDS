"""
Database Queries Module
Provides high-level database operations
"""

import logging
from datetime import datetime, timedelta
from database.models import (
    Alert, Packet, TrafficStatistics, DetectionEvent,
    Baseline, SystemLog, db
)

logger = logging.getLogger(__name__)


class AlertQueries:
    """
    Alert database operations
    """
    
    @staticmethod
    def create_alert(alert_type, severity, source_ip, destination_port=None, 
                    message=None, details=None):
        """
        Create and store a new alert
        """
        try:
            session = db.get_session()
            alert = Alert(
                alert_type=alert_type,
                severity=severity,
                source_ip=source_ip,
                destination_port=destination_port,
                message=message,
                details=details,
            )
            session.add(alert)
            session.commit()
            logger.info(f"Alert stored: {alert_type} from {source_ip}")
            session.close()
            return alert
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            session.rollback()
            session.close()
            return None
    
    @staticmethod
    def get_recent_alerts(limit=100, hours=24):
        """
        Get recent alerts
        """
        try:
            session = db.get_session()
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            alerts = session.query(Alert).filter(
                Alert.timestamp >= cutoff_time
            ).order_by(Alert.timestamp.desc()).limit(limit).all()
            
            session.close()
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            session.close()
            return []
    
    @staticmethod
    def get_alerts_by_severity(severity, limit=100):
        """
        Get alerts by severity level
        """
        try:
            session = db.get_session()
            alerts = session.query(Alert).filter(
                Alert.severity == severity
            ).order_by(Alert.timestamp.desc()).limit(limit).all()
            
            session.close()
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            session.close()
            return []
    
    @staticmethod
    def get_alerts_by_source(source_ip, limit=100):
        """
        Get alerts from specific source IP
        """
        try:
            session = db.get_session()
            alerts = session.query(Alert).filter(
                Alert.source_ip == source_ip
            ).order_by(Alert.timestamp.desc()).limit(limit).all()
            
            session.close()
            return alerts
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            session.close()
            return []
    
    @staticmethod
    def acknowledge_alert(alert_id):
        """
        Mark alert as acknowledged
        """
        try:
            session = db.get_session()
            alert = session.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.acknowledged = True
                session.commit()
                logger.info(f"Alert {alert_id} acknowledged")
                session.close()
                return True
            session.close()
            return False
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
            session.rollback()
            session.close()
            return False


class PacketQueries:
    """
    Packet database operations
    """
    
    @staticmethod
    def store_packet(source_ip, destination_ip, source_port=None, 
                    destination_port=None, protocol='TCP', packet_size=0):
        """
        Store packet information
        """
        try:
            session = db.get_session()
            packet = Packet(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                packet_size=packet_size,
            )
            session.add(packet)
            session.commit()
            session.close()
            return packet
        except Exception as e:
            logger.error(f"Error storing packet: {e}")
            session.rollback()
            session.close()
            return None
    
    @staticmethod
    def get_traffic_stats(hours=1):
        """
        Get traffic statistics
        """
        try:
            session = db.get_session()
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            stats = session.query(TrafficStatistics).filter(
                TrafficStatistics.timestamp >= cutoff_time
            ).order_by(TrafficStatistics.timestamp.desc()).first()
            
            session.close()
            return stats
        except Exception as e:
            logger.error(f"Error retrieving traffic stats: {e}")
            session.close()
            return None


class DetectionQueries:
    """
    Detection event database operations
    """
    
    @staticmethod
    def store_detection(event_type, detection_method, source_ip, 
                       destination_ip=None, destination_port=None,
                       confidence=0.0, details=None):
        """
        Store detection event
        """
        try:
            session = db.get_session()
            event = DetectionEvent(
                event_type=event_type,
                detection_method=detection_method,
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                confidence=confidence,
                details=details,
            )
            session.add(event)
            session.commit()
            logger.info(f"Detection stored: {detection_method}")
            session.close()
            return event
        except Exception as e:
            logger.error(f"Error storing detection: {e}")
            session.rollback()
            session.close()
            return None
    
    @staticmethod
    def get_detections(hours=24, min_confidence=0.5):
        """
        Get detection events
        """
        try:
            session = db.get_session()
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            detections = session.query(DetectionEvent).filter(
                DetectionEvent.timestamp >= cutoff_time,
                DetectionEvent.confidence >= min_confidence
            ).order_by(DetectionEvent.timestamp.desc()).all()
            
            session.close()
            return detections
        except Exception as e:
            logger.error(f"Error retrieving detections: {e}")
            session.close()
            return []


class BaselineQueries:
    """
    Baseline database operations
    """
    
    @staticmethod
    def store_baseline(pattern, mean, std, min_val, max_val, sample_count):
        """
        Store baseline statistics
        """
        try:
            session = db.get_session()
            baseline = Baseline(
                traffic_pattern=pattern,
                mean_value=mean,
                std_deviation=std,
                min_value=min_val,
                max_value=max_val,
                sample_count=sample_count,
            )
            session.add(baseline)
            session.commit()
            session.close()
            return baseline
        except Exception as e:
            logger.error(f"Error storing baseline: {e}")
            session.rollback()
            session.close()
            return None
    
    @staticmethod
    def get_baseline(pattern):
        """
        Get baseline for pattern
        """
        try:
            session = db.get_session()
            baseline = session.query(Baseline).filter(
                Baseline.traffic_pattern == pattern
            ).first()
            session.close()
            return baseline
        except Exception as e:
            logger.error(f"Error retrieving baseline: {e}")
            session.close()
            return None


class SystemLogQueries:
    """
    System log database operations
    """
    
    @staticmethod
    def log_event(level, component, message):
        """
        Log system event
        """
        try:
            session = db.get_session()
            log = SystemLog(
                log_level=level,
                component=component,
                message=message,
            )
            session.add(log)
            session.commit()
            session.close()
            return log
        except Exception as e:
            logger.error(f"Error logging event: {e}")
            session.rollback()
            session.close()
            return None
    
    @staticmethod
    def get_logs(hours=24, level=None):
        """
        Get system logs
        """
        try:
            session = db.get_session()
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            query = session.query(SystemLog).filter(
                SystemLog.timestamp >= cutoff_time
            )
            
            if level:
                query = query.filter(SystemLog.log_level == level)
            
            logs = query.order_by(SystemLog.timestamp.desc()).all()
            session.close()
            return logs
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            session.close()
            return []
