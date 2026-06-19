"""
Alerts Module
Handles alert management, storage, and notifications
"""

import logging
from datetime import datetime, timedelta
from collections import deque
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Alert:
    """
    Represents a security alert
    """

    def __init__(self, alert_type, severity, source, message, details=None):
        """
        Initialize an alert
        
        Args:
            alert_type: Type of alert (e.g., 'PORT_SCAN', 'DDoS')
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            source: Source IP address
            message: Alert message
            details: Additional alert details
        """
        self.id = datetime.now().timestamp()
        self.type = alert_type
        self.severity = severity
        self.source = source
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now()
        self.acknowledged = False

    def to_dict(self):
        """
        Convert alert to dictionary
        """
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity.name,
            'source': self.source,
            'message': self.message,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged,
        }


class AlertManager:
    """
    Manages alert creation, storage, and retrieval
    """

    def __init__(self, max_alerts=10000, retention_hours=24):
        """
        Initialize alert manager
        
        Args:
            max_alerts: Maximum number of alerts to keep in memory
            retention_hours: How long to keep alerts
        """
        self.alerts = deque(maxlen=max_alerts)
        self.retention_hours = retention_hours
        self.alert_stats = {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }
        self.alert_callbacks = []  # For real-time notifications
        logger.info("AlertManager initialized")

    def create_alert(self, alert_type, severity, source, message, details=None):
        """
        Create and store a new alert
        
        Args:
            alert_type: Type of alert
            severity: Severity level (string: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            source: Source IP
            message: Alert message
            details: Additional details
            
        Returns:
            Alert object
        """
        try:
            # Convert severity string to enum
            if isinstance(severity, str):
                severity = AlertSeverity[severity]
            
            alert = Alert(alert_type, severity, source, message, details)
            self.alerts.append(alert)
            
            # Update statistics
            self.alert_stats['total'] += 1
            self.alert_stats[severity.name.lower()] += 1
            
            # Trigger callbacks
            self._trigger_callbacks(alert)
            
            logger.warning(f"Alert created: {alert_type} from {source} - {message}")
            
            return alert
        
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None

    def create_alert_from_rule(self, rule_alert):
        """
        Create alert from rules engine alert
        
        Args:
            rule_alert: Dictionary from rules engine
            
        Returns:
            Alert object
        """
        try:
            alert_type = rule_alert.get('type', 'UNKNOWN')
            severity = rule_alert.get('severity', 'MEDIUM')
            source = rule_alert.get('source', 'Unknown')
            message = f"{alert_type} detected from {source}"
            
            return self.create_alert(alert_type, severity, source, message, rule_alert)
        
        except Exception as e:
            logger.error(f"Error creating alert from rule: {e}")
            return None

    def get_recent_alerts(self, limit=100, severity=None):
        """
        Get recent alerts
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity (optional)
            
        Returns:
            List of alert dictionaries
        """
        alerts = list(self.alerts)
        alerts.reverse()  # Most recent first
        
        if severity:
            if isinstance(severity, str):
                severity = AlertSeverity[severity]
            alerts = [a for a in alerts if a.severity == severity]
        
        return [a.to_dict() for a in alerts[:limit]]

    def get_alerts_by_source(self, source, limit=100):
        """
        Get alerts from a specific source IP
        
        Args:
            source: Source IP address
            limit: Maximum alerts to return
            
        Returns:
            List of alert dictionaries
        """
        matching = [a for a in self.alerts if a.source == source]
        matching.reverse()
        return [a.to_dict() for a in matching[:limit]]

    def get_alerts_by_type(self, alert_type, limit=100):
        """
        Get alerts by type
        
        Args:
            alert_type: Type of alert to filter
            limit: Maximum alerts to return
            
        Returns:
            List of alert dictionaries
        """
        matching = [a for a in self.alerts if a.type == alert_type]
        matching.reverse()
        return [a.to_dict() for a in matching[:limit]]

    def acknowledge_alert(self, alert_id):
        """
        Mark an alert as acknowledged
        
        Args:
            alert_id: Alert ID to acknowledge
            
        Returns:
            True if successful, False otherwise
        """
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                logger.info(f"Alert {alert_id} acknowledged")
                return True
        return False

    def get_statistics(self):
        """
        Get alert statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_alerts': self.alert_stats['total'],
            'critical': self.alert_stats['critical'],
            'high': self.alert_stats['high'],
            'medium': self.alert_stats['medium'],
            'low': self.alert_stats['low'],
            'in_memory': len(self.alerts),
        }

    def get_critical_alerts(self, hours=1):
        """
        Get critical alerts from the last N hours
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of critical alerts
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        critical = [
            a for a in self.alerts
            if a.severity == AlertSeverity.CRITICAL and a.timestamp > cutoff_time
        ]
        return [a.to_dict() for a in critical]

    def register_callback(self, callback):
        """
        Register a callback for alert notifications
        
        Args:
            callback: Function to call when alert is created
        """
        self.alert_callbacks.append(callback)
        logger.info(f"Alert callback registered: {callback.__name__}")

    def _trigger_callbacks(self, alert):
        """
        Trigger all registered callbacks
        
        Args:
            alert: Alert object
        """
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

    def export_alerts_json(self, limit=None):
        """
        Export alerts as JSON
        
        Args:
            limit: Maximum alerts to export
            
        Returns:
            JSON string
        """
        import json
        alerts = self.get_recent_alerts(limit=limit or len(self.alerts))
        return json.dumps(alerts, indent=2, default=str)

    def export_alerts_csv(self, limit=None):
        """
        Export alerts as CSV
        
        Args:
            limit: Maximum alerts to export
            
        Returns:
            CSV string
        """
        import csv
        from io import StringIO
        
        alerts = self.get_recent_alerts(limit=limit or len(self.alerts))
        
        output = StringIO()
        if alerts:
            writer = csv.DictWriter(output, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
        
        return output.getvalue()

    def clear_old_alerts(self):
        """
        Clear alerts older than retention period
        """
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
        initial_count = len(self.alerts)
        
        # Since deque doesn't support efficient removal, we rebuild it
        new_alerts = deque(
            [a for a in self.alerts if a.timestamp > cutoff_time],
            maxlen=self.alerts.maxlen
        )
        self.alerts = new_alerts
        
        removed = initial_count - len(self.alerts)
        logger.info(f"Cleared {removed} old alerts")
