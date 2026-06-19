"""
Dashboard Application
Web-based monitoring and analytics interface for CyberShield-IDS
"""

from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import logging
from datetime import datetime, timedelta
import json
from config.settings import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    DASHBOARD_SECRET_KEY,
    PROJECT_NAME,
)

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = DASHBOARD_SECRET_KEY
CORS(app)

# Global state (in production, use database)
ids_state = {
    'running': False,
    'sniffer': None,
    'analyzer': None,
    'rules_engine': None,
    'alert_manager': None,
    'start_time': None,
}


@app.route('/')
def index():
    """
    Main dashboard page
    """
    return render_template('dashboard.html', project_name=PROJECT_NAME)


@app.route('/api/status')
def get_status():
    """
    Get IDS system status
    """
    try:
        uptime = 0
        if ids_state['start_time']:
            uptime = (datetime.now() - ids_state['start_time']).total_seconds()
        
        status = {
            'running': ids_state['running'],
            'uptime_seconds': uptime,
            'uptime_formatted': format_uptime(uptime),
            'timestamp': datetime.now().isoformat(),
        }
        
        # Add sniffer stats
        if ids_state['sniffer']:
            status['sniffer'] = ids_state['sniffer'].get_statistics()
        
        # Add alert stats
        if ids_state['alert_manager']:
            status['alerts'] = ids_state['alert_manager'].get_statistics()
        
        return jsonify(status)
    
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    """
    Get recent alerts
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        severity = request.args.get('severity', None)
        
        if ids_state['alert_manager']:
            alerts = ids_state['alert_manager'].get_recent_alerts(limit=limit, severity=severity)
            return jsonify({
                'alerts': alerts,
                'count': len(alerts),
                'timestamp': datetime.now().isoformat(),
            })
        
        return jsonify({'alerts': [], 'count': 0})
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_type>')
def get_alerts_by_type(alert_type):
    """
    Get alerts by type
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        
        if ids_state['alert_manager']:
            alerts = ids_state['alert_manager'].get_alerts_by_type(alert_type, limit=limit)
            return jsonify({
                'type': alert_type,
                'alerts': alerts,
                'count': len(alerts),
            })
        
        return jsonify({'alerts': [], 'count': 0})
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/source/<source_ip>')
def get_alerts_by_source(source_ip):
    """
    Get alerts from specific source IP
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        
        if ids_state['alert_manager']:
            alerts = ids_state['alert_manager'].get_alerts_by_source(source_ip, limit=limit)
            return jsonify({
                'source': source_ip,
                'alerts': alerts,
                'count': len(alerts),
            })
        
        return jsonify({'alerts': [], 'count': 0})
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """
    Acknowledge an alert
    """
    try:
        if ids_state['alert_manager']:
            success = ids_state['alert_manager'].acknowledge_alert(float(alert_id))
            return jsonify({'success': success})
        return jsonify({'success': False})
    
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics')
def get_statistics():
    """
    Get comprehensive statistics
    """
    try:
        stats = {
            'sniffer': {},
            'rules_engine': {},
            'alerts': {},
            'anomaly_detector': {},
        }
        
        if ids_state['sniffer']:
            stats['sniffer'] = ids_state['sniffer'].get_statistics()
        
        if ids_state['rules_engine']:
            stats['rules_engine'] = ids_state['rules_engine'].get_statistics()
        
        if ids_state['alert_manager']:
            stats['alerts'] = ids_state['alert_manager'].get_statistics()
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/critical')
def get_critical_alerts():
    """
    Get critical alerts from last hour
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        
        if ids_state['alert_manager']:
            alerts = ids_state['alert_manager'].get_critical_alerts(hours=hours)
            return jsonify({
                'critical_alerts': alerts,
                'count': len(alerts),
                'time_range_hours': hours,
            })
        
        return jsonify({'critical_alerts': [], 'count': 0})
    
    except Exception as e:
        logger.error(f"Error getting critical alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/alerts')
def export_alerts():
    """
    Export alerts as CSV
    """
    try:
        if ids_state['alert_manager']:
            csv_data = ids_state['alert_manager'].export_alerts_csv()
            return csv_data, 200, {
                'Content-Disposition': 'attachment;filename=alerts.csv',
                'Content-Type': 'text/csv',
            }
    
    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health_check():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
    })


@app.errorhandler(404)
def not_found(error):
    """
    Handle 404 errors
    """
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """
    Handle 500 errors
    """
    logger.error(f"Server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


def format_uptime(seconds):
    """
    Format uptime in human-readable format
    
    Args:
        seconds: Uptime in seconds
        
    Returns:
        Formatted string
    """
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"


def create_app(sniffer=None, analyzer=None, rules_engine=None, alert_manager=None):
    """
    Factory function to create and configure app
    
    Args:
        sniffer: PacketSniffer instance
        analyzer: ProtocolAnalyzer instance
        rules_engine: RulesEngine instance
        alert_manager: AlertManager instance
        
    Returns:
        Configured Flask app
    """
    ids_state['sniffer'] = sniffer
    ids_state['analyzer'] = analyzer
    ids_state['rules_engine'] = rules_engine
    ids_state['alert_manager'] = alert_manager
    ids_state['running'] = True
    ids_state['start_time'] = datetime.now()
    
    return app


if __name__ == '__main__':
    logger.info(f"Starting {PROJECT_NAME} Dashboard")
    logger.info(f"Dashboard available at http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    
    app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
    )
