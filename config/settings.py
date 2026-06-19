"""
CyberShield-IDS Configuration Settings
"""

import os
from datetime import timedelta

# General Settings
PROJECT_NAME = "CyberShield-IDS"
DEBUG = os.getenv('DEBUG', 'False') == 'True'
TESTING = os.getenv('TESTING', 'False') == 'True'

# Network Settings
PACKET_CAPTURE_INTERFACE = os.getenv('PACKET_CAPTURE_INTERFACE', None)  # Auto-detect if None
PACKET_BUFFER_SIZE = 1000
PACKET_TIMEOUT = 30

# Database Settings
DATABASE_PATH = os.getenv('DATABASE_PATH', './data/cybershield.db')
DATABASE_URL = f'sqlite:///{DATABASE_PATH}'
SQLALCHEMY_ECHO = DEBUG

# Alert Settings
ALERT_THRESHOLD = 0.7  # Confidence threshold for alerts (0-1)
ALERT_RETENTION_DAYS = 30
MAX_ALERTS_PER_MINUTE = 1000

# Detection Settings
SIGNATURE_RULES_FILE = './rules/attack_signatures.json'
ANOMALY_SENSITIVITY = 0.8  # Higher = more sensitive
STATISTICAL_WINDOW = timedelta(hours=1)  # Time window for statistics

# Machine Learning Settings
ML_MODEL_PATH = './models/anomaly_detector.pkl'
TRAIN_MODEL_ON_STARTUP = True
ML_CONFIDENCE_THRESHOLD = 0.85

# Dashboard Settings
DASHBOARD_HOST = '0.0.0.0'
DASHBOARD_PORT = 5000
DASHBOARD_SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
SESSION_TIMEOUT = timedelta(hours=8)

# Logging Settings
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = './logs/cybershield.log'
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB

# Performance Settings
PACKET_PROCESSING_THREADS = 4
CACHE_TTL = 300  # Cache time-to-live in seconds
BATCH_ALERT_SIZE = 100

# Protocol Settings
MONITORED_PORTS = [
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    3306,  # MySQL
    5432,  # PostgreSQL
    5984,  # CouchDB
    6379,  # Redis
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
]

# Attack Signatures Configuration
ATTACK_CATEGORIES = {
    'ddos': {
        'threshold': 1000,  # packets per second
        'window': 10,       # seconds
    },
    'port_scan': {
        'threshold': 50,    # unique ports in window
        'window': 60,       # seconds
    },
    'brute_force': {
        'threshold': 10,    # failed attempts
        'window': 300,      # seconds
    },
    'sql_injection': {
        'patterns': ['union', 'select', 'insert', 'delete', 'drop', 'exec'],
    },
    'buffer_overflow': {
        'max_payload': 65535,  # bytes
    },
}

# Export Settings
EXPORT_FORMATS = ['csv', 'json', 'pdf']
EXPORT_PATH = './exports/'

# Backup Settings
BACKUP_ENABLED = True
BACKUP_INTERVAL_HOURS = 24
BACKUP_PATH = './backups/'

print(f"[CONFIG] {PROJECT_NAME} Configuration Loaded")
print(f"[CONFIG] Debug Mode: {DEBUG}")
print(f"[CONFIG] Database: {DATABASE_PATH}")
