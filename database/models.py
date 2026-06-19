"""
Database Models
Defines data models for the IDS system
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import logging
from config.settings import DATABASE_URL

logger = logging.getLogger(__name__)

# Create base class
Base = declarative_base()


class Alert(Base):
    """
    Represents a security alert
    """
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    alert_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip = Column(String(45), nullable=False, index=True)  # IPv6 compatible
    destination_port = Column(Integer)
    message = Column(Text)
    details = Column(Text)  # JSON string
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False, index=True)
    
    def __repr__(self):
        return f"<Alert {self.alert_type} from {self.source_ip}>"


class Packet(Base):
    """
    Represents a captured network packet
    """
    __tablename__ = 'packets'
    
    id = Column(Integer, primary_key=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer, index=True)
    protocol = Column(String(20))  # TCP, UDP, ICMP
    packet_size = Column(Integer)
    flags = Column(String(50))  # TCP flags
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<Packet {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}>"


class TrafficStatistics(Base):
    """
    Aggregated traffic statistics
    """
    __tablename__ = 'traffic_statistics'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_packets = Column(Integer, default=0)
    tcp_packets = Column(Integer, default=0)
    udp_packets = Column(Integer, default=0)
    icmp_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    average_packet_size = Column(Float)
    
    def __repr__(self):
        return f"<TrafficStatistics {self.timestamp}: {self.total_packets} packets>"


class DetectionEvent(Base):
    """
    Represents a detection event (attack or anomaly)
    """
    __tablename__ = 'detection_events'
    
    id = Column(Integer, primary_key=True)
    event_type = Column(String(100), nullable=False, index=True)  # SIGNATURE, ANOMALY
    detection_method = Column(String(100))  # E.g., SQL_INJECTION, DDoS, etc.
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45))
    destination_port = Column(Integer)
    confidence = Column(Float)  # 0.0 to 1.0
    details = Column(Text)  # JSON details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<DetectionEvent {self.detection_method} from {self.source_ip}>"


class Baseline(Base):
    """
    Stores baseline statistics for anomaly detection
    """
    __tablename__ = 'baselines'
    
    id = Column(Integer, primary_key=True)
    traffic_pattern = Column(String(100), nullable=False, unique=True, index=True)
    mean_value = Column(Float)
    std_deviation = Column(Float)
    min_value = Column(Float)
    max_value = Column(Float)
    sample_count = Column(Integer)
    last_updated = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Baseline {self.traffic_pattern}>"


class SystemLog(Base):
    """
    System operational logs
    """
    __tablename__ = 'system_logs'
    
    id = Column(Integer, primary_key=True)
    log_level = Column(String(20))  # INFO, WARNING, ERROR, CRITICAL
    component = Column(String(100))  # E.g., PacketSniffer, RulesEngine
    message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<SystemLog {self.log_level} - {self.component}>"


class Database:
    """
    Database manager
    """
    
    def __init__(self, database_url=DATABASE_URL):
        """
        Initialize database connection
        
        Args:
            database_url: SQLAlchemy database URL
        """
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
        logger.info(f"Database initialized: {database_url}")
    
    def create_tables(self):
        """
        Create all tables in the database
        """
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            raise
    
    def drop_tables(self):
        """
        Drop all tables (use with caution!)
        """
        try:
            Base.metadata.drop_all(self.engine)
            logger.warning("All database tables dropped")
        except Exception as e:
            logger.error(f"Error dropping tables: {e}")
            raise
    
    def get_session(self):
        """
        Get a new database session
        
        Returns:
            SQLAlchemy Session
        """
        return self.SessionLocal()
    
    def close(self):
        """
        Close database connection
        """
        self.engine.dispose()
        logger.info("Database connection closed")


# Global database instance
db = None


def init_database(database_url=DATABASE_URL):
    """
    Initialize global database instance
    
    Args:
        database_url: SQLAlchemy database URL
    """
    global db
    db = Database(database_url)
    db.create_tables()
    return db
