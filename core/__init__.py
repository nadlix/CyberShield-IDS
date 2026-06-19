"""
Core module for CyberShield-IDS
Handles packet capture, analysis, and detection
"""

__version__ = "1.0.0"
__author__ = "CyberShield Team"

from .packet_sniffer import PacketSniffer
from .protocol_analyzer import ProtocolAnalyzer

__all__ = [
    'PacketSniffer',
    'ProtocolAnalyzer',
]
