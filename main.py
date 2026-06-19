"""
CyberShield-IDS Main Entry Point
Advanced Intrusion Detection System
"""

import logging
import sys
import time
from core.packet_sniffer import PacketSniffer
from core.protocol_analyzer import ProtocolAnalyzer
from config.settings import PROJECT_NAME, LOG_LEVEL

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """
    Print project banner
    """
    banner = f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║          🛡️  CyberShield-IDS 🛡️                          ║
    ║     Advanced Intrusion Detection System v1.0.0           ║
    ║                                                           ║
    ║        نظام كشف الاختراقات المتقدم                       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    
    Starting network monitoring...
    """
    print(banner)


def main():
    """
    Main function - runs the IDS system
    """
    print_banner()
    
    try:
        logger.info(f"Starting {PROJECT_NAME}")
        
        # Initialize components
        logger.info("Initializing packet sniffer...")
        sniffer = PacketSniffer()
        
        logger.info("Initializing protocol analyzer...")
        analyzer = ProtocolAnalyzer()
        
        # Start packet capture
        logger.info("Starting packet capture...")
        sniffer.start()
        
        # Main detection loop
        logger.info("Entering detection loop")
        alert_count = 0
        packet_count = 0
        
        print("\n" + "="*70)
        print("MONITORING NETWORK TRAFFIC - Press Ctrl+C to stop")
        print("="*70 + "\n")
        
        while True:
            # Get next packet
            packet = sniffer.get_next_packet(timeout=1)
            
            if packet:
                packet_count += 1
                
                # Analyze packet
                analysis = analyzer.analyze_packet(packet)
                summary = analyzer.get_packet_summary(packet)
                anomalies = analyzer.detect_anomalies(analysis)
                
                # Print packet info
                print(f"[{packet_count}] {summary}")
                
                # If anomalies detected, print alert
                if anomalies:
                    alert_count += 1
                    print(f"    ⚠️  ALERT #{alert_count}: {', '.join(anomalies)}")
                    logger.warning(f"Anomaly detected: {anomalies}")
                
                # Print statistics every 100 packets
                if packet_count % 100 == 0:
                    stats = sniffer.get_statistics()
                    print(f"\n[STATS] Total packets: {stats['stats']['total_packets']}, "
                          f"Alerts: {alert_count}\n")
            
            # Short sleep to prevent busy waiting
            time.sleep(0.01)
    
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
        print("\n" + "="*70)
        print("STOPPING NETWORK MONITORING")
        print("="*70)
    
    except PermissionError:
        logger.error("Permission denied! You need administrator/sudo privileges to capture packets.")
        print("\n❌ Error: You need to run this program with administrator privileges!")
        print("   On Linux/Mac: sudo python main.py")
        print("   On Windows: Run Command Prompt as Administrator, then: python main.py")
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    
    finally:
        logger.info("Cleaning up...")
        sniffer.stop()
        sniffer.print_statistics()
        print("\n✅ CyberShield-IDS stopped successfully")


if __name__ == "__main__":
    main()
