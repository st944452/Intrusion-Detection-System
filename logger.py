"""
Logging system for the Network Monitoring System
"""

import logging
import os
import time
from datetime import datetime, timedelta
from collections import deque
import json

class SecurityLogger:
    def __init__(self, log_dir='logs'):
        """Initialize security logger"""
        self.log_dir = log_dir
        self.ensure_log_directory()
        
        # In-memory log buffer for GUI display
        self.log_buffer = deque(maxlen=1000)
        
        # Setup file logging
        self.setup_file_logging()
        
        # Setup different log levels
        self.logger = logging.getLogger('NetworkMonitor')
        self.security_logger = logging.getLogger('Security')
        self.threat_logger = logging.getLogger('Threats')
        
    def ensure_log_directory(self):
        """Create log directory if it doesn't exist"""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
        except Exception as e:
            print(f"Error creating log directory: {e}")
            
    def setup_file_logging(self):
        """Setup file-based logging"""
        try:
            # Main application log
            main_log_file = os.path.join(self.log_dir, 'network_monitor.log')
            main_handler = logging.FileHandler(main_log_file)
            main_handler.setLevel(logging.INFO)
            main_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            main_handler.setFormatter(main_formatter)
            
            # Security events log
            security_log_file = os.path.join(self.log_dir, 'security_events.log')
            security_handler = logging.FileHandler(security_log_file)
            security_handler.setLevel(logging.WARNING)
            security_formatter = logging.Formatter(
                '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
            )
            security_handler.setFormatter(security_formatter)
            
            # Threat detection log
            threat_log_file = os.path.join(self.log_dir, 'threats.log')
            threat_handler = logging.FileHandler(threat_log_file)
            threat_handler.setLevel(logging.ERROR)
            threat_formatter = logging.Formatter(
                '%(asctime)s - THREAT - %(levelname)s - %(message)s'
            )
            threat_handler.setFormatter(threat_formatter)
            
            # Configure loggers
            main_logger = logging.getLogger('NetworkMonitor')
            main_logger.setLevel(logging.INFO)
            main_logger.addHandler(main_handler)
            
            security_logger = logging.getLogger('Security')
            security_logger.setLevel(logging.WARNING)
            security_logger.addHandler(security_handler)
            security_logger.addHandler(main_handler)  # Also log to main
            
            threat_logger = logging.getLogger('Threats')
            threat_logger.setLevel(logging.ERROR)
            threat_logger.addHandler(threat_handler)
            threat_logger.addHandler(security_handler)  # Also log to security
            threat_logger.addHandler(main_handler)  # Also log to main
            
        except Exception as e:
            print(f"Error setting up file logging: {e}")
            
    def _add_to_buffer(self, level, message):
        """Add log entry to in-memory buffer"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}"
        self.log_buffer.append(log_entry)
        
    def log_info(self, message):
        """Log informational message"""
        try:
            self.logger.info(message)
            self._add_to_buffer('INFO', message)
        except Exception as e:
            print(f"Error logging info: {e}")
            
    def log_warning(self, message):
        """Log warning message"""
        try:
            self.logger.warning(message)
            self._add_to_buffer('WARNING', message)
        except Exception as e:
            print(f"Error logging warning: {e}")
            
    def log_error(self, message):
        """Log error message"""
        try:
            self.logger.error(message)
            self._add_to_buffer('ERROR', message)
        except Exception as e:
            print(f"Error logging error: {e}")
            
    def log_security(self, message):
        """Log security event"""
        try:
            self.security_logger.warning(message)
            self._add_to_buffer('SECURITY', message)
        except Exception as e:
            print(f"Error logging security event: {e}")
            
    def log_threat(self, message):
        """Log threat detection"""
        try:
            self.threat_logger.error(message)
            self._add_to_buffer('THREAT', message)
        except Exception as e:
            print(f"Error logging threat: {e}")
            
    def log_network_stats(self, stats):
        """Log network statistics"""
        try:
            stats_message = (
                f"Network Stats - "
                f"Bandwidth: {stats.get('total_bandwidth', 0) / 1024 / 1024:.2f} MB/s, "
                f"Connections: {stats.get('active_connections', 0)}, "
                f"Packets: {stats.get('packets_sent_rate', 0) + stats.get('packets_recv_rate', 0):.0f} pps"
            )
            self.log_info(stats_message)
        except Exception as e:
            self.log_error(f"Error logging network stats: {e}")
            
    def log_anomaly_detection(self, anomaly):
        """Log anomaly detection with detailed information"""
        try:
            anomaly_message = (
                f"Anomaly Detected - "
                f"Type: {anomaly.get('type', 'Unknown')}, "
                f"Severity: {anomaly.get('severity', 'Unknown')}, "
                f"Description: {anomaly.get('description', 'No description')}, "
                f"Source: {anomaly.get('source', 'Unknown')}"
            )
            
            if anomaly.get('severity') == 'high':
                self.log_threat(anomaly_message)
            else:
                self.log_security(anomaly_message)
                
        except Exception as e:
            self.log_error(f"Error logging anomaly: {e}")
            
    def log_response_action(self, action, target, result):
        """Log automated response action"""
        try:
            response_message = (
                f"Response Action - "
                f"Action: {action}, "
                f"Target: {target}, "
                f"Result: {result}, "
                f"Timestamp: {datetime.now().isoformat()}"
            )
            self.log_security(response_message)
        except Exception as e:
            self.log_error(f"Error logging response action: {e}")
            
    def get_recent_logs(self, count=100):
        """Get recent log entries from buffer"""
        try:
            return list(self.log_buffer)[-count:]
        except Exception as e:
            self.log_error(f"Error getting recent logs: {e}")
            return []
            
    def get_logs_by_level(self, level, hours=24):
        """Get logs by level within time period"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            filtered_logs = []
            
            for log_entry in self.log_buffer:
                if level.upper() in log_entry:
                    # Extract timestamp and check if within time period
                    try:
                        timestamp_str = log_entry.split(']')[0][1:]
                        log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        if log_time >= cutoff_time:
                            filtered_logs.append(log_entry)
                    except:
                        # If timestamp parsing fails, include the log
                        filtered_logs.append(log_entry)
                        
            return filtered_logs
        except Exception as e:
            self.log_error(f"Error filtering logs by level: {e}")
            return []
            
    def get_security_events(self, hours=24):
        """Get security events within time period"""
        security_logs = self.get_logs_by_level('SECURITY', hours)
        threat_logs = self.get_logs_by_level('THREAT', hours)
        return security_logs + threat_logs
        
    def export_logs(self, filename=None):
        """Export logs to file"""
        try:
            if filename is None:
                filename = f"exported_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                
            with open(filename, 'w') as f:
                f.write(f"Network Monitor Logs - Exported at {datetime.now().isoformat()}\n")
                f.write("=" * 80 + "\n\n")
                
                for log_entry in self.log_buffer:
                    f.write(log_entry + "\n")
                    
            self.log_info(f"Logs exported to {filename}")
            return filename
            
        except Exception as e:
            self.log_error(f"Error exporting logs: {e}")
            return None
            
    def clear_old_logs(self, days=30):
        """Clear log files older than specified days"""
        try:
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log'):
                    file_path = os.path.join(self.log_dir, filename)
                    if os.path.getmtime(file_path) < cutoff_time:
                        os.remove(file_path)
                        self.log_info(f"Removed old log file: {filename}")
                        
        except Exception as e:
            self.log_error(f"Error clearing old logs: {e}")
            
    def get_log_statistics(self):
        """Get logging statistics"""
        try:
            stats = {
                'total_logs': len(self.log_buffer),
                'info_logs': len(self.get_logs_by_level('INFO', 24)),
                'warning_logs': len(self.get_logs_by_level('WARNING', 24)),
                'error_logs': len(self.get_logs_by_level('ERROR', 24)),
                'security_logs': len(self.get_logs_by_level('SECURITY', 24)),
                'threat_logs': len(self.get_logs_by_level('THREAT', 24))
            }
            
            # Get log file sizes
            stats['log_files'] = {}
            for filename in ['network_monitor.log', 'security_events.log', 'threats.log']:
                file_path = os.path.join(self.log_dir, filename)
                if os.path.exists(file_path):
                    stats['log_files'][filename] = os.path.getsize(file_path)
                    
            return stats
            
        except Exception as e:
            self.log_error(f"Error getting log statistics: {e}")
            return {}
            
    def search_logs(self, search_term, case_sensitive=False):
        """Search logs for specific term"""
        try:
            results = []
            
            for log_entry in self.log_buffer:
                if case_sensitive:
                    if search_term in log_entry:
                        results.append(log_entry)
                else:
                    if search_term.lower() in log_entry.lower():
                        results.append(log_entry)
                        
            return results
            
        except Exception as e:
            self.log_error(f"Error searching logs: {e}")
            return []
            
    def log_system_startup(self):
        """Log system startup information"""
        try:
            startup_info = {
                'timestamp': datetime.now().isoformat(),
                'system': 'Network Security Monitor',
                'version': '1.0',
                'log_directory': self.log_dir
            }
            
            self.log_info(f"System startup: {json.dumps(startup_info)}")
            
        except Exception as e:
            print(f"Error logging system startup: {e}")
            
    def log_system_shutdown(self):
        """Log system shutdown information"""
        try:
            shutdown_info = {
                'timestamp': datetime.now().isoformat(),
                'system': 'Network Security Monitor',
                'total_logs_generated': len(self.log_buffer)
            }
            
            self.log_info(f"System shutdown: {json.dumps(shutdown_info)}")
            
        except Exception as e:
            print(f"Error logging system shutdown: {e}")
