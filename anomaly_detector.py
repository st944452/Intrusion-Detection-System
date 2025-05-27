"""
Anomaly detection module for identifying suspicious network activity
"""

import statistics
import time
from collections import deque, defaultdict
from datetime import datetime, timedelta
import math

class AnomalyDetector:
    def __init__(self, config_manager, logger):
        """Initialize anomaly detector"""
        self.config_manager = config_manager
        self.logger = logger
        self.baseline_data = {
            'bandwidth': deque(maxlen=100),
            'packets': deque(maxlen=100),
            'connections': deque(maxlen=100)
        }
        self.connection_tracking = defaultdict(list)
        self.blocked_ips = set()
        self.alert_history = deque(maxlen=1000)
        
    def detect_anomalies(self, stats):
        """Detect anomalies in network statistics"""
        anomalies = []
        
        try:
            # Update baseline data
            self._update_baseline(stats)
            
            # Check for bandwidth anomalies
            bandwidth_anomaly = self._check_bandwidth_anomaly(stats)
            if bandwidth_anomaly:
                anomalies.append(bandwidth_anomaly)
                
            # Check for connection anomalies
            connection_anomaly = self._check_connection_anomaly(stats)
            if connection_anomaly:
                anomalies.append(connection_anomaly)
                
            # Check for packet rate anomalies
            packet_anomaly = self._check_packet_anomaly(stats)
            if packet_anomaly:
                anomalies.append(packet_anomaly)
                
            # Check for suspicious connections
            suspicious_connections = self._check_suspicious_connections(stats)
            anomalies.extend(suspicious_connections)
            
            # Check for port scanning
            port_scan_anomaly = self._check_port_scanning(stats)
            if port_scan_anomaly:
                anomalies.append(port_scan_anomaly)
                
            # Log detected anomalies
            for anomaly in anomalies:
                self.logger.log_threat(f"Anomaly detected: {anomaly['type']} - {anomaly['description']}")
                self.alert_history.append({
                    'timestamp': datetime.now(),
                    'anomaly': anomaly
                })
                
        except Exception as e:
            self.logger.log_error(f"Error detecting anomalies: {str(e)}")
            
        return anomalies
        
    def _update_baseline(self, stats):
        """Update baseline statistics"""
        self.baseline_data['bandwidth'].append(stats['total_bandwidth'])
        self.baseline_data['packets'].append(stats['packets_sent_rate'] + stats['packets_recv_rate'])
        self.baseline_data['connections'].append(stats['active_connections'])
        
    def _check_bandwidth_anomaly(self, stats):
        """Check for unusual bandwidth usage"""
        if len(self.baseline_data['bandwidth']) < 10:
            return None
            
        try:
            current_bandwidth = stats['total_bandwidth']
            baseline_values = list(self.baseline_data['bandwidth'])
            
            if len(baseline_values) < 5:
                return None
                
            mean_bandwidth = statistics.mean(baseline_values)
            stdev_bandwidth = statistics.stdev(baseline_values) if len(baseline_values) > 1 else 0
            
            # Configure thresholds
            threshold_multiplier = self.config_manager.get_bandwidth_threshold()
            threshold = mean_bandwidth + (threshold_multiplier * stdev_bandwidth)
            
            if current_bandwidth > threshold and current_bandwidth > 1024 * 1024:  # > 1MB/s
                severity = 'high' if current_bandwidth > threshold * 2 else 'medium'
                return {
                    'type': 'bandwidth_spike',
                    'severity': severity,
                    'description': f'Unusual bandwidth usage: {current_bandwidth/1024/1024:.2f} MB/s (threshold: {threshold/1024/1024:.2f} MB/s)',
                    'current_value': current_bandwidth,
                    'threshold': threshold,
                    'timestamp': datetime.now(),
                    'source': 'bandwidth_monitor'
                }
                
        except Exception as e:
            self.logger.log_error(f"Error checking bandwidth anomaly: {str(e)}")
            
        return None
        
    def _check_connection_anomaly(self, stats):
        """Check for unusual number of connections"""
        if len(self.baseline_data['connections']) < 10:
            return None
            
        try:
            current_connections = stats['active_connections']
            baseline_values = list(self.baseline_data['connections'])
            
            if len(baseline_values) < 5:
                return None
                
            mean_connections = statistics.mean(baseline_values)
            stdev_connections = statistics.stdev(baseline_values) if len(baseline_values) > 1 else 0
            
            threshold_multiplier = self.config_manager.get_connection_threshold()
            threshold = mean_connections + (threshold_multiplier * stdev_connections)
            
            if current_connections > threshold and current_connections > 50:
                severity = 'high' if current_connections > threshold * 2 else 'medium'
                return {
                    'type': 'connection_spike',
                    'severity': severity,
                    'description': f'Unusual number of connections: {current_connections} (threshold: {threshold:.0f})',
                    'current_value': current_connections,
                    'threshold': threshold,
                    'timestamp': datetime.now(),
                    'source': 'connection_monitor'
                }
                
        except Exception as e:
            self.logger.log_error(f"Error checking connection anomaly: {str(e)}")
            
        return None
        
    def _check_packet_anomaly(self, stats):
        """Check for unusual packet rates"""
        if len(self.baseline_data['packets']) < 10:
            return None
            
        try:
            current_packets = stats['packets_sent_rate'] + stats['packets_recv_rate']
            baseline_values = list(self.baseline_data['packets'])
            
            if len(baseline_values) < 5:
                return None
                
            mean_packets = statistics.mean(baseline_values)
            stdev_packets = statistics.stdev(baseline_values) if len(baseline_values) > 1 else 0
            
            threshold_multiplier = self.config_manager.get_packet_threshold()
            threshold = mean_packets + (threshold_multiplier * stdev_packets)
            
            if current_packets > threshold and current_packets > 1000:  # > 1000 packets/s
                severity = 'high' if current_packets > threshold * 2 else 'medium'
                return {
                    'type': 'packet_rate_spike',
                    'severity': severity,
                    'description': f'Unusual packet rate: {current_packets:.0f} packets/s (threshold: {threshold:.0f})',
                    'current_value': current_packets,
                    'threshold': threshold,
                    'timestamp': datetime.now(),
                    'source': 'packet_monitor'
                }
                
        except Exception as e:
            self.logger.log_error(f"Error checking packet anomaly: {str(e)}")
            
        return None
        
    def _check_suspicious_connections(self, stats):
        """Check for suspicious connection patterns"""
        anomalies = []
        
        try:
            for connection in stats['top_connections']:
                remote_ip = connection['remote_address'].split(':')[0]
                
                # Skip local/private IP addresses
                if self._is_private_ip(remote_ip):
                    continue
                    
                # Track connection frequency
                current_time = time.time()
                self.connection_tracking[remote_ip].append(current_time)
                
                # Clean old entries (older than 5 minutes)
                self.connection_tracking[remote_ip] = [
                    t for t in self.connection_tracking[remote_ip] 
                    if current_time - t < 300
                ]
                
                # Check for rapid connections from same IP
                recent_connections = len(self.connection_tracking[remote_ip])
                if recent_connections > self.config_manager.get_max_connections_per_ip():
                    anomalies.append({
                        'type': 'rapid_connections',
                        'severity': 'high',
                        'description': f'Rapid connections from {remote_ip}: {recent_connections} in 5 minutes',
                        'source_ip': remote_ip,
                        'connection_count': recent_connections,
                        'timestamp': datetime.now(),
                        'source': 'connection_analyzer'
                    })
                    
        except Exception as e:
            self.logger.log_error(f"Error checking suspicious connections: {str(e)}")
            
        return anomalies
        
    def _check_port_scanning(self, stats):
        """Check for potential port scanning activity"""
        try:
            # Analyze connections by port to detect scanning
            port_counts = stats.get('connections_by_port', {})
            
            # Check for connections to many different ports
            if len(port_counts) > self.config_manager.get_max_ports_per_scan():
                total_connections = sum(port_counts.values())
                return {
                    'type': 'port_scanning',
                    'severity': 'high',
                    'description': f'Potential port scanning detected: {len(port_counts)} different ports accessed',
                    'port_count': len(port_counts),
                    'total_connections': total_connections,
                    'timestamp': datetime.now(),
                    'source': 'port_scanner_detector'
                }
                
        except Exception as e:
            self.logger.log_error(f"Error checking port scanning: {str(e)}")
            
        return None
        
    def _is_private_ip(self, ip):
        """Check if IP address is private/local"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
                
            first = int(octets[0])
            second = int(octets[1])
            
            # Check private IP ranges
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True
            elif ip.startswith('127.'):
                return True
                
        except (ValueError, IndexError):
            pass
            
        return False
        
    def get_alert_history(self, hours=24):
        """Get alert history for specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            alert for alert in self.alert_history 
            if alert['timestamp'] >= cutoff_time
        ]
        
    def get_anomaly_statistics(self):
        """Get statistics about detected anomalies"""
        if not self.alert_history:
            return {
                'total_alerts': 0,
                'alerts_by_type': {},
                'alerts_by_severity': {},
                'recent_alerts': 0
            }
            
        total_alerts = len(self.alert_history)
        alerts_by_type = defaultdict(int)
        alerts_by_severity = defaultdict(int)
        
        recent_cutoff = datetime.now() - timedelta(hours=1)
        recent_alerts = 0
        
        for alert in self.alert_history:
            anomaly = alert['anomaly']
            alerts_by_type[anomaly['type']] += 1
            alerts_by_severity[anomaly['severity']] += 1
            
            if alert['timestamp'] >= recent_cutoff:
                recent_alerts += 1
                
        return {
            'total_alerts': total_alerts,
            'alerts_by_type': dict(alerts_by_type),
            'alerts_by_severity': dict(alerts_by_severity),
            'recent_alerts': recent_alerts
        }
