"""
Automated threat response module for handling detected security threats
"""

import subprocess
import platform
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict
import json

class ThreatResponse:
    def __init__(self, logger):
        """Initialize threat response system"""
        self.logger = logger
        self.blocked_ips = set()
        self.response_history = []
        self.auto_response_enabled = True
        self.response_counts = defaultdict(int)
        self.last_response_time = defaultdict(float)
        
        # Rate limiting for responses (prevent response flooding)
        self.response_cooldown = 60  # 60 seconds between same type responses
        
    def handle_threat(self, anomaly):
        """Handle detected threat with appropriate response"""
        try:
            threat_type = anomaly['type']
            severity = anomaly.get('severity', 'medium')
            
            # Check if auto-response is enabled
            if not self.auto_response_enabled:
                self.logger.log_info(f"Auto-response disabled, logging threat: {threat_type}")
                return
                
            # Check rate limiting
            current_time = time.time()
            if current_time - self.last_response_time[threat_type] < self.response_cooldown:
                self.logger.log_info(f"Response rate limited for {threat_type}")
                return
                
            self.last_response_time[threat_type] = current_time
            
            # Choose response based on threat type and severity
            response_actions = []
            
            if threat_type == 'rapid_connections':
                response_actions = self._handle_rapid_connections(anomaly)
            elif threat_type == 'bandwidth_spike':
                response_actions = self._handle_bandwidth_spike(anomaly)
            elif threat_type == 'port_scanning':
                response_actions = self._handle_port_scanning(anomaly)
            elif threat_type == 'connection_spike':
                response_actions = self._handle_connection_spike(anomaly)
            elif threat_type == 'packet_rate_spike':
                response_actions = self._handle_packet_spike(anomaly)
            else:
                response_actions = self._handle_generic_threat(anomaly)
                
            # Execute response actions
            for action in response_actions:
                self._execute_response_action(action, anomaly)
                
            # Record response
            self._record_response(anomaly, response_actions)
            
        except Exception as e:
            self.logger.log_error(f"Error handling threat: {str(e)}")
            
    def _handle_rapid_connections(self, anomaly):
        """Handle rapid connection threats"""
        actions = []
        source_ip = anomaly.get('source_ip')
        
        if source_ip and source_ip not in self.blocked_ips:
            actions.append({
                'type': 'block_ip',
                'target': source_ip,
                'duration': 3600,  # 1 hour
                'reason': f"Rapid connections: {anomaly.get('connection_count', 0)} connections"
            })
            
        actions.append({
            'type': 'log_security_event',
            'priority': 'high',
            'details': anomaly
        })
        
        actions.append({
            'type': 'send_alert',
            'message': f"Rapid connections detected from {source_ip}",
            'severity': anomaly.get('severity', 'medium')
        })
        
        return actions
        
    def _handle_bandwidth_spike(self, anomaly):
        """Handle bandwidth spike threats"""
        actions = []
        
        # Log the event
        actions.append({
            'type': 'log_security_event',
            'priority': 'medium',
            'details': anomaly
        })
        
        # If severe, implement bandwidth limiting
        if anomaly.get('severity') == 'high':
            actions.append({
                'type': 'limit_bandwidth',
                'limit': '50%',
                'duration': 600  # 10 minutes
            })
            
        actions.append({
            'type': 'send_alert',
            'message': f"High bandwidth usage detected: {anomaly.get('current_value', 0)/1024/1024:.2f} MB/s",
            'severity': anomaly.get('severity', 'medium')
        })
        
        return actions
        
    def _handle_port_scanning(self, anomaly):
        """Handle port scanning threats"""
        actions = []
        
        # This is a serious threat - block and alert
        actions.append({
            'type': 'log_security_event',
            'priority': 'high',
            'details': anomaly
        })
        
        actions.append({
            'type': 'increase_monitoring',
            'duration': 1800  # 30 minutes
        })
        
        actions.append({
            'type': 'send_alert',
            'message': f"Port scanning detected: {anomaly.get('port_count', 0)} ports accessed",
            'severity': 'high'
        })
        
        return actions
        
    def _handle_connection_spike(self, anomaly):
        """Handle connection spike threats"""
        actions = []
        
        actions.append({
            'type': 'log_security_event',
            'priority': 'medium',
            'details': anomaly
        })
        
        if anomaly.get('severity') == 'high':
            actions.append({
                'type': 'limit_connections',
                'max_connections': 100,
                'duration': 300  # 5 minutes
            })
            
        actions.append({
            'type': 'send_alert',
            'message': f"Connection spike detected: {anomaly.get('current_value', 0)} active connections",
            'severity': anomaly.get('severity', 'medium')
        })
        
        return actions
        
    def _handle_packet_spike(self, anomaly):
        """Handle packet rate spike threats"""
        actions = []
        
        actions.append({
            'type': 'log_security_event',
            'priority': 'medium',
            'details': anomaly
        })
        
        actions.append({
            'type': 'send_alert',
            'message': f"High packet rate detected: {anomaly.get('current_value', 0):.0f} packets/s",
            'severity': anomaly.get('severity', 'medium')
        })
        
        return actions
        
    def _handle_generic_threat(self, anomaly):
        """Handle generic/unknown threats"""
        actions = []
        
        actions.append({
            'type': 'log_security_event',
            'priority': 'low',
            'details': anomaly
        })
        
        actions.append({
            'type': 'send_alert',
            'message': f"Security anomaly detected: {anomaly.get('description', 'Unknown threat')}",
            'severity': anomaly.get('severity', 'low')
        })
        
        return actions
        
    def _execute_response_action(self, action, anomaly):
        """Execute a specific response action"""
        try:
            action_type = action['type']
            
            if action_type == 'block_ip':
                self._block_ip(action['target'], action.get('duration', 3600), action.get('reason', ''))
            elif action_type == 'log_security_event':
                self._log_security_event(action['details'], action.get('priority', 'medium'))
            elif action_type == 'send_alert':
                self._send_alert(action['message'], action.get('severity', 'medium'))
            elif action_type == 'limit_bandwidth':
                self._limit_bandwidth(action.get('limit', '50%'), action.get('duration', 600))
            elif action_type == 'limit_connections':
                self._limit_connections(action.get('max_connections', 100), action.get('duration', 300))
            elif action_type == 'increase_monitoring':
                self._increase_monitoring(action.get('duration', 1800))
            else:
                self.logger.log_warning(f"Unknown response action: {action_type}")
                
        except Exception as e:
            self.logger.log_error(f"Error executing response action {action_type}: {str(e)}")
            
    def _block_ip(self, ip_address, duration, reason):
        """Block an IP address using system firewall"""
        try:
            if ip_address in self.blocked_ips:
                self.logger.log_info(f"IP {ip_address} already blocked")
                return
                
            system = platform.system().lower()
            
            if system == 'linux':
                # Use iptables on Linux
                cmd = f"iptables -I INPUT -s {ip_address} -j DROP"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    self.logger.log_security(f"Blocked IP {ip_address} for {duration}s: {reason}")
                    
                    # Schedule unblock (in a real implementation, you'd use a proper scheduler)
                    # For now, just log the unblock time
                    unblock_time = datetime.now() + timedelta(seconds=duration)
                    self.logger.log_info(f"IP {ip_address} scheduled for unblock at {unblock_time}")
                else:
                    self.logger.log_error(f"Failed to block IP {ip_address}: {result.stderr}")
                    
            elif system == 'windows':
                # Use Windows Firewall on Windows
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip_address}" dir=in action=block remoteip={ip_address}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    self.logger.log_security(f"Blocked IP {ip_address} for {duration}s: {reason}")
                else:
                    self.logger.log_error(f"Failed to block IP {ip_address}: {result.stderr}")
            else:
                self.logger.log_warning(f"IP blocking not implemented for {system}")
                
        except subprocess.SubprocessError as e:
            self.logger.log_error(f"Subprocess error blocking IP {ip_address}: {str(e)}")
        except Exception as e:
            self.logger.log_error(f"Error blocking IP {ip_address}: {str(e)}")
            
    def _unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            if ip_address not in self.blocked_ips:
                return
                
            system = platform.system().lower()
            
            if system == 'linux':
                cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.remove(ip_address)
                    self.logger.log_security(f"Unblocked IP {ip_address}")
                    
            elif system == 'windows':
                cmd = f'netsh advfirewall firewall delete rule name="Block_{ip_address}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.remove(ip_address)
                    self.logger.log_security(f"Unblocked IP {ip_address}")
                    
        except Exception as e:
            self.logger.log_error(f"Error unblocking IP {ip_address}: {str(e)}")
            
    def _log_security_event(self, details, priority):
        """Log security event with details"""
        self.logger.log_security(f"Security event ({priority}): {json.dumps(details, default=str)}")
        
    def _send_alert(self, message, severity):
        """Send alert notification"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{severity.upper()}] {timestamp}: {message}"
        
        self.logger.log_security(alert_msg)
        
        # In a real implementation, you might send emails, SMS, or push notifications
        print(f"SECURITY ALERT: {alert_msg}")
        
    def _limit_bandwidth(self, limit, duration):
        """Implement bandwidth limiting (placeholder)"""
        self.logger.log_info(f"Bandwidth limiting activated: {limit} for {duration}s")
        # This would require implementing actual traffic shaping
        
    def _limit_connections(self, max_connections, duration):
        """Implement connection limiting (placeholder)"""
        self.logger.log_info(f"Connection limiting activated: max {max_connections} for {duration}s")
        # This would require implementing actual connection limiting
        
    def _increase_monitoring(self, duration):
        """Increase monitoring sensitivity (placeholder)"""
        self.logger.log_info(f"Increased monitoring activated for {duration}s")
        # This would involve adjusting monitoring thresholds
        
    def _record_response(self, anomaly, actions):
        """Record response in history"""
        response_record = {
            'timestamp': datetime.now(),
            'anomaly': anomaly,
            'actions': actions,
            'response_count': len(actions)
        }
        
        self.response_history.append(response_record)
        self.response_counts[anomaly['type']] += 1
        
        # Keep only last 1000 responses
        if len(self.response_history) > 1000:
            self.response_history = self.response_history[-1000:]
            
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)
        
    def manually_block_ip(self, ip_address, duration=3600, reason="Manual block"):
        """Manually block an IP address"""
        self._block_ip(ip_address, duration, reason)
        
    def manually_unblock_ip(self, ip_address):
        """Manually unblock an IP address"""
        self._unblock_ip(ip_address)
        
    def get_response_statistics(self):
        """Get response statistics"""
        total_responses = len(self.response_history)
        recent_responses = len([
            r for r in self.response_history 
            if datetime.now() - r['timestamp'] < timedelta(hours=24)
        ])
        
        return {
            'total_responses': total_responses,
            'recent_responses': recent_responses,
            'responses_by_type': dict(self.response_counts),
            'blocked_ips_count': len(self.blocked_ips),
            'auto_response_enabled': self.auto_response_enabled
        }
        
    def set_auto_response(self, enabled):
        """Enable or disable automatic responses"""
        self.auto_response_enabled = enabled
        self.logger.log_info(f"Auto-response {'enabled' if enabled else 'disabled'}")
