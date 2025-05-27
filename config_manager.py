"""
Configuration management for the Network Monitoring System
"""

import json
import os
from datetime import datetime

class ConfigManager:
    def __init__(self, config_file='config.json'):
        """Initialize configuration manager"""
        self.config_file = config_file
        self.default_config = {
            'monitoring': {
                'interval': 5,  # seconds
                'history_size': 1000,
                'enable_auto_response': True
            },
            'thresholds': {
                'bandwidth_threshold': 2.0,  # standard deviations
                'connection_threshold': 2.5,
                'packet_threshold': 2.0,
                'max_connections_per_ip': 20,
                'max_ports_per_scan': 15
            },
            'response': {
                'auto_block_duration': 3600,  # seconds
                'response_cooldown': 60,
                'max_blocked_ips': 1000
            },
            'logging': {
                'log_level': 'INFO',
                'max_log_size': 10485760,  # 10MB
                'log_retention_days': 30
            },
            'network': {
                'monitor_interfaces': 'all',
                'capture_packets': False,
                'deep_packet_inspection': False
            }
        }
        
        self.config = self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    
                # Merge with defaults to ensure all keys exist
                config = self.default_config.copy()
                self._deep_update(config, loaded_config)
                return config
            else:
                # Create default config file
                self.save_config()
                return self.default_config.copy()
                
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return self.default_config.copy()
            
    def save_config(self):
        """Save configuration to file"""
        try:
            self.config['metadata'] = {
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
                
        except Exception as e:
            print(f"Error saving config: {e}")
            
    def _deep_update(self, base_dict, update_dict):
        """Recursively update nested dictionary"""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
                
    # Monitoring settings
    def get_monitoring_interval(self):
        """Get monitoring interval in seconds"""
        return self.config['monitoring']['interval']
        
    def set_monitoring_interval(self, interval):
        """Set monitoring interval"""
        self.config['monitoring']['interval'] = max(1, int(interval))
        
    def get_history_size(self):
        """Get history buffer size"""
        return self.config['monitoring']['history_size']
        
    def is_auto_response_enabled(self):
        """Check if auto response is enabled"""
        return self.config['monitoring']['enable_auto_response']
        
    def set_auto_response_enabled(self, enabled):
        """Enable/disable auto response"""
        self.config['monitoring']['enable_auto_response'] = bool(enabled)
        
    # Threshold settings
    def get_bandwidth_threshold(self):
        """Get bandwidth anomaly threshold (standard deviations)"""
        return self.config['thresholds']['bandwidth_threshold']
        
    def set_bandwidth_threshold(self, threshold):
        """Set bandwidth threshold"""
        self.config['thresholds']['bandwidth_threshold'] = max(0.5, float(threshold))
        
    def get_connection_threshold(self):
        """Get connection anomaly threshold (standard deviations)"""
        return self.config['thresholds']['connection_threshold']
        
    def set_connection_threshold(self, threshold):
        """Set connection threshold"""
        self.config['thresholds']['connection_threshold'] = max(0.5, float(threshold))
        
    def get_packet_threshold(self):
        """Get packet rate anomaly threshold (standard deviations)"""
        return self.config['thresholds']['packet_threshold']
        
    def set_packet_threshold(self, threshold):
        """Set packet threshold"""
        self.config['thresholds']['packet_threshold'] = max(0.5, float(threshold))
        
    def get_max_connections_per_ip(self):
        """Get maximum connections per IP before triggering alert"""
        return self.config['thresholds']['max_connections_per_ip']
        
    def set_max_connections_per_ip(self, max_connections):
        """Set max connections per IP"""
        self.config['thresholds']['max_connections_per_ip'] = max(1, int(max_connections))
        
    def get_max_ports_per_scan(self):
        """Get maximum ports per scan before triggering alert"""
        return self.config['thresholds']['max_ports_per_scan']
        
    def set_max_ports_per_scan(self, max_ports):
        """Set max ports per scan"""
        self.config['thresholds']['max_ports_per_scan'] = max(1, int(max_ports))
        
    # Response settings
    def get_auto_block_duration(self):
        """Get auto block duration in seconds"""
        return self.config['response']['auto_block_duration']
        
    def set_auto_block_duration(self, duration):
        """Set auto block duration"""
        self.config['response']['auto_block_duration'] = max(60, int(duration))
        
    def get_response_cooldown(self):
        """Get response cooldown period in seconds"""
        return self.config['response']['response_cooldown']
        
    def set_response_cooldown(self, cooldown):
        """Set response cooldown"""
        self.config['response']['response_cooldown'] = max(10, int(cooldown))
        
    def get_max_blocked_ips(self):
        """Get maximum number of IPs to block"""
        return self.config['response']['max_blocked_ips']
        
    # Logging settings
    def get_log_level(self):
        """Get logging level"""
        return self.config['logging']['log_level']
        
    def set_log_level(self, level):
        """Set logging level"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level.upper() in valid_levels:
            self.config['logging']['log_level'] = level.upper()
            
    def get_max_log_size(self):
        """Get maximum log file size in bytes"""
        return self.config['logging']['max_log_size']
        
    def get_log_retention_days(self):
        """Get log retention period in days"""
        return self.config['logging']['log_retention_days']
        
    # Network settings
    def get_monitor_interfaces(self):
        """Get interfaces to monitor"""
        return self.config['network']['monitor_interfaces']
        
    def set_monitor_interfaces(self, interfaces):
        """Set interfaces to monitor"""
        self.config['network']['monitor_interfaces'] = interfaces
        
    def is_packet_capture_enabled(self):
        """Check if packet capture is enabled"""
        return self.config['network']['capture_packets']
        
    def set_packet_capture_enabled(self, enabled):
        """Enable/disable packet capture"""
        self.config['network']['capture_packets'] = bool(enabled)
        
    def is_deep_packet_inspection_enabled(self):
        """Check if deep packet inspection is enabled"""
        return self.config['network']['deep_packet_inspection']
        
    def set_deep_packet_inspection_enabled(self, enabled):
        """Enable/disable deep packet inspection"""
        self.config['network']['deep_packet_inspection'] = bool(enabled)
        
    # Utility methods
    def get_all_config(self):
        """Get complete configuration"""
        return self.config.copy()
        
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.default_config.copy()
        self.save_config()
        
    def validate_config(self):
        """Validate current configuration"""
        errors = []
        
        # Validate monitoring settings
        if self.config['monitoring']['interval'] < 1:
            errors.append("Monitoring interval must be at least 1 second")
            
        if self.config['monitoring']['history_size'] < 10:
            errors.append("History size must be at least 10")
            
        # Validate thresholds
        for threshold_key in ['bandwidth_threshold', 'connection_threshold', 'packet_threshold']:
            if self.config['thresholds'][threshold_key] < 0.5:
                errors.append(f"{threshold_key} must be at least 0.5")
                
        # Validate response settings
        if self.config['response']['auto_block_duration'] < 60:
            errors.append("Auto block duration must be at least 60 seconds")
            
        if self.config['response']['response_cooldown'] < 10:
            errors.append("Response cooldown must be at least 10 seconds")
            
        return errors
        
    def export_config(self, filename):
        """Export configuration to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error exporting config: {e}")
            return False
            
    def import_config(self, filename):
        """Import configuration from file"""
        try:
            with open(filename, 'r') as f:
                imported_config = json.load(f)
                
            # Validate imported config
            temp_config = self.default_config.copy()
            self._deep_update(temp_config, imported_config)
            
            # If validation passes, update current config
            self.config = temp_config
            self.save_config()
            return True
            
        except Exception as e:
            print(f"Error importing config: {e}")
            return False
