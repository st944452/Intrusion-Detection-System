"""
Network monitoring module for real-time traffic analysis
"""

import psutil
import socket
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json

class NetworkMonitor:
    def __init__(self, logger):
        """Initialize network monitor"""
        self.logger = logger
        self.stats_history = deque(maxlen=1000)  # Keep last 1000 readings
        self.connection_counts = defaultdict(int)
        self.bandwidth_history = deque(maxlen=100)
        self.packet_history = deque(maxlen=100)
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.last_packets_sent = 0
        self.last_packets_recv = 0
        self.start_time = time.time()
        
        # Initialize baseline stats
        self._initialize_baseline()
        
    def _initialize_baseline(self):
        """Initialize baseline network statistics"""
        try:
            net_io = psutil.net_io_counters()
            self.last_bytes_sent = net_io.bytes_sent
            self.last_bytes_recv = net_io.bytes_recv
            self.last_packets_sent = net_io.packets_sent
            self.last_packets_recv = net_io.packets_recv
        except Exception as e:
            self.logger.log_error(f"Failed to initialize baseline: {str(e)}")
            
    def get_current_stats(self):
        """Get current network statistics"""
        try:
            current_time = time.time()
            
            # Get network I/O counters
            net_io = psutil.net_io_counters()
            
            # Calculate rates (bytes/second)
            time_diff = current_time - getattr(self, 'last_check_time', current_time - 1)
            
            bytes_sent_rate = (net_io.bytes_sent - self.last_bytes_sent) / time_diff if time_diff > 0 else 0
            bytes_recv_rate = (net_io.bytes_recv - self.last_bytes_recv) / time_diff if time_diff > 0 else 0
            packets_sent_rate = (net_io.packets_sent - self.last_packets_sent) / time_diff if time_diff > 0 else 0
            packets_recv_rate = (net_io.packets_recv - self.last_packets_recv) / time_diff if time_diff > 0 else 0
            
            # Get active connections
            connections = self._get_active_connections()
            
            # Get network interfaces
            interfaces = self._get_interface_stats()
            
            stats = {
                'timestamp': datetime.now(),
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'bytes_sent_rate': bytes_sent_rate,
                'bytes_recv_rate': bytes_recv_rate,
                'packets_sent_rate': packets_sent_rate,
                'packets_recv_rate': packets_recv_rate,
                'total_bandwidth': bytes_sent_rate + bytes_recv_rate,
                'active_connections': len(connections),
                'connections_by_status': self._count_connections_by_status(connections),
                'connections_by_port': self._count_connections_by_port(connections),
                'top_connections': connections[:10],  # Top 10 connections
                'interfaces': interfaces,
                'uptime': current_time - self.start_time
            }
            
            # Update history
            self.stats_history.append(stats)
            self.bandwidth_history.append(stats['total_bandwidth'])
            self.packet_history.append(stats['packets_sent_rate'] + stats['packets_recv_rate'])
            
            # Update last values
            self.last_bytes_sent = net_io.bytes_sent
            self.last_bytes_recv = net_io.bytes_recv
            self.last_packets_sent = net_io.packets_sent
            self.last_packets_recv = net_io.packets_recv
            self.last_check_time = current_time
            
            return stats
            
        except Exception as e:
            self.logger.log_error(f"Error getting network stats: {str(e)}")
            return self._get_empty_stats()
            
    def _get_active_connections(self):
        """Get list of active network connections"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connection_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown",
                        'status': conn.status,
                        'pid': conn.pid,
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6'
                    }
                    
                    # Try to get process name
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            connection_info['process_name'] = process.name()
                        else:
                            connection_info['process_name'] = 'Unknown'
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        connection_info['process_name'] = 'Unknown'
                        
                    connections.append(connection_info)
                    
            return connections
            
        except Exception as e:
            self.logger.log_error(f"Error getting active connections: {str(e)}")
            return []
            
    def _get_interface_stats(self):
        """Get statistics for network interfaces"""
        try:
            interfaces = {}
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            
            for interface, stats in net_if_stats.items():
                interface_info = {
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu,
                    'addresses': []
                }
                
                # Get IP addresses for this interface
                if interface in net_if_addrs:
                    for addr in net_if_addrs[interface]:
                        if addr.family == socket.AF_INET:  # IPv4
                            interface_info['addresses'].append({
                                'type': 'IPv4',
                                'address': addr.address,
                                'netmask': addr.netmask
                            })
                        elif addr.family == socket.AF_INET6:  # IPv6
                            interface_info['addresses'].append({
                                'type': 'IPv6',
                                'address': addr.address,
                                'netmask': addr.netmask
                            })
                            
                interfaces[interface] = interface_info
                
            return interfaces
            
        except Exception as e:
            self.logger.log_error(f"Error getting interface stats: {str(e)}")
            return {}
            
    def _count_connections_by_status(self, connections):
        """Count connections by status"""
        status_counts = defaultdict(int)
        try:
            for conn in psutil.net_connections(kind='inet'):
                status_counts[conn.status] += 1
        except Exception as e:
            self.logger.log_error(f"Error counting connections by status: {str(e)}")
        return dict(status_counts)
        
    def _count_connections_by_port(self, connections):
        """Count connections by local port"""
        port_counts = defaultdict(int)
        for conn in connections:
            try:
                if ':' in conn['local_address']:
                    port = conn['local_address'].split(':')[-1]
                    port_counts[port] += 1
            except Exception:
                continue
        return dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
    def _get_empty_stats(self):
        """Return empty stats structure for error cases"""
        return {
            'timestamp': datetime.now(),
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
            'bytes_sent_rate': 0,
            'bytes_recv_rate': 0,
            'packets_sent_rate': 0,
            'packets_recv_rate': 0,
            'total_bandwidth': 0,
            'active_connections': 0,
            'connections_by_status': {},
            'connections_by_port': {},
            'top_connections': [],
            'interfaces': {},
            'uptime': 0
        }
        
    def get_stats_history(self, minutes=60):
        """Get historical stats for the specified number of minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [stat for stat in self.stats_history if stat['timestamp'] >= cutoff_time]
        
    def get_bandwidth_history(self):
        """Get bandwidth history for plotting"""
        return list(self.bandwidth_history)
        
    def get_packet_history(self):
        """Get packet rate history for plotting"""
        return list(self.packet_history)
