"""
GUI Dashboard for the Network Monitoring System
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import threading
import time
from datetime import datetime, timedelta
from collections import deque

class NetworkMonitorGUI:
    def __init__(self, root, network_monitor, anomaly_detector, threat_response, config_manager, logger):
        """Initialize the GUI dashboard"""
        self.root = root
        self.network_monitor = network_monitor
        self.anomaly_detector = anomaly_detector
        self.threat_response = threat_response
        self.config_manager = config_manager
        self.logger = logger
        
        # GUI state
        self.monitoring_active = True
        self.auto_refresh = True
        self.last_update = time.time()
        
        # Data for plots
        self.bandwidth_data = deque(maxlen=50)
        self.packet_data = deque(maxlen=50)
        self.connection_data = deque(maxlen=50)
        self.time_data = deque(maxlen=50)
        
        # Setup GUI
        self._setup_window()
        self._create_widgets()
        self._create_plots()
        self._setup_bindings()
        
        # Start GUI update timer
        self._start_gui_updates()
        
    def _setup_window(self):
        """Setup main window properties"""
        self.root.title("Network Security Monitor")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
    def _create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self._create_dashboard_tab()
        self._create_alerts_tab()
        self._create_connections_tab()
        self._create_config_tab()
        self._create_logs_tab()
        
    def _create_dashboard_tab(self):
        """Create main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Top status frame
        status_frame = ttk.LabelFrame(dashboard_frame, text="System Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Status indicators
        status_inner = ttk.Frame(status_frame)
        status_inner.pack(fill=tk.X)
        
        # Left status column
        left_status = ttk.Frame(status_inner)
        left_status.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.status_labels = {}
        status_items = [
            ('monitoring_status', 'Monitoring Status:', 'Active'),
            ('uptime', 'System Uptime:', '0:00:00'),
            ('total_bandwidth', 'Current Bandwidth:', '0 MB/s'),
            ('active_connections', 'Active Connections:', '0')
        ]
        
        for i, (key, label, default) in enumerate(status_items):
            row = ttk.Frame(left_status)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
            self.status_labels[key] = ttk.Label(row, text=default)
            self.status_labels[key].pack(side=tk.LEFT, padx=(10, 0))
            
        # Right status column
        right_status = ttk.Frame(status_inner)
        right_status.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        right_status_items = [
            ('alert_count', 'Active Alerts:', '0'),
            ('blocked_ips', 'Blocked IPs:', '0'),
            ('packet_rate', 'Packet Rate:', '0 pps'),
            ('threat_level', 'Threat Level:', 'Low')
        ]
        
        for i, (key, label, default) in enumerate(right_status_items):
            row = ttk.Frame(right_status)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
            self.status_labels[key] = ttk.Label(row, text=default)
            self.status_labels[key].pack(side=tk.LEFT, padx=(10, 0))
            
        # Control buttons
        control_frame = ttk.Frame(status_frame)
        control_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(control_frame, text="Start Monitoring", 
                  command=self._toggle_monitoring).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(control_frame, text="Reset Stats", 
                  command=self._reset_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Logs", 
                  command=self._export_logs).pack(side=tk.LEFT, padx=5)
        
        # Charts frame
        charts_frame = ttk.Frame(dashboard_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        self.charts_frame = charts_frame
        
    def _create_alerts_tab(self):
        """Create alerts tab"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="Alerts")
        
        # Alert summary
        summary_frame = ttk.LabelFrame(alerts_frame, text="Alert Summary", padding=10)
        summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.alert_summary_labels = {}
        summary_items = [
            ('total_alerts', 'Total Alerts:', '0'),
            ('high_severity', 'High Severity:', '0'),
            ('medium_severity', 'Medium Severity:', '0'),
            ('recent_alerts', 'Last Hour:', '0')
        ]
        
        summary_grid = ttk.Frame(summary_frame)
        summary_grid.pack(fill=tk.X)
        
        for i, (key, label, default) in enumerate(summary_items):
            row = i // 2
            col = i % 2
            
            item_frame = ttk.Frame(summary_grid)
            item_frame.grid(row=row, column=col, sticky=tk.W, padx=(0, 20), pady=2)
            
            ttk.Label(item_frame, text=label, font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
            self.alert_summary_labels[key] = ttk.Label(item_frame, text=default)
            self.alert_summary_labels[key].pack(side=tk.LEFT, padx=(10, 0))
            
        # Alert list
        list_frame = ttk.LabelFrame(alerts_frame, text="Recent Alerts", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for alerts
        columns = ('Time', 'Type', 'Severity', 'Description')
        self.alerts_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=150)
            
        # Scrollbar for alerts
        alerts_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def _create_connections_tab(self):
        """Create connections tab"""
        connections_frame = ttk.Frame(self.notebook)
        self.notebook.add(connections_frame, text="Connections")
        
        # Connection summary
        conn_summary_frame = ttk.LabelFrame(connections_frame, text="Connection Summary", padding=10)
        conn_summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.connection_summary_labels = {}
        conn_summary_items = [
            ('established', 'Established:', '0'),
            ('listening', 'Listening:', '0'),
            ('time_wait', 'Time Wait:', '0'),
            ('unique_ips', 'Unique IPs:', '0')
        ]
        
        conn_grid = ttk.Frame(conn_summary_frame)
        conn_grid.pack(fill=tk.X)
        
        for i, (key, label, default) in enumerate(conn_summary_items):
            row = i // 2
            col = i % 2
            
            item_frame = ttk.Frame(conn_grid)
            item_frame.grid(row=row, column=col, sticky=tk.W, padx=(0, 20), pady=2)
            
            ttk.Label(item_frame, text=label, font=('Arial', 9, 'bold')).pack(side=tk.LEFT)
            self.connection_summary_labels[key] = ttk.Label(item_frame, text=default)
            self.connection_summary_labels[key].pack(side=tk.LEFT, padx=(10, 0))
            
        # Active connections list
        conn_list_frame = ttk.LabelFrame(connections_frame, text="Active Connections", padding=10)
        conn_list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for connections
        conn_columns = ('Local Address', 'Remote Address', 'Status', 'Process')
        self.connections_tree = ttk.Treeview(conn_list_frame, columns=conn_columns, show='headings', height=15)
        
        for col in conn_columns:
            self.connections_tree.heading(col, text=col)
            self.connections_tree.column(col, width=150)
            
        # Scrollbar for connections
        conn_scrollbar = ttk.Scrollbar(conn_list_frame, orient=tk.VERTICAL, command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Blocked IPs frame
        blocked_frame = ttk.LabelFrame(connections_frame, text="Blocked IPs", padding=10)
        blocked_frame.pack(fill=tk.X, pady=(10, 0))
        
        blocked_inner = ttk.Frame(blocked_frame)
        blocked_inner.pack(fill=tk.X)
        
        self.blocked_ips_var = tk.StringVar(value="No blocked IPs")
        ttk.Label(blocked_inner, textvariable=self.blocked_ips_var).pack(side=tk.LEFT)
        
        ttk.Button(blocked_inner, text="Unblock All", 
                  command=self._unblock_all_ips).pack(side=tk.RIGHT)
        
    def _create_config_tab(self):
        """Create configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # Detection thresholds
        thresh_frame = ttk.LabelFrame(config_frame, text="Detection Thresholds", padding=10)
        thresh_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.config_vars = {}
        
        # Bandwidth threshold
        bw_frame = ttk.Frame(thresh_frame)
        bw_frame.pack(fill=tk.X, pady=2)
        ttk.Label(bw_frame, text="Bandwidth Threshold (std dev):").pack(side=tk.LEFT)
        self.config_vars['bandwidth_threshold'] = tk.DoubleVar(value=self.config_manager.get_bandwidth_threshold())
        ttk.Scale(bw_frame, from_=1.0, to=5.0, variable=self.config_vars['bandwidth_threshold'], 
                 orient=tk.HORIZONTAL, length=200).pack(side=tk.LEFT, padx=10)
        ttk.Label(bw_frame, textvariable=self.config_vars['bandwidth_threshold']).pack(side=tk.LEFT)
        
        # Connection threshold
        conn_frame = ttk.Frame(thresh_frame)
        conn_frame.pack(fill=tk.X, pady=2)
        ttk.Label(conn_frame, text="Connection Threshold (std dev):").pack(side=tk.LEFT)
        self.config_vars['connection_threshold'] = tk.DoubleVar(value=self.config_manager.get_connection_threshold())
        ttk.Scale(conn_frame, from_=1.0, to=5.0, variable=self.config_vars['connection_threshold'], 
                 orient=tk.HORIZONTAL, length=200).pack(side=tk.LEFT, padx=10)
        ttk.Label(conn_frame, textvariable=self.config_vars['connection_threshold']).pack(side=tk.LEFT)
        
        # Monitoring interval
        interval_frame = ttk.Frame(thresh_frame)
        interval_frame.pack(fill=tk.X, pady=2)
        ttk.Label(interval_frame, text="Monitoring Interval (seconds):").pack(side=tk.LEFT)
        self.config_vars['monitoring_interval'] = tk.IntVar(value=self.config_manager.get_monitoring_interval())
        ttk.Scale(interval_frame, from_=1, to=30, variable=self.config_vars['monitoring_interval'], 
                 orient=tk.HORIZONTAL, length=200).pack(side=tk.LEFT, padx=10)
        ttk.Label(interval_frame, textvariable=self.config_vars['monitoring_interval']).pack(side=tk.LEFT)
        
        # Auto-response settings
        response_frame = ttk.LabelFrame(config_frame, text="Response Settings", padding=10)
        response_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.auto_response_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(response_frame, text="Enable Automatic Response", 
                       variable=self.auto_response_var,
                       command=self._toggle_auto_response).pack(anchor=tk.W)
        
        # Save button
        ttk.Button(config_frame, text="Save Configuration", 
                  command=self._save_config).pack(pady=10)
        
    def _create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log controls
        controls_frame = ttk.Frame(logs_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(controls_frame, text="Refresh Logs", 
                  command=self._refresh_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(controls_frame, text="Clear Logs", 
                  command=self._clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export Logs", 
                  command=self._export_logs).pack(side=tk.LEFT, padx=5)
        
        # Log display
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25, font=('Courier', 9))
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
    def _create_plots(self):
        """Create matplotlib plots"""
        # Create figure with subplots
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.tight_layout(pad=3.0)
        
        # Setup plots
        self.ax1.set_title('Bandwidth Usage (MB/s)')
        self.ax1.set_xlabel('Time')
        self.ax1.set_ylabel('MB/s')
        
        self.ax2.set_title('Packet Rate (packets/s)')
        self.ax2.set_xlabel('Time')
        self.ax2.set_ylabel('Packets/s')
        
        self.ax3.set_title('Active Connections')
        self.ax3.set_xlabel('Time')
        self.ax3.set_ylabel('Count')
        
        self.ax4.set_title('Threat Level')
        self.ax4.set_xlabel('Time')
        self.ax4.set_ylabel('Level')
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, self.charts_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def _setup_bindings(self):
        """Setup event bindings"""
        # Bind double-click on alerts to show details
        self.alerts_tree.bind('<Double-1>', self._show_alert_details)
        
        # Bind right-click on connections for context menu
        self.connections_tree.bind('<Button-3>', self._show_connection_menu)
        
    def _start_gui_updates(self):
        """Start GUI update timer"""
        self._update_gui()
        self.root.after(1000, self._start_gui_updates)  # Update every second
        
    def update_dashboard(self, stats, anomalies):
        """Update dashboard with new data"""
        self.current_stats = stats
        self.current_anomalies = anomalies
        
    def _update_gui(self):
        """Update GUI elements"""
        try:
            if hasattr(self, 'current_stats'):
                self._update_status_labels(self.current_stats)
                self._update_plots(self.current_stats)
                
            if hasattr(self, 'current_anomalies'):
                self._update_alerts(self.current_anomalies)
                
            self._update_connections()
            self._update_blocked_ips()
            
        except Exception as e:
            self.logger.log_error(f"Error updating GUI: {str(e)}")
            
    def _update_status_labels(self, stats):
        """Update status labels"""
        try:
            # Format uptime
            uptime_seconds = int(stats.get('uptime', 0))
            hours = uptime_seconds // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Update labels
            self.status_labels['uptime'].config(text=uptime_str)
            self.status_labels['total_bandwidth'].config(
                text=f"{stats.get('total_bandwidth', 0) / 1024 / 1024:.2f} MB/s"
            )
            self.status_labels['active_connections'].config(
                text=str(stats.get('active_connections', 0))
            )
            self.status_labels['packet_rate'].config(
                text=f"{stats.get('packets_sent_rate', 0) + stats.get('packets_recv_rate', 0):.0f} pps"
            )
            
            # Update threat level based on recent anomalies
            recent_anomalies = self.anomaly_detector.get_alert_history(hours=1)
            if len(recent_anomalies) > 10:
                threat_level = "High"
            elif len(recent_anomalies) > 5:
                threat_level = "Medium"
            else:
                threat_level = "Low"
            self.status_labels['threat_level'].config(text=threat_level)
            
        except Exception as e:
            self.logger.log_error(f"Error updating status labels: {str(e)}")
            
    def _update_plots(self, stats):
        """Update real-time plots"""
        try:
            current_time = datetime.now()
            
            # Add new data points
            self.time_data.append(current_time)
            self.bandwidth_data.append(stats.get('total_bandwidth', 0) / 1024 / 1024)  # MB/s
            self.packet_data.append(stats.get('packets_sent_rate', 0) + stats.get('packets_recv_rate', 0))
            self.connection_data.append(stats.get('active_connections', 0))
            
            # Update plots
            self.ax1.clear()
            self.ax1.plot(list(self.time_data), list(self.bandwidth_data), 'b-')
            self.ax1.set_title('Bandwidth Usage (MB/s)')
            self.ax1.set_ylabel('MB/s')
            
            self.ax2.clear()
            self.ax2.plot(list(self.time_data), list(self.packet_data), 'g-')
            self.ax2.set_title('Packet Rate (packets/s)')
            self.ax2.set_ylabel('Packets/s')
            
            self.ax3.clear()
            self.ax3.plot(list(self.time_data), list(self.connection_data), 'r-')
            self.ax3.set_title('Active Connections')
            self.ax3.set_ylabel('Count')
            
            # Threat level plot (placeholder)
            threat_levels = [1] * len(self.time_data)  # Simple implementation
            self.ax4.clear()
            self.ax4.plot(list(self.time_data), threat_levels, 'orange')
            self.ax4.set_title('Threat Level')
            self.ax4.set_ylabel('Level')
            
            # Format x-axis
            for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
                ax.tick_params(axis='x', rotation=45)
                
            self.canvas.draw()
            
        except Exception as e:
            self.logger.log_error(f"Error updating plots: {str(e)}")
            
    def _update_alerts(self, anomalies):
        """Update alerts display"""
        try:
            # Update alert summary
            alert_stats = self.anomaly_detector.get_anomaly_statistics()
            
            self.alert_summary_labels['total_alerts'].config(text=str(alert_stats['total_alerts']))
            self.alert_summary_labels['high_severity'].config(
                text=str(alert_stats['alerts_by_severity'].get('high', 0))
            )
            self.alert_summary_labels['medium_severity'].config(
                text=str(alert_stats['alerts_by_severity'].get('medium', 0))
            )
            self.alert_summary_labels['recent_alerts'].config(text=str(alert_stats['recent_alerts']))
            
            # Update alerts tree (only if there are new alerts)
            if anomalies:
                for anomaly in anomalies:
                    self.alerts_tree.insert('', 0, values=(
                        anomaly['timestamp'].strftime('%H:%M:%S'),
                        anomaly['type'],
                        anomaly['severity'],
                        anomaly['description'][:50] + '...' if len(anomaly['description']) > 50 else anomaly['description']
                    ))
                    
                # Keep only last 100 alerts in display
                items = self.alerts_tree.get_children()
                if len(items) > 100:
                    for item in items[100:]:
                        self.alerts_tree.delete(item)
                        
        except Exception as e:
            self.logger.log_error(f"Error updating alerts: {str(e)}")
            
    def _update_connections(self):
        """Update connections display"""
        try:
            if hasattr(self, 'current_stats'):
                stats = self.current_stats
                
                # Update connection summary
                conn_by_status = stats.get('connections_by_status', {})
                self.connection_summary_labels['established'].config(
                    text=str(conn_by_status.get('ESTABLISHED', 0))
                )
                self.connection_summary_labels['listening'].config(
                    text=str(conn_by_status.get('LISTEN', 0))
                )
                self.connection_summary_labels['time_wait'].config(
                    text=str(conn_by_status.get('TIME_WAIT', 0))
                )
                
                # Count unique IPs
                connections = stats.get('top_connections', [])
                unique_ips = set()
                for conn in connections:
                    if 'remote_address' in conn:
                        ip = conn['remote_address'].split(':')[0]
                        unique_ips.add(ip)
                self.connection_summary_labels['unique_ips'].config(text=str(len(unique_ips)))
                
                # Update connections tree
                # Clear existing items
                for item in self.connections_tree.get_children():
                    self.connections_tree.delete(item)
                    
                # Add current connections
                for conn in connections[:20]:  # Show top 20
                    self.connections_tree.insert('', 'end', values=(
                        conn.get('local_address', 'Unknown'),
                        conn.get('remote_address', 'Unknown'),
                        conn.get('status', 'Unknown'),
                        conn.get('process_name', 'Unknown')
                    ))
                    
        except Exception as e:
            self.logger.log_error(f"Error updating connections: {str(e)}")
            
    def _update_blocked_ips(self):
        """Update blocked IPs display"""
        try:
            blocked_ips = self.threat_response.get_blocked_ips()
            if blocked_ips:
                self.blocked_ips_var.set(f"Blocked IPs: {', '.join(blocked_ips)}")
            else:
                self.blocked_ips_var.set("No blocked IPs")
                
            self.status_labels['blocked_ips'].config(text=str(len(blocked_ips)))
            
        except Exception as e:
            self.logger.log_error(f"Error updating blocked IPs: {str(e)}")
            
    def _toggle_monitoring(self):
        """Toggle monitoring on/off"""
        # This would be connected to the main monitoring system
        pass
        
    def _reset_stats(self):
        """Reset statistics"""
        if messagebox.askyesno("Reset Statistics", "Are you sure you want to reset all statistics?"):
            # Clear plot data
            self.bandwidth_data.clear()
            self.packet_data.clear()
            self.connection_data.clear()
            self.time_data.clear()
            
            # Clear alerts
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
                
            self.logger.log_info("Statistics reset by user")
            
    def _export_logs(self):
        """Export logs to file"""
        try:
            filename = f"network_monitor_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            self.logger.export_logs(filename)
            messagebox.showinfo("Export Complete", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {str(e)}")
            
    def _toggle_auto_response(self):
        """Toggle automatic response"""
        enabled = self.auto_response_var.get()
        self.threat_response.set_auto_response(enabled)
        
    def _save_config(self):
        """Save configuration changes"""
        try:
            # Update configuration
            for key, var in self.config_vars.items():
                if key == 'bandwidth_threshold':
                    self.config_manager.set_bandwidth_threshold(var.get())
                elif key == 'connection_threshold':
                    self.config_manager.set_connection_threshold(var.get())
                elif key == 'monitoring_interval':
                    self.config_manager.set_monitoring_interval(var.get())
                    
            self.config_manager.save_config()
            messagebox.showinfo("Configuration", "Configuration saved successfully")
            
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to save configuration: {str(e)}")
            
    def _show_alert_details(self, event):
        """Show detailed alert information"""
        selection = self.alerts_tree.selection()
        if selection:
            item = self.alerts_tree.item(selection[0])
            values = item['values']
            
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Alert Details")
            detail_window.geometry("500x300")
            
            details_text = scrolledtext.ScrolledText(detail_window, height=15)
            details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            details_text.insert(tk.END, f"Time: {values[0]}\n")
            details_text.insert(tk.END, f"Type: {values[1]}\n")
            details_text.insert(tk.END, f"Severity: {values[2]}\n")
            details_text.insert(tk.END, f"Description: {values[3]}\n")
            
    def _show_connection_menu(self, event):
        """Show context menu for connections"""
        selection = self.connections_tree.selection()
        if selection:
            item = self.connections_tree.item(selection[0])
            remote_addr = item['values'][1]
            
            if remote_addr and ':' in remote_addr:
                ip = remote_addr.split(':')[0]
                
                menu = tk.Menu(self.root, tearoff=0)
                menu.add_command(label=f"Block IP {ip}", 
                               command=lambda: self._block_ip_manual(ip))
                menu.add_command(label="Copy IP", 
                               command=lambda: self.root.clipboard_clear() or self.root.clipboard_append(ip))
                
                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()
                    
    def _block_ip_manual(self, ip):
        """Manually block an IP address"""
        if messagebox.askyesno("Block IP", f"Are you sure you want to block {ip}?"):
            self.threat_response.manually_block_ip(ip, reason="Manual block from GUI")
            
    def _unblock_all_ips(self):
        """Unblock all IPs"""
        if messagebox.askyesno("Unblock All", "Are you sure you want to unblock all IPs?"):
            blocked_ips = self.threat_response.get_blocked_ips()
            for ip in blocked_ips:
                self.threat_response.manually_unblock_ip(ip)
                
    def _refresh_logs(self):
        """Refresh log display"""
        try:
            logs = self.logger.get_recent_logs(1000)
            self.logs_text.delete(1.0, tk.END)
            for log_entry in logs:
                self.logs_text.insert(tk.END, log_entry + '\n')
            self.logs_text.see(tk.END)
        except Exception as e:
            self.logger.log_error(f"Error refreshing logs: {str(e)}")
            
    def _clear_logs(self):
        """Clear log display"""
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear the log display?"):
            self.logs_text.delete(1.0, tk.END)
