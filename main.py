#!/usr/bin/env python3
"""
Main entry point for the Network Monitoring System
"""

import tkinter as tk
from tkinter import messagebox
import sys
import os
import threading
import time

from gui_dashboard import NetworkMonitorGUI
from network_monitor import NetworkMonitor
from anomaly_detector import AnomalyDetector
from threat_response import ThreatResponse
from config_manager import ConfigManager
from logger import SecurityLogger

class NetworkMonitoringSystem:
    def __init__(self):
        """Initialize the network monitoring system"""
        self.config_manager = ConfigManager()
        self.logger = SecurityLogger()
        self.network_monitor = NetworkMonitor(self.logger)
        self.anomaly_detector = AnomalyDetector(self.config_manager, self.logger)
        self.threat_response = ThreatResponse(self.logger)
        
        # Initialize GUI
        self.root = tk.Tk()
        self.gui = NetworkMonitorGUI(
            self.root,
            self.network_monitor,
            self.anomaly_detector,
            self.threat_response,
            self.config_manager,
            self.logger
        )
        
        # Start monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None
        
    def start_monitoring(self):
        """Start the network monitoring process"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            self.logger.log_info("Network monitoring started")
            
    def stop_monitoring(self):
        """Stop the network monitoring process"""
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2)
        self.logger.log_info("Network monitoring stopped")
        
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Get current network stats
                stats = self.network_monitor.get_current_stats()
                
                # Check for anomalies
                anomalies = self.anomaly_detector.detect_anomalies(stats)
                
                # Process any detected threats
                for anomaly in anomalies:
                    self.threat_response.handle_threat(anomaly)
                
                # Update GUI with new data
                self.gui.update_dashboard(stats, anomalies)
                
                # Sleep for configured interval
                time.sleep(self.config_manager.get_monitoring_interval())
                
            except Exception as e:
                self.logger.log_error(f"Error in monitoring loop: {str(e)}")
                time.sleep(5)  # Wait before retrying
                
    def run(self):
        """Run the application"""
        try:
            # Start monitoring automatically
            self.start_monitoring()
            
            # Configure window close event
            self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
            
            # Start GUI main loop
            self.root.mainloop()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start application: {str(e)}")
            self.logger.log_error(f"Application startup error: {str(e)}")
            
    def _on_closing(self):
        """Handle application closing"""
        try:
            self.stop_monitoring()
            self.root.destroy()
        except Exception as e:
            print(f"Error during shutdown: {e}")
            
if __name__ == "__main__":
    try:
        app = NetworkMonitoringSystem()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
