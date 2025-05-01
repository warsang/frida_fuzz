import dearpygui.dearpygui as dpg
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import time
from enum import Enum

class LogLevel(Enum):
    """Enum for log levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

@dataclass
class LogEntry:
    """
    Dataclass for storing log information
    
    Attributes:
        timestamp: When the log entry was created
        level: Log level (INFO, WARNING, ERROR)
        message: The log message content
        packet_id: Optional reference to a specific packet
        sequence_id: Optional reference to a sequence
        additional_data: Optional dictionary for any extra information
    """
    timestamp: float
    level: LogLevel
    message: str
    packet_id: Optional[str] = None
    sequence_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None

class RepeaterConsoleWindow:
    """
    Window for displaying logs of packets sent/received using the repeater tab
    
    This window can be toggled open/closed from the Repeater tab and displays
    logs with timestamps, log levels, and packet/sequence references.
    """
    def __init__(self, tag: str = "repeater_console_window", max_logs: int = 1000):
        """
        Initialize the console window
        
        Args:
            tag: Unique tag for the window
            max_logs: Maximum number of logs to keep (for log rotation)
        """
        self.tag = tag
        self.max_logs = max_logs
        self.logs: List[LogEntry] = []
        self.window_visible = False
        
        # Create the window but don't show it initially
        with dpg.window(label="Repeater Console", show=False, tag=self.tag, width=800, height=600):
            # Add controls at the top
            with dpg.group(horizontal=True):
                dpg.add_button(label="Clear Logs", callback=self.clear_logs)
                dpg.add_checkbox(label="Auto-scroll", default_value=True, tag=f"{self.tag}_autoscroll")
            
            # Add separator
            dpg.add_separator()
            
            # Add log display area
            dpg.add_child_window(tag=f"{self.tag}_log_area", width=-1, height=-1)
    
    def toggle_visibility(self):
        """Toggle the visibility of the console window"""
        self.window_visible = not self.window_visible
        dpg.configure_item(self.tag, show=self.window_visible)
        
        # If showing the window, update the log display
        if self.window_visible:
            self._update_log_display()
    
    def add_log(self, level: LogLevel, message: str, packet_id: Optional[str] = None, 
                sequence_id: Optional[str] = None, additional_data: Optional[Dict[str, Any]] = None):
        """
        Add a log entry to the console
        
        Args:
            level: Log level (INFO, WARNING, ERROR)
            message: The log message
            packet_id: Optional ID of the related packet
            sequence_id: Optional ID of the related sequence
            additional_data: Optional dictionary with additional data
        """
        # Create log entry
        log_entry = LogEntry(
            timestamp=time.time(),
            level=level,
            message=message,
            packet_id=packet_id,
            sequence_id=sequence_id,
            additional_data=additional_data
        )
        
        # Add to logs list with rotation if needed
        self.logs.append(log_entry)
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        
        # Update the UI if window is visible
        if self.window_visible:
            self._update_log_display()
    
    def clear_logs(self):
        """Clear all logs"""
        self.logs = []
        self._update_log_display()
    
    def _update_log_display(self):
        """Update the log display in the UI"""
        # Clear existing logs
        dpg.delete_item(f"{self.tag}_log_area", children_only=True)
        
        # Add logs to display
        for log in self.logs:
            # Format timestamp
            timestamp_str = time.strftime("%H:%M:%S", time.localtime(log.timestamp))
            
            # Format log entry
            log_text = f"[{timestamp_str}] [{log.level.value}] {log.message}"
            if log.packet_id:
                log_text += f" (Packet: {log.packet_id})"
            if log.sequence_id:
                log_text += f" (Sequence: {log.sequence_id})"
            
            # Add to UI with appropriate color based on log level
            if log.level == LogLevel.ERROR:
                dpg.add_text(log_text, color=(255, 0, 0), parent=f"{self.tag}_log_area")
            elif log.level == LogLevel.WARNING:
                dpg.add_text(log_text, color=(255, 255, 0), parent=f"{self.tag}_log_area")
            else:
                dpg.add_text(log_text, parent=f"{self.tag}_log_area")
        
        # Auto-scroll to bottom if enabled
        if dpg.get_value(f"{self.tag}_autoscroll"):
            dpg.set_y_scroll(f"{self.tag}_log_area", -1.0)