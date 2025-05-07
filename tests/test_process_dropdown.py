import unittest
from unittest.mock import patch, MagicMock, call
import sys
import os

# Add the parent directory to sys.path to import app and frida_handler
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dearpygui.dearpygui as dpg
from fridafuzzer_core import frida_handler
import app

class TestProcessDropdown(unittest.TestCase):
    """Test cases for the process selection dropdown feature."""
    
    def setUp(self):
        """Set up test environment before each test."""
        # Mock dpg functions
        self.dpg_patcher = patch('app.dpg')
        self.mock_dpg = self.dpg_patcher.start()
        
        # Reset global variables in app.py
        app.is_running = False
        app.target_process = ""
        app.process_map = {}
        
    def tearDown(self):
        """Clean up after each test."""
        self.dpg_patcher.stop()
    
    @patch('fridafuzzer_core.frida_handler.get_process_list')
    def test_populate_process_dropdown_success(self, mock_get_process_list):
        """Test that the dropdown is populated with a sorted list of processes."""
        # Mock the return value of get_process_list
        mock_process_list = [
            ("chrome", 1234, "chrome (1234)"),
            ("firefox", 5678, "firefox (5678)"),
            ("app", 9012, "app (9012)")
        ]
        mock_get_process_list.return_value = mock_process_list
        
        # Call the function
        result = app.populate_process_dropdown()
        
        # Verify the result
        self.assertTrue(result)
        
        # Verify process_map was populated correctly
        self.assertEqual(app.process_map, {
            "chrome (1234)": 1234,
            "firefox (5678)": 5678,
            "app (9012)": 9012
        })
        
        # Verify the dropdown was configured with the display strings
        self.mock_dpg.configure_item.assert_called_with(
            "process_dropdown", 
            items=["app (9012)", "chrome (1234)", "firefox (5678)"]
        )
        
        # Verify a default selection was set
        self.mock_dpg.set_value.assert_called_with(
            "process_dropdown", 
            ["app (9012)", "chrome (1234)", "firefox (5678)"][0]
        )
    
    @patch('fridafuzzer_core.frida_handler.get_process_list')
    def test_populate_process_dropdown_empty_list(self, mock_get_process_list):
        """Test behavior when get_process_list returns an empty list."""
        # Mock an empty process list
        mock_get_process_list.return_value = []
        
        # Call the function
        result = app.populate_process_dropdown()
        
        # Verify the result
        self.assertFalse(result)
        
        # Verify the dropdown was configured with an error message
        self.mock_dpg.configure_item.assert_called_with(
            "process_dropdown", 
            items=["No processes found or Frida error"]
        )
    
    @patch('fridafuzzer_core.frida_handler.get_process_list')
    def test_populate_process_dropdown_exception(self, mock_get_process_list):
        """Test behavior when get_process_list raises an exception."""
        # Mock an exception
        mock_get_process_list.side_effect = Exception("Test exception")
        
        # Call the function
        result = app.populate_process_dropdown()
        
        # Verify the result
        self.assertFalse(result)
        
        # Verify the dropdown was configured with an error message
        self.mock_dpg.configure_item.assert_called_with(
            "process_dropdown", 
            items=["Error loading processes"]
        )
    
    def test_refresh_process_list_success(self):
        """Test that the refresh button updates the process list."""
        # Mock populate_process_dropdown to return True and populate process_map
        with patch('app.populate_process_dropdown') as mock_populate:
            mock_populate.return_value = True
            app.process_map = {"test (123)": 123}
            
            # Call the function
            app.refresh_process_list(None, None)
            
            # Verify the refresh button was disabled during refresh
            self.mock_dpg.configure_item.assert_any_call("refresh_button", enabled=False)
            
            # Verify populate_process_dropdown was called
            mock_populate.assert_called_once()
            
            # Verify the refresh button was re-enabled after refresh
            self.mock_dpg.configure_item.assert_any_call("refresh_button", enabled=True)
            
            # Verify the status message was updated
            self.mock_dpg.set_value.assert_called_with("status", "Process list refreshed")
    
    def test_refresh_process_list_empty(self):
        """Test refresh when process list is empty."""
        # Mock populate_process_dropdown to return True but empty process_map
        with patch('app.populate_process_dropdown') as mock_populate:
            mock_populate.return_value = True
            app.process_map = {}
            
            # Call the function
            app.refresh_process_list(None, None)
            
            # Verify the status message indicates empty list
            self.mock_dpg.set_value.assert_called_with(
                "status", 
                "Process list refreshed (empty or Frida error)"
            )
    
    def test_refresh_process_list_failure(self):
        """Test refresh when populate_process_dropdown fails."""
        # Mock populate_process_dropdown to return False
        with patch('app.populate_process_dropdown') as mock_populate:
            mock_populate.return_value = False
            
            # Call the function
            app.refresh_process_list(None, None)
            
            # Verify the status message indicates failure
            self.mock_dpg.set_value.assert_called_with(
                "status", 
                "Failed to refresh process list"
            )
    
    @patch('fridafuzzer_core.frida_handler.start_frida')
    def test_start_intercepting_success(self, mock_start_frida):
        """Test starting interception with a valid process selection."""
        # Mock successful Frida start
        mock_start_frida.return_value = True
        
        # Set up process map and dropdown selection
        app.process_map = {"test (123)": 123}
        self.mock_dpg.get_value.return_value = "test (123)"
        
        # Call the function
        app.start_intercepting(None, None)
        
        # Verify Frida was started with the correct PID
        mock_start_frida.assert_called_with(123, app.message_queue)
        
        # Verify is_running was set to True
        self.assertTrue(app.is_running)
        
        # Verify target_process was set
        self.assertEqual(app.target_process, 123)
        
        # Verify UI was updated correctly
        self.mock_dpg.set_value.assert_called_with("status", "Running: Intercepting test (123)")
        self.mock_dpg.configure_item.assert_any_call("start_button", enabled=False)
        self.mock_dpg.configure_item.assert_any_call("stop_button", enabled=True)
        self.mock_dpg.configure_item.assert_any_call("process_dropdown", enabled=False)
        self.mock_dpg.configure_item.assert_any_call("refresh_button", enabled=False)
    
    def test_start_intercepting_no_selection(self):
        """Test starting interception with no process selected."""
        # Mock no selection in dropdown
        self.mock_dpg.get_value.return_value = None
        
        # Call the function
        app.start_intercepting(None, None)
        
        # Verify error message was displayed
        self.mock_dpg.set_value.assert_called_with(
            "status", 
            "No process selected or error in list."
        )
        
        # Verify is_running remains False
        self.assertFalse(app.is_running)
    
    def test_start_intercepting_error_selection(self):
        """Test starting interception with an error message selected."""
        # Mock error selection in dropdown
        self.mock_dpg.get_value.return_value = "No processes found or Frida error"
        
        # Call the function
        app.start_intercepting(None, None)
        
        # Verify error message was displayed
        self.mock_dpg.set_value.assert_called_with(
            "status", 
            "No process selected or error in list."
        )
        
        # Verify is_running remains False
        self.assertFalse(app.is_running)
    
    def test_start_intercepting_invalid_selection(self):
        """Test starting interception with a selection not in the process map."""
        # Set up process map and invalid dropdown selection
        app.process_map = {"test (123)": 123}
        self.mock_dpg.get_value.return_value = "invalid (456)"
        
        # Call the function
        app.start_intercepting(None, None)
        
        # Verify error message was displayed
        self.mock_dpg.set_value.assert_called_with(
            "status", 
            "Selected process PID not found. Try refreshing."
        )
        
        # Verify is_running remains False
        self.assertFalse(app.is_running)
    
    @patch('fridafuzzer_core.frida_handler.stop_frida')
    def test_stop_intercepting(self, mock_stop_frida):
        """Test stopping interception."""
        # Set up running state
        app.is_running = True
        
        # Call the function
        app.stop_intercepting(None, None)
        
        # Verify Frida was stopped
        mock_stop_frida.assert_called_once()
        
        # Verify is_running was set to False
        self.assertFalse(app.is_running)
        
        # Verify UI was updated correctly
        self.mock_dpg.set_value.assert_called_with("status", "Stopped")
        self.mock_dpg.configure_item.assert_any_call("start_button", enabled=True)
        self.mock_dpg.configure_item.assert_any_call("stop_button", enabled=False)
        self.mock_dpg.configure_item.assert_any_call("process_dropdown", enabled=True)
        self.mock_dpg.configure_item.assert_any_call("refresh_button", enabled=True)
    
    @patch('frida.get_local_device')
    def test_frida_handler_get_process_list(self, mock_get_local_device):
        """Test the get_process_list function in frida_handler."""
        # Create mock processes
        mock_process1 = MagicMock()
        mock_process1.name = "chrome"
        mock_process1.pid = 1234
        
        mock_process2 = MagicMock()
        mock_process2.name = "firefox"
        mock_process2.pid = 5678
        
        mock_process3 = MagicMock()
        mock_process3.name = "app"
        mock_process3.pid = 9012
        
        # Set up the mock device
        mock_device = MagicMock()
        mock_device.enumerate_processes.return_value = [mock_process1, mock_process2, mock_process3]
        mock_get_local_device.return_value = mock_device
        
        # Call the function
        result = frida_handler.get_process_list()
        
        # Verify the result is sorted alphabetically by process name
        expected = [
            ("app", 9012, "app (9012)"),
            ("chrome", 1234, "chrome (1234)"),
            ("firefox", 5678, "firefox (5678)")
        ]
        self.assertEqual(result, expected)
    
    @patch('frida.get_local_device')
    def test_frida_handler_get_process_list_transport_error(self, mock_get_local_device):
        """Test get_process_list when a TransportError occurs."""
        # Mock a TransportError
        import frida
        mock_get_local_device.side_effect = frida.TransportError("Test transport error")
        
        # Call the function
        result = frida_handler.get_process_list()
        
        # Verify an empty list is returned
        self.assertEqual(result, [])
    
    @patch('frida.get_local_device')
    def test_frida_handler_get_process_list_general_exception(self, mock_get_local_device):
        """Test get_process_list when a general exception occurs."""
        # Mock a general exception
        mock_get_local_device.side_effect = Exception("Test exception")
        
        # Call the function
        result = frida_handler.get_process_list()
        
        # Verify an empty list is returned
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main()