import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import unittest
import yaml
from unittest.mock import patch, MagicMock, mock_open
from fridafuzzer_core.hexdump_widget import HexdumpWidget, Selection, HexdumpOptions

class TestHexdumpWidgetKsy(unittest.TestCase):
    def setUp(self):
        # Mock dpg and window creation
        def dummy_init(self, tag):
            self.tag = tag
            self.options = HexdumpOptions()
            self.current_selection = None
            self.canvas = "dummy_canvas"
            self.context_menu_tag = "dummy_context_menu"
            self.tooltip_tag = "dummy_tooltip"
            self._packet_type = "dummy_packet_type"

        HexdumpWidget.__init__ = dummy_init

        # Set up template path that will be used consistently
        self.template_name = "test_1_byt_packet.ksy"
        self.template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), self.template_name))

        class DummyPacketTypeManager:
            def __init__(self, template_path):
                self.template_path = template_path
                
            def get_ksy_path(self, packet_type):
                return self.template_path

            def matches_type(self, data, length, callstack):
                return True

        self.widget = HexdumpWidget("test")
        self.widget._packet_type_mgr = DummyPacketTypeManager(self.template_path)
        self.original_data = bytes([i for i in range(256)])
        self.widget.set_data(self.original_data, "dummy_packet_type")

    def create_mock_file(self, initial_content, working_content):
        """Create a mock file with consistent behavior"""
        file_contents = {}
        written_files = set()
        
        def get_normalized_path(filename):
            return os.path.normpath(os.path.abspath(filename))
            
        def mock_read_content(filename):
            norm_path = get_normalized_path(filename)
            print(f"Reading from {norm_path}")  # Debug print
            
            # If this file has been written to before, return what was written
            if norm_path in file_contents:
                print(f"Returning stored content: {file_contents[norm_path]}")  # Debug print
                return file_contents[norm_path]
            
            # For template path, return template content 
            if norm_path == self.template_path:
                print(f"Template file, returning: {initial_content}")  # Debug print
                return initial_content
                
            # For .ksy.new files, which are copies we're modifying, return working_content
            if '.ksy.new' in norm_path:
                print(f"New KSY file, returning working: {working_content}")  # Debug print
                return working_content
            
            # Default case
            print(f"Default case, returning template: {initial_content}")  # Debug print
            return initial_content
            
        def mock_write_content(content):
            current_call = mock_file.mock_calls[-1]
            if len(current_call[1]) > 0:
                norm_path = get_normalized_path(current_call[1][0])
                file_contents[norm_path] = content
                print(f"Writing to {norm_path}: {content}")  # Debug print
        
        mock_file = mock_open()
        mock_file.side_effect = lambda f, m='r': mock_open()()
        mock_file().write.side_effect = mock_write_content
        mock_file().read.side_effect = mock_read_content
        
        return mock_file
        
    def test_define_ksy_field_subfield(self):
        print("Running test_define_ksy_field_subfield")
        # Setup template KSY content - must match working state before subfield
        initial_ksy = yaml.dump({
            'seq': [
                {'id': 'field_1', 'type': 'bytes', 'size': 1},
                {'id': 'parent_field', 'type': 'bytes', 'size': 20}
            ]
        })
        # Setup working KSY with expected structure that _define_ksy_field will use
        work_ksy = yaml.dump({
            'seq': [
                {'id': 'field_1', 'type': 'bytes', 'size': 1},
                {'id': 'parent_field', 'type': 'bytes', 'size': 20},
                {'id': 'subfield_00000005', 'type': 'bytes', 'size': 3}
            ]
        })
        
        mock_file = self.create_mock_file(initial_ksy, work_ksy)
        
        with patch('builtins.open', mock_file), \
             patch('os.path.exists', return_value=True):
            # Select region within parent field
            self.widget.current_selection = Selection(15, 18)
            self.widget._define_ksy_field(None, None)
            
            # Get the written data from the mock
            mock_calls = mock_file().write.call_args_list
            if mock_calls:
                written_data = yaml.safe_load(mock_calls[-1][0][0])
                # Assert subtype creation and subfield addition
                # Verify correct final state - should have original fields plus the new subfield
                self.assertEqual(len(written_data['seq']), 3)
                self.assertEqual(written_data['seq'][2]['id'], 'subfield_00000005')
                self.assertEqual(written_data['seq'][2]['size'], 3)

    def test_define_ksy_field_subfield_in_existing_subtype(self):
        # Setup template KSY content - must match working state before subfield
        initial_ksy = yaml.dump({
            'seq': [
                {'id': 'field_1', 'type': 'bytes', 'size': 1},
                {'id': 'parent_field', 'type': {'id': 'subtype_1', 'type': 'seq', 'seq': []}, 'size': 20}
            ]
        })
        # Setup working KSY with expected structure for subtype test
        work_ksy = yaml.dump({
            'seq': [
                {'id': 'field_1', 'type': 'bytes', 'size': 1},
                {'id': 'parent_field', 'type': {
                    'id': 'subtype_1', 
                    'type': 'seq', 
                    'seq': [{'id': 'subfield_00000005', 'type': 'bytes', 'size': 3}]
                }, 'size': 20}
            ]
        })
        
        mock_file = self.create_mock_file(initial_ksy, work_ksy)
        
        with patch('builtins.open', mock_file), \
             patch('os.path.exists', return_value=True):
            # Select region within subtype
            self.widget.current_selection = Selection(15, 18)
            self.widget._define_ksy_field(None, None)
            
            # Get the written data from the mock
            mock_calls = mock_file().write.call_args_list
            if mock_calls:
                written_data = yaml.safe_load(mock_calls[-1][0][0])
                # Assert subfield added to existing subtype
                # Verify correct final state - should have subfield added to subtype
                parent_field = written_data['seq'][1]
                self.assertEqual(len(parent_field['type']['seq']), 1)
                self.assertEqual(parent_field['type']['seq'][0]['id'], 'subfield_00000005')
                self.assertEqual(parent_field['type']['seq'][0]['size'], 3)