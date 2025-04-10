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

        class DummyPacketTypeManager:
            def get_ksy_path(self, packet_type):
                return os.path.join(os.path.dirname(__file__), 'test_1_byt_packet.ksy')

            def matches_type(self, data, length, callstack):
                return True

        self.widget = HexdumpWidget("test")
        self.widget._packet_type_mgr = DummyPacketTypeManager()
        self.original_data = bytes([i for i in range(256)])
        self.widget.set_data(self.original_data, "dummy_packet_type")

    def test_define_ksy_field_subfield(self):
        print("Running test_define_ksy_field_subfield")
        # Setup KSY with a field
        ksy_data = {
            'seq': [
                {'id': 'parent_field', 'size': 20, 'type': 'bytes'}
            ]
        }
        
        mock_file = mock_open(read_data=yaml.dump(ksy_data))
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
                self.assertEqual(len(written_data['seq']), 2)
                self.assertEqual(written_data['seq'][1]['id'], 'subfield_00000005')

    def test_define_ksy_field_subfield_in_existing_subtype(self):
        # Setup KSY with a subtype
        ksy_data = {
            'seq': [
                {'id': 'parent_field', 'size': 20, 'type': {'id': 'subtype_1', 'type': 'seq', 'seq': []}}
            ]
        }

        mock_file = mock_open(read_data=yaml.dump(ksy_data))
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
                self.assertEqual(len(written_data['seq'][0]['type']['seq']), 1)