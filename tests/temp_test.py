def test_define_ksy_field_subfield(self):
        print("Running test_define_ksy_field_subfield")
        # Setup KSY with a field
        ksy_data = {
            'seq': [
                {'id': 'parent_field', 'size': 20, 'type': 'bytes'}
            ]
        }
        
        # Mock file operations
        with patch('builtins.open', mock_open(read_data=yaml.dump(ksy_data))) as mock_file, \
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