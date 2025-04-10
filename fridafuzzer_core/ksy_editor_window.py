import dearpygui.dearpygui as dpg
from typing import Optional, Dict, Any, List
import yaml
from .ksy_manager import KsyManager, KsyField

class KsyEditorWindow:
    """Window for editing KSY file structure"""
    
    def __init__(self, parent_widget):
        """Initialize KSY editor window"""
        self.parent = parent_widget
        self.window_tag = f"{self.parent.tag}_ksy_editor"
        self.ksy_manager = parent_widget.packet_type_manager.ksy_manager
        self.current_packet_type = None
        self.ksy_data = None
        
        # Create window
        with dpg.window(
            label="KSY Structure Editor",
            tag=self.window_tag,
            width=600,
            height=800,
            show=False,
            on_close=self.hide
        ):
            # Field list
            with dpg.group(horizontal=False):
                dpg.add_text("Fields:")
                self.fields_list = dpg.add_listbox(
                    tag=f"{self.window_tag}_fields",
                    width=-1,
                    num_items=10,
                    callback=self._on_field_selected
                )
                
            dpg.add_separator()
            
            # Field editor
            with dpg.group(horizontal=False):
                # Field ID
                dpg.add_text("Field ID:")
                self.field_id_input = dpg.add_input_text(
                    tag=f"{self.window_tag}_field_id",
                    width=-1
                )
                
                # Field type
                dpg.add_text("Field Type:")
                self.field_type_combo = dpg.add_combo(
                    tag=f"{self.window_tag}_field_type",
                    items=[
                        "u1", "u2", "u4", "u8",
                        "s1", "s2", "s4", "s8",
                        "str", "strz"
                    ],
                    width=-1
                )
                
                # Field size
                dpg.add_text("Field Size (optional):")
                self.field_size_input = dpg.add_input_int(
                    tag=f"{self.window_tag}_field_size",
                    width=-1
                )
                
                # Field documentation
                dpg.add_text("Documentation:")
                self.field_doc_input = dpg.add_input_text(
                    tag=f"{self.window_tag}_field_doc",
                    width=-1,
                    multiline=True,
                    height=100
                )
                
                # Fuzzable checkbox
                self.field_fuzzable = dpg.add_checkbox(
                    label="Mark as Fuzzable",
                    tag=f"{self.window_tag}_field_fuzzable"
                )
            
            dpg.add_separator()
            
            # Buttons
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Add Field",
                    callback=self._add_field
                )
                dpg.add_button(
                    label="Update Field",
                    callback=self._update_field
                )
                dpg.add_button(
                    label="Delete Field",
                    callback=self._delete_field
                )
                dpg.add_button(
                    label="Save Changes",
                    callback=self._save_changes
                )
    
    def show(self, packet_type: str):
        """Show the KSY editor window"""
        self.current_packet_type = packet_type
        self._load_ksy_data()
        dpg.show_item(self.window_tag)
        dpg.focus_item(self.window_tag)
        
    def hide(self):
        """Hide the KSY editor window"""
        dpg.hide_item(self.window_tag)
        
    def _load_ksy_data(self):
        """Load KSY data for current packet type"""
        if not self.current_packet_type:
            return
            
        ksy_path = self.parent.packet_type_manager.get_ksy_path(self.current_packet_type)
        if not ksy_path:
            return
            
        try:
            with open(ksy_path, 'r') as f:
                self.ksy_data = yaml.safe_load(f)
                
            # Update fields list
            field_names = [field['id'] for field in self.ksy_data.get('seq', [])]
            dpg.configure_item(self.fields_list, items=field_names)
            
        except Exception as e:
            print(f"Error loading KSY data: {e}")
            
    def _on_field_selected(self, sender, app_data):
        """Handle field selection from list"""
        if not self.ksy_data or not app_data:
            return
            
        # Find selected field
        for field in self.ksy_data.get('seq', []):
            if field['id'] == app_data:
                # Update field editor
                dpg.set_value(self.field_id_input, field['id'])
                dpg.set_value(self.field_type_combo, field.get('type', 'u1'))
                dpg.set_value(self.field_size_input, field.get('size', 0))
                dpg.set_value(self.field_doc_input, field.get('doc', ''))
                
                # Check if field is fuzzable
                is_fuzzable = field['id'] in self.ksy_data.get('meta', {}).get('fuzzable_fields', [])
                dpg.set_value(self.field_fuzzable, is_fuzzable)
                break
                
    def _add_field(self):
        """Add a new field to the KSY structure"""
        if not self.ksy_data:
            return
            
        field = KsyField(
            id=dpg.get_value(self.field_id_input),
            type=dpg.get_value(self.field_type_combo),
            size=dpg.get_value(self.field_size_input) or None,
            doc=dpg.get_value(self.field_doc_input),
            is_fuzzable=dpg.get_value(self.field_fuzzable)
        )
        
        # Add the field data directly to the loaded ksy_data first
        field_data = {
            "id": field.id,
            "type": field.type
        }
        if field.doc: field_data["doc"] = field.doc
        if field.size: field_data["size"] = field.size
        # size-eos is not handled by KsyField currently, add if needed

        if 'seq' not in self.ksy_data: self.ksy_data['seq'] = []
        self.ksy_data['seq'].append(field_data)

        # Save the changes to the file
        self._save_changes()
        
        # Now, mark as fuzzable if needed using the manager
        if field.is_fuzzable:
            self.ksy_manager.mark_field_fuzzable(self.current_packet_type, field.id)
            
        self._load_ksy_data()  # Refresh display after all changes
            
    def _update_field(self):
        """Update existing field in KSY structure"""
        if not self.ksy_data or 'seq' not in self.ksy_data:
            return
            
        selected_field_id = dpg.get_value(self.fields_list)
        if not selected_field_id:
            print("No field selected to update.")
            return

        # Find the field to update in the loaded data
        field_to_update = None
        field_index = -1
        for i, f in enumerate(self.ksy_data['seq']):
            if f['id'] == selected_field_id:
                field_to_update = f
                field_index = i
                break
        
        if field_to_update is None:
            print(f"Error: Selected field '{selected_field_id}' not found in ksy_data.")
            return

        # Get updated values from inputs
        new_id = dpg.get_value(self.field_id_input)
        new_type = dpg.get_value(self.field_type_combo)
        new_size = dpg.get_value(self.field_size_input) or None # Use None if 0
        new_doc = dpg.get_value(self.field_doc_input)
        is_fuzzable = dpg.get_value(self.field_fuzzable)

        # Basic validation
        if not new_id:
             print("Error: Field ID cannot be empty.")
             return
        # Check if ID changed and conflicts with another existing ID
        if new_id != selected_field_id and any(f['id'] == new_id for f in self.ksy_data['seq']):
             print(f"Error: Field ID '{new_id}' already exists.")
             return

        # Update the field data in the dictionary
        field_to_update['id'] = new_id
        field_to_update['type'] = new_type
        if new_size is not None:
            field_to_update['size'] = new_size
        elif 'size' in field_to_update:
            del field_to_update['size'] # Remove size if cleared
        if new_doc:
             field_to_update['doc'] = new_doc
        elif 'doc' in field_to_update:
             del field_to_update['doc'] # Remove doc if cleared
        # Note: size-eos is not currently editable here

        # Save the changes to the file
        self._save_changes()

        # Update fuzzable status using the manager
        if is_fuzzable:
            self.ksy_manager.mark_field_fuzzable(self.current_packet_type, new_id)
        else:
            # Unmark both old and new ID in case ID changed
            self.ksy_manager.unmark_field_fuzzable(self.current_packet_type, selected_field_id)
            if new_id != selected_field_id:
                 self.ksy_manager.unmark_field_fuzzable(self.current_packet_type, new_id)

        self._load_ksy_data()  # Refresh display
                
    def _delete_field(self):
        """Delete selected field from KSY structure"""
        if not self.ksy_data:
            return
            
        selected = dpg.get_value(self.fields_list)
        if not selected:
            return
            
        # Unmark field as fuzzable *before* removing it from seq
        self.ksy_manager.unmark_field_fuzzable(self.current_packet_type, selected)
        
        # Remove field from seq in the loaded data
        if 'seq' in self.ksy_data:
            self.ksy_data['seq'] = [f for f in self.ksy_data['seq'] if f['id'] != selected]
        # No need to manually remove from fuzzable list here, manager handles it
            
        self._save_changes()
        self._load_ksy_data()  # Refresh display
        
    def _save_changes(self):
        """Save changes to KSY file"""
        if not self.ksy_data or not self.current_packet_type:
            return
            
        ksy_path = self.parent.packet_type_manager.get_ksy_path(self.current_packet_type)
        if not ksy_path:
            return
            
        try:
            with open(ksy_path, 'w') as f:
                yaml.dump(self.ksy_data, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving KSY data: {e}")