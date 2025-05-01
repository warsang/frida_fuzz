"""
Packet Types Editor Module for Frida Network Interceptor
Handles the creation, editing, and management of packet types
"""

import dearpygui.dearpygui as dpg
from fridafuzzer_core.packet_type_manager import PacketTypeManager, PacketTypeCriteria

# Shared state
packet_type_manager = None
sequences = None

def initialize(shared_packet_type_manager, shared_sequences):
    """Initialize the packet types editor module with shared resources"""
    global packet_type_manager, sequences
    packet_type_manager = shared_packet_type_manager
    sequences = shared_sequences

def create_packet_type(sender, app_data):
    """Create a new packet type from form data"""
    try:
        name = dpg.get_value("type_name_input").strip()
        description = dpg.get_value("type_description_input").strip()
        hex_value = dpg.get_value("type_hex_value_input").strip()
        hex_offset = dpg.get_value("type_hex_offset_input")
        packet_size = dpg.get_value("type_size_input")
        callstack = dpg.get_value("type_callstack_input").strip()

        if not name:
            return

        # Create criteria object
        criteria = PacketTypeCriteria(
            hex_value=hex_value if hex_value else None,
            hex_offset=hex_offset if hex_offset != 0 else None,
            packet_size=packet_size if packet_size != 0 else None,
            callstack=callstack if callstack else None
        )

        # Create the type
        if packet_type_manager.create_type(name, description, criteria):
            # Clear form
            dpg.set_value("type_name_input", "")
            dpg.set_value("type_description_input", "")
            dpg.set_value("type_hex_value_input", "")
            dpg.set_value("type_hex_offset_input", 0)
            dpg.set_value("type_size_input", 0)
            dpg.set_value("type_callstack_input", "")
            
            # Update existing sequences with the new type
            update_existing_sequences_types()
            
            # Update UI
            update_packet_types_list()
            from fridafuzzer_core.main_view import update_sequences_list
            update_sequences_list()
    except Exception as e:
        print(f"Error creating packet type: {e}")
        import traceback
        print(traceback.format_exc())

def delete_packet_type(sender, app_data, user_data):
    """Delete a packet type"""
    try:
        type_name = user_data
        if packet_type_manager.delete_type(type_name):
            # Update existing sequences after type deletion
            update_existing_sequences_types()
            
            # Update UI
            update_packet_types_list()
            from fridafuzzer_core.main_view import update_sequences_list
            update_sequences_list()
    except Exception as e:
        print(f"Error deleting packet type: {e}")
        import traceback
        print(traceback.format_exc())

def update_packet_types_list():
    """Update the packet types list in the UI and packet type management buttons"""
    try:
        # Update packet types list
        dpg.delete_item("packet_types_list", children_only=True)
        
        for type_data in packet_type_manager.types:
            try:
                # Create group for each type
                group_id = dpg.add_group(horizontal=True, parent="packet_types_list")
                dpg.add_text(type_data['name'], parent=group_id)
                dpg.add_button(label="Delete", callback=delete_packet_type, user_data=type_data['name'], parent=group_id)
                
                # Add description text
                desc = f"Description: {type_data['description']}\n"
                criteria = type_data['criteria']
                if criteria['hex_value']:
                    desc += f"Hex Value: {criteria['hex_value']}"
                    if criteria['hex_offset'] is not None:
                        desc += f" at offset {criteria['hex_offset']}"
                    desc += "\n"
                if criteria['packet_size'] is not None:
                    desc += f"Packet Size: {criteria['packet_size']}\n"
                if criteria['callstack']:
                    desc += f"Callstack: {criteria['callstack']}\n"
                    
                dpg.add_text(desc, parent="packet_types_list")
                dpg.add_separator(parent="packet_types_list")
            except Exception as e:
                print(f"Error adding packet type {type_data.get('name', 'unknown')}: {e}")
        
        # Update packet type management buttons
        try:
            if dpg.does_item_exist("type_management_buttons"):
                dpg.delete_item("type_management_buttons")
            
            buttons_group = dpg.add_group(horizontal=True, tag="type_management_buttons", parent="sequence_details_group")
            dpg.add_button(label="Remove Type", callback=remove_packet_type, tag="remove_type_button",
                        enabled=False, parent=buttons_group)
            dpg.add_text("Assign Type:", parent=buttons_group)
            for type_data in packet_type_manager.types:
                dpg.add_button(label=type_data['name'], callback=assign_packet_type,
                            tag=f"assign_type_{type_data['name']}", enabled=False,
                            parent=buttons_group)
        except Exception as e:
            print(f"Error updating packet type management buttons: {e}")
    except Exception as e:
        print(f"Error updating packet types list: {e}")
        import traceback
        print(traceback.format_exc())

def assign_packet_type(sender, app_data, user_data):
    """Assign a packet type to the current sequence"""
    seq_id, type_name = user_data
    for seq in sequences:
        if seq['id'] == seq_id:
            seq['packet_type'] = type_name
            from fridafuzzer_core.main_view import save_sequences
            save_sequences()
            from fridafuzzer_core.main_view import show_sequence_details
            show_sequence_details(None, None, seq)
            break

def remove_packet_type(sender, app_data, user_data):
    """Remove packet type from the current sequence"""
    seq_id = user_data
    for seq in sequences:
        if seq['id'] == seq_id:
            seq['packet_type'] = None
            from fridafuzzer_core.main_view import save_sequences
            save_sequences()
            from fridafuzzer_core.main_view import show_sequence_details
            show_sequence_details(None, None, seq)
            break

def update_existing_sequences_types():
    """Update packet types for all existing sequences"""
    for seq in sequences:
        try:
            data = bytes.fromhex(seq['hex_data'])
            callstack = "\n".join(seq['backtrace'])
            packet_type = packet_type_manager.matches_type(data, seq['buffer_length'], callstack)
            seq['packet_type'] = packet_type if packet_type else 'undefined'
        except ValueError:
            print(f"Invalid hex data in sequence {seq['id']}")
    
    # Save updated sequences
    from fridafuzzer_core.main_view import save_sequences
    save_sequences()

def setup_packet_types_tab():
    """Set up the packet types tab UI components"""
    with dpg.child_window(width=-1, height=600, parent="packet_types_tab"):
        # Form for creating new packet types
        dpg.add_text("Create New Packet Type")
        dpg.add_input_text(label="Name", tag="type_name_input", width=200)
        dpg.add_input_text(label="Description", tag="type_description_input", width=400, height=50, multiline=True)
        
        dpg.add_separator()
        dpg.add_text("Criteria (all optional)")
        
        dpg.add_input_text(label="Hex Value (e.g., FF00FF)", tag="type_hex_value_input", width=200)
        dpg.add_input_int(label="at Offset (0 = anywhere)", tag="type_hex_offset_input", width=100)
        dpg.add_input_int(label="Packet Size (bytes)", tag="type_size_input", width=100)
        dpg.add_input_text(label="Callstack Contains", tag="type_callstack_input", width=400)
        
        dpg.add_button(label="Create Type", callback=create_packet_type)
        
        dpg.add_separator()
        dpg.add_text("Existing Packet Types")
        dpg.add_child_window(tag="packet_types_list", height=300)