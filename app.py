import dearpygui.dearpygui as dpg
from fridafuzzer_core import frida_handler
from queue import Queue
import json
from fridafuzzer_core.packet_type_manager import PacketTypeManager, PacketTypeCriteria
import threading
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from fridafuzzer_core.hexdump_widget import HexdumpWidget
import uuid
import socket

# --- Biodiff Algorithm Imports ---
from fridafuzzer_core.biodiff_algorithms import (
    needleman_wunsch,
    smith_waterman,
    wavefront_alignment
)
# --- Repeater Data Structures ---
@dataclass
class RepeaterPacket:
    id: str                      # Unique identifier
    original_id: str             # ID of the original packet
    sequence_id: str             # ID of the sequence this packet belongs to
    hex_data: str                # Hex representation of packet data
    modified_hex_data: str       # Modified hex data (if edited)
    metadata: Dict[str, Any]     # Original packet metadata
    is_modified: bool            # Flag indicating if packet was modified
    created_at: float            # Timestamp when added to Repeater
    last_edited_at: float        # Timestamp of last edit
    replay_history: List[Dict]   # History of replays with timestamps and responses

@dataclass
class RepeaterSequence:
    id: str                      # Unique identifier
    name: str                    # User-friendly name
    packet_ids: List[str]        # IDs of packets in this sequence
    created_at: float            # Timestamp when created
    last_replayed_at: float      # Timestamp of last replay

# Global state
message_queue = Queue()
sequences = []
is_running = False
target_process = ""
current_sequence = None  # Store current sequence for filter operations
packet_type_manager = PacketTypeManager()

# Diff view state
diff_source_1_data: Optional[bytes] = None
diff_source_2_data: Optional[bytes] = None
diff_source_1_id: Optional[str] = None
diff_source_2_id: Optional[str] = None
diff_algorithm: str = "Basic Byte Diff"
diff_hexdump_1 = None
diff_hexdump_2 = None

# Global Repeater state
repeater_packets = {}            # Dictionary of RepeaterPacket objects by ID
repeater_sequences = {}          # Dictionary of RepeaterSequence objects by ID
repeater_connection_mode = "frida"  # "frida" or "direct"
repeater_connection_params = {    # Parameters for direct socket connection
    "host": "",
    "port": 0,
    "protocol": "TCP",
    "timeout": 5.0,
    "custom_params": {}
}
current_repeater_packet_id = None  # Currently selected packet
current_repeater_sequence_id = None  # Currently selected sequence
diff_hexdump_2 = None

def save_sequences():
    """Save sequences to JSON file"""
    with open('sequences.json', 'w') as f:
        json.dump(sequences, f, indent=2)

def load_sequences():
    """Load sequences from JSON file"""
    global sequences
    try:
        with open('sequences.json', 'r') as f:
            sequences = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        sequences = []

def process_messages():
    """Background thread to process messages from Frida"""
    global sequences
    while True:
        try:
            if not message_queue.empty():
                message = message_queue.get_nowait()
                if message.get('type') == 'sequence':
                    # Check if packet matches any type
                    try:
                        data = bytes.fromhex(message['hex_data'])
                        callstack = "\n".join(message['backtrace'])
                        packet_type = packet_type_manager.matches_type(data, message['buffer_length'], callstack)
                        if packet_type:
                            message['packet_type'] = packet_type
                    except ValueError:
                        print("Invalid hex data in message")
                    
                    # Add ID if not present
                    if 'id' not in message:
                        message['id'] = len(sequences) + 1
                    # Add markers if not present
                    if 'markers' not in message:
                        message['markers'] = []
                    sequences.append(message)
                    
                    try:
                        # Update console
                        # Fix: handle None for console value
                        console_val = dpg.get_value("console")
                        if console_val is None:
                            console_val = ""
                        console_text = console_val + "\n" + json.dumps(message, indent=2)
                        dpg.set_value("console", console_text)
                        
                        # Update sequences list
                        update_sequences_list()
                        
                        # Save sequences to file
                        save_sequences()
                    except Exception as e:
                        print(f"Error updating UI after processing message: {e}")
                        import traceback
                        print(traceback.format_exc())
            time.sleep(0.1)  # Small delay to prevent high CPU usage
        except Exception as e:
            print(f"Error processing messages: {e}")
            import traceback
            print(traceback.format_exc())

def start_intercepting(sender, app_data):
    """Start Frida interception"""
    global is_running, target_process
    if not is_running:
        target = dpg.get_value("target_input").strip()
        if target:
            try:
                target = int(target)
            except ValueError:
                pass
            
            success = frida_handler.start_frida(target, message_queue)
            if success:
                is_running = True
                target_process = target
                dpg.set_value("status", f"Running: Intercepting {target}")
                dpg.configure_item("start_button", enabled=False)
                dpg.configure_item("stop_button", enabled=True)
                dpg.configure_item("target_input", enabled=False)

def stop_intercepting(sender, app_data):
    """Stop Frida interception"""
    global is_running
    if is_running:
        frida_handler.stop_frida()
        is_running = False
        dpg.set_value("status", "Stopped")
        dpg.configure_item("start_button", enabled=True)
        dpg.configure_item("stop_button", enabled=False)
        dpg.configure_item("target_input", enabled=True)

def set_callstack_filter(sender, app_data):
    """Set the callstack filter from the currently selected sequence"""
    global current_sequence
    if current_sequence:
        dpg.set_value("callstack_filter", "\n".join(current_sequence['backtrace']))
        update_sequences_list()

def reset_callstack_filter(sender, app_data):
    """Reset the callstack filter"""
    dpg.set_value("callstack_filter", "")
    update_sequences_list()

def reset_all_filters(sender, app_data):
    """Reset all filters to their default values"""
    dpg.set_value("size_filter", 0)
    dpg.set_value("exclude_size_filter", 0)
    dpg.set_value("host_filter", "")
    dpg.set_value("exclude_host_filter", "")
    dpg.set_value("port_filter", "")
    dpg.set_value("exclude_port_filter", "")
    dpg.set_value("callstack_filter", "")
    dpg.set_value("callstack_word_filter", "")
    update_sequences_list()

def apply_filters(sequences_list):
    """Apply filters to the sequences list"""
    size_filter = dpg.get_value("size_filter")
    exclude_size_filter = dpg.get_value("exclude_size_filter")
    host_filter = dpg.get_value("host_filter").strip()
    exclude_host_filter = dpg.get_value("exclude_host_filter").strip()
    port_filter = dpg.get_value("port_filter").strip()
    exclude_port_filter = dpg.get_value("exclude_port_filter").strip()
    hide_received = dpg.get_value("hide_received")
    callstack_filter = dpg.get_value("callstack_filter").strip()
    callstack_word = dpg.get_value("callstack_word_filter").strip()

    filtered = sequences_list.copy()
    
    # Apply size filter
    if size_filter > 0:
        filtered = [seq for seq in filtered if seq['buffer_length'] == size_filter]
    
    # Apply host filter
    if host_filter:
        filtered = [seq for seq in filtered if host_filter in seq['socket_info']]
    
    # Apply port filter
    if port_filter:
        filtered = [seq for seq in filtered if port_filter in seq['socket_info']]
    
    # Apply callstack filter from selected packet
    if callstack_filter:
        filtered = [seq for seq in filtered if "\n".join(seq['backtrace']) == callstack_filter]
    
    # Apply callstack word filter
    if callstack_word:
        filtered = [seq for seq in filtered if any(callstack_word.lower() in frame.lower() for frame in seq['backtrace'])]
    
    # Filter out received packets if hide_received is enabled
    if hide_received:
        filtered = [seq for seq in filtered if seq.get('direction') != 'receive']

    # Apply exclusion filters
    if exclude_size_filter > 0:
        filtered = [seq for seq in filtered if seq['buffer_length'] != exclude_size_filter]
    if exclude_host_filter:
        filtered = [seq for seq in filtered if exclude_host_filter not in seq['socket_info']]
    if exclude_port_filter:
        filtered = [seq for seq in filtered if exclude_port_filter not in seq['socket_info']]
    
    return filtered

def update_sequences_list():
    """Update the sequences list in the UI"""
    try:
        dpg.delete_item("sequences_list", children_only=True)
        
        # Apply filters to sequences
        filtered_sequences = apply_filters(sequences)

        # Prepare descriptive labels for diff dropdowns (unfiltered list)
        # Fix: skip sequences missing 'id' or 'buffer_length'
        diff_labels = [
            f"#{seq['id']} - {seq.get('packet_type', 'undefined')} ({seq['buffer_length']} bytes)"
            for seq in sequences
            if 'id' in seq and 'buffer_length' in seq
        ]
        dpg.configure_item("diff_source_1_dropdown", items=diff_labels)
        dpg.configure_item("diff_source_2_dropdown", items=diff_labels)
        
        for seq in filtered_sequences:
            try:
                # Create group for each sequence with spacing
                group_id = dpg.add_group(horizontal=True, parent="sequences_list")
                
                # Details button
                packet_type = seq.get('packet_type', 'undefined')
                label = f"#{seq['id']} - {packet_type} - {seq['function_name']} ({seq['buffer_length']} bytes)"
                btn_id = dpg.add_button(label=label, callback=show_sequence_details, user_data=seq, width=300, parent=group_id)
        
                # Add right-click popup for diff options
                # Store the sequence ID in a local variable to ensure it's properly captured by the lambda
                seq_id = seq['id']
                with dpg.popup(btn_id, mousebutton=dpg.mvMouseButton_Right):
                    dpg.add_menu_item(label="Send to Diff Pane 1", callback=lambda s, a, u=seq_id: send_to_diff_pane_1(u))
                    dpg.add_menu_item(label="Send to Diff Pane 2", callback=lambda s, a, u=seq_id: send_to_diff_pane_2(u))
                    dpg.add_menu_item(label="Send to Repeater", callback=lambda s, a, u=seq_id: send_to_repeater(u))
                    dpg.add_menu_item(label="Send Filtered to Repeater", callback=lambda s, a: send_filtered_to_repeater())
                
                # Remove button with red tint
                delete_btn = dpg.add_button(label="Delete", callback=remove_sequence, user_data=seq['id'], width=50, parent=group_id)
                dpg.bind_item_theme(delete_btn, "delete_button_theme")
            except Exception as e:
                print(f"Error adding sequence {seq.get('id', 'unknown')}: {e}")
        
        # Run diff after updating dropdowns and list
        run_diff()
    except Exception as e:
        print(f"Error updating sequences list: {e}")
        import traceback
        print(traceback.format_exc())

def show_sequence_details(sender, app_data, user_data):
    """Show details of selected sequence"""
    seq = user_data
    # Update sequence details
    details = (
        f"Function: {seq['function_name']}\n"
        f"Direction: {seq.get('direction', 'send')}\n"
        f"Socket ID: {seq['socket_id']}\n"
        f"Socket Info: {seq['socket_info']}\n"
        f"Buffer Length: {seq['buffer_length']}\n"
        f"Flags: {seq['flags']}\n"
        f"Packet Type: {seq.get('packet_type', 'undefined')}\n\n"
        f"Raw Hex Data:\n{seq['hex_data']}\n\n"
        f"Backtrace:\n" + "\n".join(seq['backtrace']) + "\n\n"
        f"Markers:\n"
    )
    
    if seq.get('markers'):
        for marker in seq['markers']:
            details += f"  {marker['start_offset']}-{marker['end_offset']}: {marker['tag_name']}"
            if marker['properties']:
                details += f" ({', '.join(f'{k}={v}' for k, v in marker['properties'].items())})"
            details += "\n"
    else:
        details += "  None\n"
    
    dpg.set_value("sequence_details", details)
    
    # Store current sequence for filter button
    global current_sequence
    current_sequence = seq
    
    # Update hexdump with raw bytes and fuzzable regions
    try:
        data = bytes.fromhex(seq['hex_data'])
        # Temporarily disable the callback while loading regions
        original_callback = hexdump_widget.on_regions_changed
        hexdump_widget.on_regions_changed = None
        
        # Set data and sequence ID
        hexdump_widget.set_data(data, seq['id'])
        
        # Update packet type management buttons
        # Only configure the button if it exists
        if dpg.does_item_exist("remove_type_button"):
            dpg.configure_item("remove_type_button", user_data=seq['id'], enabled=True)
        # Only configure assign_type buttons if they exist
        for type_data in packet_type_manager.types:
            btn_name = f"assign_type_{type_data['name']}"
            if dpg.does_item_exist(btn_name):
                dpg.configure_item(btn_name, user_data=(seq['id'], type_data['name']), enabled=True)
        
        # Set data with markers
        hexdump_widget.set_data(data, seq['id'], seq.get('markers', []))
            
        # Restore the callback
        hexdump_widget.on_regions_changed = original_callback
    except ValueError:
        print("Invalid hex data")

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
            save_sequences()
            show_sequence_details(None, None, seq)
            break

def remove_packet_type(sender, app_data, user_data):
    """Remove packet type from the current sequence"""
    seq_id = user_data
    for seq in sequences:
        if seq['id'] == seq_id:
            seq['packet_type'] = None
            save_sequences()
            show_sequence_details(None, None, seq)
            break

def update_existing_sequences_types():
    """Update packet types for all existing sequences"""
    global sequences
    for seq in sequences:
        try:
            data = bytes.fromhex(seq['hex_data'])
            callstack = "\n".join(seq['backtrace'])
            packet_type = packet_type_manager.matches_type(data, seq['buffer_length'], callstack)
            seq['packet_type'] = packet_type if packet_type else 'undefined'
        except ValueError:
            print(f"Invalid hex data in sequence {seq['id']}")
    
    # Save updated sequences
    save_sequences()
def update_sequence_regions(sequence_id, regions):
    """Update markers for a sequence and save to file"""
    for seq in sequences:
        if seq['id'] == sequence_id:
            seq['markers'] = [
                {
                    'start_offset': r.start_offset,
                    'end_offset': r.end_offset,
                    'tag_name': r.tag_name,
                    'tag_type': r.tag_type,
                    'properties': r.properties
                }
                for r in regions
            ]
            save_sequences()
            break

def remove_sequence(sender, app_data, user_data):
    """Remove a single sequence by its ID"""
    try:
        global sequences
        sequences = [seq for seq in sequences if seq['id'] != user_data]
        save_sequences()
        update_sequences_list()
    except Exception as e:
        print(f"Error removing sequence: {e}")
        import traceback
        print(traceback.format_exc())

def clear_filtered_sequences(sender, app_data):
    """Remove all sequences that match the current filters"""
    try:
        global sequences
        filtered = apply_filters(sequences)
        filtered_ids = {seq['id'] for seq in filtered}
        sequences = [seq for seq in sequences if seq['id'] not in filtered_ids]
        save_sequences()
        update_sequences_list()
    except Exception as e:
        print(f"Error clearing filtered sequences: {e}")
        import traceback
        print(traceback.format_exc())

# --- Repeater Tab Core Functionality ---

def send_filtered_to_repeater():
    """
    Send all currently filtered packets to the Repeater tab as a new sequence.
    
    This function:
    1. Gets all currently filtered packets
    2. Creates a new repeater sequence
    3. Adds all filtered packets to this sequence
    
    Returns:
        str: ID of the new RepeaterSequence or None if failed
    """
    global repeater_sequences, repeater_packets
    
    # Get all currently filtered packets
    filtered_packets = apply_filters(sequences)
    
    if not filtered_packets:
        print("No filtered packets to send to Repeater")
        return None
    
    # Generate a unique ID for the repeater sequence
    repeater_sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    current_time = time.time()
    repeater_sequence = RepeaterSequence(
        id=repeater_sequence_id,
        name=f"Filtered Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=current_time,
        last_replayed_at=0  # Never replayed yet
    )
    
    # Add each filtered packet to the repeater
    for packet in filtered_packets:
        # Create a repeater packet for each filtered packet
        repeater_packet_id = send_to_repeater(packet['id'])
        if repeater_packet_id:
            # Update the sequence_id of the repeater packet
            repeater_packets[repeater_packet_id].sequence_id = repeater_sequence_id
            # Add the packet ID to the sequence
            repeater_sequence.packet_ids.append(repeater_packet_id)
    
    # Add the sequence to the repeater sequences dictionary
    repeater_sequences[repeater_sequence_id] = repeater_sequence
    
    # Save repeater state
    save_repeater_state()
    
    # Update the UI
    update_repeater_ui()
    
    return repeater_sequence_id

def send_to_repeater(packet_id):
    """
    Send a packet to the Repeater tab.
    Creates a new RepeaterPacket based on the original packet.
    
    Args:
        packet_id: ID of the packet to send to Repeater
    
    Returns:
        str: ID of the new RepeaterPacket or None if failed
    """
    global repeater_packets
    
    # Find the original packet
    original_packet = next((p for p in sequences if p['id'] == packet_id), None)
    if not original_packet:
        print(f"Packet with ID {packet_id} not found")
        return None
    
    # Create a unique ID for the repeater packet
    repeater_id = str(uuid.uuid4())
    
    # Create a new RepeaterPacket
    current_time = time.time()
    repeater_packet = RepeaterPacket(
        id=repeater_id,
        original_id=str(packet_id),
        sequence_id="",  # Not part of a sequence initially
        hex_data=original_packet['hex_data'],
        modified_hex_data=original_packet['hex_data'],  # Initially the same as original
        metadata={
            "function_name": original_packet.get('function_name', ''),
            "direction": original_packet.get('direction', 'send'),
            "socket_id": original_packet.get('socket_id', ''),
            "socket_info": original_packet.get('socket_info', ''),
            "buffer_length": original_packet.get('buffer_length', 0),
            "flags": original_packet.get('flags', ''),
            "packet_type": original_packet.get('packet_type', 'undefined'),
            "backtrace": original_packet.get('backtrace', []),
            "markers": original_packet.get('markers', [])
        },
        is_modified=False,
        created_at=current_time,
        last_edited_at=current_time,
        replay_history=[]
    )
    
    # Add to repeater packets dictionary
    repeater_packets[repeater_id] = repeater_packet
    
    # Save repeater state
    save_repeater_state()
    
    return repeater_id

def send_sequence_to_repeater(sequence_id):
    """
    Create a new sequence in the Repeater tab based on an existing sequence.
    
    Args:
        sequence_id: ID of the sequence to send to Repeater
    
    Returns:
        str: ID of the new RepeaterSequence or None if failed
    """
    global repeater_sequences, repeater_packets
    
    # Generate a unique ID for the repeater sequence
    repeater_sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    current_time = time.time()
    repeater_sequence = RepeaterSequence(
        id=repeater_sequence_id,
        name=f"Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=current_time,
        last_replayed_at=0  # Never replayed yet
    )
    
    # Find all packets in the original sequence
    sequence_packets = [p for p in sequences if p.get('sequence_id') == sequence_id]
    
    # Add each packet to the repeater
    for packet in sequence_packets:
        # Create a repeater packet for each packet in the sequence
        repeater_packet_id = send_to_repeater(packet['id'])
        if repeater_packet_id:
            # Update the sequence_id of the repeater packet
            repeater_packets[repeater_packet_id].sequence_id = repeater_sequence_id
            # Add the packet ID to the sequence
            repeater_sequence.packet_ids.append(repeater_packet_id)
    
    # Add the sequence to the repeater sequences dictionary
    repeater_sequences[repeater_sequence_id] = repeater_sequence
    
    # Save repeater state
    save_repeater_state()
    
    return repeater_sequence_id

def replay_packet_frida(packet_id):
    """
    Replay a packet using Frida.
    
    Args:
        packet_id: ID of the RepeaterPacket to replay
    
    Returns:
        bool: True if successful, False otherwise
    """
    global repeater_packets
    
    # Check if packet exists
    if packet_id not in repeater_packets:
        print(f"Repeater packet with ID {packet_id} not found")
        return False
    
    # Get the packet
    packet = repeater_packets[packet_id]
    
    # Check if Frida is running
    if not is_running:
        print("Frida is not running")
        return False
    
    try:
        # Get the hex data to send (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        
        # Use Frida to send the packet
        success = frida_handler.send_data(hex_data)
        
        if success:
            # Record the replay in history
            replay_record = {
                "timestamp": time.time(),
                "mode": "frida",
                "success": True,
                "response": None  # Frida mode doesn't capture responses
            }
            packet.replay_history.append(replay_record)
            
            # Update last replayed timestamp
            packet.last_edited_at = replay_record["timestamp"]
            
            # Save state
            save_repeater_state()
            
            return True
        else:
            # Record failed replay
            replay_record = {
                "timestamp": time.time(),
                "mode": "frida",
                "success": False,
                "error": "Failed to send data through Frida"
            }
            packet.replay_history.append(replay_record)
            save_repeater_state()
            
            return False
    
    except Exception as e:
        print(f"Error replaying packet with Frida: {e}")
        import traceback
        print(traceback.format_exc())
        
        # Record error in history
        replay_record = {
            "timestamp": time.time(),
            "mode": "frida",
            "success": False,
            "error": str(e)
        }
        packet.replay_history.append(replay_record)
        save_repeater_state()
        
        return False

def replay_packet_direct(packet_id, connection_params):
    """
    Replay a packet using direct socket connection.
    
    Args:
        packet_id: ID of the RepeaterPacket to replay
        connection_params: Dictionary with connection parameters
    
    Returns:
        bool: True if successful, False otherwise
    """
    global repeater_packets
    
    # Check if packet exists
    if packet_id not in repeater_packets:
        print(f"Repeater packet with ID {packet_id} not found")
        return False
    
    # Get the packet
    packet = repeater_packets[packet_id]
    
    try:
        # Get the hex data to send (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        data = bytes.fromhex(hex_data)
        
        # Extract connection parameters
        host = connection_params.get("host", "")
        port = connection_params.get("port", 0)
        protocol = connection_params.get("protocol", "TCP")
        timeout = connection_params.get("timeout", 5.0)
        
        if not host or not port:
            print("Invalid connection parameters: host and port are required")
            return False
        
        # Create socket based on protocol
        if protocol.upper() == "TCP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol.upper() == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            print(f"Unsupported protocol: {protocol}")
            return False
        
        # Set timeout
        sock.settimeout(timeout)
        
        response = None
        
        try:
            # Connect and send data for TCP
            if protocol.upper() == "TCP":
                sock.connect((host, port))
                sock.sendall(data)
                
                # Try to receive response
                try:
                    response = sock.recv(4096)
                except socket.timeout:
                    # No response within timeout is not an error
                    pass
            
            # Send data for UDP
            elif protocol.upper() == "UDP":
                sock.sendto(data, (host, port))
                
                # Try to receive response
                try:
                    response, addr = sock.recvfrom(4096)
                except socket.timeout:
                    # No response within timeout is not an error
                    pass
            
            # Record successful replay in history
            replay_record = {
                "timestamp": time.time(),
                "mode": "direct",
                "protocol": protocol,
                "host": host,
                "port": port,
                "success": True,
                "response": response.hex() if response else None
            }
            packet.replay_history.append(replay_record)
            
            # Update last replayed timestamp
            packet.last_edited_at = replay_record["timestamp"]
            
            # Save state
            save_repeater_state()
            
            return True
            
        finally:
            # Always close the socket
            sock.close()
    
    except Exception as e:
        print(f"Error replaying packet with direct connection: {e}")
        import traceback
        print(traceback.format_exc())
        
        # Record error in history
        replay_record = {
            "timestamp": time.time(),
            "mode": "direct",
            "protocol": connection_params.get("protocol", "TCP"),
            "host": connection_params.get("host", ""),
            "port": connection_params.get("port", 0),
            "success": False,
            "error": str(e)
        }
        packet.replay_history.append(replay_record)
        save_repeater_state()
        
        return False

def replay_sequence_frida(sequence_id):
    """
    Replay a sequence of packets using Frida.
    
    Args:
        sequence_id: ID of the RepeaterSequence to replay
    
    Returns:
        bool: True if all packets were sent successfully, False otherwise
    """
    global repeater_sequences
    
    # Check if sequence exists
    if sequence_id not in repeater_sequences:
        print(f"Repeater sequence with ID {sequence_id} not found")
        return False
    
    # Get the sequence
    sequence = repeater_sequences[sequence_id]
    
    # Track overall success
    all_success = True
    
    # Replay each packet in the sequence
    for packet_id in sequence.packet_ids:
        success = replay_packet_frida(packet_id)
        if not success:
            all_success = False
    
    # Update last replayed timestamp
    sequence.last_replayed_at = time.time()
    
    # Save state
    save_repeater_state()
    
    return all_success

def replay_sequence_direct(sequence_id, connection_params):
    """
    Replay a sequence of packets using direct socket connection.
    
    Args:
        sequence_id: ID of the RepeaterSequence to replay
        connection_params: Dictionary with connection parameters
    
    Returns:
        bool: True if all packets were sent successfully, False otherwise
    """
    global repeater_sequences
    
    # Check if sequence exists
    if sequence_id not in repeater_sequences:
        print(f"Repeater sequence with ID {sequence_id} not found")
        return False
    
    # Get the sequence
    sequence = repeater_sequences[sequence_id]
    
    # Track overall success
    all_success = True
    
    # Replay each packet in the sequence
    for packet_id in sequence.packet_ids:
        success = replay_packet_direct(packet_id, connection_params)
        if not success:
            all_success = False
    
    # Update last replayed timestamp
    sequence.last_replayed_at = time.time()
    
    # Save state
    save_repeater_state()
    
    return all_success

def save_repeater_state():
    """Save repeater state to JSON file"""
    try:
        # Convert RepeaterPacket objects to dictionaries
        packets_dict = {}
        for packet_id, packet in repeater_packets.items():
            packets_dict[packet_id] = {
                "id": packet.id,
                "original_id": packet.original_id,
                "sequence_id": packet.sequence_id,
                "hex_data": packet.hex_data,
                "modified_hex_data": packet.modified_hex_data,
                "metadata": packet.metadata,
                "is_modified": packet.is_modified,
                "created_at": packet.created_at,
                "last_edited_at": packet.last_edited_at,
                "replay_history": packet.replay_history
            }
        
        # Convert RepeaterSequence objects to dictionaries
        sequences_dict = {}
        for seq_id, sequence in repeater_sequences.items():
            sequences_dict[seq_id] = {
                "id": sequence.id,
                "name": sequence.name,
                "packet_ids": sequence.packet_ids,
                "created_at": sequence.created_at,
                "last_replayed_at": sequence.last_replayed_at
            }
        
        # Create state dictionary
        repeater_state = {
            "packets": packets_dict,
            "sequences": sequences_dict,
            "connection_mode": repeater_connection_mode,
            "connection_params": repeater_connection_params,
            "current_packet_id": current_repeater_packet_id,
            "current_sequence_id": current_repeater_sequence_id
        }
        
        # Save to file
        with open('repeater_state.json', 'w') as f:
            json.dump(repeater_state, f, indent=2)
        
        return True
    
    except Exception as e:
        print(f"Error saving repeater state: {e}")
        import traceback
        print(traceback.format_exc())
        return False

def load_repeater_state():
    """Load repeater state from JSON file"""
    global repeater_packets, repeater_sequences, repeater_connection_mode
    global repeater_connection_params, current_repeater_packet_id, current_repeater_sequence_id
    
    try:
        with open('repeater_state.json', 'r') as f:
            repeater_state = json.load(f)
        
        # Load packets
        packets_dict = repeater_state.get("packets", {})
        repeater_packets = {}
        for packet_id, packet_data in packets_dict.items():
            repeater_packets[packet_id] = RepeaterPacket(
                id=packet_data["id"],
                original_id=packet_data["original_id"],
                sequence_id=packet_data["sequence_id"],
                hex_data=packet_data["hex_data"],
                modified_hex_data=packet_data["modified_hex_data"],
                metadata=packet_data["metadata"],
                is_modified=packet_data["is_modified"],
                created_at=packet_data["created_at"],
                last_edited_at=packet_data["last_edited_at"],
                replay_history=packet_data["replay_history"]
            )
        
        # Load sequences
        sequences_dict = repeater_state.get("sequences", {})
        repeater_sequences = {}
        for seq_id, seq_data in sequences_dict.items():
            repeater_sequences[seq_id] = RepeaterSequence(
                id=seq_data["id"],
                name=seq_data["name"],
                packet_ids=seq_data["packet_ids"],
                created_at=seq_data["created_at"],
                last_replayed_at=seq_data["last_replayed_at"]
            )
        
        # Load other state
        repeater_connection_mode = repeater_state.get("connection_mode", "frida")
        repeater_connection_params = repeater_state.get("connection_params", {
            "host": "",
            "port": 0,
            "protocol": "TCP",
            "timeout": 5.0,
            "custom_params": {}
        })
        current_repeater_packet_id = repeater_state.get("current_packet_id")
        current_repeater_sequence_id = repeater_state.get("current_sequence_id")
        
        return True
    
    except (FileNotFoundError, json.JSONDecodeError):
        # Initialize with empty state if file doesn't exist or is invalid
        repeater_packets = {}
        repeater_sequences = {}
        repeater_connection_mode = "frida"
        repeater_connection_params = {
            "host": "",
            "port": 0,
            "protocol": "TCP",
            "timeout": 5.0,
            "custom_params": {}
        }
        current_repeater_packet_id = None
        current_repeater_sequence_id = None
        return False
    
    except Exception as e:
        print(f"Error loading repeater state: {e}")
        import traceback
        print(traceback.format_exc())
        return False

def update_repeater_packet_regions(sequence_id, regions):
    """Update markers for a repeater packet"""
    global repeater_packets
    
    # Check if packet exists
    if sequence_id not in repeater_packets:
        return
    
    # Get the packet
    packet = repeater_packets[sequence_id]
    
    # Update markers
    packet.metadata["markers"] = [
        {
            'start_offset': r.start_offset,
            'end_offset': r.end_offset,
            'tag_name': r.tag_name,
            'tag_type': r.tag_type,
            'properties': r.properties
        }
        for r in regions
    ]
    
    # Mark as modified
    packet.is_modified = True
    packet.last_edited_at = time.time()
    
    # Save repeater state
    save_repeater_state()

def update_repeater_packet_data(sequence_id, hex_data):
    """Update the hex data of a repeater packet"""
    global repeater_packets
    
    # Check if packet exists
    if sequence_id not in repeater_packets:
        return
    
    # Get the packet
    packet = repeater_packets[sequence_id]
    
    # Update hex data
    packet.modified_hex_data = hex_data
    
    # Mark as modified
    packet.is_modified = True
    packet.last_edited_at = time.time()
    
    # Save repeater state
    save_repeater_state()

def select_diff_algorithm(sender, app_data, user_data):
    """Callback when diff algorithm is selected.
    Shows/hides parameter fields for the selected algorithm.
    """
    global diff_algorithm
    diff_algorithm = app_data

    # Hide all parameter fields by default
    dpg.configure_item("gap_penalty_input", show=False)
    dpg.configure_item("match_score_input", show=False)
    dpg.configure_item("mismatch_penalty_input", show=False)
    dpg.configure_item("gap_opening_input", show=False)
    dpg.configure_item("gap_extension_input", show=False)

    # Show relevant fields for each algorithm
    if diff_algorithm in ["Needleman-Wunsch", "Smith-Waterman"]:
        dpg.configure_item("gap_penalty_input", show=True)
    elif diff_algorithm == "Wavefront Alignment":
        dpg.configure_item("match_score_input", show=True)
        dpg.configure_item("mismatch_penalty_input", show=True)
        dpg.configure_item("gap_opening_input", show=True)
        dpg.configure_item("gap_extension_input", show=True)

    run_diff()

def select_diff_source_1(sender, app_data, user_data):
    """Callback when source 1 packet is selected"""
    global diff_source_1_data, diff_source_1_id
    # Parse ID from label string
    try:
        label = app_data
        id_str = label.split('-')[0].strip().lstrip('#')
        seq_id = int(id_str)
    except Exception:
        print("Failed to parse diff source 1 ID from label")
        diff_source_1_data = None
        diff_source_1_id = None
        run_diff()
        return

    # Find sequence by ID
    # Safely handle sequences that may not have an 'id'
    seq = next((s for s in sequences if 'id' in s and s['id'] == seq_id), None)
    if seq:
        try:
            diff_source_1_data = bytes.fromhex(seq['hex_data'])
            diff_source_1_id = seq['id']
            diff_hexdump_1.set_data(diff_source_1_data, seq['id'], seq.get('markers', []))
        except ValueError:
            print("Invalid hex data in sequence")
            diff_source_1_data = None
            diff_source_1_id = None
    else:
        diff_source_1_data = None
        diff_source_1_id = None

    run_diff()

def select_diff_source_2(sender, app_data, user_data):
    """Callback when source 2 packet is selected"""
    global diff_source_2_data, diff_source_2_id
    # Parse ID from label string
    try:
        label = app_data
        id_str = label.split('-')[0].strip().lstrip('#')
        seq_id = int(id_str)
    except Exception:
        print("Failed to parse diff source 2 ID from label")
        diff_source_2_data = None
        diff_source_2_id = None
        run_diff()
        return

    # Find sequence by ID
    # Safely handle sequences that may not have an 'id'
    seq = next((s for s in sequences if 'id' in s and s['id'] == seq_id), None)
    if seq:
        try:
            diff_source_2_data = bytes.fromhex(seq['hex_data'])
            diff_source_2_id = seq['id']
            diff_hexdump_2.set_data(diff_source_2_data, seq['id'], seq.get('markers', []))
        except ValueError:
            print("Invalid hex data in sequence")
            diff_source_2_data = None
            diff_source_2_id = None
    else:
        diff_source_2_data = None
        diff_source_2_id = None

def send_to_diff_pane_1(sequence_id):
    """Send the specified sequence to Diff Pane 1."""
    global diff_source_1_id, diff_source_1_data

    # Find the sequence dict by ID
    seq = next((s for s in sequences if s['id'] == sequence_id), None)
    if not seq:
        print(f"Sequence with ID {sequence_id} not found.")
        return

    try:
        diff_source_1_data = bytes.fromhex(seq['hex_data'])
    except ValueError:
        print("Invalid hex data in sequence")
        diff_source_1_data = None
        diff_source_1_id = None
        run_diff()
        return

    diff_source_1_id = seq['id']

    # Construct label as in update_sequences_list
    packet_type = seq.get('packet_type', 'undefined')
    label = f"#{seq['id']} - {packet_type} - {seq['function_name']} ({seq['buffer_length']} bytes)"
    try:
        dpg.set_value("diff_source_1_dropdown", label)
    except:
        pass

    # Update diff hexdump widget
    if diff_hexdump_1:
        diff_hexdump_1.set_data(diff_source_1_data, seq['id'], seq.get('markers', []))

    run_diff()


def send_to_diff_pane_2(sequence_id):
    """Send the specified sequence to Diff Pane 2."""
    global diff_source_2_id, diff_source_2_data

    # Find the sequence dict by ID
    seq = next((s for s in sequences if s['id'] == sequence_id), None)
    if not seq:
        print(f"Sequence with ID {sequence_id} not found.")
        return

    try:
        diff_source_2_data = bytes.fromhex(seq['hex_data'])
    except ValueError:
        print("Invalid hex data in sequence")
        diff_source_2_data = None
        diff_source_2_id = None
        run_diff()
        return

    diff_source_2_id = seq['id']

    # Construct label as in update_sequences_list
    packet_type = seq.get('packet_type', 'undefined')
    label = f"#{seq['id']} - {packet_type} - {seq['function_name']} ({seq['buffer_length']} bytes)"
    try:
        dpg.set_value("diff_source_2_dropdown", label)
    except:
        pass

    # Update diff hexdump widget
    if diff_hexdump_2:
        diff_hexdump_2.set_data(diff_source_2_data, seq['id'], seq.get('markers', []))

    run_diff()


def run_diff():
    """
    Perform diffing between source 1 and source 2 and highlight differences (diff: red, same: green).
    Integrates new biodiff algorithms: Wavefront Alignment, Needleman-Wunsch, Smith-Waterman.
    Handles algorithm-specific parameters and error cases.
    """
    # Clear existing highlights
    if diff_hexdump_1:
        diff_hexdump_1.set_highlights([], (0, 0, 0, 0), [], (0, 0, 0, 0))
    if diff_hexdump_2:
        diff_hexdump_2.set_highlights([], (0, 0, 0, 0), [], (0, 0, 0, 0))

    # Check if both sources are available
    if diff_source_1_data is None or diff_source_2_data is None:
        return

    # Implement multiple diff algorithms
    data1 = diff_source_1_data
    data2 = diff_source_2_data
    len1 = len(data1)
    len2 = len(data2)
    min_len = min(len1, len2)

    diffs_1 = []
    diffs_2 = []
    sames_1 = []
    sames_2 = []

    # --- Biodiff Algorithm Integration ---
    try:
        if diff_algorithm == "Basic Byte Diff":
            # Compare byte by byte up to shorter length
            for i in range(min_len):
                if data1[i] != data2[i]:
                    diffs_1.append(i)
                    diffs_2.append(i)
                else:
                    sames_1.append(i)
                    sames_2.append(i)
            # Extra bytes in source 1
            if len1 > min_len:
                extra_offsets = list(range(min_len, len1))
                diffs_1.extend(extra_offsets)
            # Extra bytes in source 2
            if len2 > min_len:
                extra_offsets = list(range(min_len, len2))
                diffs_2.extend(extra_offsets)
            diff_color = (255, 0, 0, 100)  # red
            same_color = (0, 255, 0, 100)  # green

        elif diff_algorithm == "Histogram Diff":
            from collections import Counter
            c1 = Counter(data1)
            c2 = Counter(data2)
            unique1 = set(c1.keys()) - set(c2.keys())
            unique2 = set(c2.keys()) - set(c1.keys())
            for i, b in enumerate(data1):
                if b in unique1:
                    diffs_1.append(i)
                else:
                    sames_1.append(i)
            for i, b in enumerate(data2):
                if b in unique2:
                    diffs_2.append(i)
                else:
                    sames_2.append(i)
            diff_color = (255, 0, 0, 100)
            same_color = (0, 255, 0, 100)

        elif diff_algorithm == "Binary Delta":
            try:
                import bsdiff4
            except ImportError:
                dpg.show_item_registry()
                dpg.add_text("bsdiff4 not installed. Please install bsdiff4 to use Binary Delta.", parent="diff_view_tab")
                return
            patch = bsdiff4.diff(data1, data2)
            for i in range(min_len):
                if data1[i] != data2[i]:
                    diffs_1.append(i)
                    diffs_2.append(i)
                else:
                    sames_1.append(i)
                    sames_2.append(i)
            if len1 > min_len:
                diffs_1.extend(range(min_len, len1))
            if len2 > min_len:
                diffs_2.extend(range(min_len, len2))
            diff_color = (255, 0, 0, 100)
            same_color = (0, 255, 0, 100)

        elif diff_algorithm == "Fuzzy Block Matching":
            import difflib
            block_size = 16
            num_blocks1 = (len(data1) + block_size - 1) // block_size
            num_blocks2 = (len(data2) + block_size - 1) // block_size
            min_blocks = min(num_blocks1, num_blocks2)
            green = (0, 255, 0, 100)
            yellow = (255, 255, 0, 100)
            orange = (255, 165, 0, 100)
            red = (255, 0, 0, 100)
            color_map_1 = {}
            color_map_2 = {}
            for b in range(min_blocks):
                start = b * block_size
                end1 = min(start + block_size, len(data1))
                end2 = min(start + block_size, len(data2))
                block1 = data1[start:end1]
                block2 = data2[start:end2]
                sm = difflib.SequenceMatcher(None, block1, block2)
                ratio = sm.ratio()
                if ratio > 0.9:
                    color = green
                elif ratio > 0.7:
                    color = yellow
                elif ratio > 0.5:
                    color = orange
                else:
                    color = red
                for i in range(start, end1):
                    color_map_1[i] = color
                for i in range(start, end2):
                    color_map_2[i] = color
            for b in range(min_blocks, num_blocks1):
                start = b * block_size
                end = min(start + block_size, len(data1))
                for i in range(start, end):
                    color_map_1[i] = red
            for b in range(min_blocks, num_blocks2):
                start = b * block_size
                end = min(start + block_size, len(data2))
                for i in range(start, end):
                    color_map_2[i] = red
            sames_1 = [i for i, c in color_map_1.items() if c == green]
            diffs_1 = [i for i, c in color_map_1.items() if c != green]
            sames_2 = [i for i, c in color_map_2.items() if c == green]
            diffs_2 = [i for i, c in color_map_2.items() if c != green]
            diff_color = red
            same_color = green

        elif diff_algorithm == "Needleman-Wunsch":
            # Get gap penalty from UI
            gap_penalty = dpg.get_value("gap_penalty_input")
            # Limit input size for performance
            if len1 > 10000 or len2 > 10000:
                dpg.add_text("Input too large for Needleman-Wunsch (max 10,000 bytes).", parent="diff_view_tab")
                return
            result = needleman_wunsch(data1, data2, gap_penalty=gap_penalty)
            aligned_indices = result["aligned_indices"]
            # Highlight: green for matches, red for mismatches/gaps
            for idx1, idx2 in aligned_indices:
                if idx1 is not None and idx2 is not None and data1[idx1] == data2[idx2]:
                    sames_1.append(idx1)
                    sames_2.append(idx2)
                else:
                    if idx1 is not None:
                        diffs_1.append(idx1)
                    if idx2 is not None:
                        diffs_2.append(idx2)
            diff_color = (255, 0, 0, 100)
            same_color = (0, 255, 0, 100)

        elif diff_algorithm == "Smith-Waterman":
            gap_penalty = dpg.get_value("gap_penalty_input")
            if len1 > 10000 or len2 > 10000:
                dpg.add_text("Input too large for Smith-Waterman (max 10,000 bytes).", parent="diff_view_tab")
                return
            result = smith_waterman(data1, data2, gap_penalty=gap_penalty)
            aligned_indices = result["aligned_indices"]
            for idx1, idx2 in aligned_indices:
                if idx1 is not None and idx2 is not None and data1[idx1] == data2[idx2]:
                    sames_1.append(idx1)
                    sames_2.append(idx2)
                else:
                    if idx1 is not None:
                        diffs_1.append(idx1)
                    if idx2 is not None:
                        diffs_2.append(idx2)
            diff_color = (255, 0, 0, 100)
            same_color = (0, 255, 0, 100)

        elif diff_algorithm == "Wavefront Alignment":
            match_score = dpg.get_value("match_score_input")
            mismatch_penalty = dpg.get_value("mismatch_penalty_input")
            gap_opening = dpg.get_value("gap_opening_input")
            gap_extension = dpg.get_value("gap_extension_input")
            if len1 > 20000 or len2 > 20000:
                dpg.add_text("Input too large for Wavefront Alignment (max 20,000 bytes).", parent="diff_view_tab")
                return
            try:
                result = wavefront_alignment(
                    data1, data2,
                    match_score=match_score,
                    mismatch_penalty=mismatch_penalty,
                    gap_opening=gap_opening,
                    gap_extension=gap_extension
                )
            except ImportError:
                dpg.add_text("wfa2 package is not installed. Please install wfa2 to use Wavefront Alignment.", parent="diff_view_tab")
                return
            aligned_indices = result["aligned_indices"]
            for idx1, idx2 in aligned_indices:
                if idx1 is not None and idx2 is not None and data1[idx1] == data2[idx2]:
                    sames_1.append(idx1)
                    sames_2.append(idx2)
                else:
                    if idx1 is not None:
                        diffs_1.append(idx1)
                    if idx2 is not None:
                        diffs_2.append(idx2)
            diff_color = (255, 0, 0, 100)
            same_color = (0, 255, 0, 100)

        else:
            dpg.add_text(f"Unknown diff algorithm: {diff_algorithm}", parent="diff_view_tab")
            return

        # Set highlights for all algorithms except Fuzzy Block Matching (already set)
        if diff_algorithm != "Fuzzy Block Matching":
            if diff_hexdump_1:
                diff_hexdump_1.set_highlights(diffs_1, diff_color, sames_1, same_color)
            if diff_hexdump_2:
                diff_hexdump_2.set_highlights(diffs_2, diff_color, sames_2, same_color)

    except Exception as e:
        # General error handling for unexpected failures
        dpg.add_text(f"Error running diff: {str(e)}", parent="diff_view_tab")
        import traceback
        print(traceback.format_exc())

# The following functions are outside of run_diff and should not be indented.
def clear_console(sender, app_data):
    """Clear the console output"""
    dpg.set_value("console", "")

# Initialize DearPyGui
dpg.create_context()

# --- Repeater Tab Event Handlers ---

def update_repeater_ui():
    """Update the Repeater UI with the current state"""
    try:
        # Update sequences list
        update_repeater_sequences_list()
        
        # Update connection mode radio button
        if repeater_connection_mode == "frida":
            dpg.set_value("repeater_connection_mode", 0)  # Frida
            dpg.configure_item("repeater_direct_connection_settings", show=False)
        else:
            dpg.set_value("repeater_connection_mode", 1)  # Direct Socket
            dpg.configure_item("repeater_direct_connection_settings", show=True)
        
        # Update connection settings inputs
        dpg.set_value("repeater_host_input", repeater_connection_params["host"])
        dpg.set_value("repeater_port_input", repeater_connection_params["port"])
        dpg.set_value("repeater_protocol_input", repeater_connection_params["protocol"])
        dpg.set_value("repeater_timeout_input", repeater_connection_params["timeout"])
        
        # If there's a current packet selected, update the editor
        if current_repeater_packet_id and current_repeater_packet_id in repeater_packets:
            select_repeater_packet(None, None, current_repeater_packet_id)
        
        # If there's a current sequence selected, update the sequence view
        if current_repeater_sequence_id and current_repeater_sequence_id in repeater_sequences:
            select_repeater_sequence(None, None, current_repeater_sequence_id)
    except Exception as e:
        print(f"Error updating repeater UI: {e}")
        import traceback
        print(traceback.format_exc())

def update_repeater_sequences_list():
    """Update the list of sequences in the Repeater UI"""
    try:
        # Clear existing items
        dpg.delete_item("repeater_sequences_list", children_only=True)
        
        # Add each sequence to the list
        for seq_id, sequence in repeater_sequences.items():
            # Create a button for each sequence
            btn_id = dpg.add_button(
                label=f"{sequence.name} ({len(sequence.packet_ids)} packets)",
                callback=select_repeater_sequence,
                user_data=seq_id,
                width=-1,
                parent="repeater_sequences_list"
            )
            
            # Highlight the currently selected sequence
            if seq_id == current_repeater_sequence_id:
                dpg.bind_item_theme(btn_id, "selected_item_theme")
    except Exception as e:
        print(f"Error updating repeater sequences list: {e}")
        import traceback
        print(traceback.format_exc())

def update_repeater_packets_list():
    """Update the list of packets in the currently selected sequence"""
    try:
        # Clear existing items
        dpg.delete_item("repeater_packets_list", children_only=True)
        
        # If no sequence is selected, return
        if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
            return
        
        # Get the current sequence
        sequence = repeater_sequences[current_repeater_sequence_id]
        
        # Add each packet in the sequence to the list
        for packet_id in sequence.packet_ids:
            if packet_id in repeater_packets:
                packet = repeater_packets[packet_id]
                
                # Get packet metadata
                packet_type = packet.metadata.get("packet_type", "undefined")
                buffer_length = packet.metadata.get("buffer_length", 0)
                
                # Create a button for each packet
                btn_id = dpg.add_button(
                    label=f"{packet_type} ({buffer_length} bytes)",
                    callback=select_repeater_packet,
                    user_data=packet_id,
                    width=-1,
                    parent="repeater_packets_list"
                )
                
                # Highlight the currently selected packet
                if packet_id == current_repeater_packet_id:
                    dpg.bind_item_theme(btn_id, "selected_item_theme")
    except Exception as e:
        print(f"Error updating repeater packets list: {e}")
        import traceback
        print(traceback.format_exc())

def select_repeater_sequence(sender, app_data, user_data):
    """Handle selection of a sequence in the Repeater UI"""
    global current_repeater_sequence_id
    
    # Set the current sequence ID
    current_repeater_sequence_id = user_data
    
    # Enable the sequence replay button
    dpg.configure_item("replay_sequence_btn", enabled=True)
    dpg.configure_item("delete_repeater_sequence_btn", enabled=True)
    
    # Update the packets list
    update_repeater_packets_list()
    
    # Save repeater state
    save_repeater_state()

def select_repeater_packet(sender, app_data, user_data):
    """Handle selection of a packet in the Repeater UI"""
    global current_repeater_packet_id
    
    # Set the current packet ID
    current_repeater_packet_id = user_data
    
    # Get the packet
    packet = repeater_packets[user_data]
    
    # Update the packet editor
    try:
        # Get the hex data to display (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        data = bytes.fromhex(hex_data)
        
        # Update the hexdump widget
        repeater_hexdump_widget.set_data(data, user_data, packet.metadata.get("markers", []))
        
        # Update the packet editor title
        packet_type = packet.metadata.get("packet_type", "undefined")
        buffer_length = packet.metadata.get("buffer_length", 0)
        dpg.set_value("repeater_packet_editor_title", f"Packet Editor - {packet_type} ({buffer_length} bytes)")
        
        # Enable the packet replay button
        dpg.configure_item("replay_packet_btn", enabled=True)
        
        # If there's a response in the history, display it
        if packet.replay_history:
            last_replay = packet.replay_history[-1]
            if last_replay.get("response"):
                try:
                    response_data = bytes.fromhex(last_replay["response"])
                    repeater_response_hexdump_widget.set_data(response_data, None)
                    
                    # Update response title with timestamp
                    import datetime
                    timestamp = datetime.datetime.fromtimestamp(last_replay["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    dpg.set_value("repeater_response_title", f"Response - {timestamp}")
                except ValueError:
                    print("Invalid hex data in response")
    except Exception as e:
        print(f"Error selecting repeater packet: {e}")
        import traceback
        print(traceback.format_exc())
    
    # Save repeater state
    save_repeater_state()

def set_repeater_connection_mode(sender, app_data):
    """Set the connection mode for the Repeater"""
    global repeater_connection_mode
    
    # Set the connection mode based on radio button value
    if app_data == 0:
        repeater_connection_mode = "frida"
        dpg.configure_item("repeater_direct_connection_settings", show=False)
    else:
        repeater_connection_mode = "direct"
        dpg.configure_item("repeater_direct_connection_settings", show=True)
    
    # Save repeater state
    save_repeater_state()

def update_repeater_connection_settings(sender, app_data):
    """Update the connection settings for direct socket mode"""
    global repeater_connection_params
    
    # Get values from UI
    host = dpg.get_value("repeater_host_input")
    port = dpg.get_value("repeater_port_input")
    protocol = dpg.get_value("repeater_protocol_input")
    timeout = dpg.get_value("repeater_timeout_input")
    
    # Update connection params
    repeater_connection_params["host"] = host
    repeater_connection_params["port"] = port
    repeater_connection_params["protocol"] = protocol
    repeater_connection_params["timeout"] = timeout
    
    # Save repeater state
    save_repeater_state()

def create_new_repeater_sequence():
    """Create a new empty sequence in the Repeater"""
    global repeater_sequences
    
    # Generate a unique ID
    sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    sequence = RepeaterSequence(
        id=sequence_id,
        name=f"Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=time.time(),
        last_replayed_at=0
    )
    
    # Add to sequences dictionary
    repeater_sequences[sequence_id] = sequence
    
    # Update UI
    update_repeater_sequences_list()
    
    # Select the new sequence
    select_repeater_sequence(None, None, sequence_id)
    
    # Save repeater state
    save_repeater_state()

def delete_repeater_sequence():
    """Delete the currently selected sequence"""
    global repeater_sequences, current_repeater_sequence_id, current_repeater_packet_id
    
    # Check if a sequence is selected
    if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
        return
    
    # Get the sequence
    sequence = repeater_sequences[current_repeater_sequence_id]
    
    # Remove all packets in the sequence
    for packet_id in sequence.packet_ids:
        if packet_id in repeater_packets:
            del repeater_packets[packet_id]
    
    # Remove the sequence
    del repeater_sequences[current_repeater_sequence_id]
    
    # Reset current selections
    if current_repeater_sequence_id == current_repeater_sequence_id:
        current_repeater_sequence_id = None
    if current_repeater_packet_id in sequence.packet_ids:
        current_repeater_packet_id = None
    
    # Update UI
    update_repeater_sequences_list()
    update_repeater_packets_list()
    
    # Disable buttons
    dpg.configure_item("replay_sequence_btn", enabled=False)
    dpg.configure_item("delete_repeater_sequence_btn", enabled=False)
    
    # Save repeater state
    save_repeater_state()

def replay_current_repeater_packet():
    """Replay the currently selected packet"""
    # Check if a packet is selected
    if not current_repeater_packet_id or current_repeater_packet_id not in repeater_packets:
        return
    
    # Replay based on connection mode
    if repeater_connection_mode == "frida":
        success = replay_packet_frida(current_repeater_packet_id)
    else:
        success = replay_packet_direct(current_repeater_packet_id, repeater_connection_params)
    
    # Update UI after replay
    if success:
        # Refresh the packet view to show the response
        select_repeater_packet(None, None, current_repeater_packet_id)

def replay_current_repeater_sequence():
    """Replay the currently selected sequence"""
    # Check if a sequence is selected
    if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
        return
    
    # Replay based on connection mode
    if repeater_connection_mode == "frida":
        success = replay_sequence_frida(current_repeater_sequence_id)
    else:
        success = replay_sequence_direct(current_repeater_sequence_id, repeater_connection_params)
    
    # Update UI after replay
    if success and current_repeater_packet_id:
        # Refresh the packet view to show the response
        select_repeater_packet(None, None, current_repeater_packet_id)


# Create theme for delete button
with dpg.theme(tag="delete_button_theme"):
    with dpg.theme_component(dpg.mvButton):
        dpg.add_theme_color(dpg.mvThemeCol_Button, (150, 20, 20))
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (200, 30, 30))
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (250, 40, 40))

dpg.create_viewport(title="Frida Network Interceptor", width=1600, height=800)
dpg.setup_dearpygui()

# Create the main window
with dpg.window(label="Frida Network Interceptor", tag="main_window"):
    # Control panel
    with dpg.group(horizontal=True):
        dpg.add_input_text(label="Target Process/PID", tag="target_input", width=200)
        dpg.add_button(label="Start", callback=start_intercepting, tag="start_button")
        dpg.add_button(label="Stop", callback=stop_intercepting, tag="stop_button", enabled=False)
        dpg.add_text("Stopped", tag="status")

    # Add tabs for different views
    with dpg.tab_bar(tag="main_tab_bar"):
        # Main view tab
        with dpg.tab(label="Main View", tag="main_view_tab"):
            # Main content area
            with dpg.group(horizontal=True):
                # Left panel - Console and Sequences
                with dpg.child_window(width=400, height=600):
                    dpg.add_text("Console Output")
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="Clear Console", callback=clear_console)
                    dpg.add_input_text(multiline=True, width=-1, height=250, tag="console", readonly=True)
                    
                    dpg.add_separator()
                    dpg.add_text("Filters")
                    
                    # Size filter
                    with dpg.group(horizontal=True):
                        dpg.add_text("Size:")
                        dpg.add_input_int(tag="size_filter", width=100, default_value=0, callback=update_sequences_list)
                        dpg.add_text("Exclude Size:")
                        dpg.add_input_int(tag="exclude_size_filter", width=100, default_value=0, callback=update_sequences_list)
                    
                    # Host filter
                    with dpg.group(horizontal=True):
                        dpg.add_text("Host:")
                        dpg.add_input_text(tag="host_filter", width=100, callback=update_sequences_list)
                        dpg.add_text("Exclude Host:")
                        dpg.add_input_text(tag="exclude_host_filter", width=100, callback=update_sequences_list)
                    
                    # Port filter
                    with dpg.group(horizontal=True):
                        dpg.add_text("Port:")
                        dpg.add_input_text(tag="port_filter", width=100, callback=update_sequences_list)
                        dpg.add_text("Exclude Port:")
                        dpg.add_input_text(tag="exclude_port_filter", width=100, callback=update_sequences_list)
                    
                    # Callstack filter
                    with dpg.group(horizontal=True):
                        dpg.add_text("Callstack from selected:")
                        dpg.add_button(label="Set from current", callback=set_callstack_filter)
                        dpg.add_button(label="Reset", callback=reset_callstack_filter)
                    dpg.add_input_text(tag="callstack_filter", width=-1, height=50, readonly=True)
                    
                    # Callstack word filter
                    with dpg.group(horizontal=True):
                        dpg.add_text("Callstack contains:")
                        dpg.add_input_text(tag="callstack_word_filter", width=100, callback=update_sequences_list)
                    
                    # Hide received packets filter
                    with dpg.group(horizontal=True):
                        dpg.add_checkbox(label="Hide Received Packets", tag="hide_received", callback=update_sequences_list)
                    
                    dpg.add_separator()
                    
                    # Reset all filters button
                    dpg.add_button(label="Reset All Filters", callback=reset_all_filters)
                    
                    dpg.add_separator()
                    # Add buttons for sequence management
                    with dpg.group(horizontal=True):
                        dpg.add_text("Captured Sequences")
                        dpg.add_button(label="Clear Filtered", callback=clear_filtered_sequences)
                    dpg.add_child_window(tag="sequences_list", height=250)

                # Middle panel - Sequence Details
                with dpg.child_window(width=350, height=600):
                    dpg.add_group(tag="sequence_details_group")
                    dpg.add_text("Sequence Details", parent="sequence_details_group")
                    dpg.add_input_text(multiline=True, width=-1, height=400, tag="sequence_details", readonly=True, parent="sequence_details_group")
                    
                    # Add packet type management section
                    dpg.add_separator()
                    dpg.add_text("Packet Type Management")
                    dpg.add_group(horizontal=True, tag="type_management_buttons")

                # Right panel - Hexdump Display
                with dpg.child_window(width=800, height=600):
                    dpg.add_text("Hexdump View")
                    # Create hexdump widget instance
                    global hexdump_widget
                    hexdump_widget = HexdumpWidget(packet_type_manager=packet_type_manager,
                        tag="hexdump_view",
                        width=780,
                        height=570,
                        on_regions_changed=update_sequence_regions,
                        on_send_to_diff_1=send_to_diff_pane_1,
                        on_send_to_diff_2=send_to_diff_pane_2
                    )
                    # The hexdump widget handles its own context menu

        # Packet Types tab
        with dpg.tab(label="Packet Types", tag="packet_types_tab", parent="main_tab_bar"):
            with dpg.child_window(width=-1, height=600):
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

        # Diff View tab
        with dpg.tab(label="Diff View", tag="diff_view_tab", parent="main_tab_bar"):
            # Controls at the top
            # --- Diff Algorithm Selection and Parameter Controls ---
            with dpg.group(horizontal=True):
                dpg.add_combo(
                    items=[
                        "Basic Byte Diff",
                        "Histogram Diff",
                        "Binary Delta",
                        "Fuzzy Block Matching",
                        "Wavefront Alignment",
                        "Needleman-Wunsch",
                        "Smith-Waterman"
                    ],
                    default_value="Basic Byte Diff",
                    callback=select_diff_algorithm,
                    tag="diff_algorithm_dropdown",
                    label="Diff Algorithm"
                )
                # Parameter fields for alignment algorithms (hidden unless needed)
                dpg.add_input_int(
                    label="Gap Penalty",
                    default_value=-2,
                    tag="gap_penalty_input",
                    width=120,
                    min_value=-100,
                    max_value=0,
                    show=False
                )
                dpg.add_input_int(
                    label="Match Score",
                    default_value=3,
                    tag="match_score_input",
                    width=120,
                    min_value=1,
                    max_value=10,
                    show=False
                )
                dpg.add_input_int(
                    label="Mismatch Penalty",
                    default_value=-2,
                    tag="mismatch_penalty_input",
                    width=120,
                    min_value=-100,
                    max_value=0,
                    show=False
                )
                dpg.add_input_int(
                    label="Gap Opening",
                    default_value=-2,
                    tag="gap_opening_input",
                    width=120,
                    min_value=-100,
                    max_value=0,
                    show=False
                )
                dpg.add_input_int(
                    label="Gap Extension",
                    default_value=-2,
                    tag="gap_extension_input",
                    width=120,
                    min_value=-100,
                    max_value=0,
                    show=False
                )
                dpg.add_button(label="Refresh diff", callback=run_diff)

            # Split screen container
            with dpg.group(horizontal=True):
                # Left pane
                with dpg.child_window(width=600, height=600, tag="diff_pane_1"):
                    dpg.add_combo(
                        items=[],
                        callback=select_diff_source_1,
                        tag="diff_source_1_dropdown",
                        label="Source Packet 1",
                        width=200
                    )
                    # Create left hexdump widget
                    diff_hexdump_1 = HexdumpWidget(
                        packet_type_manager=packet_type_manager,
                        tag="diff_hexdump_1",
                        width=580,
                        height=550,
                        marker_editor_window_tag="diff_marker_editor_window_1",
                        marker_editor_tag_suffix="_diff1"
                    )

                # Right pane
                with dpg.child_window(width=600, height=600, tag="diff_pane_2"):
                    dpg.add_combo(
                        items=[],
                        callback=select_diff_source_2,
                        tag="diff_source_2_dropdown",
                        label="Source Packet 2",
                        width=200
                    )
                    # Create right hexdump widget
                    diff_hexdump_2 = HexdumpWidget(
                        packet_type_manager=packet_type_manager,
                        tag="diff_hexdump_2",
                        width=580,
                        height=550,
                        marker_editor_window_tag="diff_marker_editor_window_2",
                        marker_editor_tag_suffix="_diff2"
                    )
                    
        # Repeater tab
        with dpg.tab(label="Repeater", tag="repeater_tab", parent="main_tab_bar"):
            # Main layout with three panels
            with dpg.group(horizontal=True):
                # Left panel - Sequences Panel
                with dpg.child_window(width=300, height=500, tag="repeater_sequences_panel"):
                    dpg.add_text("Repeater Sequences")
                    
                    # Add buttons for sequence management
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="New Sequence", callback=lambda s, a: create_new_repeater_sequence(), tag="new_repeater_sequence_btn")
                        dpg.add_button(label="Delete", callback=lambda s, a: delete_repeater_sequence(), tag="delete_repeater_sequence_btn", enabled=False)
                    
                    # Sequences list
                    dpg.add_text("Sequences:")
                    dpg.add_child_window(tag="repeater_sequences_list", height=150)
                    
                    # Packets in selected sequence
                    dpg.add_separator()
                    dpg.add_text("Packets in Sequence:")
                    dpg.add_child_window(tag="repeater_packets_list", height=250)
                
                # Middle panel - Packet Editor Panel
                with dpg.child_window(width=500, height=500, tag="repeater_packet_editor_panel"):
                    dpg.add_text("Packet Editor", tag="repeater_packet_editor_title")
                    
                    # Create hexdump widget for packet editing
                    global repeater_hexdump_widget
                    repeater_hexdump_widget = HexdumpWidget(
                        packet_type_manager=packet_type_manager,
                        tag="repeater_hexdump_view",
                        width=480,
                        height=450,
                        on_regions_changed=update_repeater_packet_regions,
                        on_data_changed=update_repeater_packet_data,
                        marker_editor_window_tag="repeater_marker_editor_window",
                        marker_editor_tag_suffix="_repeater"
                    )
                
                # Right panel - Response Panel
                with dpg.child_window(width=400, height=500, tag="repeater_response_panel"):
                    dpg.add_text("Response", tag="repeater_response_title")
                    
                    # Response hexdump widget
                    global repeater_response_hexdump_widget
                    repeater_response_hexdump_widget = HexdumpWidget(
                        packet_type_manager=packet_type_manager,
                        tag="repeater_response_hexdump_view",
                        width=380,
                        height=450,
                        marker_editor_window_tag="repeater_response_marker_editor_window",
                        marker_editor_tag_suffix="_repeater_resp"
                        # Removed readonly=True as it's not a valid parameter
                    )
            
            # Bottom panel - Connection Controls Panel
            with dpg.child_window(height=150, tag="repeater_connection_panel"):
                with dpg.group(horizontal=True):
                    # Connection mode selection
                    dpg.add_text("Connection Mode:")
                    dpg.add_radio_button(
                        items=["Frida", "Direct Socket"],
                        horizontal=True,
                        callback=set_repeater_connection_mode,
                        tag="repeater_connection_mode"
                    )
                    
                    # Replay buttons
                    dpg.add_button(label="Replay Packet", callback=lambda s, a: replay_current_repeater_packet(), tag="replay_packet_btn", enabled=False)
                    dpg.add_button(label="Replay Sequence", callback=lambda s, a: replay_current_repeater_sequence(), tag="replay_sequence_btn", enabled=False)
                
                # Direct connection settings (hidden by default)
                with dpg.group(tag="repeater_direct_connection_settings", show=False):
                    with dpg.group(horizontal=True):
                        dpg.add_input_text(label="Host", tag="repeater_host_input", width=150, default_value=repeater_connection_params["host"])
                        dpg.add_input_int(label="Port", tag="repeater_port_input", width=100, default_value=repeater_connection_params["port"])
                        dpg.add_combo(label="Protocol", items=["TCP", "UDP"], default_value=repeater_connection_params["protocol"], tag="repeater_protocol_input", width=100)
                        dpg.add_input_float(label="Timeout (s)", tag="repeater_timeout_input", width=100, default_value=repeater_connection_params["timeout"])
                    
                    # Apply connection settings button
                    dpg.add_button(label="Apply Connection Settings", callback=update_repeater_connection_settings, tag="apply_connection_settings_btn")

# Create theme for selected items
with dpg.theme(tag="selected_item_theme"):
    with dpg.theme_component(dpg.mvButton):
        dpg.add_theme_color(dpg.mvThemeCol_Button, (0, 120, 255))
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (30, 150, 255))
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (60, 180, 255))

# Load existing sequences
load_sequences()

# Load repeater state
load_repeater_state()

# Update repeater UI with loaded state
update_repeater_ui()

# Initialize packet type management buttons
# update_packet_types_list()


# Start message processing thread
message_thread = threading.Thread(target=process_messages, daemon=True)
message_thread.start()

# Save sequences and repeater state when exiting
def save_on_exit():
    save_sequences()
    save_repeater_state()

dpg.set_exit_callback(save_on_exit)

# Show the GUI
dpg.show_viewport()
dpg.set_primary_window("main_window", True)
dpg.start_dearpygui()
dpg.destroy_context()