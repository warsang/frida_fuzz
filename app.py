import dearpygui.dearpygui as dpg
from fridafuzzer_core import frida_handler
from queue import Queue
import json
from fridafuzzer_core.packet_type_manager import PacketTypeManager, PacketTypeCriteria
import threading
import time
from typing import Optional
from fridafuzzer_core.hexdump_widget import HexdumpWidget

# --- Biodiff Algorithm Imports ---
from fridafuzzer_core.biodiff_algorithms import (
    needleman_wunsch,
    smith_waterman,
    wavefront_alignment
)

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
                popup_id = dpg.add_popup(parent=btn_id, mousebutton=dpg.mvMouseButton_Right)
                dpg.add_menu_item(label="Send to Diff Pane 1", callback=lambda s, a, u=seq['id']: send_to_diff_pane_1(u), parent=popup_id)
                dpg.add_menu_item(label="Send to Diff Pane 2", callback=lambda s, a, u=seq['id']: send_to_diff_pane_2(u), parent=popup_id)
                
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
# Load existing sequences
load_sequences()

# Initialize packet type management buttons
# update_packet_types_list()


# Start message processing thread
message_thread = threading.Thread(target=process_messages, daemon=True)
message_thread.start()

# Save sequences when exiting
dpg.set_exit_callback(save_sequences)

# Show the GUI
dpg.show_viewport()
dpg.set_primary_window("main_window", True)
dpg.start_dearpygui()
dpg.destroy_context()