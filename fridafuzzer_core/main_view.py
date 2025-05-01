"""
Main View Module for Frida Network Interceptor
Handles the main UI, sequence management, and filtering functionality
"""

import dearpygui.dearpygui as dpg
import json
import time
import threading
from queue import Queue
from typing import Optional, Dict, Any, List
from fridafuzzer_core import frida_handler
from fridafuzzer_core.packet_type_manager import PacketTypeManager

# Global state that will be shared across modules
message_queue = Queue()
sequences = []
is_running = False
target_process = ""
current_sequence = None  # Store current sequence for filter operations
packet_type_manager = None
hexdump_widget = None

def initialize(shared_packet_type_manager):
    """Initialize the main view module with shared resources"""
    global packet_type_manager
    packet_type_manager = shared_packet_type_manager

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
        from fridafuzzer_core.diff_view import run_diff
        run_diff()
    except Exception as e:
        print(f"Error updating sequences list: {e}")
        import traceback
        print(traceback.format_exc())

def show_sequence_details(sender, app_data, user_data):
    """Show details of selected sequence"""
    global current_sequence, hexdump_widget
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

def clear_console(sender, app_data):
    """Clear the console output"""
    dpg.set_value("console", "")

def setup_main_view_ui():
    """Set up the main view UI components"""
    # Main content area
    with dpg.group(horizontal=True, parent="main_view_tab"):
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

def send_to_diff_pane_1(sequence_id):
    """Forward to diff_view module"""
    from fridafuzzer_core.diff_view import send_to_diff_pane_1 as diff_send_to_pane_1
    diff_send_to_pane_1(sequence_id)

def send_to_diff_pane_2(sequence_id):
    """Forward to diff_view module"""
    from fridafuzzer_core.diff_view import send_to_diff_pane_2 as diff_send_to_pane_2
    diff_send_to_pane_2(sequence_id)

def send_to_repeater(sequence_id):
    """Forward to repeater_tab module"""
    from fridafuzzer_core.repeater_tab import send_to_repeater as repeater_send
    return repeater_send(sequence_id)

def send_filtered_to_repeater():
    """Forward to repeater_tab module"""
    from fridafuzzer_core.repeater_tab import send_filtered_to_repeater as repeater_send_filtered
    return repeater_send_filtered()