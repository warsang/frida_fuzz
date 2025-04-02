import dearpygui.dearpygui as dpg
import frida_handler
from queue import Queue
import json
import threading
import time
from hexdump_widget import HexdumpWidget

# Global state
message_queue = Queue()
sequences = []
is_running = False
target_process = ""
current_sequence = None  # Store current sequence for filter operations

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
                    # Add ID if not present
                    if 'id' not in message:
                        message['id'] = len(sequences) + 1
                    # Add fuzzable_regions if not present
                    if 'fuzzable_regions' not in message:
                        message['fuzzable_regions'] = []
                    sequences.append(message)
                    # Update console
                    console_text = dpg.get_value("console") + "\n" + json.dumps(message, indent=2)
                    dpg.set_value("console", console_text)
                    # Update sequences list
                    update_sequences_list()
                    # Save sequences to file
                    save_sequences()
            time.sleep(0.1)  # Small delay to prevent high CPU usage
        except Exception as e:
            print(f"Error processing messages: {e}")

def start_intercepting(sender, app_data):
    """Start Frida interception"""
    global is_running, target_process
    if not is_running:
        target = dpg.get_value("target_input")
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
    dpg.set_value("host_filter", "")
    dpg.set_value("port_filter", "")
    dpg.set_value("callstack_filter", "")
    dpg.set_value("callstack_word_filter", "")
    update_sequences_list()

def apply_filters(sequences_list):
    """Apply filters to the sequences list"""
    size_filter = dpg.get_value("size_filter")
    host_filter = dpg.get_value("host_filter").strip()
    port_filter = dpg.get_value("port_filter").strip()
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
    
    return filtered

def update_sequences_list():
    """Update the sequences list in the UI"""
    dpg.delete_item("sequences_list", children_only=True)
    
    # Apply filters to sequences
    filtered_sequences = apply_filters(sequences)
    
    for seq in filtered_sequences:
        label = f"#{seq['id']} - {seq['function_name']} ({seq['buffer_length']} bytes)"
        dpg.add_button(label=label, callback=show_sequence_details, user_data=seq, parent="sequences_list", width=-1)

def show_sequence_details(sender, app_data, user_data):
    """Show details of selected sequence"""
    seq = user_data
    # Update sequence details
    details = (
        f"Function: {seq['function_name']}\n"
        f"Socket ID: {seq['socket_id']}\n"
        f"Socket Info: {seq['socket_info']}\n"
        f"Buffer Length: {seq['buffer_length']}\n"
        f"Flags: {seq['flags']}\n\n"
        f"Raw Hex Data:\n{seq['hex_data']}\n\n"
        f"Backtrace:\n" + "\n".join(seq['backtrace']) + "\n\n"
        f"Fuzzable Regions:\n"
    )
    
    if seq.get('fuzzable_regions'):
        for region in seq['fuzzable_regions']:
            details += f"  {region['start_offset']}-{region['end_offset']}: {region['mutation_type']}\n"
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
        
        # Clear existing fuzzable regions
        hexdump_widget.fuzzable_regions.clear()
        
        # Add regions from sequence
        for region in seq.get('fuzzable_regions', []):
            hexdump_widget.add_fuzzable_region(
                region['start_offset'],
                region['end_offset'],
                region['mutation_type']
            )
            
        # Restore the callback
        hexdump_widget.on_regions_changed = original_callback
    except ValueError:
        print("Invalid hex data")

def update_sequence_regions(sequence_id, regions):
    """Update fuzzable regions for a sequence and save to file"""
    for seq in sequences:
        if seq['id'] == sequence_id:
            seq['fuzzable_regions'] = [
                {
                    'start_offset': r.start_offset,
                    'end_offset': r.end_offset,
                    'mutation_type': r.mutation_type
                }
                for r in regions
            ]
            save_sequences()
            break

def clear_console(sender, app_data):
    """Clear the console output"""
    dpg.set_value("console", "")

# Initialize DearPyGui
dpg.create_context()
dpg.create_viewport(title="Frida Network Interceptor", width=1600, height=800)  # Increased viewport width
dpg.setup_dearpygui()

# Create the main window
with dpg.window(label="Frida Network Interceptor", tag="main_window"):
    # Control panel
    with dpg.group(horizontal=True):
        dpg.add_input_text(label="Target Process/PID", tag="target_input", width=200)
        dpg.add_button(label="Start", callback=start_intercepting, tag="start_button")
        dpg.add_button(label="Stop", callback=stop_intercepting, tag="stop_button", enabled=False)
        dpg.add_text("Stopped", tag="status")

    # Main content area
    with dpg.group(horizontal=True):
        # Left panel - Console and Sequences
        with dpg.child_window(width=350, height=600):  # Slightly reduced to give more space to hexdump
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
            
            # Host filter
            with dpg.group(horizontal=True):
                dpg.add_text("Host:")
                dpg.add_input_text(tag="host_filter", width=100, callback=update_sequences_list)
            
            # Port filter
            with dpg.group(horizontal=True):
                dpg.add_text("Port:")
                dpg.add_input_text(tag="port_filter", width=100, callback=update_sequences_list)
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
            
            dpg.add_separator()
            
            # Reset all filters button
            dpg.add_button(label="Reset All Filters", callback=reset_all_filters)
            
            dpg.add_separator()
            dpg.add_text("Captured Sequences")
            dpg.add_child_window(tag="sequences_list", height=250)

        # Middle panel - Sequence Details
        with dpg.child_window(width=350, height=600):  # Slightly reduced to give more space to hexdump
            dpg.add_text("Sequence Details")
            dpg.add_input_text(multiline=True, width=-1, height=-1, tag="sequence_details", readonly=True)

        # Right panel - Hexdump Display
        with dpg.child_window(width=800, height=600):  # Doubled the width
            dpg.add_text("Hexdump View")
            # Create hexdump widget instance
            global hexdump_widget
            hexdump_widget = HexdumpWidget(
                tag="hexdump_view",
                width=780,  # Doubled the width (minus padding)
                height=570,
                on_regions_changed=update_sequence_regions
            )

# Load existing sequences
load_sequences()

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