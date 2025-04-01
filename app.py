import dearpygui.dearpygui as dpg
import frida_handler
from queue import Queue
import json
import threading
import time

# Global state
message_queue = Queue()
sequences = []
is_running = False
target_process = ""

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
                    sequences.append(message)
                    # Update the console
                    try:
                        console_text = dpg.get_value("console_text") + "\n" + json.dumps(message, indent=2)
                        dpg.set_value("console_text", console_text)
                        # Update sequences list
                        update_sequences_list()
                    except Exception as e:
                        print(f"Error updating UI: {e}")
            time.sleep(0.1)  # Small delay to prevent high CPU usage
        except Exception as e:
            print(f"Error processing messages: {e}")

def start_intercepting(sender, app_data):
    """Start Frida interception"""
    global is_running, target_process
    if not is_running:
        target = dpg.get_value("target_input")
        if target:
            # Try converting to PID if possible
            try:
                target = int(target)
            except ValueError:
                pass
            
            success = frida_handler.start_frida(target, message_queue)
            if success:
                is_running = True
                target_process = target
                dpg.set_value("status_text", f"Running: Intercepting {target}")
                dpg.configure_item("start_button", enabled=False)
                dpg.configure_item("stop_button", enabled=True)
                dpg.configure_item("target_input", enabled=False)

def stop_intercepting(sender, app_data):
    """Stop Frida interception"""
    global is_running
    if is_running:
        frida_handler.stop_frida()
        is_running = False
        dpg.set_value("status_text", "Stopped")
        dpg.configure_item("start_button", enabled=True)
        dpg.configure_item("stop_button", enabled=False)
        dpg.configure_item("target_input", enabled=True)

def update_sequences_list():
    """Update the sequences list in the UI"""
    global sequences
    try:
        dpg.delete_item("sequences_list", children_only=True)
        for seq in sequences:
            label = f"#{seq['id']} - {seq['function_name']} ({seq['buffer_length']} bytes)"
            dpg.add_button(label=label, callback=show_sequence_details, user_data=seq, parent="sequences_list", width=-1)
    except Exception as e:
        print(f"Error updating sequences list: {e}")

def format_hexdump(hex_string):
    """Format hex string into a hexdump with offset, hex values, and ASCII"""
    # Convert hex string to bytes
    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        return "Invalid hex data"

    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        # Hex offset
        line = f"{i:08x}  "
        
        # Hex values (in groups of 8 bytes)
        hex_values = []
        for j in range(0, len(chunk), 8):
            group = chunk[j:j+8]
            hex_values.append(" ".join(f"{b:02x}" for b in group))
        line += "  ".join(hex_values)
        
        # Padding for incomplete lines
        if len(chunk) < 16:
            padding = "   " * (16 - len(chunk))
            if len(chunk) < 8:
                padding = padding + " "
            line += padding
        
        # ASCII representation
        line += "  |"
        for b in chunk:
            if 32 <= b <= 126:  # Printable ASCII
                line += chr(b)
            else:
                line += "."
        line += "|"
        
        result.append(line)
    
    return "\n".join(result)

def show_sequence_details(sender, app_data, user_data):
    """Show details of selected sequence"""
    seq = user_data
    details = (
        f"Function: {seq['function_name']}\n"
        f"Socket ID: {seq['socket_id']}\n"
        f"Socket Info: {seq['socket_info']}\n"
        f"Buffer Length: {seq['buffer_length']}\n"
        f"Flags: {seq['flags']}\n\n"
        f"Raw Hex Data:\n{seq['hex_data']}\n\n"
        f"Hexdump:\n{format_hexdump(seq['hex_data'])}\n\n"
        f"Backtrace:\n" + "\n".join(seq['backtrace'])
    )
    dpg.set_value("sequence_details_text", details)

def clear_console(sender, app_data):
    """Clear the console output"""
    dpg.set_value("console_text", "")

# Initialize DearPyGui
dpg.create_context()

# Create value registry
with dpg.value_registry():
    dpg.add_string_value(default_value="", tag="console_text")
    dpg.add_string_value(default_value="", tag="sequence_details_text")
    dpg.add_string_value(default_value="Stopped", tag="status_text")

# Create viewport
dpg.create_viewport(title="Frida Network Interceptor", width=1200, height=800)
dpg.setup_dearpygui()

# Create the main window
with dpg.window(label="Frida Network Interceptor", tag="main_window"):
    # Control panel
    with dpg.group(horizontal=True):
        dpg.add_input_text(label="Target Process/PID", tag="target_input", width=200)
        dpg.add_button(label="Start", callback=start_intercepting, tag="start_button")
        dpg.add_button(label="Stop", callback=stop_intercepting, tag="stop_button", enabled=False)
        dpg.add_text(source="status_text", tag="status")

    # Main content area
    with dpg.group(horizontal=True):
        # Left panel - Console and Sequences
        with dpg.child_window(width=400, height=600):
            dpg.add_text("Console Output")
            with dpg.group(horizontal=True):
                dpg.add_button(label="Clear Console", callback=clear_console)
            dpg.add_input_text(source="console_text", multiline=True, width=-1, height=250, tag="console", readonly=True)
            
            dpg.add_separator()
            dpg.add_text("Captured Sequences")
            dpg.add_child_window(tag="sequences_list", height=250)

        # Right panel - Sequence Details
        with dpg.child_window(width=-1, height=600):
            dpg.add_text("Sequence Details")
            dpg.add_input_text(source="sequence_details_text", multiline=True, width=-1, height=-1, tag="sequence_details", readonly=True)

# Start message processing thread
message_thread = threading.Thread(target=process_messages, daemon=True)
message_thread.start()

# Show the GUI
dpg.show_viewport()
dpg.set_primary_window("main_window", True)
dpg.start_dearpygui()
dpg.destroy_context()