import streamlit as st
import frida_handler # Import our Frida logic
import json
import pathlib
import time
from queue import Queue
import difflib # For diffing later

# --- Configuration ---
SAVE_FILE = pathlib.Path("sequences.json")
MAX_QUEUE_CHECKS_PER_RUN = 10 # Avoid blocking Streamlit for too long

# --- Helper Functions ---

def load_sequences():
    """Loads sequences from the JSON save file."""
    if SAVE_FILE.exists():
        try:
            with open(SAVE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            st.error(f"Error: Could not decode JSON from {SAVE_FILE}. Starting with empty sequence list.")
            return []
        except Exception as e:
            st.error(f"Error loading sequences from {SAVE_FILE}: {e}")
            return []
    else:
        return []

def save_sequences(sequences):
    """Saves sequences to the JSON save file."""
    try:
        with open(SAVE_FILE, "w", encoding="utf-8") as f:
            json.dump(sequences, f, indent=2) # Use indent for readability
    except Exception as e:
        st.error(f"Error saving sequences to {SAVE_FILE}: {e}")

def format_sequence_title(seq):
    """Creates a concise title for a sequence expander."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seq.get('timestamp', 0)))
    func_name = seq.get('function_name', 'N/A')
    length = seq.get('buffer_length', 0)
    return f"#{seq.get('id', 'N/A')} - {ts} - {func_name} ({length} bytes)"

def format_hex_for_diff(hex_string, bytes_per_line=16):
    """Formats a raw hex string into lines for better diffing."""
    lines = []
    for i in range(0, len(hex_string), bytes_per_line * 2):
        lines.append(hex_string[i:i + bytes_per_line * 2])
    return lines

def generate_side_by_side_diff(hex_a, hex_b, bytes_per_line=16):
    """Generates two lists of strings representing a side-by-side diff."""
    lines_a = format_hex_for_diff(hex_a, bytes_per_line)
    lines_b = format_hex_for_diff(hex_b, bytes_per_line)

    diff = list(difflib.ndiff(lines_a, lines_b))

    output_a = []
    output_b = []
    placeholder = "." * (bytes_per_line * 2) # Placeholder for added/removed lines

    for line in diff:
        code = line[:2]
        content = line[2:]
        if code == '- ':
            output_a.append(f"- {content}")
            output_b.append(f"  {placeholder}") # Add placeholder to keep alignment
        elif code == '+ ':
            output_a.append(f"  {placeholder}") # Add placeholder
            output_b.append(f"+ {content}")
        elif code == '  ':
            output_a.append(f"  {content}")
            output_b.append(f"  {content}")
        # Ignore '? ' lines for this basic diff view

    return "\n".join(output_a), "\n".join(output_b)

# --- Initialize Session State ---
# Ensure session state variables are initialized only once

if 'sequences' not in st.session_state:
    st.session_state.sequences = load_sequences()
    print(f"Loaded {len(st.session_state.sequences)} sequences initially.")

if 'is_running' not in st.session_state:
    st.session_state.is_running = False

if 'target_process' not in st.session_state:
    st.session_state.target_process = "" # Store the currently targeted process

if 'frida_session' not in st.session_state:
    st.session_state.frida_session = None # Managed by frida_handler

if 'frida_script' not in st.session_state:
    st.session_state.frida_script = None # Managed by frida_handler

if 'message_queue' not in st.session_state:
    st.session_state.message_queue = Queue()

if 'console_queue' not in st.session_state:
    st.session_state.console_queue = None

if 'console_logs' not in st.session_state:
    st.session_state.console_logs = []

if 'selected_seq_a' not in st.session_state:
    st.session_state.selected_seq_a = None

if 'selected_seq_b' not in st.session_state:
    st.session_state.selected_seq_b = None


# --- UI Layout ---
st.set_page_config(layout="wide") # Use wide layout for better display
st.title("🔬 Frida Network Interceptor")

# --- Control Panel ---
with st.expander("Controls & Status", expanded=True):
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        # Input for target process
        target_input = st.text_input(
            "Target Process Name or PID:",
            value=st.session_state.target_process,
            key="target_process_input",
            disabled=st.session_state.is_running # Disable input while running
        )

    with col2:
        # Start Button
        if st.button("🚀 Start Intercepting", disabled=st.session_state.is_running or not target_input):
            st.session_state.target_process = st.session_state.target_process_input # Update stored target
            st.info(f"Attempting to attach to '{st.session_state.target_process}'...")
            # Try converting to int if possible for PID targeting
            try:
                target = int(st.session_state.target_process)
            except ValueError:
                target = st.session_state.target_process # Keep as string name

            success, console_queue = frida_handler.start_frida(target, st.session_state.message_queue)
            if success:
                st.session_state.is_running = True
                st.session_state.console_queue = console_queue
                st.success(f"Successfully attached to '{st.session_state.target_process}'!")
                st.rerun() # Rerun to update UI state
            else:
                st.error(f"Failed to attach to '{st.session_state.target_process}'. Check console output.")
                st.session_state.is_running = False # Ensure state is correct
                st.session_state.console_queue = None

    with col3:
        # Stop Button
        if st.button("🛑 Stop Intercepting", disabled=not st.session_state.is_running):
            st.info("Detaching from process...")
            frida_handler.stop_frida()
            st.session_state.is_running = False
            st.session_state.console_queue = None
            st.session_state.console_logs = []  # Clear console logs when stopping
            st.success("Detached successfully.")
            st.rerun() # Rerun to update UI state

    # Status Indicator
    if st.session_state.is_running:
        st.success(f"🟢 Running: Intercepting '{st.session_state.target_process}'")
    else:
        st.info("⚪ Idle: Not intercepting.")

# --- Process Messages from Queue ---
new_sequences_added = False
processed_count = 0
while not st.session_state.message_queue.empty() and processed_count < MAX_QUEUE_CHECKS_PER_RUN:
    try:
        message = st.session_state.message_queue.get_nowait() # Non-blocking get
        if message.get('type') == 'sequence':
            # Assign a unique ID
            message['id'] = len(st.session_state.sequences) + 1
            st.session_state.sequences.append(message)
            new_sequences_added = True
        elif message.get('type') == 'error':
             # Display errors from Frida JS in the UI
             st.warning(f"Frida Error ({message.get('source', '?')}): {message.get('message', 'Unknown error')}")
        # Add handling for other message types if needed (e.g., 'return')

        st.session_state.message_queue.task_done()
        processed_count += 1
    except Exception as e:
        # Should not happen with Queue.empty check, but safety first
        st.error(f"Error processing message queue: {e}")
        break # Exit loop on error

# Save sequences if new ones were added
if new_sequences_added:
    save_sequences(st.session_state.sequences)
    # Trigger a rerun to update the display immediately
    st.rerun()


# --- Display Console Logs ---
st.header("🖥️ Console Output")
with st.expander("Raw Console Logs", expanded=True):
    # Process any new console logs
    if st.session_state.console_queue:
        while not st.session_state.console_queue.empty():
            try:
                log = st.session_state.console_queue.get_nowait()
                st.session_state.console_logs.append(log)
            except:
                break
    
    # Display all logs
    if st.session_state.console_logs:
        st.code("\n".join(st.session_state.console_logs), language="json")
    else:
        st.info("No console output yet.")

# --- Display Sequences ---
st.header(f"📜 Captured Sequences ({len(st.session_state.sequences)})")
if not st.session_state.sequences:
    st.info("No sequences captured yet. Start intercepting to capture data.")
else:
    # Display sequences in reverse order (newest first)
    for seq in reversed(st.session_state.sequences):
        with st.expander(format_sequence_title(seq)):
            # Display detailed information within the expander
            st.markdown(f"**Timestamp:** `{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seq.get('timestamp', 0)))}`")
            st.markdown(f"**Function:** `{seq.get('function_name', 'N/A')}`")
            st.markdown(f"**Socket ID:** `{seq.get('socket_id', 'N/A')}`")
            st.markdown(f"**Socket Info:** `{seq.get('socket_info', 'N/A')}`")
            st.markdown(f"**Flags:** `{seq.get('flags', 'N/A')}`")
            st.markdown(f"**Buffer Length:** `{seq.get('buffer_length', 0)}` bytes")

            st.markdown("**Hex Data:**")
            hex_data = seq.get('hex_data', '')
            if hex_data:
                # Display hex data in a code block, potentially formatting it
                # For now, just display the raw hex string
                st.code(hex_data, language=None) # Use None for plain text
            else:
                st.text("No data captured.")

            st.markdown("**Backtrace:**")
            backtrace = seq.get('backtrace', [])
            if backtrace:
                st.text('\n'.join(backtrace)) # Display backtrace lines
            else:
                st.text("No backtrace available.")


# --- Diffing Section ---
st.header("↔️ Sequence Diffing")
if len(st.session_state.sequences) < 2:
    st.info("Need at least two sequences to perform a diff.")
else:
    # Prepare options for select boxes (using sequence titles)
    # Store mapping from title back to sequence ID
    seq_options = {format_sequence_title(seq): seq['id'] for seq in st.session_state.sequences}
    # Reverse mapping for finding default index
    seq_id_to_title = {v: k for k, v in seq_options.items()}

    # Get current selections or set default to None
    current_a_title = seq_id_to_title.get(st.session_state.selected_seq_a)
    current_b_title = seq_id_to_title.get(st.session_state.selected_seq_b)

    col_a, col_b = st.columns(2)
    with col_a:
        selected_title_a = st.selectbox(
            "Select Sequence A:",
            options=list(seq_options.keys()),
            index=list(seq_options.keys()).index(current_a_title) if current_a_title in seq_options else 0, # Default index or 0
            key="select_a"
        )
        st.session_state.selected_seq_a = seq_options[selected_title_a] # Store selected ID

    with col_b:
        selected_title_b = st.selectbox(
            "Select Sequence B:",
            options=list(seq_options.keys()),
            index=list(seq_options.keys()).index(current_b_title) if current_b_title in seq_options else 1 if len(seq_options) > 1 else 0, # Default index or 1
            key="select_b"
        )
        st.session_state.selected_seq_b = seq_options[selected_title_b] # Store selected ID

    # Perform and display diff if two valid sequences are selected
    if st.session_state.selected_seq_a is not None and st.session_state.selected_seq_b is not None:
        # Find the actual sequence dictionaries
        seq_a = next((s for s in st.session_state.sequences if s['id'] == st.session_state.selected_seq_a), None)
        seq_b = next((s for s in st.session_state.sequences if s['id'] == st.session_state.selected_seq_b), None)

        if seq_a and seq_b:
            if st.session_state.selected_seq_a == st.session_state.selected_seq_b:
                 st.warning("Please select two different sequences to compare.")
            else:
                hex_a = seq_a.get('hex_data', '')
                hex_b = seq_b.get('hex_data', '')

                diff_a, diff_b = generate_side_by_side_diff(hex_a, hex_b)

                st.subheader("Diff Results:")
                diff_col_a, diff_col_b = st.columns(2)
                with diff_col_a:
                    st.markdown(f"**Sequence A (#{st.session_state.selected_seq_a})**")
                    st.text_area("Diff A", value=diff_a, height=300, key="diff_a_text", help="Lines starting with '-' are unique to A.")
                with diff_col_b:
                    st.markdown(f"**Sequence B (#{st.session_state.selected_seq_b})**")
                    st.text_area("Diff B", value=diff_b, height=300, key="diff_b_text", help="Lines starting with '+' are unique to B.")
        else:
            st.error("Could not find selected sequence data.") # Should not happen if IDs are correct


# --- Footer ---
st.markdown("---")
st.caption(f"Loaded {len(st.session_state.sequences)} sequences. Save file: {SAVE_FILE.resolve()}")