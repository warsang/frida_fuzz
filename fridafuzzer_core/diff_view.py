"""
Diff View Module for Frida Network Interceptor
Handles the comparison and diffing of packets
"""

import dearpygui.dearpygui as dpg
from typing import Optional
from fridafuzzer_core.hexdump_widget import HexdumpWidget

# --- Biodiff Algorithm Imports ---
from fridafuzzer_core.biodiff_algorithms import (
    needleman_wunsch,
    smith_waterman,
    wavefront_alignment
)

# Global state
diff_source_1_data: Optional[bytes] = None
diff_source_2_data: Optional[bytes] = None
diff_source_1_id: Optional[str] = None
diff_source_2_id: Optional[str] = None
diff_algorithm: str = "Basic Byte Diff"
diff_hexdump_1 = None
diff_hexdump_2 = None

# Shared state
sequences = None
packet_type_manager = None

def initialize(shared_sequences, shared_packet_type_manager):
    """Initialize the diff view module with shared resources"""
    global sequences, packet_type_manager
    sequences = shared_sequences
    packet_type_manager = shared_packet_type_manager

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

    run_diff()

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

def setup_diff_view_ui():
    """Set up the diff view UI components"""
    global diff_hexdump_1, diff_hexdump_2
    
    # Controls at the top
    with dpg.group(horizontal=True, parent="diff_view_tab"):
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
    with dpg.group(horizontal=True, parent="diff_view_tab"):
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
            global diff_hexdump_1
            # Get the widget ID for the parent
            parent_id = "diff_pane_1"  # Just use the tag directly
            diff_hexdump_1 = HexdumpWidget(
                packet_type_manager=packet_type_manager,
                tag="diff_hexdump_1",
                width=580,
                height=550,
                marker_editor_window_tag="diff_marker_editor_window_1",
                marker_editor_tag_suffix="_diff1",
                parent=parent_id  # Pass parent ID
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
            global diff_hexdump_2
            # Get the widget ID for the parent
            parent_id = "diff_pane_2"  # Just use the tag directly
            diff_hexdump_2 = HexdumpWidget(
                packet_type_manager=packet_type_manager,
                tag="diff_hexdump_2",
                width=580,
                height=550,
                marker_editor_window_tag="diff_marker_editor_window_2",
                marker_editor_tag_suffix="_diff2",
                parent=parent_id  # Pass parent ID
            )