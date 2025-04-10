import dearpygui.dearpygui as dpg
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Any
import struct
import hashlib
import zlib
import importlib.util # Added for dynamic KSY loading
import os # Needed for path operations in set_data
from ruamel.yaml import YAML
from .marker_manager import MarkerManager, MarkerRegion, MarkerType
from .packet_type_manager import PacketTypeManager
from .entropy_window import EntropyWindow
from .frequency_window import FrequencyWindow
from .ksy_editor_window import KsyEditorWindow # Keep for editing
from .marker_editor_window import MarkerEditorWindow

@dataclass
class MarkedRegion: # Keep for potential future use or reference, though KSY is primary now
    start_offset: int
    end_offset: int
    tag_name: str
    tag_type: str
    properties: Dict[str, Any]
@dataclass
class Selection:
    start_offset: int
    end_offset: int

@dataclass
class HexdumpOptions:
    uppercase_hex: bool = True
    show_ascii: bool = True
    grey_out_zeroes: bool = True
    show_hexii: bool = False  # HexII representation
    columns: int = 16
    mid_cols_count: int = 8  # Add spacing every X columns
    show_data_preview: bool = True
    show_statusbar: bool = True
    scroll_to_addr: Optional[int] = None  # Address to scroll to

class HexdumpWidget:
    # Update __init__ signature and add new instance variables
    def __init__(self, tag: str, width: int = 1200, height: int = 1600,
                 on_regions_changed=None,
                 packet_type_manager: Optional[PacketTypeManager] = None, # Added parameter
                 all_packets_data: Optional[Dict[str, Dict]] = {}): # Added parameter
        """Initialize the hexdump widget with default size."""
        self.tag = tag
        self.width = width
        self.height = height
        self.data = bytes()
        # self.marked_regions: List[MarkedRegion] = [] # Replaced by KSY structure
        self.current_selection: Optional[Selection] = None
        try:
            self.marker_manager = MarkerManager()
            self.marker_manager.load_marker_types()
        except FileNotFoundError:
            print("Warning: marker_types.json not found, no marker types loaded.")
        # Removed self.markers; markers are now managed by MarkerManager per packet type
        self.show_markers = True  # Default to showing markers
        self.marker_colors = {}  # Optional: for caching colors if needed
        self.ksy_struct = None # Holds the parsed Kaitai Struct object
        self.ksy_parse_error = None # Holds any error during KSY parsing
        # Instantiate the MarkerEditorWindow and store as instance variable
        self.marker_editor_window = MarkerEditorWindow(parent_widget=self, save_callback=self._handle_marker_save)
        self.is_selecting = False
        self.sequence_id = None # ID of the currently displayed packet
        self.on_regions_changed = on_regions_changed # Callback for when markers change (might need adjustment for KSY)
        self.options = HexdumpOptions()

        # Initialize analysis windows
        self.entropy_window = None
        self.frequency_window = None
        # Removed KSY editor window initialization
        self.addr_input = ""  # For goto address feature
        self.hovered_offset: Optional[int] = None  # For tooltips
        self.tooltip_tag = f"{self.tag}_tooltip"  # Tag for marker tooltip (might adapt for KSY fields)

        # Added instance variables for packet type handling and propagation
        self.packet_type_manager = packet_type_manager
        # Store KSY path instead of markers directly? Or maybe store parsed KSY?
        # Let's keep storing raw data for now, KSY is parsed on load.
        self.all_packets_data = all_packets_data if all_packets_data is not None else {} # Stores {sequence_id: {'data': bytes, 'type': str, 'callstack': str}}
        self.current_packet_type: Optional[str] = None # Type of the currently displayed packet
        self.current_type_markers: List[MarkerRegion] = []  # Markers for the current packet type

        # Initialize analysis windows
        self.entropy_window = None
        # Build the UI immediately after initialization
        self.build_ui()

    def build_ui(self):
        # Colors
        self.selection_color = (255, 255, 0, 100)  # Light yellow
        self.text_color = (255, 255, 255, 255)  # White
        # self.marker_colors = {} # Colors will be derived from KSY or default highlighting
        self.disabled_color = (128, 128, 128, 255)  # Grey for zero bytes
        self.separator_color = (128, 128, 128, 100)  # Grey for separator
        self.statusbar_color = (70, 70, 70, 255)  # Dark grey for status bar
        # Set font scale for optimal readability
        dpg.set_global_font_scale(1.0)

        # Create error modal and ensure it is hidden by default
        with dpg.window(label="Error", tag=f"{self.tag}_error_modal", width=300, height=100, show=False):
            dpg.add_text("", tag=f"{self.tag}_error_modal_text")
            dpg.hide_item(f"{self.tag}_error_modal") # Ensure initially hidden

        # Create widget structure
        with dpg.child_window(tag=self.tag, width=-1, height=-1, horizontal_scrollbar=True):
            # Add keyboard and mouse wheel handlers
            with dpg.handler_registry():
                dpg.add_key_press_handler(callback=self._on_key_press)
                dpg.add_mouse_wheel_handler(callback=self._on_mouse_wheel)

            # Create drawing canvas
            # Calculate minimum width based on content
            min_width = int(40 * dpg.get_global_font_scale())  # Base padding
            min_width += (8 + 4) * int(10 * dpg.get_global_font_scale())  # Offset area
            min_width += (self.options.columns * 3 + (self.options.columns // self.options.mid_cols_count) * 2) * int(10 * dpg.get_global_font_scale())  # Hex area
            if self.options.show_ascii:
                min_width += self.options.columns * int(10 * dpg.get_global_font_scale())  # ASCII area
                min_width += int(20 * dpg.get_global_font_scale())  # Separator padding

            # Force an extra wide content area
            content_width = max(8000, min_width)  # Much wider minimum width
            content_height = 3000  # Taller height too

            # Create a group to help with scrolling
            with dpg.group(horizontal=True):
                with dpg.drawlist(
                    width=content_width,
                    height=content_height,
                    tag=f"{self.tag}_canvas"
                ) as self.canvas:
                    # Add click and hover handlers
                    with dpg.item_handler_registry() as handler:
                        dpg.add_item_clicked_handler(callback=self._on_click)
                        dpg.add_item_hover_handler(callback=self._on_hover)
                    dpg.bind_item_handler_registry(self.canvas, handler)

            # Create context menu
            self.context_menu_tag = f"{self.tag}_context_menu"
            with dpg.popup(self.canvas, tag=self.context_menu_tag, mousebutton=dpg.mvMouseButton_Right):
                # Options submenu
                with dpg.menu(label="Options"):
                    dpg.add_checkbox(label="Uppercase Hex", default_value=self.options.uppercase_hex,
                                    callback=lambda s, a: self._set_option('uppercase_hex', a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Display hex values in uppercase")
                    
                    dpg.add_checkbox(label="Show ASCII", default_value=self.options.show_ascii,
                                   callback=lambda s, a: self._set_option('show_ascii', a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Show ASCII representation")
                    
                    dpg.add_checkbox(label="Grey Out Zeroes", default_value=self.options.grey_out_zeroes,
                                   callback=lambda s, a: self._set_option('grey_out_zeroes', a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Display null bytes in grey")
                    
                    dpg.add_checkbox(label="Show HexII", default_value=self.options.show_hexii,
                                   callback=lambda s, a: self._set_option('show_hexii', a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Hide null bytes, show ASCII as dots")
                    
                    dpg.add_checkbox(label="Show Data Preview", default_value=self.options.show_data_preview,
                                   callback=lambda s, a: self._set_option('show_data_preview', a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Show numeric interpretation of selected bytes")
                    
                    dpg.add_checkbox(label="Show Status Bar", default_value=self.options.show_statusbar,
                                   callback=lambda s, a: self._set_option('show_statusbar', a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Show offset and selection information")
                    
                    dpg.add_checkbox(label="Show Markers", default_value=True,
                                   callback=lambda s, a: self._toggle_show_markers(a))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Toggle between marker and KSY highlighting")
                    
                    dpg.add_slider_int(label="Columns", default_value=self.options.columns,
                                     min_value=4, max_value=32, callback=self._on_columns_changed)
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Number of bytes per row")

                dpg.add_separator()
                # Goto address input
                with dpg.group(horizontal=True):
                    dpg.add_input_text(label="Goto", callback=self._goto_addr,
                                     hint="hex addr", width=80, tag=f"{self.tag}_goto_input")
                    dpg.add_button(label="Go", callback=lambda: self._goto_addr(None, dpg.get_value(f"{self.tag}_goto_input")))
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Jump to specific hex address")

                dpg.add_separator()
                dpg.add_separator()
                
                with dpg.menu(label="Markers"):
                    dpg.add_menu_item(label="Add Marker", callback=self._add_marker)
                    dpg.add_menu_item(label="Modify Marker", callback=self._modify_marker)
                    dpg.add_menu_item(label="Remove Marker", callback=self._remove_marker)
                
                dpg.add_separator()

                # New KSY context menu items
                dpg.add_separator()
                dpg.add_menu_item(label="Define KSY Field Here", callback=self._define_ksy_field, tag=f"{self.tag}_define_ksy_field")
                dpg.add_menu_item(label="Modify KSY Field", callback=self._modify_ksy_field, tag=f"{self.tag}_modify_ksy_field", enabled=False)
                dpg.add_menu_item(label="Remove KSY Field", callback=self._remove_ksy_field, tag=f"{self.tag}_remove_ksy_field", enabled=False)
                dpg.add_separator()
                dpg.add_menu_item(label="Copy Selection", callback=self._copy_selection)
                dpg.add_menu_item(label="Copy as Hex", callback=self._copy_as_hex)
                dpg.add_separator()
                # Add analysis menu items with unique tags
                self.entropy_menu_tag = f"{self.tag}_entropy_menu_{dpg.generate_uuid()}"
                dpg.add_menu_item(
                    label="Analyze Entropy",
                    callback=self._show_entropy_analysis,
                    enabled=True,
                    tag=self.entropy_menu_tag
                )
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Show entropy analysis of selected bytes")

                self.frequency_menu_tag = f"{self.tag}_frequency_menu_{dpg.generate_uuid()}"
                dpg.add_menu_item(
                    label="Analyze Byte Frequencies",
                    callback=self._show_frequency_analysis,
                    enabled=True,
                    tag=self.frequency_menu_tag
                )
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Show frequency analysis of selected bytes")

                # Add KSY editor button as a standalone element
                dpg.add_separator()
                # Removed KSY Edit button in context menu

            # Data preview section
            if self.options.show_data_preview:
                with dpg.group(tag=f"{self.tag}_preview"):
                    dpg.add_text("Data Preview")
                    # Add endianness selector
                    with dpg.group(horizontal=True):
                        dpg.add_text("Byte Order:")
                        dpg.add_combo(items=["LE", "BE"], default_value="LE", width=50, tag=f"{self.tag}_preview_endian")
                        with dpg.tooltip(dpg.last_item()):
                            dpg.add_text("Little Endian (LE) or Big Endian (BE)")


            # Status bar
            if self.options.show_statusbar:
                with dpg.group(horizontal=True, tag=f"{self.tag}_statusbar"):
                    dpg.add_text("", tag=f"{self.tag}_status_text")
        self.frequency_window = None

    def _handle_marker_save(self, updated_marker):
        """
        Callback to update the marker list with the saved marker from the editor.
        """
        print("[DEBUG] HexdumpWidget._handle_marker_save: Entered")
        print(f"[DEBUG] HexdumpWidget._handle_marker_save: marker_id={updated_marker.marker_id}, properties={updated_marker.properties}")

        packet_type = self.current_packet_type
        if not packet_type:
            print("[HexdumpWidget] Warning: No current_packet_type set during marker save.")
            return

        # Load existing markers for this packet type
        marker_list = self.marker_manager.load_markers_for_type(packet_type)

        # Update or add the marker
        found = False
        for idx, marker in enumerate(marker_list):
            if marker.marker_id == updated_marker.marker_id:
                print(f"[DEBUG] HexdumpWidget._handle_marker_save: Found matching marker at index {idx}. Updating.")
                marker_list[idx] = updated_marker
                found = True
                break

        if not found:
            print(f"[HexdumpWidget] Adding new marker with ID {updated_marker.marker_id} for packet type '{packet_type}'.")
            marker_list.append(updated_marker)

        # Save updated marker list back to file
        self.marker_manager.save_markers_for_type(packet_type, marker_list)
        # Reload markers for this packet type after saving
        self.current_type_markers = self.marker_manager.load_markers_for_type(packet_type) or []

        # Trigger re-render to reflect updated markers
        self.render()
        # Build UI if not already built (safe to call multiple times)
        if not hasattr(self, 'canvas'):
            self.build_ui()

    def _on_mouse_wheel(self, sender, data):
        """Handle mouse wheel scrolling."""
        if not self.data:
            return

        scroll_amount = data * self.options.columns
        current_scroll = dpg.get_y_scroll(self.tag)
        dpg.set_y_scroll(self.tag, current_scroll - scroll_amount)

    def _update_status_bar(self):
        """Update the status bar text."""
        if not self.options.show_statusbar:
            return

        status_text = []

        # Show current offset under cursor
        if self.hovered_offset is not None:
            status_text.append(f"Offset: 0x{self.hovered_offset:08X}")
            # Safely access data at offset
            if 0 <= self.hovered_offset < len(self.data):
                 byte_val = self.data[self.hovered_offset]
                 status_text.append(f"Value: {byte_val:02X}h ({byte_val:d})")
            else:
                 status_text.append("Value: N/A")


        # Show selection info
        if self.current_selection:
            start = min(self.current_selection.start_offset, self.current_selection.end_offset)
            end = max(self.current_selection.start_offset, self.current_selection.end_offset)
            size = end - start + 1
            status_text.append(f"Selection: [{start:08X}..{end:08X}] ({size} bytes)")

        # Show total size
        status_text.append(f"Size: {len(self.data)} bytes")

        dpg.set_value(f"{self.tag}_status_text", "  |  ".join(status_text))

    def _on_columns_changed(self, sender, value):
        """Handle columns slider change."""
        self.options.columns = value
        self.render()

    def _set_option(self, option: str, value):
        """Set an option and trigger re-render."""
        setattr(self.options, option, value)

        # Special handling for status bar visibility
        if option == 'show_statusbar':
            dpg.configure_item(self.canvas, height=self.height - (30 if value else 0))
            if value:
                dpg.show_item(f"{self.tag}_statusbar")
            else:
                dpg.hide_item(f"{self.tag}_statusbar")

        self.render()

    def _goto_addr(self, sender, value):
        """Handle goto address input."""
        try:
            addr = int(value, 16)
            if 0 <= addr < len(self.data):
                self.options.scroll_to_addr = addr
                self.current_selection = Selection(addr, addr)
                self.render()
        except ValueError:
            pass

    def _on_key_press(self, sender, key):
        """Handle keyboard navigation."""
        if not self.current_selection or not self.data:
            return

        curr_pos = self.current_selection.end_offset
        new_pos = curr_pos

        if key == dpg.mvKey_Left and curr_pos > 0:
            new_pos = curr_pos - 1
        elif key == dpg.mvKey_Right and curr_pos < len(self.data) - 1:
            new_pos = curr_pos + 1
        elif key == dpg.mvKey_Up and curr_pos >= self.options.columns:
            new_pos = curr_pos - self.options.columns
        elif key == dpg.mvKey_Down and curr_pos + self.options.columns < len(self.data):
            new_pos = curr_pos + self.options.columns
        elif key == dpg.mvKey_Prior:  # PageUp
            new_pos = max(0, curr_pos - (self.options.columns * 16))
        elif key == dpg.mvKey_Next:  # PageDown
            new_pos = min(len(self.data) - 1, curr_pos + (self.options.columns * 16))
        elif key == dpg.mvKey_Home:
            new_pos = (curr_pos // self.options.columns) * self.options.columns
        elif key == dpg.mvKey_End:
            new_pos = min(len(self.data) - 1,
                         ((curr_pos // self.options.columns) + 1) * self.options.columns - 1)

        if new_pos != curr_pos:
            if dpg.is_key_down(dpg.mvKey_Shift):
                # Extend selection
                self.current_selection.end_offset = new_pos
            else:
                # Move cursor
                self.current_selection = Selection(new_pos, new_pos)
                self._update_analysis_menu_items()

            # Ensure the cursor is visible
            self.options.scroll_to_addr = new_pos
            self.render()

    def _get_preview_data(self, offset: int) -> Dict[str, str]:
        """Get data preview string for all types."""
        if not self.current_selection or not self.options.show_data_preview:
            return {}

        endian = dpg.get_value(f"{self.tag}_preview_endian")
        endian_prefix = '<' if endian == 'LE' else '>'

        start = min(self.current_selection.start_offset, self.current_selection.end_offset)
        end = max(self.current_selection.start_offset, self.current_selection.end_offset)
        size = end - start + 1
        data = self.data[start:start + size]

        results = {}

        # Handle numeric previews
        format_map = {
            'Int8': 'b', 'UInt8': 'B',
            'Int16': 'h', 'UInt16': 'H',
            'Int32': 'i', 'UInt32': 'I',
            'Int64': 'q', 'UInt64': 'Q',
            'Float': 'f', 'Double': 'd'
        }

        for preview_type, fmt_char in format_map.items():
            try:
                fmt = endian_prefix + fmt_char
                if len(data) >= struct.calcsize(fmt):
                    value = struct.unpack(fmt, data[:struct.calcsize(fmt)])[0]
                    if 'Int' in preview_type or 'UInt' in preview_type:
                        results[preview_type] = f"Dec: {value}, Hex: {hex(value)}, Bin: {bin(value)}"
                    else:
                        results[preview_type] = f"{value}"
                else:
                    results[preview_type] = "Insufficient data"
            except Exception as e:
                results[preview_type] = "Invalid data"

        # Handle hash previews
        try:
            results['MD5'] = hashlib.md5(data).hexdigest()
        except Exception:
            results['MD5'] = "Error computing MD5"

        try:
            results['SHA256'] = hashlib.sha256(data).hexdigest()
        except Exception:
            results['SHA256'] = "Error computing SHA256"

        try:
            results['CRC32'] = hex(zlib.crc32(data) & 0xFFFFFFFF)
        except Exception:
            results['CRC32'] = "Error computing CRC32"

        return results

    def _on_click(self, sender, app_data):
        """Handle mouse click."""
        print("Click handler called")  # Debug print
        if not self.data:
            print("No data to display")  # Debug print
            return

        mouse_pos = dpg.get_mouse_pos(local=True)
        x, y = mouse_pos[0], mouse_pos[1]
        print(f"Mouse position: ({x}, {y})")  # Debug print

        # Determine offset under mouse
        offset = self._get_offset_at_position(x, y)
        print(f"Clicked offset: {offset}")

        # Enable/disable Modify and Remove menu items based on KSY field presence
        field_info = self._get_ksy_field_at_offset(offset) if offset is not None else None
        has_field = field_info is not None
        dpg.configure_item(f"{self.tag}_modify_ksy_field", enabled=has_field)
        dpg.configure_item(f"{self.tag}_remove_ksy_field", enabled=has_field)

        # Handle left click for selection
        if dpg.is_mouse_button_down(dpg.mvMouseButton_Left):
            print("Left click detected")  # Debug print
            self.is_selecting = True
            start_offset = offset
            print(f"Calculated offset: {start_offset}")  # Debug print
            if start_offset is not None:
                if dpg.is_key_down(dpg.mvKey_Shift) and self.current_selection:
                    # Extend selection
                    self.current_selection.end_offset = start_offset
                else:
                    # New selection
                    self.current_selection = Selection(start_offset, start_offset)
                    print("Created new selection at offset", start_offset)  # Debug print
                    self._update_analysis_menu_items()
                self.render()

    def _show_entropy_analysis(self):
        """Show entropy analysis window for selected bytes."""
        if not self.current_selection:
            return

        try:
            # Create entropy window if it doesn't exist
            if not self.entropy_window:
                self.entropy_window = EntropyWindow(self)

            # Show the window and update plot
            self.entropy_window.show()
        except Exception as e:
            print(f"Error showing entropy analysis: {e}")

    def _show_frequency_analysis(self):
        """Show frequency analysis window for selected bytes."""
        if not self.current_selection:
            return

        try:
            # Create frequency window if it doesn't exist
            if not self.frequency_window:
                self.frequency_window = FrequencyWindow(self)

            # Show the window and update plot
            self.frequency_window.show()
        except Exception as e:
            print(f"Error showing frequency analysis: {e}")

    def _update_analysis_menu_items(self):
        """Update the enabled state of analysis menu items."""
        # Update entropy menu item
        if hasattr(self, 'entropy_menu_tag') and dpg.does_item_exist(self.entropy_menu_tag):
            dpg.configure_item(
                self.entropy_menu_tag,
                enabled=self.current_selection is not None
            )

        # Update frequency menu item
        if hasattr(self, 'frequency_menu_tag') and dpg.does_item_exist(self.frequency_menu_tag):
            dpg.configure_item(
                self.frequency_menu_tag,
                enabled=self.current_selection is not None
            )

    def _on_hover(self, sender, app_data):
        """Handle mouse hover/drag."""
        if not self.data:
            return

        mouse_pos = dpg.get_mouse_pos(local=True)
        x, y = mouse_pos[0], mouse_pos[1]

        # Update hovered offset
        self.hovered_offset = self._get_offset_at_position(x, y)
        self._update_status_bar()

        # Handle KSY field tooltips
        tooltip_shown = False
        if self.hovered_offset is not None:
            field_info = self._get_ksy_field_at_offset(self.hovered_offset)
            if field_info:
                field_id = field_info.get('id', 'Unknown Field')
                tooltip_text = f"Field: {field_id}"
                if field_info.get('is_fuzzable'): # Check if fuzzable info is available
                    tooltip_text += " (Fuzzable)"

                # Create or update tooltip
                if not dpg.does_item_exist(self.tooltip_tag):
                    with dpg.tooltip(parent=self.canvas, tag=self.tooltip_tag):
                        dpg.add_text("", tag=f"{self.tooltip_tag}_text")
                dpg.set_value(f"{self.tooltip_tag}_text", tooltip_text)
                dpg.configure_item(self.tooltip_tag, show=True)
                tooltip_shown = True # Mark tooltip as shown

        # Hide tooltip if not over a KSY field
        if not tooltip_shown and dpg.does_item_exist(self.tooltip_tag):
            dpg.configure_item(self.tooltip_tag, show=False)

        # Update selection if dragging
        if self.is_selecting and dpg.is_mouse_button_down(dpg.mvMouseButton_Left):
            end_offset = self.hovered_offset
            if end_offset is not None and self.current_selection:
                self.current_selection.end_offset = end_offset
                self.render()

        # Handle mouse release
        if not dpg.is_mouse_button_down(dpg.mvMouseButton_Left):
            if self.is_selecting and self.current_selection:
                 # Finalize selection: ensure start <= end
                 if self.current_selection.start_offset > self.current_selection.end_offset:
                      self.current_selection.start_offset, self.current_selection.end_offset = \
                          self.current_selection.end_offset, self.current_selection.start_offset
                 self.render() # Re-render with finalized selection
            self.is_selecting = False


    def _get_offset_at_position(self, x: int, y: int) -> Optional[int]:
        """Convert screen coordinates to byte offset."""
        # Font metrics (optimized for readability)
        scale = dpg.get_global_font_scale()
        char_width = int(10 * scale)  # Reduced width for better spacing
        char_height = int(20 * scale)  # Reduced height
        line_spacing = int(5 * scale)  # Reduced spacing between lines

        # Layout constants
        offset_width = 8  # 8 hex digits for offset
        bytes_per_line = self.options.columns

        # Calculate column positions
        offset_x = int(40 * scale)
        hex_x = offset_x + (offset_width + 4) * char_width
        ascii_x = hex_x + (bytes_per_line * 3 + (bytes_per_line // self.options.mid_cols_count) * 2) * char_width

        # Adjust coordinates relative to content area
        x = x - offset_x # Adjust for left margin (where offset numbers are)
        y = y - int(20 * scale) # Adjust for top margin (above first line)

        # Calculate line number
        line = y // (char_height + line_spacing)
        if line < 0 or line * bytes_per_line >= len(self.data): # Check if line is valid
            return None

        # Determine if click was in hex or ASCII area
        col = -1
        if hex_x - offset_x <= x < ascii_x - offset_x:
            # Hex area
            x_hex = x - (hex_x - offset_x)
            # Account for spaces between hex values (every char) and groups (every mid_cols_count)
            # Calculate byte index based on character position, considering 3 chars per byte ('XX ')
            # and 2 extra chars for group spacing ('  ')
            effective_x = x_hex
            num_group_spaces = effective_x // (char_width * (3 * self.options.mid_cols_count + 2))
            effective_x -= num_group_spaces * 2 * char_width # Subtract group spacing width

            # Now calculate column based on 3 chars per byte ('XX ')
            col = effective_x // (char_width * 3)

        elif self.options.show_ascii and x >= ascii_x - offset_x:
            # ASCII area
            x_ascii = x - (ascii_x - offset_x)
            col = x_ascii // char_width
        else:
            # Click was in offset area or padding
            return None

        # Clamp column to valid range for the line
        col = max(0, min(col, bytes_per_line - 1))

        # Calculate final offset
        offset = line * bytes_per_line + col
        if 0 <= offset < len(self.data):
            return offset
        return None # Offset is outside data bounds

    # def _refresh_custom_markers_menu(self): # Obsolete with KSY
    #     """Refresh the custom markers menu with current marker types."""
    #     pass # Logic moved to KSY editor

    # def _get_marker_at_offset(self, offset: int) -> Optional[MarkedRegion]: # Replaced by KSY logic
    #     """Get marker at the specified offset."""
    #     # ... (removed implementation) ...
    #     return None

    def _find_ksy_field_recursive(self, obj: Any, debug_info: Dict, target_offset: int) -> Optional[Dict[str, Any]]:
        """Recursive helper to find the KSY field covering the target offset."""
        if not isinstance(debug_info, dict):
            return None

        # Check fields defined in this object's sequence
        for field_id, field_debug in debug_info.items():
            if not isinstance(field_debug, dict) or 'start' not in field_debug or 'end' not in field_debug:
                continue

            start = field_debug['start']
            end = field_debug['end']

            if start <= target_offset < end:
                # Target offset falls within this field's range
                field_value = getattr(obj, field_id, None)

                # If this field is a KaitaiStruct object itself, recurse
                if isinstance(field_value, kaitaistruct.KaitaiStruct) and hasattr(field_value, '_debug'):
                    nested_result = self._find_ksy_field_recursive(field_value, field_value._debug, target_offset)
                    if nested_result:
                        # Found a more specific field inside the nested structure
                        # Prepend parent field ID for path? (e.g., "parent.child") - complex
                        return nested_result # Return the most specific field found

                # If not recursing or recursion didn't find a more specific field, this field is the one
                is_fuzzable = False
                if hasattr(self.ksy_struct, '_ks_meta') and 'fuzzable_fields' in self.ksy_struct._ks_meta:
                    # Need to construct the full path if nested (e.g., "parent_id.field_id")
                    # For now, just check the direct field_id
                    if field_id in self.ksy_struct._ks_meta['fuzzable_fields']:
                        is_fuzzable = True
                return {"id": field_id, "start": start, "end": end, "is_fuzzable": is_fuzzable}

        # Target offset not found within the direct fields of this object
        return None

    def _get_ksy_field_at_offset(self, offset: int) -> Optional[Dict[str, Any]]:
        """
        Find the KSY field definition covering the given offset by traversing the debug info.
        """
        if not self.ksy_struct or not hasattr(self.ksy_struct, '_debug'):
            return None

        try:
            return self._find_ksy_field_recursive(self.ksy_struct, self.ksy_struct._debug, offset)
        except Exception as e:
            # print(f"Debug: Error during KSY field lookup: {e}") # Optional debug
            return None

    def _parse_color(self, color_str: str) -> Tuple[int, int, int, int]:
        """Convert hex color string to RGBA tuple."""
        # Remove '#' if present
        color_str = color_str.lstrip('#')
        print(f"[DEBUG] Parsing color string: '{color_str}'")  # Debug print

        try:
            if len(color_str) == 3:
                # Shorthand #RGB -> expand to #RRGGBB
                r = int(color_str[0]*2, 16)
                g = int(color_str[1]*2, 16)
                b = int(color_str[2]*2, 16)
                a = 100
            elif len(color_str) == 6:
                # Standard #RRGGBB
                r = int(color_str[0:2], 16)
                g = int(color_str[2:4], 16)
                b = int(color_str[4:6], 16)
                a = 100
            elif len(color_str) == 8:
                # #RRGGBBAA, parse alpha but ignore or convert
                r = int(color_str[0:2], 16)
                g = int(color_str[2:4], 16)
                b = int(color_str[4:6], 16)
                alpha_hex = int(color_str[6:8], 16)
                # Map 0-255 alpha to 0-100 scale
                a = int((alpha_hex / 255) * 100)
            else:
                # Unexpected length
                print(f"Warning: Unexpected color string length '{color_str}', using default.")
                return (128, 128, 128, 100)

            return (r, g, b, a)

        except (ValueError, IndexError):
            # Return default color on error
            print(f"Warning: Invalid color string '{color_str}', using default.")
            return (128, 128, 128, 100)  # Default grey


    def _copy_selection(self):
        """Copy selected bytes as ASCII."""
        if self.current_selection:
            start = min(self.current_selection.start_offset, self.current_selection.end_offset)
            end = max(self.current_selection.start_offset, self.current_selection.end_offset)
            selected = self.data[start:end + 1]
            dpg.set_clipboard_text(selected.decode('ascii', errors='replace'))

    def _copy_as_hex(self):
        """Copy selected bytes as hex string."""
        if self.current_selection:
            start = min(self.current_selection.start_offset, self.current_selection.end_offset)
    def _toggle_show_markers(self, value):
        """Toggle marker visibility and re-render."""
        self.show_markers = value
        self.render()

    def _get_marker_at_offset(self, offset: int):
        """Return the first marker covering the offset, or None."""
        for marker in self.markers.get(self.sequence_id, []):
            if marker.start_offset <= offset < marker.end_offset:
                return marker
        return None

    def _add_marker(self, sender=None, app_data=None):
        """Add a marker for the current selection."""
        if not self.current_selection:
            print("No selection to add marker for.")
            return
        start = min(self.current_selection.start_offset, self.current_selection.end_offset)
        end = max(self.current_selection.start_offset, self.current_selection.end_offset) + 1
        marker_types = self.marker_manager.get_marker_types()
        if not marker_types:
            print("No marker types loaded.")
            return
        marker_type = marker_types[0]  # For now, pick the first marker type
        new_marker = MarkerRegion(start_offset=start, end_offset=end, marker_type=marker_type)
        # Ensure marker color is set
        new_marker.properties['color'] = '#FFFFFF'
        print(f"[DEBUG] _add_marker (777): Set new marker color to {new_marker.properties['color']}")
        self.markers.setdefault(self.sequence_id, []).append(new_marker)
        self.render()

    def _remove_marker(self, sender=None, app_data=None):
        """Remove the first marker overlapping the start of the current selection."""
        if not self.current_selection:
            print("No selection to remove marker from.")
            return
        start = min(self.current_selection.start_offset, self.current_selection.end_offset)
        marker_list = self.markers.get(self.sequence_id, [])
        for marker in marker_list:
            if marker.start_offset <= start < marker.end_offset:
                marker_list.remove(marker)
                break
        self.render()

    def _modify_marker(self, sender=None, app_data=None):
        print("Modify Marker clicked")

    def set_data(self, data: bytes, sequence_id: str, callstack: Optional[str] = None):
        """Set the data to display in the hexdump view."""
        self.data = data
        self.sequence_id = sequence_id
        self.current_selection = None
        self.options.scroll_to_addr = None
        self.hovered_offset = None

        self.markers.setdefault(sequence_id, [])

        # The rest of the original set_data logic follows...

    def _show_error(self, message: str):
        """Show error modal with the given message."""
        print(f"Debug: Showing error modal with message: {message}")
        dpg.set_value(f"{self.tag}_error_modal_text", message)
        dpg.show_item(f"{self.tag}_error_modal")
        # Optionally bring modal to front
        dpg.split_frame()
        dpg.focus_item(f"{self.tag}_error_modal")
    def _define_ksy_field(self, sender, app_data):
        """Define a new KSY field at the current selection offset."""

        # Check if there is a current selection
        if not self.current_selection:
            self._show_error("No selection made to define a field.")
            return

        # Extract start and end offsets, ensure start <= end
        start = min(self.current_selection.start_offset, self.current_selection.end_offset)
        end = max(self.current_selection.start_offset, self.current_selection.end_offset)
        size = end - start + 1

        ksy_path = self.packet_type_manager.get_ksy_path(self.current_packet_type)
        if ksy_path and not os.path.isabs(ksy_path):
            # Resolve relative to project root (parent of current file directory)
            ksy_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', ksy_path))
        if not ksy_path or not os.path.exists(ksy_path):
            self._show_error(f"KSY file not found or invalid path: {ksy_path}")
            return

        try:
            yaml = YAML()
            yaml.preserve_quotes = True

            # Load existing KSY YAML
            with open(ksy_path, 'r') as f:
                ksy_data = yaml.load(f)

            # Validate KSY structure
            if not isinstance(ksy_data, dict) or 'seq' not in ksy_data or not isinstance(ksy_data['seq'], list):
                self._show_error("Invalid KSY structure: missing 'seq' list.")
                return

            # Prepare new field
            field_id = f"field_{start:08x}"
            new_field = {
                'id': field_id,
                'size': size,
                'type': 'bytes'
            }

            # Calculate insertion index based on offset
            current_offset = 0
            insertion_index = len(ksy_data['seq'])  # default to append at end

            for idx, field in enumerate(ksy_data['seq']):
                # Check if 'size' exists
                if 'size' not in field:
                    self._show_error(f"Existing field at index {idx} missing 'size'. Cannot determine insertion point.")
                    return

                field_size = field['size']

                # For simplicity, only handle integer sizes
                if not isinstance(field_size, int):
                    self._show_error(f"Field '{field.get('id', 'unknown')}' has non-integer size. Cannot insert new field safely.")
                    return

                field_end_offset = current_offset + field_size

                # Check for overlap
                if start <= field_end_offset and end >= current_offset:
                    self._show_error(f"Selection overlaps with existing field '{field.get('id', 'unknown')}'.")
                    return

                # If new field starts before this field ends, insert here
                if start < field_end_offset:
                    insertion_index = idx
                    break

                # Otherwise, move offset forward
                current_offset = field_end_offset

            # Calculate gap before insertion point
            gap = start - current_offset

            # Insert skip field if there is a gap
            if gap > 0:
                skip_field = {
                    'id': f"skip_{current_offset:08x}",
                    'size': gap
                }
                ksy_data['seq'].insert(insertion_index, skip_field)
                insertion_index += 1  # new field goes after skip

            # Insert the new field at the determined index
            ksy_data['seq'].insert(insertion_index, new_field)

            # Save updated KSY YAML
            with open(ksy_path, 'w') as f:
                yaml.dump(ksy_data, f)

            # Reload data and KSY structure
            self.set_data(
                self.data,
                self.sequence_id,
                self.all_packets_data.get(self.sequence_id, {}).get('callstack')
            )

        except Exception as e:
            self._show_error(f"Unexpected error: {str(e)}")
            return
    

    def _modify_ksy_field(self, sender, app_data):
        """Placeholder for modifying an existing KSY field."""
        print("Debug: _modify_ksy_field called.")

    def _modify_ksy_field(self, sender, app_data):
        """Placeholder for modifying an existing KSY field."""
        print("Debug: _modify_ksy_field called.")

    def _remove_ksy_field(self, sender, app_data):
        """Placeholder for removing an existing KSY field."""
        print("Debug: _remove_ksy_field called.")

    def _toggle_show_markers(self, value):
        """Toggle marker visibility and re-render."""
        self.show_markers = value
        self.render()
    
    def _get_marker_at_offset(self, offset: int):
        """Return the first marker covering the offset, or None."""
        for marker in self.current_type_markers:
            if marker.start_offset <= offset < marker.end_offset:
                return marker
        return None
    
    def _add_marker(self, sender=None, app_data=None):
        """Add a marker for the current selection."""
        if not self.current_selection:
            print("No selection to add marker for.")
            return
        start = min(self.current_selection.start_offset, self.current_selection.end_offset)
        end = max(self.current_selection.start_offset, self.current_selection.end_offset) + 1
        # Retrieve all MarkerType objects from the marker manager's dictionary
        marker_types = list(self.marker_manager.marker_types.values())
        if not marker_types:
            print("No marker types loaded.")
            return
        marker_type = marker_types[0]  # For now, pick the first marker type
        print(f"[DEBUG] _add_marker: marker_type.name = '{marker_type.name}', marker_type.display_name = '{marker_type.display_name}'")
        new_marker = MarkerRegion(
            start_offset=start,
            end_offset=end,
            tag_name=marker_type.display_name,
            tag_type=marker_type.name
        )
        # Ensure marker color is set
        new_marker.properties['color'] = '#FFFFFF'
        print(f"[DEBUG] _add_marker: Created new marker with tag_name = '{new_marker.tag_name}'")
        # Load current markers for this packet type
        marker_list = self.marker_manager.load_markers_for_type(self.current_packet_type) or []
        # Append the new marker
        marker_list.append(new_marker)
        # Save updated markers back to the manager
        self.marker_manager.save_markers_for_type(self.current_packet_type, marker_list)
        # Update widget's current marker list
        self.current_type_markers = marker_list
        self.render()
    
    def _remove_marker(self, sender=None, app_data=None):
        """Remove the first marker overlapping the start of the current selection."""
        if not self.current_selection:
            print("No selection to remove marker from.")
            return
        start = min(self.current_selection.start_offset, self.current_selection.end_offset)
        # Load current markers for this packet type
        marker_list = self.marker_manager.load_markers_for_type(self.current_packet_type) or []
        for marker in marker_list:
            if marker.start_offset <= start < marker.end_offset:
                marker_list.remove(marker)
                break
        # Save updated markers back to the manager
        self.marker_manager.save_markers_for_type(self.current_packet_type, marker_list)
        # Update widget's current marker list
        self.current_type_markers = marker_list
        self.render()
    
    def _modify_marker(self, sender=None, app_data=None):
        # Check if there is a current selection
        if not self.current_selection:
            print("No selection to modify marker for.")
            return

        # Determine start offset of current selection
        # Assuming self.current_selection is a tuple/list or has start attribute
        # Access start_offset directly from the Selection dataclass
        start_offset = self.current_selection.start_offset

        if start_offset is None:
            print("Invalid selection format.")
            return

        # Find marker at the start offset
        marker = self._get_marker_at_offset(start_offset)

        if marker:
            # Debug: print marker info to verify correct data is passed
            print(f"Modifying marker: id={getattr(marker, 'marker_id', None)}, "
                  f"tag_name={getattr(marker, 'tag_name', None)}, "
                  f"start_offset={getattr(marker, 'start_offset', None)}, "
                  f"end_offset={getattr(marker, 'end_offset', None)}")
            # Load the marker data into the editor before showing
            all_current_markers = self.current_type_markers
            self.marker_editor_window.load_marker(marker, all_current_markers)
            self.marker_editor_window.show()
        else:
            print("No marker found at the current selection to modify.")
    
    def set_data(self, data: bytes, sequence_id: str, callstack: Optional[str] = None):
        """Set the data to display in the hexdump view."""
        self.data = data
        self.sequence_id = sequence_id
        self.current_selection = None # Reset selection when data changes
        self.options.scroll_to_addr = None # Clear previous scroll request
        self.hovered_offset = None # Reset hover offset

        # Determine packet type
        packet_type = "undefined" # Default type
        if self.packet_type_manager and self.data:
            # Use provided callstack or fetch from all_packets_data if available
            current_callstack = callstack if callstack is not None else self.all_packets_data.get(sequence_id, {}).get('callstack', '')
            packet_type = self.packet_type_manager.matches_type(self.data, len(self.data), current_callstack) or "undefined"

        self.current_packet_type = packet_type
        # Load markers for this packet type
        self.current_type_markers = self.marker_manager.load_markers_for_type(self.current_packet_type) or []

        # Update or initialize packet info in all_packets_data
        if sequence_id not in self.all_packets_data:
            # Initialize if new sequence_id
            self.all_packets_data[sequence_id] = {'data': self.data, 'type': self.current_packet_type, 'callstack': callstack or ''}
        else:
            # Update existing entry
            self.all_packets_data[sequence_id]['data'] = self.data
            self.all_packets_data[sequence_id]['type'] = self.current_packet_type
            if callstack is not None: # Only update callstack if provided
                 self.all_packets_data[sequence_id]['callstack'] = callstack

        # Load and parse KSY file for the current packet type
        self.ksy_struct = None
        self.ksy_parse_error = None
        ksy_path = None
        if self.packet_type_manager and self.current_packet_type != "undefined":
            ksy_path = self.packet_type_manager.get_ksy_path(self.current_packet_type)

        if ksy_path and os.path.exists(ksy_path): # Check if path exists
            try:
                # Dynamically load the KSY class - assumes KSY file is compiled to Python
                # Construct module path based on ksy_path relative to project root
                rel_path = os.path.relpath(ksy_path, start=os.getcwd())
                module_path_parts = os.path.splitext(rel_path)[0].split(os.sep)
                module_name = ".".join(module_path_parts)

                # Ensure the parent directory is importable if needed (might require __init__.py)
                # Example: if ksy_path is ksy_definitions/my_packet.ksy, module_name is ksy_definitions.my_packet

                # The following code attempted to import a .ksy YAML file as a Python module,
                # which is invalid and causes repeated errors.
                # Proper approach: compile .ksy files to .py files using kaitai-struct-compiler,
                # then import the generated Python modules.
                # This block is disabled to prevent errors.
                # spec = importlib.util.spec_from_file_location(module_name, ksy_path)
                # if spec and spec.loader:
                #     importlib.invalidate_caches()
                #     ksy_module = importlib.util.module_from_spec(spec)
                #     import sys
                #     sys.modules[module_name] = ksy_module
                #     spec.loader.exec_module(ksy_module)

                    # The following code depends on dynamically importing a .ksy YAML file as a Python module,
                    # which is invalid and causes errors. It is disabled to prevent syntax and runtime errors.
                    # Find the main class within the module (usually matches the KSY ID in camel case)
                    # ksy_meta_id = None
                    # Attempt to read meta.id directly from the compiled module if possible
                    # This structure might vary based on KS compiler version
                    # if hasattr(ksy_module, 'KsySchema'): # Common pattern?
                    #      if hasattr(ksy_module.KsySchema, 'meta') and hasattr(ksy_module.KsySchema.meta, 'id'):
                    #           ksy_meta_id = ksy_module.KsySchema.meta.id
                    # elif hasattr(ksy_module, '_ks_meta') and 'id' in ksy_module._ks_meta: # Another possible pattern
                    #      ksy_meta_id = ksy_module._ks_meta['id']
                    #
                    # KsyClass = None
                    # if ksy_meta_id:
                    #      # Convert snake_case id to CamelCase for class name
                    #      class_name = "".join(word.capitalize() for word in ksy_meta_id.split('_'))
                    #      if hasattr(ksy_module, class_name):
                    #          KsyClass = getattr(ksy_module, class_name)
                    #      else:
                    #           self.ksy_parse_error = f"Class '{class_name}' (from meta.id) not found in KSY module: {ksy_path}"
                    #           print(self.ksy_parse_error)
                    # else:
                    #      # Fallback: Try finding the first KaitaiStruct subclass if meta.id fails
                    #      for name, obj in inspect.getmembers(ksy_module):
                    #           if inspect.isclass(obj) and issubclass(obj, kaitaistruct.KaitaiStruct) and obj is not kaitaistruct.KaitaiStruct:
                    #                KsyClass = obj
                    #                print(f"Warning: Using fallback class '{name}' from KSY module: {ksy_path}")
                    #                break
                    #      if not KsyClass:
                    #           self.ksy_parse_error = f"Could not find KaitaiStruct class in KSY module: {ksy_path}"
                    #           print(self.ksy_parse_error)
                    #
                    # if KsyClass:
                    #      # Parse the data
                    #      # Ensure the KSY class is compiled with debug info for offset mapping
                    #      self.ksy_struct = KsyClass.from_bytes(self.data)
                    #      # Manually trigger parsing of all fields to populate _debug info if needed
                    #      # This might be necessary depending on how KS lazy-loads attributes
                    #      if hasattr(self.ksy_struct, '_read'):
                    #           self.ksy_struct._read()
                    #      print(f"Successfully parsed data with KSY: {ksy_path}")
                    #      # Store the parsed struct in all_packets_data? Maybe not necessary.
                    #      # self.all_packets_data[sequence_id]['ksy_struct'] = self.ksy_struct
                    #
                    # else:
                    #      self.ksy_parse_error = f"Could not create module spec for KSY: {ksy_path}"
                    #      print(self.ksy_parse_error)


            except FileNotFoundError:
                 self.ksy_parse_error = f"KSY file not found: {ksy_path}"
                 print(self.ksy_parse_error)
            except Exception as e:
                # Catch KaitaiStruct parsing errors specifically if possible
                if isinstance(e, kaitaistruct.KaitaiError):
                     self.ksy_parse_error = f"Kaitai parsing error in {ksy_path}: {e}"
                else:
                     self.ksy_parse_error = f"Error loading/parsing KSY {ksy_path}: {type(e).__name__}: {e}"
                import traceback
                traceback.print_exc() # Print full traceback for debugging
                print(self.ksy_parse_error)
        elif self.current_packet_type != "undefined":
             # Only report missing KSY if a type is defined but the file is missing
             if ksy_path and not os.path.exists(ksy_path):
                  self.ksy_parse_error = f"KSY file not found for type '{self.current_packet_type}': {ksy_path}"
                  print(self.ksy_parse_error)
             elif not ksy_path:
                  self.ksy_parse_error = f"No KSY file defined for packet type: {self.current_packet_type}"
                  # print(self.ksy_parse_error) # Don't spam if it's just undefined

        # Enable/disable KSY editor based on whether we have a valid packet type
        ksy_editor_enabled = self.current_packet_type != "undefined"
        print(f"Debug: KSY editor enabled state: {ksy_editor_enabled}")
        print(f"Debug: Current packet type: {self.current_packet_type}")
        print(f"Debug: KSY path: {ksy_path}")
        if hasattr(self, 'ksy_menu_tag') and dpg.does_item_exist(self.ksy_menu_tag):
            dpg.configure_item(self.ksy_menu_tag, enabled=ksy_editor_enabled)

        self.render() # Update the display

    # def get_markers(self) -> List[MarkedRegion]: # Obsolete with KSY
    #     """Get all markers in the current view."""
    #     return [] # Return empty list or remove method

    def render(self):
        """Render the hexdump display."""
        if not self.data:
            if dpg.does_item_exist(self.canvas):
                dpg.delete_item(self.canvas, children_only=True)
            return
    
        if dpg.does_item_exist(self.canvas):
            dpg.delete_item(self.canvas, children_only=True)
        else:
            print("Error: Canvas item does not exist for rendering.")
            return
    
        scale = dpg.get_global_font_scale()
        char_width = int(10 * scale)
        char_height = int(20 * scale)
        line_spacing = int(5 * scale)
    
        offset_width = 8
        bytes_per_line = self.options.columns
    
        offset_x = int(40 * scale)
        hex_x = offset_x + (offset_width + 4) * char_width
        ascii_x = hex_x + (bytes_per_line * 3 + (bytes_per_line // self.options.mid_cols_count) * 2) * char_width
    
        canvas_width = dpg.get_item_configuration(self.canvas)["width"]
        canvas_height = dpg.get_item_configuration(self.canvas)["height"]
    
        if self.options.show_ascii:
            separator_x = ascii_x - char_width
            dpg.draw_line(
                parent=self.canvas,
                p1=(separator_x, 0),
                p2=(separator_x, canvas_height),
                color=self.separator_color,
                thickness=1
            )
    
        y = int(20 * scale)
    
        for i in range(0, len(self.data), bytes_per_line):
            chunk = self.data[i:i+bytes_per_line]
            line_y = y + (i // bytes_per_line) * (char_height + line_spacing)
    
            offset_text = f"{i:08x}: " if not self.options.uppercase_hex else f"{i:08X}: "
            dpg.draw_text(
                parent=self.canvas,
                pos=(offset_x, line_y),
                text=offset_text,
                color=(200, 200, 200, 255),
                size=char_height
            )
    
            for j, byte in enumerate(chunk):
                group_idx = j // self.options.mid_cols_count
                byte_x = hex_x + (j * 3 + group_idx * 2) * char_width
                byte_offset = i + j
    
                marker_color = None
                is_fuzzable = False

                if self.show_markers:
                    marker = self._get_marker_at_offset(byte_offset)
                    if marker:
                        # Try to get the specific color saved in marker properties
                        marker_color_str = marker.properties.get('color')
                        print(f"[DEBUG] Marker color string from properties: '{marker_color_str}'")

                        if marker_color_str:
                            parsed_color = self._parse_color(marker_color_str)
                            if parsed_color is not None:
                                marker_color = parsed_color  # Use saved marker color

                        # If no valid saved color, try marker type default color
                        if marker_color is None:
                            marker_type_obj = self.marker_manager.get_marker_type(marker.tag_type)
                            if marker_type_obj and marker_type_obj.color:
                                print(f"[DEBUG] Marker type color: '{marker_type_obj.color}'")
                                parsed_type_color = self._parse_color(marker_type_obj.color)
                                if parsed_type_color is not None:
                                    marker_color = parsed_type_color
                                    print(f"[DEBUG] Using marker type color: {marker_color}")

                        # If still no valid color, fallback to grey
                        if marker_color is None:
                            marker_color = self._parse_color("#808080")
                            print(f"[DEBUG] Using fallback grey color: {marker_color}")
                else:
                    field_info = self._get_ksy_field_at_offset(byte_offset)
                    if field_info:
                        marker_color = (100, 100, 255, 100)
                        field_path = field_info.get('id', '')
                        if hasattr(self.ksy_struct, '_ks_meta') and 'fuzzable_fields' in self.ksy_struct._ks_meta:
                            if field_path in self.ksy_struct._ks_meta['fuzzable_fields']:
                                is_fuzzable = True
                                marker_color = (255, 100, 100, 120)
                        elif field_info.get('is_fuzzable', False):
                            is_fuzzable = True
                            marker_color = (255, 100, 100, 120)
    
                is_selected = (
                    self.current_selection and
                    min(self.current_selection.start_offset, self.current_selection.end_offset) <= byte_offset <= max(self.current_selection.start_offset, self.current_selection.end_offset)
                )
    
                is_cursor = (
                    self.current_selection and
                    self.current_selection.start_offset == self.current_selection.end_offset and
                    byte_offset == self.current_selection.start_offset
                )
    
                if marker_color or is_selected or is_fuzzable:
                    highlight_width = char_width * 2.5
                    highlight_height = char_height
    
                    if is_selected:
                        color = self.selection_color
                    elif is_fuzzable:
                        color = (255, 100, 100, 120)
                    else:
                        color = marker_color if marker_color else (0, 0, 0, 0)
    
                    if color[3] > 0:
                        dpg.draw_rectangle(
                            parent=self.canvas,
                            pmin=(byte_x, line_y),
                            pmax=(byte_x + highlight_width, line_y + highlight_height),
                            fill=color
                        )
    
                        if self.options.show_ascii:
                            ascii_highlight_x = ascii_x + j * char_width
                            dpg.draw_rectangle(
                                parent=self.canvas,
                                pmin=(ascii_highlight_x, line_y),
                                pmax=(ascii_highlight_x + char_width, line_y + highlight_height),
                                fill=color
                            )
    
                if is_cursor:
                    cursor_color = (255, 255, 255, 200)
                    dpg.draw_line(
                        parent=self.canvas,
                        p1=(byte_x, line_y),
                        p2=(byte_x, line_y + char_height),
                        color=cursor_color,
                        thickness=2
                    )
                    if self.options.show_ascii:
                        ascii_x_pos = ascii_x + j * char_width
                        dpg.draw_line(
                            parent=self.canvas,
                            p1=(ascii_x_pos, line_y),
                            p2=(ascii_x_pos, line_y + char_height),
                            color=cursor_color,
                            thickness=2
                        )
    
                if self.options.show_hexii and byte == 0:
                    hex_text = "  "
                elif self.options.show_hexii and 32 <= byte <= 126:
                    hex_text = f".{chr(byte)}"
                else:
                    hex_text = f"{byte:02X}" if self.options.uppercase_hex else f"{byte:02x}"
    
                text_color = self.disabled_color if byte == 0 and self.options.grey_out_zeroes else self.text_color
                dpg.draw_text(
                    parent=self.canvas,
                    pos=(byte_x, line_y),
                    text=hex_text + " ",
                    color=text_color,
                    size=char_height
                )

            # Draw ASCII representation if enabled
            if self.options.show_ascii:
                for j, byte in enumerate(chunk):
                    # Format ASCII character
                    if self.options.show_hexii:
                        if byte == 0:
                            ascii_char = " "
                        elif 32 <= byte <= 126:
                            ascii_char = "."
                        else:
                            ascii_char = chr(byte)
                    else:
                        # Standard ASCII view - show printable chars, dots for others
                        ascii_char = chr(byte) if 32 <= byte <= 126 else '.'

                    # Use same text color as hex display for consistency
                    text_color = self.disabled_color if byte == 0 and self.options.grey_out_zeroes else self.text_color

                    # Draw ASCII character
                    dpg.draw_text(
                        parent=self.canvas,
                        pos=(ascii_x + j * char_width, line_y),
                        text=ascii_char,
                        color=text_color,
                        size=char_height
                    )

        # Update data preview if enabled
        if self.options.show_data_preview and self.current_selection:
            preview_data = self._get_preview_data(self.current_selection.start_offset)
            if preview_data:
                # Calculate position below the hex data
                total_lines = (len(self.data) + bytes_per_line - 1) // bytes_per_line
                preview_y = y + total_lines * (char_height + line_spacing) + 20 # Add some padding

                # Draw preview table
                table_y = preview_y
                # First column: numeric types
                numeric_types = ['Int8', 'UInt8', 'Int16', 'UInt16', 'Int32', 'UInt32', 'Int64', 'UInt64', 'Float', 'Double']
                for i, type_name in enumerate(numeric_types):
                    type_y = table_y + i * char_height
                    # Draw type name
                    dpg.draw_text(
                        parent=self.canvas,
                        pos=(offset_x, type_y),
                        text=f"{type_name}:",
                        color=self.text_color,
                        size=char_height
                    )
                    # Draw value
                    dpg.draw_text(
                        parent=self.canvas,
                        pos=(offset_x + 120, type_y), # Adjust x position for value
                        text=preview_data.get(type_name, "N/A"),
                        color=self.text_color,
                        size=char_height
                    )

                # Second column: hash types
                hash_types = ['MD5', 'SHA256', 'CRC32']
                for i, type_name in enumerate(hash_types):
                    type_y = table_y + i * char_height
                    # Draw type name
                    dpg.draw_text(
                        parent=self.canvas,
                        pos=(offset_x + 500, type_y), # Adjust x position for second column
                        text=f"{type_name}:",
                        color=self.text_color,
                        size=char_height
                    )
                    # Draw value
                    dpg.draw_text(
                        parent=self.canvas,
                        pos=(offset_x + 600, type_y), # Adjust x position for value
                        text=preview_data.get(type_name, "N/A"),
                        color=self.text_color,
                        size=char_height
                    )

        # Handle scrolling to address
        if self.options.scroll_to_addr is not None:
            target_line = self.options.scroll_to_addr // bytes_per_line
            scroll_y = target_line * (char_height + line_spacing)
            # Ensure scroll target is within bounds
            # Use canvas height for max scroll calculation
            max_scroll = max(0, canvas_height - dpg.get_item_configuration(self.tag)["height"]) # Estimate max scroll based on canvas vs window
            scroll_y = min(scroll_y, max_scroll)
            dpg.set_y_scroll(self.tag, scroll_y)
            self.options.scroll_to_addr = None # Clear scroll request

        self._update_status_bar() # Update status bar with offset/selection info

        # Display KSY parsing errors if any
        if self.ksy_parse_error:
             # Draw error message at the bottom or top of the canvas
             error_y = canvas_height - (char_height + line_spacing) # Position near the bottom
             dpg.draw_text(parent=self.canvas, pos=(offset_x, error_y), text=f"KSY Error: {self.ksy_parse_error}", color=(255, 0, 0, 255), size=char_height)