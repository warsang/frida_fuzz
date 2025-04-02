import dearpygui.dearpygui as dpg
from dataclasses import dataclass
from typing import Optional, List, Tuple
import struct

@dataclass
class FuzzableRegion:
    start_offset: int
    end_offset: int
    mutation_type: str

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
    def __init__(self, tag: str, width: int = 1200, height: int = 1600, on_regions_changed=None):
        """Initialize the hexdump widget with default size."""
        self.tag = tag
        self.width = width
        self.height = height
        self.data = bytes()
        self.fuzzable_regions: List[FuzzableRegion] = []
        self.current_selection: Optional[Selection] = None
        self.is_selecting = False
        self.sequence_id = None
        self.on_regions_changed = on_regions_changed
        self.options = HexdumpOptions()
        self.addr_input = ""  # For goto address feature
        self.hovered_offset: Optional[int] = None  # For tooltips
        
        # Colors
        self.selection_color = (255, 255, 0, 100)  # Light yellow
        self.fuzzable_color = (100, 149, 237, 100)  # Cornflower blue
        self.text_color = (255, 255, 255, 255)  # White
        self.disabled_color = (128, 128, 128, 255)  # Grey for zero bytes
        self.separator_color = (128, 128, 128, 100)  # Grey for separator
        self.statusbar_color = (70, 70, 70, 255)  # Dark grey for status bar
        # Set font scale for optimal readability
        dpg.set_global_font_scale(1.0)
        
        # Create widget structure
        with dpg.child_window(tag=self.tag, width=-1, height=-1, horizontal_scrollbar=True):
            # Add keyboard handler
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
                    # Add mouse handlers
                    with dpg.item_handler_registry() as handler:
                        dpg.add_item_clicked_handler(callback=self._on_click)
                        dpg.add_item_hover_handler(callback=self._on_hover)
                    dpg.bind_item_handler_registry(self.canvas, handler)
                # Add mouse handlers
                with dpg.item_handler_registry() as handler:
                    dpg.add_item_clicked_handler(callback=self._on_click)
                    dpg.add_item_hover_handler(callback=self._on_hover)
                dpg.bind_item_handler_registry(self.canvas, handler)
            
            # Create context menu
            with dpg.popup(self.canvas, tag=f"{self.tag}_context_menu", mousebutton=dpg.mvMouseButton_Right):
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
                # Fuzzable region submenu
                with dpg.menu(label="Mark as Fuzzable"):
                    dpg.add_menu_item(label="Size Field", callback=lambda: self._mark_fuzzable("size_field"))
                    dpg.add_menu_item(label="Checksum", callback=lambda: self._mark_fuzzable("checksum"))
                    dpg.add_menu_item(label="Data Field", callback=lambda: self._mark_fuzzable("data"))
                    dpg.add_menu_item(label="Magic Constant", callback=lambda: self._mark_fuzzable("magic"))
                    dpg.add_menu_item(label="Delimiter", callback=lambda: self._mark_fuzzable("delimiter"))
                dpg.add_menu_item(label="Remove Fuzzable Mark", callback=self._remove_fuzzable)
                dpg.add_separator()
                dpg.add_menu_item(label="Copy Selection", callback=self._copy_selection)
                dpg.add_menu_item(label="Copy as Hex", callback=self._copy_as_hex)

            # Data preview section
            if self.options.show_data_preview:
                with dpg.group(horizontal=True, tag=f"{self.tag}_preview"):
                    dpg.add_text("Preview as:")
                    dpg.add_combo(items=["Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Float", "Double"],
                                default_value="Int32", width=100, tag=f"{self.tag}_preview_type")
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Data type for numeric preview")
                    
                    dpg.add_combo(items=["LE", "BE"], default_value="LE", width=50, tag=f"{self.tag}_preview_endian")
                    with dpg.tooltip(dpg.last_item()):
                        dpg.add_text("Byte order (Little/Big Endian)")

            # Status bar
            if self.options.show_statusbar:
                with dpg.group(horizontal=True, tag=f"{self.tag}_statusbar"):
                    dpg.add_text("", tag=f"{self.tag}_status_text")

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
            byte_val = self.data[self.hovered_offset]
            status_text.append(f"Value: {byte_val:02X}h ({byte_val:d})")
        
        # Show selection info
        if self.current_selection:
            start = self.current_selection.start_offset
            end = self.current_selection.end_offset
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
            
            # Ensure the cursor is visible
            self.options.scroll_to_addr = new_pos
            self.render()

    def _get_preview_data(self, offset: int) -> str:
        """Get data preview string for the selected bytes."""
        if not self.current_selection or not self.options.show_data_preview:
            return ""

        preview_type = dpg.get_value(f"{self.tag}_preview_type")
        endian = dpg.get_value(f"{self.tag}_preview_endian")
        endian_prefix = '<' if endian == 'LE' else '>'

        try:
            start = self.current_selection.start_offset
            size = self.current_selection.end_offset - start + 1
            data = self.data[start:start + size]

            format_map = {
                'Int8': 'b', 'UInt8': 'B',
                'Int16': 'h', 'UInt16': 'H',
                'Int32': 'i', 'UInt32': 'I',
                'Int64': 'q', 'UInt64': 'Q',
                'Float': 'f', 'Double': 'd'
            }

            if preview_type in format_map:
                fmt = endian_prefix + format_map[preview_type]
                if len(data) >= struct.calcsize(fmt):
                    value = struct.unpack(fmt, data[:struct.calcsize(fmt)])[0]
                    if 'Int' in preview_type or 'UInt' in preview_type:
                        return f"Dec: {value}, Hex: {hex(value)}, Bin: {bin(value)}"
                    else:
                        return f"{value}"
        except Exception as e:
            return f"Invalid data for {preview_type}"

        return ""

    def _on_click(self, sender, app_data):
        """Handle mouse click."""
        if not self.data:
            return
            
        mouse_pos = dpg.get_mouse_pos(local=True)
        x, y = mouse_pos[0], mouse_pos[1]
        
        # Handle left click for selection
        if dpg.is_mouse_button_down(dpg.mvMouseButton_Left):
            self.is_selecting = True
            start_offset = self._get_offset_at_position(x, y)
            if start_offset is not None:
                if dpg.is_key_down(dpg.mvKey_Shift) and self.current_selection:
                    # Extend selection
                    self.current_selection.end_offset = start_offset
                else:
                    # New selection
                    self.current_selection = Selection(start_offset, start_offset)
                self.render()

    def _on_hover(self, sender, app_data):
        """Handle mouse hover/drag."""
        if not self.data:
            return
            
        mouse_pos = dpg.get_mouse_pos(local=True)
        x, y = mouse_pos[0], mouse_pos[1]
        
        # Update hovered offset
        self.hovered_offset = self._get_offset_at_position(x, y)
        self._update_status_bar()
        
        # Update selection if dragging
        if self.is_selecting and dpg.is_mouse_button_down(dpg.mvMouseButton_Left):
            end_offset = self.hovered_offset
            if end_offset is not None and self.current_selection:
                self.current_selection.end_offset = end_offset
                self.render()
        else:
            # Mouse released
            self.is_selecting = False
            if self.current_selection:
                # Ensure start_offset <= end_offset
                if self.current_selection.start_offset > self.current_selection.end_offset:
                    self.current_selection.start_offset, self.current_selection.end_offset = \
                        self.current_selection.end_offset, self.current_selection.start_offset
                self.render()

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
        x = x - offset_x
        y = y - int(40 * scale)
        
        # Calculate line number
        line = y // (char_height + line_spacing)
        if line < 0 or line >= (len(self.data) + bytes_per_line - 1) // bytes_per_line:
            return None
            
        # Determine if click was in hex or ASCII area
        if hex_x <= x + offset_x < ascii_x:
            # Hex area
            x = x - (hex_x - offset_x)
            # Account for spaces between hex values and groups
            group_spaces = (x // (char_width * 3 * self.options.mid_cols_count)) * 2 * char_width
            x = x - group_spaces
            col = x // (char_width * 3)
        elif self.options.show_ascii and x + offset_x >= ascii_x:
            # ASCII area
            x = x - (ascii_x - offset_x)
            col = x // char_width
        else:
            return None
            
        # Calculate final offset
        offset = line * bytes_per_line + col
        if 0 <= offset < len(self.data):
            return offset
        return None

    def _mark_fuzzable(self, mutation_type: str):
        """Mark the current selection as a fuzzable region."""
        if self.current_selection:
            if self.add_fuzzable_region(
                self.current_selection.start_offset,
                self.current_selection.end_offset,
                mutation_type
            ):
                self.current_selection = None
                self.render()

    def _remove_fuzzable(self):
        """Remove fuzzable region at current selection/click position."""
        if self.current_selection:
            self.remove_fuzzable_region(self.current_selection.start_offset)

    def _copy_selection(self):
        """Copy selected bytes as ASCII."""
        if self.current_selection:
            selected = self.data[self.current_selection.start_offset:self.current_selection.end_offset + 1]
            dpg.set_clipboard_text(selected.decode('ascii', errors='replace'))

    def _copy_as_hex(self):
        """Copy selected bytes as hex string."""
        if self.current_selection:
            selected = self.data[self.current_selection.start_offset:self.current_selection.end_offset + 1]
            hex_str = selected.hex() if not self.options.uppercase_hex else selected.hex().upper()
            dpg.set_clipboard_text(hex_str)

    def set_data(self, data: bytes, sequence_id=None):
        """Set the byte data to display."""
        self.data = data
        self.sequence_id = sequence_id
        self.current_selection = None
        self.options.scroll_to_addr = None
        self.hovered_offset = None
        self.render()

    def add_fuzzable_region(self, start: int, end: int, mutation_type: str) -> bool:
        """Add a new fuzzable region if it doesn't overlap with existing ones."""
        # Check for overlaps
        for region in self.fuzzable_regions:
            if (start <= region.end_offset and end >= region.start_offset):
                return False
                
        self.fuzzable_regions.append(FuzzableRegion(start, end, mutation_type))
        self.render()
        if self.on_regions_changed and self.sequence_id is not None:
            self.on_regions_changed(self.sequence_id, self.fuzzable_regions)
        return True

    def remove_fuzzable_region(self, offset: int):
        """Remove fuzzable region containing the given offset."""
        self.fuzzable_regions = [
            r for r in self.fuzzable_regions 
            if not (r.start_offset <= offset <= r.end_offset)
        ]
        self.render()
        if self.on_regions_changed and self.sequence_id is not None:
            self.on_regions_changed(self.sequence_id, self.fuzzable_regions)

    def render(self):
        """Render the hexdump display."""
        if not self.data:
            return
            
        # Clear existing content
        dpg.delete_item(self.canvas, children_only=True)
        
        # Font metrics (optimized for readability)
        scale = dpg.get_global_font_scale()
        char_width = int(10 * scale)  # Reduced width for better spacing
        char_height = int(20 * scale)  # Reduced height
        line_spacing = int(5 * scale)  # Reduced spacing between lines
        
        # Layout calculations
        offset_width = 8  # 8 hex digits for offset
        bytes_per_line = self.options.columns
        
        # Calculate column positions
        offset_x = int(40 * scale)
        hex_x = offset_x + (offset_width + 4) * char_width
        ascii_x = hex_x + (bytes_per_line * 3 + (bytes_per_line // self.options.mid_cols_count) * 2) * char_width
        
        # Draw vertical separator if ASCII view is enabled
        if self.options.show_ascii:
            separator_x = ascii_x - char_width
            dpg.draw_line(
                parent=self.canvas,
                p1=(separator_x, 0),
                p2=(separator_x, self.height),
                color=self.separator_color,
                thickness=1
            )

        y = int(20 * scale)  # Reduced starting y position
        
        # Process data in chunks
        for i in range(0, len(self.data), bytes_per_line):
            chunk = self.data[i:i+bytes_per_line]
            line_y = y + (i // bytes_per_line) * (char_height + line_spacing)
            
            # Draw offset with colon
            offset_text = f"{i:08x}: " if not self.options.uppercase_hex else f"{i:08X}: "
            dpg.draw_text(
                parent=self.canvas,
                pos=(offset_x, line_y),
                text=offset_text,
                color=(200, 200, 200, 255),
                size=char_height
            )
            
            # Draw hex values with improved spacing
            # Draw hex values with improved spacing
            for j, byte in enumerate(chunk):
                # Calculate position for this byte
                group_idx = j // self.options.mid_cols_count
                byte_x = hex_x + (j * 3 + group_idx * 2) * char_width
                byte_offset = i + j
                
                # Check if this byte is in a fuzzable region or selected
                is_fuzzable = any(
                    r.start_offset <= byte_offset <= r.end_offset
                    for r in self.fuzzable_regions
                )
                is_selected = (
                    self.current_selection and
                    self.current_selection.start_offset <= byte_offset <= self.current_selection.end_offset
                )
                is_cursor = (
                    self.current_selection and
                    self.current_selection.start_offset == self.current_selection.end_offset and
                    byte_offset == self.current_selection.start_offset
                )
                
                # Draw highlight backgrounds if needed
                if is_fuzzable or is_selected:
                    highlight_width = char_width * 2.5  # Width of two hex chars plus space
                    highlight_height = char_height
                    color = self.selection_color if is_selected else self.fuzzable_color
                    
                    # Highlight hex
                    dpg.draw_rectangle(
                        parent=self.canvas,
                        pmin=(byte_x, line_y),
                        pmax=(byte_x + highlight_width, line_y + highlight_height),
                        fill=color
                    )
                    
                    # Highlight ASCII if enabled
                    if self.options.show_ascii:
                        ascii_highlight_x = ascii_x + j * char_width
                        dpg.draw_rectangle(
                            parent=self.canvas,
                            pmin=(ascii_highlight_x, line_y),
                            pmax=(ascii_highlight_x + char_width, line_y + highlight_height),
                            fill=color
                        )
                
                # Draw cursor indicator
                if is_cursor:
                    cursor_color = (255, 255, 255, 200)  # Semi-transparent white
                    # Cursor in hex area
                    dpg.draw_line(
                        parent=self.canvas,
                        p1=(byte_x, line_y),
                        p2=(byte_x, line_y + char_height),
                        color=cursor_color,
                        thickness=2
                    )
                    # Cursor in ASCII area if enabled
                    if self.options.show_ascii:
                        ascii_x_pos = ascii_x + j * char_width
                        dpg.draw_line(
                            parent=self.canvas,
                            p1=(ascii_x_pos, line_y),
                            p2=(ascii_x_pos, line_y + char_height),
                            color=cursor_color,
                            thickness=2
                        )
                
                # Format and draw hex value
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
            preview_text = self._get_preview_data(self.current_selection.start_offset)
            if preview_text:
                preview_y = y + ((len(self.data) + bytes_per_line - 1) // bytes_per_line) * (char_height + line_spacing)
                dpg.draw_text(
                    parent=self.canvas,
                    pos=(offset_x, preview_y),
                    text=preview_text,
                    color=self.text_color,
                    size=char_height
                )

        # Handle scrolling to address
        if self.options.scroll_to_addr is not None:
            target_line = self.options.scroll_to_addr // bytes_per_line
            scroll_y = target_line * (char_height + line_spacing)
            dpg.set_y_scroll(self.tag, scroll_y)
            self.options.scroll_to_addr = None

        # Update status bar
        self._update_status_bar()