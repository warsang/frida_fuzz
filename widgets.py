import dearpygui.dearpygui as dpg
from dataclasses import dataclass
from typing import Optional, List, Tuple

@dataclass
class FuzzableRegion:
    start_offset: int
    end_offset: int
    mutation_type: str

@dataclass
class Selection:
    start_offset: int
    end_offset: int

class HexdumpWidget:
    def __init__(self, tag: str, width: int, height: int, on_regions_changed=None):
        """Initialize the hexdump widget.
        
        Args:
            tag: Unique identifier for the widget
            width: Widget width in pixels
            height: Widget height in pixels
            on_regions_changed: Callback function when fuzzable regions are modified
        """
        self.tag = tag
        self.width = width
        self.height = height
        self.data = bytes()  # Raw byte data
        self.fuzzable_regions: List[FuzzableRegion] = []
        self.current_selection: Optional[Selection] = None
        self.is_selecting = False
        self.selection_start_pos = (0, 0)
        self.sequence_id = None  # Current sequence ID being displayed
        self.on_regions_changed = on_regions_changed
        
        # Colors
        self.selection_color = (255, 255, 0, 100)  # Light yellow, semi-transparent
        self.fuzzable_color = (100, 149, 237, 100)  # Cornflower blue, semi-transparent
        
        # Create the widget
        with dpg.child_window(tag=self.tag, width=self.width, height=self.height):
            # Add clickable area for mouse interaction
            self.click_area = dpg.add_button(
                label="",
                width=-1,
                height=self.height,
                callback=self._on_click
            )
            
            # Add the drawing canvas
            self.canvas = dpg.add_drawlist(
                width=self.width,
                height=self.height,
                tag=f"{self.tag}_canvas",
                parent=self.click_area
            )
            
            # Add context menu
            with dpg.popup(self.click_area, tag=f"{self.tag}_context_menu", mousebutton=dpg.mvMouseButton_Right):
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
        

    def set_data(self, data: bytes, sequence_id=None):
        """Set the byte data to display.
        
        Args:
            data: Raw bytes to display in the hexdump
            sequence_id: ID of the sequence being displayed
        """
        self.data = data
        self.sequence_id = sequence_id
        self.current_selection = None
        self.render()

    def add_fuzzable_region(self, start: int, end: int, mutation_type: str) -> bool:
        """Add a new fuzzable region if it doesn't overlap with existing ones.
        
        Args:
            start: Start offset in bytes
            end: End offset in bytes
            mutation_type: Type of mutation strategy to use
            
        Returns:
            bool: True if region was added, False if it would overlap
        """
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
        """Remove fuzzable region containing the given offset.
        
        Args:
            offset: Byte offset to check for removal
        """
        self.fuzzable_regions = [
            r for r in self.fuzzable_regions 
            if not (r.start_offset <= offset <= r.end_offset)
        ]
        self.render()
        if self.on_regions_changed and self.sequence_id is not None:
            self.on_regions_changed(self.sequence_id, self.fuzzable_regions)

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
            selected = self.data[self.current_selection.start_offset:self.current_selection.end_offset]
            dpg.set_clipboard_text(selected.decode('ascii', errors='replace'))

    def _copy_as_hex(self):
        """Copy selected bytes as hex string."""
        if self.current_selection:
            selected = self.data[self.current_selection.start_offset:self.current_selection.end_offset]
            dpg.set_clipboard_text(selected.hex())

    def _get_offset_at_position(self, x: int, y: int) -> Optional[int]:
        """Convert screen coordinates to byte offset.
        
        Args:
            x: X coordinate relative to widget
            y: Y coordinate relative to widget
            
        Returns:
            int: Byte offset at the given position, or None if invalid
        """
        # Font metrics
        char_width = 8
        char_height = 16
        line_spacing = 4
        
        # Layout constants
        offset_width = 8  # 8 hex digits for offset
        hex_group_size = 8
        bytes_per_line = 16
        
        # Calculate column positions
        offset_x = 10
        hex_x = offset_x + (offset_width + 2) * char_width
        ascii_x = hex_x + (bytes_per_line * 3 + 2) * char_width
        
        # Adjust coordinates relative to content area
        x = x - 10  # Adjust for left margin
        y = y - 10  # Adjust for top margin
        
        # Calculate line number
        line = y // (char_height + line_spacing)
        if line < 0 or line >= (len(self.data) + bytes_per_line - 1) // bytes_per_line:
            return None
            
        # Determine if click was in hex or ASCII area
        if hex_x <= x < ascii_x:
            # Hex area
            x = x - hex_x
            # Account for spaces between hex values and groups
            group_spaces = (x // (char_width * 3 * hex_group_size)) * 2 * char_width
            x = x - group_spaces
            col = x // (char_width * 3)
        elif x >= ascii_x:
            # ASCII area
            x = x - ascii_x
            col = x // char_width
        else:
            return None
            
        # Calculate final offset
        offset = line * bytes_per_line + col
        if 0 <= offset < len(self.data):
            return offset
        return None

    def _on_mouse_down(self, sender, app_data):
        """Handle mouse button press."""
        if not self.data:
            return
            
        x = app_data[1]
        y = app_data[2]
        button = app_data[3]
        
        # Handle left click for selection
        if button == dpg.mvMouseButton_Left:
            self.is_selecting = True
            self.selection_start_pos = (x, y)
            start_offset = self._get_offset_at_position(x, y)
            if start_offset is not None:
                self.current_selection = Selection(start_offset, start_offset)
                self.render()

        # Handle drag if selecting
        if self.is_selecting:
            end_offset = self._get_offset_at_position(x, y)
            if end_offset is not None and self.current_selection:
                self.current_selection.end_offset = end_offset
                self.render()
        
        # Handle release
        if not left_clicked and self.is_selecting:
            self.is_selecting = False
            if self.current_selection:
                # Ensure start_offset <= end_offset
                if self.current_selection.start_offset > self.current_selection.end_offset:
                    self.current_selection.start_offset, self.current_selection.end_offset = \
                        self.current_selection.end_offset, self.current_selection.start_offset
                self.render()

    def render(self):
        """Render the hexdump display."""
        if not self.data:
            return
            
        # Clear existing content
        dpg.delete_item(f"{self.tag}_canvas", children_only=True)
        
        # Font metrics
        char_width = 8  # Width of a single character
        char_height = 16  # Height of a single character
        line_spacing = 4  # Extra space between lines
        
        # Layout calculations
        offset_width = 8  # 8 hex digits for offset
        hex_group_size = 8  # Number of bytes per group
        bytes_per_line = 16
        
        # Calculate column positions
        offset_x = 10  # Starting x position for offset
        hex_x = offset_x + (offset_width + 2) * char_width  # +2 for "  " after offset
        ascii_x = hex_x + (bytes_per_line * 3 + 2) * char_width  # 3 chars per byte (2 hex + 1 space) + 2 for group spacing
        
        y = 10  # Starting y position
        
        # Process data in 16-byte chunks
        for i in range(0, len(self.data), bytes_per_line):
            chunk = self.data[i:i+bytes_per_line]
            line_y = y + (i // bytes_per_line) * (char_height + line_spacing)
            
            # Draw offset
            offset_text = f"{i:08x}"
            dpg.draw_text(parent=self.canvas, pos=(offset_x, line_y), text=offset_text, color=(200, 200, 200, 255))
            
            # Draw hex values
            for j, byte in enumerate(chunk):
                # Calculate position for this byte
                group_idx = j // hex_group_size
                byte_x = hex_x + (j * 3 + group_idx * 2) * char_width
                
                # Check if this byte is in a fuzzable region
                byte_offset = i + j
                is_fuzzable = any(
                    r.start_offset <= byte_offset <= r.end_offset
                    for r in self.fuzzable_regions
                )
                
                # Check if this byte is selected
                is_selected = (
                    self.current_selection and
                    self.current_selection.start_offset <= byte_offset <= self.current_selection.end_offset
                )
                
                # Draw highlight backgrounds if needed
                if is_fuzzable or is_selected:
                    highlight_width = char_width * 2  # Width of two hex chars
                    highlight_height = char_height
                    color = self.selection_color if is_selected else self.fuzzable_color
                    
                    # Highlight hex
                    dpg.draw_rectangle(
                        parent=self.canvas,
                        pmin=(byte_x, line_y),
                        pmax=(byte_x + highlight_width, line_y + highlight_height),
                        fill=color
                    )
                    
                    # Highlight ASCII
                    ascii_highlight_x = ascii_x + j * char_width
                    dpg.draw_rectangle(
                        parent=self.canvas,
                        pmin=(ascii_highlight_x, line_y),
                        pmax=(ascii_highlight_x + char_width, line_y + highlight_height),
                        fill=color
                    )
                
                # Draw hex value
                hex_text = f"{byte:02x}"
                dpg.draw_text(parent=self.canvas, pos=(byte_x, line_y), text=hex_text, color=(255, 255, 255, 255))
            
            # Draw ASCII representation
            for j, byte in enumerate(chunk):
                ascii_char = chr(byte) if 32 <= byte <= 126 else '.'
                dpg.draw_text(
                    parent=self.canvas,
                    pos=(ascii_x + j * char_width, line_y),
                    text=ascii_char,
                    color=(255, 255, 255, 255)
                )