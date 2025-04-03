import dearpygui.dearpygui as dpg
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Any
from marker_manager import MarkerManager, MarkerRegion

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
            on_regions_changed: Callback function when markers are modified
        """
        self.tag = tag
        self.width = width
        self.height = height
        self.data = bytes()  # Raw byte data
        self.marked_regions: List[MarkerRegion] = []
        self.current_selection: Optional[Selection] = None
        self.is_selecting = False
        self.selection_start_pos = (0, 0)
        self.sequence_id = None  # Current sequence ID being displayed
        self.on_regions_changed = on_regions_changed
        self.marker_manager = MarkerManager()
        
        # Colors
        self.selection_color = (255, 255, 0, 100)  # Light yellow, semi-transparent
        self.marker_colors = {}  # Will be populated from marker_manager
        
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
                # Built-in markers submenu
                with dpg.menu(label="Add Built-in Marker"):
                    for marker_type in self.marker_manager.get_builtin_marker_types():
                        dpg.add_menu_item(
                            label=marker_type.display_name,
                            callback=lambda s, a, mt=marker_type: self._add_marker(mt.name)
                        )
                
                # Custom markers submenu
                with dpg.menu(label="Add Custom Marker"):
                    for marker_type in self.marker_manager.get_custom_marker_types():
                        dpg.add_menu_item(
                            label=marker_type.display_name,
                            callback=lambda s, a, mt=marker_type: self._add_marker(mt.name)
                        )
                    dpg.add_separator()
                    dpg.add_menu_item(label="Create New Marker Type...", callback=self._create_marker_type)
                dpg.add_menu_item(label="Remove Marker", callback=self._remove_marker)
                dpg.add_separator()
                dpg.add_menu_item(label="Copy Selection", callback=self._copy_selection)
                dpg.add_menu_item(label="Copy as Hex", callback=self._copy_as_hex)
        
    def set_data(self, data: bytes, sequence_id=None, markers=None):
        """Set the byte data to display.
        
        Args:
            data: Raw bytes to display in the hexdump
            sequence_id: ID of the sequence being displayed
            markers: List of markers to apply
        """
        self.data = data
        self.sequence_id = sequence_id
        self.current_selection = None
        
        # Update markers
        self.marked_regions = []
        if markers:
            for marker in markers:
                marker_type = self.marker_manager.get_marker_type(marker.tag_type)
                if marker_type:
                    self.marked_regions.append(marker)
                    self.marker_colors[marker.tag_type] = self._parse_color(marker_type.color)
        
        self.render()

    def _add_marker(self, marker_type_name: str):
        """Add a marker of the specified type to the current selection."""
        if not self.current_selection:
            return
            
        marker_type = self.marker_manager.get_marker_type(marker_type_name)
        if not marker_type:
            return
            
        # Check for overlaps
        for region in self.marked_regions:
            if (self.current_selection.start_offset <= region.end_offset and
                self.current_selection.end_offset >= region.start_offset):
                return
                
        # Create new marker region
        new_marker = MarkerRegion(
            start_offset=self.current_selection.start_offset,
            end_offset=self.current_selection.end_offset,
            tag_name=marker_type.name,
            tag_type=marker_type.name,
            properties=marker_type.default_properties.copy()
        )
        self.marked_regions.append(new_marker)
        
        # Update marker colors
        if marker_type.name not in self.marker_colors:
            self.marker_colors[marker_type.name] = self._parse_color(marker_type.color)
        
        # Clear selection and update display
        self.current_selection = None
        self.render()
        
        # Notify of changes if callback is set
        if self.on_regions_changed and self.sequence_id is not None:
            self.on_regions_changed(self.sequence_id, self.marked_regions)

    def _remove_marker(self):
        """Remove marker at current selection/click position."""
        if not self.current_selection:
            return
            
        self.marked_regions = [
            r for r in self.marked_regions 
            if not (r.start_offset <= self.current_selection.start_offset <= r.end_offset)
        ]
        self.render()
        
        if self.on_regions_changed and self.sequence_id is not None:
            self.on_regions_changed(self.sequence_id, self.marked_regions)

    def _parse_color(self, color_str: str) -> Tuple[int, int, int, int]:
        """Convert hex color string to RGBA tuple."""
        # Remove '#' if present
        color_str = color_str.lstrip('#')
        # Convert hex to RGB
        r = int(color_str[0:2], 16)
        g = int(color_str[2:4], 16)
        b = int(color_str[4:6], 16)
        # Add alpha
        return (r, g, b, 100)

    def _create_marker_type(self):
        """Open dialog to create a new marker type."""
        dialog_tag = f"{self.tag}_marker_dialog"
        
        def create_callback(sender, app_data, user_data):
            name_tag, display_name_tag, color_tag, dialog_tag = user_data
            name = dpg.get_value(name_tag)
            display_name = dpg.get_value(display_name_tag)
            color = dpg.get_value(color_tag)
            print(f"Creating marker with name={name}, display_name={display_name}, color={color}")
            self._finish_create_marker_type(name, display_name, color, dialog_tag)
        
        with dpg.window(label="Create New Marker Type", modal=True, width=400, tag=dialog_tag):
            name_tag = f"{dialog_tag}_name"
            display_name_tag = f"{dialog_tag}_display_name"
            color_tag = f"{dialog_tag}_color"
            
            dpg.add_input_text(label="Name", hint="marker_name", tag=name_tag)
            dpg.add_input_text(label="Display Name", hint="Marker Display Name", tag=display_name_tag)
            dpg.add_color_picker(label="Color", no_alpha=True, default_value=[100, 149, 237], tag=color_tag)
            
            dpg.add_button(
                label="Create",
                callback=create_callback,
                user_data=(name_tag, display_name_tag, color_tag, dialog_tag)
            )

    def _finish_create_marker_type(self, name: str, display_name: str, color: List[int], dialog_tag: str):
        """Handle creation of new marker type from dialog input."""
        if not name or not display_name:
            print("Error: Name or display name is empty")
            return
            
        # Sanitize name (remove spaces and special characters)
        name = "".join(c for c in name if c.isalnum() or c == '_').lower()
        if not name:
            print("Error: Invalid name after sanitization")
            return
            
        # Convert RGB values to hex string
        try:
            color_hex = "#{:02x}{:02x}{:02x}".format(
                int(color[0]),
                int(color[1]),
                int(color[2])
            )
            print(f"Creating marker type: {name} ({display_name}) with color {color_hex}")
        except (TypeError, IndexError, ValueError) as e:
            print(f"Error converting color: {e}")
            return
        
        # Create new marker type
        if self.marker_manager.create_marker_type(name, display_name, color_hex):
            print(f"Successfully created marker type: {name}")
            # Update marker colors
            self.marker_colors[name] = (color[0], color[1], color[2], 100)
            # Close dialog
            dpg.delete_item(dialog_tag)
            # Apply marker if there's a selection
            if self.current_selection:
                print(f"Applying marker {name} to selection")
                self._add_marker(name)
            # Refresh context menu
            self._refresh_context_menu()
        else:
            print(f"Failed to create marker type: {name}")
            
    def _refresh_context_menu(self):
        """Refresh the context menu to show new marker types."""
        menu_tag = f"{self.tag}_context_menu"
        
        # Delete old menu items
        dpg.delete_item(menu_tag, children_only=True)
        
        # Rebuild menu
        with dpg.popup(self.click_area, tag=menu_tag, mousebutton=dpg.mvMouseButton_Right):
            # Built-in markers submenu
            with dpg.menu(label="Add Built-in Marker"):
                for marker_type in self.marker_manager.get_builtin_marker_types():
                    dpg.add_menu_item(
                        label=marker_type.display_name,
                        callback=lambda s, a, mt=marker_type: self._add_marker(mt.name)
                    )
            
            # Custom markers submenu
            with dpg.menu(label="Add Custom Marker"):
                for marker_type in self.marker_manager.get_custom_marker_types():
                    dpg.add_menu_item(
                        label=marker_type.display_name,
                        callback=lambda s, a, mt=marker_type: self._add_marker(mt.name)
                    )
                dpg.add_separator()
                dpg.add_menu_item(label="Create New Marker Type...", callback=self._create_marker_type)
            dpg.add_menu_item(label="Remove Marker", callback=self._remove_marker)
            dpg.add_separator()
            dpg.add_menu_item(label="Copy Selection", callback=self._copy_selection)
            dpg.add_menu_item(label="Copy as Hex", callback=self._copy_as_hex)

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
                
                # Check if this byte is in a marked region
                byte_offset = i + j
                marker_color = None
                for region in self.marked_regions:
                    if region.start_offset <= byte_offset <= region.end_offset:
                        color = self.marker_colors.get(region.tag_type)
                        if color:
                            marker_color = color
                            break
                
                # Check if this byte is selected
                is_selected = (
                    self.current_selection and
                    self.current_selection.start_offset <= byte_offset <= self.current_selection.end_offset
                )
                
                # Draw highlight backgrounds if needed
                if marker_color or is_selected:
                    highlight_width = char_width * 2  # Width of two hex chars
                    highlight_height = char_height
                    highlight_color = self.selection_color if is_selected else marker_color
                    
                    # Highlight hex
                    dpg.draw_rectangle(
                        parent=self.canvas,
                        pmin=(byte_x, line_y),
                        pmax=(byte_x + highlight_width, line_y + highlight_height),
                        fill=highlight_color
                    )
                    
                    # Highlight ASCII
                    ascii_highlight_x = ascii_x + j * char_width
                    dpg.draw_rectangle(
                        parent=self.canvas,
                        pmin=(ascii_highlight_x, line_y),
                        pmax=(ascii_highlight_x + char_width, line_y + highlight_height),
                        fill=highlight_color
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