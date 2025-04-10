import dearpygui.dearpygui as dpg
import uuid

class MarkerEditorWindow:
    def __init__(self, parent_widget, save_callback=None):
        """
        Initialize the Marker Editor window.

        Args:
            parent_widget: The HexdumpWidget instance.
            save_callback: Optional callback to invoke on save.
        """
        self.parent_widget = parent_widget
        self.save_callback = save_callback
        self.current_marker = None

        with dpg.window(label="Marker Editor", show=False, width=400, height=600, tag="marker_editor_window") as self.window_id:
            # Group: Marker Basic Info
            with dpg.group():
                dpg.add_text("Marker Name:")
                self.name_input = dpg.add_input_text(tag="marker_name_input")

                dpg.add_separator()

                dpg.add_text("Marker Color:")
                self.color_picker = dpg.add_color_picker(no_alpha=False, tag="marker_color_picker", width=200)

                dpg.add_separator()

            # Group: Marker Size
            with dpg.group():
                dpg.add_text("Marker Size:")
                self.size_input = dpg.add_input_text(tag="marker_size_input")

                dpg.add_text("Read Size From Offset:")
                self.size_offset_input = dpg.add_input_text(tag="marker_size_offset_input")

                self.size_mode_radio = dpg.add_radio_button(items=["Direct Size", "Read from Offset"], default_value="Direct Size", horizontal=True, tag="marker_size_mode_radio", callback=self._on_size_mode_change)

                dpg.add_separator()

            # Group: Offset Finding Methods
            with dpg.group():
                dpg.add_text("Start Offset:")
                self.start_offset_input = dpg.add_input_text(tag="marker_start_offset_input")

                dpg.add_text("Find Offset by Byte Sequence:")
                self.byte_sequence_input = dpg.add_input_text(tag="marker_byte_sequence_input")

                dpg.add_text("Read Offset From Offset:")
                self.offset_from_offset_input = dpg.add_input_text(tag="marker_offset_from_offset_input")

                self.offset_mode_radio = dpg.add_radio_button(items=["Direct Offset", "Find by Byte Sequence", "Read from Offset"], default_value="Direct Offset", horizontal=True, tag="marker_offset_mode_radio", callback=self._on_offset_mode_change)

                dpg.add_separator()

            # Group: Related Marker Section with Packet Type and Marker dropdowns
            with dpg.group():
                # Packet Type Dropdown
                dpg.add_text("Packet Type:")
                self.packet_type_dropdown = dpg.add_combo(items=["None"], default_value="None", tag="packet_type_dropdown", callback=self._on_packet_type_change)

                # Marker Dropdown (filtered by packet type)
                dpg.add_text("Related Marker:")
                self.related_marker_dropdown = dpg.add_combo(items=["None"], default_value="None", tag="marker_related_dropdown")

                dpg.add_separator()

            # Group: Action Buttons
            with dpg.group(horizontal=True):
                self.save_button = dpg.add_button(label="Save", callback=self._on_save)
                self.cancel_button = dpg.add_button(label="Cancel", callback=self._on_cancel)

    def show(self):
        dpg.show_item(self.window_id)

    def hide(self):
        dpg.hide_item(self.window_id)

    def load_marker(self, marker, all_markers):
        """
        Load a marker into the editor.

        Args:
            marker: MarkerRegion instance.
            all_markers: List of all MarkerRegion instances for dropdown.
        """
        self.current_marker = marker

        # Debug print for marker name
        print(f"[DEBUG] load_marker: Received marker.tag_name = '{getattr(marker, 'tag_name', None)}'")

        # Populate basic info
        marker_name = getattr(marker, 'tag_name', "")
        if not marker_name:
            print("[WARNING] load_marker: marker.tag_name is empty or None, setting placeholder 'Unnamed Marker'")
            marker_name = "Unnamed Marker"
        dpg.set_value(self.name_input, marker_name)

        try:
            color_tuple = tuple(int(marker.properties.get('color', '#FFFFFF').lstrip('#')[i:i+2], 16)/255.0 for i in (0, 2, 4))
            dpg.set_value(self.color_picker, (*color_tuple, 1.0))
        except:
            dpg.set_value(self.color_picker, (1.0, 1.0, 1.0, 1.0))

        # Size mode
        if marker.size_definition_mode == 'read_offset':
            dpg.set_value(self.size_mode_radio, "Read from Offset")
            dpg.set_value(self.size_offset_input, str(marker.size_read_offset) if marker.size_read_offset is not None else "")
            dpg.disable_item(self.size_input)
            dpg.enable_item(self.size_offset_input)
        else:
            dpg.set_value(self.size_mode_radio, "Direct Size")
            dpg.set_value(self.size_input, str(marker.end_offset - marker.start_offset))
            dpg.enable_item(self.size_input)
            dpg.disable_item(self.size_offset_input)

        # Offset mode
        if marker.offset_definition_mode == 'read_offset':
            dpg.set_value(self.offset_mode_radio, "Read from Offset")
            dpg.set_value(self.offset_from_offset_input, str(marker.offset_read_offset) if marker.offset_read_offset is not None else "")
            dpg.disable_item(self.start_offset_input)
            dpg.disable_item(self.byte_sequence_input)
            dpg.enable_item(self.offset_from_offset_input)
        elif marker.offset_definition_mode == 'byte_sequence':
            dpg.set_value(self.offset_mode_radio, "Find by Byte Sequence")
            dpg.set_value(self.byte_sequence_input, marker.offset_byte_sequence or "")
            dpg.disable_item(self.start_offset_input)
            dpg.enable_item(self.byte_sequence_input)
            dpg.disable_item(self.offset_from_offset_input)
        else:
            dpg.set_value(self.offset_mode_radio, "Direct Offset")
            dpg.set_value(self.start_offset_input, str(marker.start_offset))
            dpg.enable_item(self.start_offset_input)
            dpg.disable_item(self.byte_sequence_input)
            dpg.disable_item(self.offset_from_offset_input)

        # Populate packet type dropdown
        # Fetch packet type names from the PacketTypeManager's loaded types
        packet_types = ["None"] + [ptype["name"] for ptype in self.parent_widget.packet_type_manager.types]
        dpg.configure_item(self.packet_type_dropdown, items=packet_types)

        # Determine related marker's packet type (default to parent's current packet type)
        related_packet_type = "None"
        related_marker_id = marker.related_marker_id

        # Find the related marker in all_markers to get its packet type
        for m in all_markers:
            if m.marker_id == related_marker_id:
                related_packet_type = m.packet_type if hasattr(m, 'packet_type') else self.parent_widget.current_packet_type
                break

        # Set packet type dropdown value
        if related_packet_type in packet_types:
            dpg.set_value(self.packet_type_dropdown, related_packet_type)
        else:
            dpg.set_value(self.packet_type_dropdown, "None")

        # Populate marker dropdown based on selected packet type
        self._update_marker_dropdown(related_packet_type, all_markers, exclude_marker_id=marker.marker_id, select_marker_id=related_marker_id)

    def _on_size_mode_change(self, sender, app_data, user_data):
        mode = dpg.get_value(self.size_mode_radio)
        if mode == "Read from Offset":
            dpg.disable_item(self.size_input)
            dpg.enable_item(self.size_offset_input)
        else:
            dpg.enable_item(self.size_input)
            dpg.disable_item(self.size_offset_input)

    def _on_offset_mode_change(self, sender, app_data, user_data):
        mode = dpg.get_value(self.offset_mode_radio)
        if mode == "Read from Offset":
            dpg.disable_item(self.start_offset_input)
            dpg.disable_item(self.byte_sequence_input)
            dpg.enable_item(self.offset_from_offset_input)
        elif mode == "Find by Byte Sequence":
            dpg.disable_item(self.start_offset_input)
            dpg.enable_item(self.byte_sequence_input)
            dpg.disable_item(self.offset_from_offset_input)
        else:
            dpg.enable_item(self.start_offset_input)
            dpg.disable_item(self.byte_sequence_input)
            dpg.disable_item(self.offset_from_offset_input)

    def _on_save(self, sender, app_data, user_data):
        print("[DEBUG] MarkerEditorWindow._on_save: Entered")  # ADDED
        marker = self.current_marker
        if marker is None:
            return

        # Name
        marker.tag_name = dpg.get_value(self.name_input)

        # Color
        color = dpg.get_value(self.color_picker)
        print(f"[DEBUG] Raw color picker value: {color}")  # Debug print to inspect tuple

        # Defensive: use only RGB components, clamp to [0,1], convert to 0-255 int
        r = int(max(0, min(1, color[0])) * 255)
        g = int(max(0, min(1, color[1])) * 255)
        b = int(max(0, min(1, color[2])) * 255)

        hex_color = '#%02x%02x%02x' % (r, g, b)
        print(f"[DEBUG] Converted hex color: {hex_color}")  # Debug print to verify hex string

        marker.properties['color'] = hex_color
        print(f"[DEBUG] Saved marker color property: {marker.properties['color']}")  # Debug print to verify persistence

        # Size
        size_mode = dpg.get_value(self.size_mode_radio)
        if size_mode == "Read from Offset":
            marker.size_definition_mode = 'read_offset'
            try:
                marker.size_read_offset = int(dpg.get_value(self.size_offset_input), 0)
            except:
                print("Invalid size offset input")
                return
        else:
            marker.size_definition_mode = 'direct'
            try:
                size_val = int(dpg.get_value(self.size_input), 0)
                marker.end_offset = marker.start_offset + size_val
            except:
                print("Invalid size input")
                return

        # Offset
        offset_mode = dpg.get_value(self.offset_mode_radio)
        if offset_mode == "Read from Offset":
            marker.offset_definition_mode = 'read_offset'
            try:
                target_offset = int(dpg.get_value(self.offset_from_offset_input), 0)
                marker.offset_read_offset = target_offset
            except:
                print("Invalid offset from offset input")
                return
            # Check or create marker at target_offset
            target_marker = self.parent_widget._get_marker_at_offset(target_offset)
            if not target_marker:
                # Create new marker at target_offset
                new_marker = self._create_basic_marker(target_offset)
                # Save new related marker persistently
                packet_type = self.parent_widget.current_packet_type
                if packet_type:
                    existing_markers = self.parent_widget.marker_manager.load_markers_for_type(packet_type)
                    existing_markers.append(new_marker)
                    self.parent_widget.marker_manager.save_markers_for_type(packet_type, existing_markers)
                target_marker = new_marker
            marker.related_marker_id = target_marker.marker_id
        elif offset_mode == "Find by Byte Sequence":
            marker.offset_definition_mode = 'byte_sequence'
            byte_seq_str = dpg.get_value(self.byte_sequence_input).replace(" ", "")
            try:
                byte_seq = bytes.fromhex(byte_seq_str)
            except:
                print("Invalid byte sequence hex")
                return
            data = self.parent_widget.data
            found_at = data.find(byte_seq)
            if found_at == -1:
                print("Byte sequence not found in data")
                return
            marker.start_offset = found_at
            marker.offset_byte_sequence = byte_seq_str
        else:
            marker.offset_definition_mode = 'direct'
            try:
                start_offset_val = int(dpg.get_value(self.start_offset_input), 0)
                marker.start_offset = start_offset_val
            except:
                print("Invalid start offset input")
                return

        # Related marker dropdown
        selected_label = dpg.get_value(self.related_marker_dropdown)
        marker.related_marker_id = self._marker_id_map.get(selected_label, None)

        # Assign marker_id if missing
        if not marker.marker_id:
            marker.marker_id = str(uuid.uuid4())

        # Save callback
        print(f"[DEBUG] MarkerEditorWindow._on_save: Preparing to call save_callback for marker ID {marker.marker_id} with data: {vars(marker)}")  # ADDED
        if self.save_callback:
            self.save_callback(marker)
            print("[DEBUG] MarkerEditorWindow._on_save: save_callback completed.")  # ADDED

        # Refresh parent widget
        self.parent_widget.render()

        # Hide editor
        self.hide()

    def _on_packet_type_change(self, sender, app_data, user_data):
        """
        Callback when packet type dropdown changes.
        Updates the marker dropdown to show markers for the selected packet type.
        """
        selected_packet_type = dpg.get_value(self.packet_type_dropdown)

        # Fetch all markers for the selected packet type
        if selected_packet_type == "None":
            markers = []
        else:
            markers = self.parent_widget.marker_manager.load_markers_for_type(selected_packet_type)

        # Exclude the current marker itself
        current_marker_id = self.current_marker.marker_id if self.current_marker else None
        self._update_marker_dropdown(selected_packet_type, markers, exclude_marker_id=current_marker_id)

    def _update_marker_dropdown(self, packet_type, markers, exclude_marker_id=None, select_marker_id=None):
        """
        Helper to update the marker dropdown based on packet type and markers list.
        """
        dropdown_items = ["None"]
        marker_id_map = {"None": None}

        for m in markers:
            if exclude_marker_id and m.marker_id == exclude_marker_id:
                continue
            label = f"{m.tag_name} ({m.marker_id[:8]})"
            dropdown_items.append(label)
            marker_id_map[label] = m.marker_id

        dpg.configure_item(self.related_marker_dropdown, items=dropdown_items)

        # Select marker if specified
        selected_label = "None"
        if select_marker_id:
            for label, mid in marker_id_map.items():
                if mid == select_marker_id:
                    selected_label = label
                    break
        dpg.set_value(self.related_marker_dropdown, selected_label)

        # Save the map for _on_save
        self._marker_id_map = marker_id_map
    def _create_basic_marker(self, offset):
        """
        Helper to create a minimal marker at a given offset.
        """
        from fridafuzzer_core.marker_manager import MarkerRegion
        new_marker = MarkerRegion(
            start_offset=offset,
            end_offset=offset + 1,
            tag_name=f"AutoMarker_{offset}",
            tag_type="auto",
            properties={'color': '#CCCCCC'},
            marker_id=str(uuid.uuid4())
        )
        return new_marker

    def _on_cancel(self, sender, app_data, user_data):
        self.current_marker = None
        self.hide()