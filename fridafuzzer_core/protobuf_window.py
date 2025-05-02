import dearpygui.dearpygui as dpg
from typing import Optional, Tuple, Dict, Any
from .protobuf_analyzer import ProtobufAnalyzer

class ProtobufInspectorWindow:
    """Window for displaying Protocol Buffer analysis of selected bytes."""
    
    def __init__(self, parent_widget):
        """
        Initialize protobuf analysis window.
        
        Args:
            parent_widget: Parent HexdumpWidget instance
        """
        self.parent = parent_widget
        self.window_tag = f"{parent_widget.tag}_protobuf_window"
        self.tree_tag = f"{self.window_tag}_tree"
        self.last_selection: Optional[Tuple[int, int]] = None
        self.parsed_fields = {}
        self.field_offsets = {}
        self.error_message = None
        
        try:
            # Delete existing window if it exists
            if dpg.does_item_exist(self.window_tag):
                dpg.delete_item(self.window_tag)
            
            # Create window
            with dpg.window(
                label="Protobuf Analysis",
                tag=self.window_tag,
                width=800,
                height=600,
                show=False,
                on_close=self.hide,
                no_close=False
            ):
                # Controls
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Update",
                        callback=self.update_tree
                    )
                    dpg.add_button(
                        label="Expand All",
                        callback=self._expand_all
                    )
                    dpg.add_button(
                        label="Collapse All",
                        callback=self._collapse_all
                    )
                
                # Add separator
                dpg.add_separator()
                
                # Error message text
                dpg.add_text("", tag=f"{self.window_tag}_error", color=(255, 100, 100))
                
                # Create tree
                try:
                    ProtobufAnalyzer.setup_tree(self.window_tag)
                    print("Protobuf tree setup successful")
                except Exception as e:
                    print(f"Error in protobuf tree setup: {str(e)}")
                    raise
                
                # Add help text
                with dpg.collapsing_header(label="Help", default_open=False):
                    dpg.add_text(
                        "This window displays the parsed Protocol Buffer structure of the selected data.\n"
                        "- Click on a field to highlight its bytes in the hexdump view\n"
                        "- Expand/collapse nested messages using the tree controls\n"
                        "- If parsing fails, try selecting a different range of bytes\n"
                        "\n"
                        "Note: Since Protocol Buffers are a binary format without self-description,\n"
                        "this tool attempts to infer the structure without a .proto definition.\n"
                        "The results may not be 100% accurate for all protobuf messages."
                    )
        except Exception as e:
            print(f"Error creating protobuf window: {e}")
            raise
    
    def show(self):
        """Show the protobuf analysis window."""
        print("Attempting to show protobuf window")
        try:
            window_exists = dpg.does_item_exist(self.window_tag)
            print(f"Window exists? {window_exists}")
            if window_exists:
                print(f"Showing window with tag: {self.window_tag}")
                dpg.show_item(self.window_tag)
                print("Window shown, updating tree")
                self.update_tree()
                print("Tree update completed")
            else:
                print("Error: Protobuf window does not exist, recreating")
                # Recreate the window
                try:
                    self.__init__(self.parent)
                    print("Window recreation successful")
                    print("Showing recreated window")
                    dpg.show_item(self.window_tag)
                    print("Updating tree in recreated window")
                    self.update_tree()
                    print("Recreation and update complete")
                except Exception as e:
                    print(f"Error recreating window: {str(e)}")
                    raise
        except Exception as e:
            print(f"Error showing protobuf window: {e}")
            raise
    
    def hide(self):
        """Hide the protobuf analysis window."""
        dpg.hide_item(self.window_tag)
    
    def update_tree(self, sender=None, app_data=None):
        """Update the protobuf tree with current selection."""
        if not self.parent.current_selection:
            return
            
        # Get selected data
        start = self.parent.current_selection.start_offset
        end = self.parent.current_selection.end_offset
        # Ensure we don't go past the end of data
        end = min(end, len(self.parent.data) - 1)
        data = self.parent.data[start:end + 1]
        
        # Clear previous error message
        dpg.set_value(f"{self.window_tag}_error", "")
        
        # Parse protobuf data
        self.parsed_fields, self.field_offsets, self.error_message = ProtobufAnalyzer.parse_protobuf(data)
        
        # Display error message if parsing failed
        if self.error_message:
            dpg.set_value(f"{self.window_tag}_error", f"Error: {self.error_message}")
        
        # Update tree with parsed fields
        ProtobufAnalyzer.update_tree(self.window_tag, self.parsed_fields, self.field_offsets)
        
        # Store selection for comparison
        self.last_selection = (start, end)
    
    def _expand_all(self, sender=None, app_data=None):
        """Expand all tree nodes."""
        def _expand_recursive(item):
            children = dpg.get_item_children(item)
            if children:
                for child in children[1]:  # [1] contains the actual children
                    if dpg.get_item_type(child) == "mvAppItemType::mvTreeNode":
                        dpg.set_value(child, True)  # Set to open state
                        _expand_recursive(child)
        
        tree_tag = f"{self.window_tag}_tree"
        if dpg.does_item_exist(tree_tag):
            _expand_recursive(tree_tag)
    
    def _collapse_all(self, sender=None, app_data=None):
        """Collapse all tree nodes."""
        def _collapse_recursive(item):
            children = dpg.get_item_children(item)
            if children:
                for child in children[1]:  # [1] contains the actual children
                    if dpg.get_item_type(child) == "mvAppItemType::mvTreeNode":
                        dpg.set_value(child, False)  # Set to closed state
                        _collapse_recursive(child)
        
        tree_tag = f"{self.window_tag}_tree"
        if dpg.does_item_exist(tree_tag):
            _collapse_recursive(tree_tag)