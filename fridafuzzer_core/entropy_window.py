import dearpygui.dearpygui as dpg
from typing import Optional, Tuple
from .entropy_analyzer import EntropyAnalyzer

class EntropyWindow:
    """Window for displaying entropy analysis of selected bytes."""
    
    def __init__(self, parent_widget):
        """
        Initialize entropy analysis window.
        
        Args:
            parent_widget: Parent HexdumpWidget instance
        """
        self.parent = parent_widget
        self.window_tag = f"{parent_widget.tag}_entropy_window"
        self.plot_tag = f"{self.window_tag}_plot"
        self.window_size = 32  # Default window size
        self.auto_update = True
        self.last_selection: Optional[Tuple[int, int]] = None
        
        try:
            # Delete existing window if it exists
            if dpg.does_item_exist(self.window_tag):
                dpg.delete_item(self.window_tag)
            
            # Create window
            with dpg.window(
                label="Entropy Analysis",
                tag=self.window_tag,
                width=800,
                height=500,
                show=False,
                on_close=self.hide,
                no_close=False
            ):
                # Controls
                with dpg.group(horizontal=True):
                    dpg.add_text("Window Size:")
                    dpg.add_slider_int(
                        default_value=self.window_size,
                        min_value=8,
                        max_value=256,
                        callback=self._on_window_size_changed,
                        width=150,
                        tag=f"{self.window_tag}_window_size"
                    )
                    dpg.add_checkbox(
                        label="Auto Update",
                        default_value=self.auto_update,
                        callback=self._on_auto_update_changed,
                        tag=f"{self.window_tag}_auto_update"
                    )
                    dpg.add_button(
                        label="Update",
                        callback=self.update_plot
                    )
                
                # Add separator
                dpg.add_separator()
                
                print("[DEBUG] Setting up entropy plot")
                # Create plot
                try:
                    EntropyAnalyzer.setup_plot(self.window_tag)
                    print("[DEBUG] Entropy plot setup successful")
                except Exception as e:
                    print(f"[DEBUG] Error in entropy plot setup: {str(e)}")
                    raise
        except Exception as e:
            print(f"Error creating entropy window: {e}")
            raise
    
    def show(self):
        """Show the entropy analysis window."""
        print("[DEBUG] Attempting to show entropy window")
        try:
            window_exists = dpg.does_item_exist(self.window_tag)
            print(f"[DEBUG] Window exists? {window_exists}")
            if window_exists:
                print(f"[DEBUG] Showing window with tag: {self.window_tag}")
                dpg.show_item(self.window_tag)
                print("[DEBUG] Window shown, updating plot")
                self.update_plot()
                print("[DEBUG] Plot update completed")
            else:
                print("[DEBUG] Error: Entropy window does not exist, recreating")
                # Recreate the window
                try:
                    self.__init__(self.parent)
                    print("[DEBUG] Window recreation successful")
                except Exception as e:
                    print(f"[DEBUG] Error recreating window: {str(e)}")
                    raise
                    print("[DEBUG] Showing recreated window")
                    dpg.show_item(self.window_tag)
                    print("[DEBUG] Updating plot in recreated window")
                    self.update_plot()
                    print("[DEBUG] Recreation and update complete")
        except Exception as e:
            print(f"Error showing entropy window: {e}")
            raise
    
    def hide(self):
        """Hide the entropy analysis window."""
        dpg.hide_item(self.window_tag)
    
    def _on_window_size_changed(self, sender, value):
        """Handle window size slider change."""
        self.window_size = value
        if self.auto_update:
            self.update_plot()
    
    def _on_auto_update_changed(self, sender, value):
        """Handle auto update checkbox change."""
        self.auto_update = value
    
    def update_plot(self):
        """Update the entropy plot with current selection."""
        if not self.parent.current_selection:
            return
            
        # Get selected data
        start = self.parent.current_selection.start_offset
        end = self.parent.current_selection.end_offset
        # Ensure we don't go past the end of data
        end = min(end, len(self.parent.data) - 1)
        data = self.parent.data[start:end + 1]
        
        # Update plot
        EntropyAnalyzer.update_plot(
            self.window_tag,
            data,
            self.window_size,
            (start, end)
        )
        
        # Store selection for comparison
        self.last_selection = (start, end)