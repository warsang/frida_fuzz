import dearpygui.dearpygui as dpg
from typing import Optional, Tuple
from .frequency_analyzer import FrequencyAnalyzer

class FrequencyWindow:
    """Window for displaying byte frequency analysis."""
    
    def __init__(self, parent_widget):
        """
        Initialize frequency analysis window.
        
        Args:
            parent_widget: Parent HexdumpWidget instance
        """
        self.parent = parent_widget
        self.window_tag = f"{parent_widget.tag}_frequency_window"
        self.plot_tag = f"{self.window_tag}_plot"
        self.auto_update = True
        self.last_selection: Optional[Tuple[int, int]] = None
        
        try:
            # Delete existing window if it exists
            if dpg.does_item_exist(self.window_tag):
                dpg.delete_item(self.window_tag)
            
            # Create window
            with dpg.window(
                label="Frequency Analysis",
                tag=self.window_tag,
                width=800,
                height=500,
                show=False,
                on_close=self.hide,
                no_close=False
            ):
                # Controls
                with dpg.group(horizontal=True):
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
                
                print("[DEBUG] Setting up frequency plot")
                # Create plot
                try:
                    FrequencyAnalyzer.setup_plot(self.window_tag)
                    print("[DEBUG] Frequency plot setup successful")
                except Exception as e:
                    print(f"[DEBUG] Error in frequency plot setup: {str(e)}")
                    raise
        except Exception as e:
            print(f"Error creating frequency window: {e}")
            raise
    
    def show(self):
        """Show the frequency analysis window."""
        print("[DEBUG] Attempting to show frequency window")
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
                print("[DEBUG] Error: Frequency window does not exist, recreating")
                # Recreate the window
                try:
                    self.__init__(self.parent)
                    print("[DEBUG] Window recreation successful")
                    print("[DEBUG] Showing recreated window")
                    dpg.show_item(self.window_tag)
                    print("[DEBUG] Updating plot in recreated window")
                    self.update_plot()
                    print("[DEBUG] Recreation and update complete")
                except Exception as e:
                    print(f"[DEBUG] Error recreating window: {str(e)}")
                    raise
        except Exception as e:
            print(f"Error showing frequency window: {e}")
            raise
    
    def hide(self):
        """Hide the frequency analysis window."""
        dpg.hide_item(self.window_tag)
    
    def _on_auto_update_changed(self, sender, value):
        """Handle auto update checkbox change."""
        self.auto_update = value
    
    def update_plot(self):
        """Update the frequency plot with current selection."""
        if not self.parent.current_selection:
            return
            
        # Get selected data
        start = self.parent.current_selection.start_offset
        end = self.parent.current_selection.end_offset
        # Ensure we don't go past the end of data
        end = min(end, len(self.parent.data) - 1)
        data = self.parent.data[start:end + 1]
        
        # Update plot
        FrequencyAnalyzer.update_plot(
            self.window_tag,
            data
        )
        
        # Store selection for comparison
        self.last_selection = (start, end)