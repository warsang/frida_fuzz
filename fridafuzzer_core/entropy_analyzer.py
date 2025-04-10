import numpy as np
from typing import List, Tuple
import dearpygui.dearpygui as dpg
from scipy.stats import entropy

class EntropyAnalyzer:
    """Class for analyzing and visualizing entropy in byte sequences."""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of a byte sequence.
        
        Args:
            data: Bytes to analyze
            
        Returns:
            float: Shannon entropy value between 0 and 8 (for bytes)
        """
        if not data:
            return 0.0
            
        try:
            # Calculate frequency of each byte value
            freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            # Normalize frequencies
            freq = freq / len(data)
            # Use scipy.stats.entropy which handles edge cases better
            print(f"We got our entropy here! {entropy(freq, base=2)}")
            return entropy(freq, base=2)
        except Exception as e:
            print(f"Error calculating entropy: {e}")
            return 0.0
    
    @staticmethod
    def sliding_window_entropy(data: bytes, window_size: int) -> Tuple[List[float], List[int]]:
        """
        Calculate entropy using a sliding window.
        
        Args:
            data: Bytes to analyze
            window_size: Size of sliding window
            
        Returns:
            Tuple containing:
            - List of entropy values
            - List of corresponding offsets
        """
        if not data or window_size <= 0:
            return [], []
            
        # Adjust window size if larger than data
        window_size = min(window_size, len(data))
            
        entropy_values = []
        offsets = []
        
        # Convert to numpy array for faster processing
        byte_array = np.frombuffer(data, dtype=np.uint8)
        
        # Calculate entropy for each window
        for i in range(len(data) - window_size + 1):
            window = byte_array[i:i + window_size]
            entropy = EntropyAnalyzer.calculate_entropy(window.tobytes())
            entropy_values.append(entropy)
            offsets.append(i)
            
        return entropy_values, offsets
    
    @staticmethod
    def setup_plot(tag: str, width: int = 800, height: int = 400) -> None:
        """
        Create a DearPyGui simple plot for entropy visualization.
        
        Args:
            tag: Base tag for the plot
            width: Plot width in pixels
            height: Plot height in pixels
        """
        print(f"[DEBUG] Setting up simple plot with tag={tag}")
        try:
            # Create a simple plot with min/max scale for entropy values (0-8)
            dpg.add_simple_plot(
                label="Entropy Analysis",
                min_scale=0.0,
                max_scale=8.0,
                height=height,
                width=width,
                tag=f"{tag}_plot"
            )
            print("[DEBUG] Simple plot setup successful")
        except Exception as e:
            print(f"[DEBUG] Error setting up simple plot: {str(e)}")
            raise
    
    @staticmethod
    def update_plot(tag: str, data: bytes, window_size: int, selection: Tuple[int, int] = None) -> None:
        """
        Update the entropy plot with new data.
        
        Args:
            tag: Base tag for the plot components
            data: Bytes to analyze
            window_size: Size of sliding window
            selection: Optional tuple of (start, end) offsets to highlight
        """
        print(f"[DEBUG] Starting update_plot with tag={tag}, window_size={window_size}")
        print(f"[DEBUG] Calculating entropy values for data length={len(data)}")
        # Calculate entropy values
        entropy_values, offsets = EntropyAnalyzer.sliding_window_entropy(data, window_size)
        print(f"[DEBUG] Got entropy_values length={len(entropy_values)}, offsets length={len(offsets)}")
        
        # Get plot tag
        plot_tag = f"{tag}_plot"
        print(f"[DEBUG] Looking for plot with tag: {plot_tag}")

        # Check if plot exists
        plot_exists = dpg.does_item_exist(plot_tag)
        print(f"[DEBUG] Plot exists? {plot_exists}")

        # If plot doesn't exist, we can't proceed
        if not plot_exists:
            print(f"[DEBUG] Error: Plot {plot_tag} does not exist!")
            # Try to recreate the plot
            try:
                print("[DEBUG] Attempting to recreate plot")
                dpg.add_simple_plot(
                    label="Entropy Analysis",
                    min_scale=0.0,
                    max_scale=8.0,
                    height=400,
                    width=800,
                    tag=plot_tag
                )
                print("[DEBUG] Plot recreation successful")
            except Exception as e:
                print(f"[DEBUG] Error recreating plot: {str(e)}")
                return

        if not entropy_values:
            print("[DEBUG] No entropy values, clearing plot")
            if dpg.does_item_exist(f"{tag}_plot"):
                dpg.set_value(f"{tag}_plot", [])
            return
            
        print("[DEBUG] Preparing to update plot")
        try:
            plot_tag = f"{tag}_plot"
            if dpg.does_item_exist(plot_tag):
                print(f"[DEBUG] Updating plot with {len(entropy_values)} values")
                dpg.set_value(plot_tag, entropy_values)
                print("[DEBUG] Plot update successful")
            else:
                print(f"[DEBUG] Error: Plot {plot_tag} does not exist")
        except Exception as e:
            print(f"[DEBUG] Error updating plot: {str(e)}")
            raise

        # --- Start: Original (flawed) shade logic - commented out ---
        # # Update selection highlight if provided
        # if selection and len(selection) == 2:
        #     start, end = selection # These are original offsets
        #     # The offsets_list contains indices relative to the *sliced* data (0 to len(data)-window_size)
        #     # Comparing them directly to original offsets (start, end) is incorrect.
        #     # The logic for what the shade should represent needs clarification.
        #     # For now, we just clear the shade.
        #
        #     # Example of incorrect mask:
        #     # offsets_array = np.array(offsets_list) # Need numpy array for masking
        #     # entropy_array = np.array(entropy_list) # Need numpy array for masking
        #     # mask = (offsets_array >= start) & (offsets_array <= end) # Incorrect comparison
        #     # shade_x = offsets_array[mask]
        #     # shade_y1 = entropy_array[mask]
        #     # shade_y2 = np.zeros_like(shade_y1)
        #     # if dpg.does_item_exist(shade_tag):
        #     #     dpg.configure_item(shade_tag, x=shade_x.tolist(), y=shade_y1.tolist(), y2=shade_y2.tolist())
        #     if dpg.does_item_exist(shade_tag):
        #         dpg.configure_item(shade_tag, x=[], y=[], y2=[]) # Clear shade
        # else:
        #     # Clear selection highlight
        #     if dpg.does_item_exist(shade_tag):
        #         dpg.configure_item(shade_tag, x=[], y=[], y2=[])
        # --- End: Original (flawed) shade logic ---