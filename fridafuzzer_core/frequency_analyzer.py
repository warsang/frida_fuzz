import numpy as np
from typing import List, Tuple
import dearpygui.dearpygui as dpg

class FrequencyAnalyzer:
    """Class for analyzing and visualizing byte frequencies in sequences."""
    
    @staticmethod
    def calculate_frequencies(data: bytes) -> List[Tuple[int, float]]:
        """
        Calculate frequency of each byte value in the sequence.
        
        Args:
            data: Bytes to analyze
            
        Returns:
            List of tuples (byte_value, frequency) sorted by frequency descending
        """
        if not data:
            return []
            
        try:
            # Calculate frequency of each byte value
            freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            # Normalize frequencies to percentages
            freq = (freq / len(data)) * 100
            # Create list of (byte_value, frequency) tuples
            freq_list = [(i, freq[i]) for i in range(256) if freq[i] > 0]
            # Sort by frequency descending
            freq_list.sort(key=lambda x: x[1], reverse=True)
            return freq_list
        except Exception as e:
            print(f"Error calculating frequencies: {e}")
            return []
    
    @staticmethod
    def setup_plot(tag: str, width: int = 800, height: int = 400) -> None:
        """
        Create a DearPyGui plot for frequency visualization.
        
        Args:
            tag: Base tag for the plot
            width: Plot width in pixels
            height: Plot height in pixels
        """
        print(f"[DEBUG] Setting up frequency plot with tag={tag}")
        try:
            # Create a plot for frequency distribution
            with dpg.plot(
                label="Byte Frequency Distribution",
                height=height,
                width=width,
                tag=f"{tag}_plot"
            ):
                # Add legend
                dpg.add_plot_legend()
                
                # Add axes
                dpg.add_plot_axis(dpg.mvXAxis, label="Byte Value", tag=f"{tag}_x_axis")
                dpg.add_plot_axis(dpg.mvYAxis, label="Frequency (%)", tag=f"{tag}_y_axis")
                
                # Add series for the histogram
                dpg.add_bar_series(
                    [],  # x (byte values)
                    [],  # y (frequencies)
                    label="Frequency",
                    parent=f"{tag}_y_axis",
                    tag=f"{tag}_series"
                )
                
            print("[DEBUG] Frequency plot setup successful")
        except Exception as e:
            print(f"[DEBUG] Error setting up frequency plot: {str(e)}")
            raise
    
    @staticmethod
    def update_plot(tag: str, data: bytes) -> None:
        """
        Update the frequency plot with new data.
        
        Args:
            tag: Base tag for the plot components
            data: Bytes to analyze
        """
        print(f"[DEBUG] Starting update_plot with tag={tag}")
        
        # Calculate frequencies
        freq_list = FrequencyAnalyzer.calculate_frequencies(data)
        
        if not freq_list:
            print("[DEBUG] No frequency data to display")
            return
            
        # Separate byte values and frequencies
        byte_values, frequencies = zip(*freq_list)
        
        try:
            # Update the plot series
            dpg.configure_item(
                f"{tag}_series",
                x=list(byte_values),
                y=list(frequencies)
            )
            
            # Update axis limits
            dpg.set_axis_limits(f"{tag}_x_axis", 0, 255)
            max_freq = max(frequencies)
            dpg.set_axis_limits(f"{tag}_y_axis", 0, max_freq * 1.1)  # Add 10% padding
            
            print("[DEBUG] Plot update successful")
        except Exception as e:
            print(f"[DEBUG] Error updating plot: {str(e)}")
            raise