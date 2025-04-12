# Network Traffic Analysis Tool with Real-time Packet Inspection and Visualization

This tool provides real-time network traffic analysis and visualization capabilities by intercepting network communication functions in target processes using Frida. It offers advanced packet inspection, entropy analysis, and pattern recognition features with an intuitive graphical interface.

The application enables security researchers and network analysts to:
- Intercept and monitor network traffic (send, sendto, recv, recvfrom) in real-time
- Visualize packet data with an interactive hexdump viewer
- Analyze packet entropy and byte frequency patterns
- Define and detect packet types using customizable criteria
- Mark and annotate regions of interest in captured packets
- Generate Kaitai Struct definitions for packet formats
- Save and load captured network sequences for offline analysis
- Compare binary data using advanced diffing algorithms

## Binary Diffing Capabilities

The tool includes advanced binary diffing algorithms for comparing and analyzing differences between captured packets:

- **Wavefront Alignment (WFA2)**: Fast and memory-efficient alignment for large binary sequences
- **Needleman-Wunsch**: Global alignment for comparing entire packet structures
- **Smith-Waterman**: Local alignment for finding similar regions in different packets

For detailed documentation on these algorithms and how to use them, see [Binary Diffing Algorithms](docs/biodiff_algorithms.md).

## Repository Structure
```
.
├── app.py                  # Main application entry point with DearPyGui UI and core logic
├── docs/                   # Documentation directory
│   └── biodiff_algorithms.md # Documentation for binary diffing algorithms
├── fridafuzzer_core/       # Core functionality modules
│   ├── biodiff_algorithms.py # Binary diffing algorithms implementation
│   ├── entropy_analyzer.py   # Entropy calculation and visualization components
│   ├── entropy_window.py     # Window for displaying entropy analysis results
│   ├── frequency_analyzer.py # Byte frequency analysis components
│   ├── frequency_window.py   # Window for displaying frequency analysis results
│   ├── frida_handler.py      # Frida integration for network function interception
│   ├── hexdump_widget.py     # Interactive hexadecimal data viewer widget
│   ├── ksy_editor_window.py  # Editor for Kaitai Struct YAML definitions
│   ├── ksy_manager.py        # Management of Kaitai Struct definitions
│   ├── marker_manager.py     # Management of data region markers
│   ├── packet_type_manager.py # Management of packet type definitions
│   └── widgets.py            # Common UI widget components
├── main.py                 # Standalone Frida script for testing/development
├── marker_types.json       # Configuration for marker types
├── packet_types.json       # Configuration for packet type definitions
├── requirements.txt        # Python package dependencies
└── tests/                  # Test files and test data
```

## Usage Instructions
### Prerequisites
- Python 3.8 or higher
- Frida target process must be running on the local machine
- Administrative privileges may be required for process attachment

Required Python packages:
```
dearpygui==1.10.1
frida==16.1.10
numpy>=1.24.0
scipy>=1.10.0
pyyaml>=6.0.1
kaitaistruct>=0.10
```

### Installation

> **See the full [Installation Guide](docs/installation.md) for detailed setup instructions, OS-specific notes, and troubleshooting.**

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create and activate a virtual environment:
```bash
# MacOS/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Quick Start
1. Start the application:
```bash
python app.py
```

2. Enter the target process name or PID in the input field.

3. Click "Start" to begin intercepting network traffic.

4. Use the hexdump viewer to inspect captured packets:
   - Select regions with the mouse
   - Right-click to access analysis options
   - Use markers to annotate regions of interest

### More Detailed Examples

1. Creating a custom packet type:
```python
# Via UI:
1. Click "New Packet Type"
2. Enter name and description
3. Set criteria (size, hex value, offset, callstack)
4. Click "Create"

# Via packet_types.json:
{
    "name": "custom_packet",
    "description": "Custom packet format",
    "criteria": {
        "packet_size": 154,
        "hex_value": "0x1234",
        "hex_offset": 0,
        "callstack": "protobuf"
    }
}
```

2. Analyzing packet entropy:
```python
# Select a region in the hexdump viewer
# Right-click -> Analyze Entropy
# Adjust window size using the slider
```

### Troubleshooting

1. Process Attachment Fails
- Error: "Unable to attach to process"
   - Verify process is running with `ps aux | grep <process-name>`
   - Check permissions (run as administrator/sudo)
   - Ensure Frida version matches target architecture

2. No Packets Captured
- Check if target process is making network calls
- Verify network functions are not stripped/obfuscated
- Enable debug logging:
  ```python
  import logging
  logging.basicConfig(level=logging.DEBUG)
  ```

3. Performance Issues
- Reduce window sizes for entropy/frequency analysis
- Clear packet history periodically
- Monitor memory usage with:
  ```python
  import psutil
  print(psutil.Process().memory_info().rss)
  ```

## Data Flow
The application intercepts network function calls using Frida, processes the captured data through various analysis components, and presents the results in real-time through the GUI.

```ascii
[Target Process] --> [Frida Interceptor] --> [Message Queue]
     |                                            |
     v                                           v
[Network Calls]                          [Packet Processor]
                                              |
                                              v
[GUI Components] <-- [Analysis Engine] <-- [Packet Store]
```

Component interactions:
1. Frida intercepts network functions in the target process
2. Captured data is sent to Python via message queue
3. PacketTypeManager identifies packet types based on criteria
4. HexdumpWidget displays packet data and handles user interaction
5. Analysis components (entropy, frequency) process selected data
6. MarkerManager tracks and persists annotations
7. Results are displayed in real-time through DearPyGui interface