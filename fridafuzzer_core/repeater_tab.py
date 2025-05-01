"""
Repeater Tab Module for Frida Network Interceptor
Handles packet replay functionality
"""

import dearpygui.dearpygui as dpg
import json
import time
import uuid
import socket
from typing import Dict, Any, List
from dataclasses import dataclass
from fridafuzzer_core.hexdump_widget import HexdumpWidget
from fridafuzzer_core.repeater_console_window import RepeaterConsoleWindow, LogLevel

# --- Repeater Data Structures ---
@dataclass
class RepeaterPacket:
    id: str                      # Unique identifier
    original_id: str             # ID of the original packet
    sequence_id: str             # ID of the sequence this packet belongs to
    hex_data: str                # Hex representation of packet data
    modified_hex_data: str       # Modified hex data (if edited)
    metadata: Dict[str, Any]     # Original packet metadata
    is_modified: bool            # Flag indicating if packet was modified
    created_at: float            # Timestamp when added to Repeater
    last_edited_at: float        # Timestamp of last edit
    replay_history: List[Dict]   # History of replays with timestamps and responses

@dataclass
class RepeaterSequence:
    id: str                      # Unique identifier
    name: str                    # User-friendly name
    packet_ids: List[str]        # IDs of packets in this sequence
    created_at: float            # Timestamp when created
    last_replayed_at: float      # Timestamp of last replay

# Global Repeater state
repeater_packets = {}            # Dictionary of RepeaterPacket objects by ID
repeater_sequences = {}          # Dictionary of RepeaterSequence objects by ID
repeater_connection_mode = "frida"  # "frida" or "direct"
repeater_connection_params = {    # Parameters for direct socket connection
    "host": "",
    "port": 0,
    "protocol": "TCP",
    "timeout": 5.0,
    "custom_params": {}
}
current_repeater_packet_id = None  # Currently selected packet
repeater_console_window = None    # Console window for logging
current_repeater_sequence_id = None  # Currently selected sequence
repeater_hexdump_widget = None
repeater_response_hexdump_widget = None

# Shared state
sequences = None
frida_handler = None
is_running = None
packet_type_manager = None

def initialize(shared_sequences, shared_frida_handler, shared_is_running, shared_packet_type_manager):
    """Initialize the repeater tab module with shared resources"""
    global sequences, frida_handler, is_running, packet_type_manager
    global repeater_console_window
    
    sequences = shared_sequences
    frida_handler = shared_frida_handler
    is_running = shared_is_running
    packet_type_manager = shared_packet_type_manager
    
    # Initialize repeater console window
    repeater_console_window = RepeaterConsoleWindow()
    
    # Load repeater state
    load_repeater_state()

def send_filtered_to_repeater():
    """
    Send all currently filtered packets to the Repeater tab as a new sequence.
    
    This function:
    1. Gets all currently filtered packets
    2. Creates a new repeater sequence
    3. Adds all filtered packets to this sequence
    
    Returns:
        str: ID of the new RepeaterSequence or None if failed
    """
    global repeater_sequences, repeater_packets
    
    # Get all currently filtered packets
    from fridafuzzer_core.main_view import apply_filters
    filtered_packets = apply_filters(sequences)
    
    if not filtered_packets:
        print("No filtered packets to send to Repeater")
        return None
    
    # Generate a unique ID for the repeater sequence
    repeater_sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    current_time = time.time()
    repeater_sequence = RepeaterSequence(
        id=repeater_sequence_id,
        name=f"Filtered Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=current_time,
        last_replayed_at=0  # Never replayed yet
    )
    
    # Add each filtered packet to the repeater
    for packet in filtered_packets:
        # Create a repeater packet for each filtered packet
        repeater_packet_id = send_to_repeater(packet['id'])
        if repeater_packet_id:
            # Update the sequence_id of the repeater packet
            repeater_packets[repeater_packet_id].sequence_id = repeater_sequence_id
            # Add the packet ID to the sequence
            repeater_sequence.packet_ids.append(repeater_packet_id)
    
    # Add the sequence to the repeater sequences dictionary
    repeater_sequences[repeater_sequence_id] = repeater_sequence
    
    # Save repeater state
    save_repeater_state()
    
    # Update the UI
    update_repeater_ui()
    
    return repeater_sequence_id

def send_to_repeater(packet_id):
    """
    Send a packet to the Repeater tab.
    Creates a new RepeaterPacket based on the original packet.
    
    Args:
        packet_id: ID of the packet to send to Repeater
    
    Returns:
        str: ID of the new RepeaterPacket or None if failed
    """
    global repeater_packets
    
    # Find the original packet
    original_packet = next((p for p in sequences if p['id'] == packet_id), None)
    if not original_packet:
        print(f"Packet with ID {packet_id} not found")
        return None
    
    # Create a unique ID for the repeater packet
    repeater_id = str(uuid.uuid4())
    
    # Create a new RepeaterPacket
    current_time = time.time()
    repeater_packet = RepeaterPacket(
        id=repeater_id,
        original_id=str(packet_id),
        sequence_id="",  # Not part of a sequence initially
        hex_data=original_packet['hex_data'],
        modified_hex_data=original_packet['hex_data'],  # Initially the same as original
        metadata={
            "function_name": original_packet.get('function_name', ''),
            "direction": original_packet.get('direction', 'send'),
            "socket_id": original_packet.get('socket_id', ''),
            "socket_info": original_packet.get('socket_info', ''),
            "buffer_length": original_packet.get('buffer_length', 0),
            "flags": original_packet.get('flags', ''),
            "packet_type": original_packet.get('packet_type', 'undefined'),
            "backtrace": original_packet.get('backtrace', []),
            "markers": original_packet.get('markers', [])
        },
        is_modified=False,
        created_at=current_time,
        last_edited_at=current_time,
        replay_history=[]
    )
    
    # Add to repeater packets dictionary
    repeater_packets[repeater_id] = repeater_packet
    
    # Save repeater state
    save_repeater_state()
    
    return repeater_id

def send_sequence_to_repeater(sequence_id):
    """
    Create a new sequence in the Repeater tab based on an existing sequence.
    
    Args:
        sequence_id: ID of the sequence to send to Repeater
    
    Returns:
        str: ID of the new RepeaterSequence or None if failed
    """
    global repeater_sequences, repeater_packets
    
    # Generate a unique ID for the repeater sequence
    repeater_sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    current_time = time.time()
    repeater_sequence = RepeaterSequence(
        id=repeater_sequence_id,
        name=f"Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=current_time,
        last_replayed_at=0  # Never replayed yet
    )
    
    # Find all packets in the original sequence
    sequence_packets = [p for p in sequences if p.get('sequence_id') == sequence_id]
    
    # Add each packet to the repeater
    for packet in sequence_packets:
        # Create a repeater packet for each packet in the sequence
        repeater_packet_id = send_to_repeater(packet['id'])
        if repeater_packet_id:
            # Update the sequence_id of the repeater packet
            repeater_packets[repeater_packet_id].sequence_id = repeater_sequence_id
            # Add the packet ID to the sequence
            repeater_sequence.packet_ids.append(repeater_packet_id)
    
    # Add the sequence to the repeater sequences dictionary
    repeater_sequences[repeater_sequence_id] = repeater_sequence
    
    # Save repeater state
    save_repeater_state()
    
    return repeater_sequence_id

def parse_socket_info(socket_info_string):
    """
    Parse socket information string into host and port.
    
    Args:
        socket_info_string: String in format "IP:PORT" or "[IPv6]:PORT"
    
    Returns:
        tuple: (host, port) or (None, None) if parsing fails
    """
    if not socket_info_string:
        return None, None
    
    try:
        # Handle IPv6 addresses which are enclosed in square brackets
        if socket_info_string.startswith('['):
            # Format: [IPv6]:PORT
            if ']' not in socket_info_string:
                return None, None
                
            # Split at the closing bracket + colon
            closing_bracket_pos = socket_info_string.find(']')
            if closing_bracket_pos == -1 or closing_bracket_pos + 1 >= len(socket_info_string) or socket_info_string[closing_bracket_pos + 1] != ':':
                return None, None
                
            host = socket_info_string[:closing_bracket_pos + 1]  # Include the brackets
            port_str = socket_info_string[closing_bracket_pos + 2:]  # Skip the ']:' part
            port = int(port_str)
            return host, port
        
        # Handle IPv4 addresses or hostnames
        elif ':' in socket_info_string:
            # Format: IP:PORT or hostname:PORT
            parts = socket_info_string.split(':')
            if len(parts) != 2:
                # If there are multiple colons and it's not an IPv6 address, it's invalid
                return None, None
                
            host = parts[0]
            port = int(parts[1])
            return host, port
    
    except (ValueError, IndexError) as e:
        print(f"Error parsing socket_info: {e}")
    
    return None, None

def replay_packet_frida(packet_id):
    """
    Replay a packet using Frida.
    
    Args:
        packet_id: ID of the RepeaterPacket to replay
    
    Returns:
        bool: True if successful, False otherwise
    """
    global repeater_packets, is_running, frida_handler
    
    # Check if packet exists
    if packet_id not in repeater_packets:
        print(f"Repeater packet with ID {packet_id} not found")
        return False
    
    # Get the packet
    packet = repeater_packets[packet_id]
    
    # Check if Frida is running
    if not is_running:
        print("Frida is not running")
        return False
    
    try:
        # Log the attempt
        repeater_console_window.add_log(
            LogLevel.INFO,
            f"Sending packet via Frida",
            packet_id=packet_id
        )
        
        # Get the hex data to send (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        
        # Get socket ID from metadata
        socket_id = packet.metadata.get("socket_id")
        if not socket_id:
            print("No socket ID found in packet metadata")
            repeater_console_window.add_log(
                LogLevel.ERROR,
                "No socket ID found in packet metadata",
                packet_id=packet_id
            )
            return False
        
        # Convert to bytes for sending
        if isinstance(hex_data, bytes):
            data = hex_data
        else:
            data = bytes.fromhex(hex_data)
            
        # Use Frida to send the packet
        result = frida_handler.replay_packet(socket_id, data)
        
        # Process result
        success = result.get("success", False)
        
        # Record the replay in history
        timestamp = time.time()
        replay_record = {
            "timestamp": timestamp,
            "mode": "frida",
            "success": success,
            "error": result.get("error"),
            "response": result.get("response_hex")
        }
        packet.replay_history.append(replay_record)
        
        # Update last replayed timestamp
        packet.last_edited_at = timestamp
        
        # Save state
        save_repeater_state()
        
        # Log the result
        if success:
            repeater_console_window.add_log(
                LogLevel.INFO,
                f"Packet sent successfully via Frida",
                packet_id=packet_id
            )
        else:
            repeater_console_window.add_log(
                LogLevel.WARNING,
                f"Failed to send packet via Frida: {result.get('error', 'Unknown error')}",
                packet_id=packet_id
            )
        
        return success
    
    except Exception as e:
        print(f"Error replaying packet with Frida: {e}")
        import traceback
        print(traceback.format_exc())
        
        # Log the error
        repeater_console_window.add_log(
            LogLevel.ERROR,
            f"Error replaying packet with Frida: {str(e)}",
            packet_id=packet_id
        )
        
        # Record error in history
        replay_record = {
            "timestamp": time.time(),
            "mode": "frida",
            "success": False,
            "error": str(e)
        }
        packet.replay_history.append(replay_record)
        save_repeater_state()
        
        return False

def replay_packet_direct(packet_id, connection_params):
    """
    Replay a packet using direct socket connection.
    
    Args:
        packet_id: ID of the RepeaterPacket to replay
        connection_params: Dictionary with connection parameters
    
    Returns:
        bool: True if successful, False otherwise
    """
    global repeater_packets
    
    # Check if packet exists
    if packet_id not in repeater_packets:
        print(f"Repeater packet with ID {packet_id} not found")
        return False
    
    # Get the packet
    packet = repeater_packets[packet_id]
    
    try:
        # Log the attempt
        repeater_console_window.add_log(
            LogLevel.INFO,
            f"Sending packet via direct connection",
            packet_id=packet_id
        )
        
        # Get the hex data to send (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        
        # Convert to bytes for sending
        if isinstance(hex_data, bytes):
            data = hex_data
        else:
            data = bytes.fromhex(hex_data)
        
        # Extract connection parameters
        host = connection_params.get("host", "")
        port = connection_params.get("port", 0)
        protocol = connection_params.get("protocol", "TCP")
        timeout = connection_params.get("timeout", 5.0)
        
        # If host/port not provided, try to parse from socket_info
        if not host or not port:
            socket_info = packet.metadata.get("socket_info", "")
            if socket_info:
                host, port = parse_socket_info(socket_info)
                
            if not host or not port:
                print("Invalid connection parameters: host and port are required")
                repeater_console_window.add_log(
                    LogLevel.ERROR,
                    "Invalid connection parameters: host and port are required",
                    packet_id=packet_id
                )
                return False
        
        # Create socket based on protocol
        if protocol.upper() == "TCP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol.upper() == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            print(f"Unsupported protocol: {protocol}")
            repeater_console_window.add_log(
                LogLevel.ERROR,
                f"Unsupported protocol: {protocol}",
                packet_id=packet_id
            )
            return False
        
        # Set timeout
        sock.settimeout(timeout)
        
        response = None
        timestamp = time.time()
        
        try:
            # Connect and send data for TCP
            if protocol.upper() == "TCP":
                sock.connect((host, port))
                sock.sendall(data)
                
                # Try to receive response with timeout
                response_chunks = []
                start_time = time.time()
                
                while time.time() - start_time < timeout:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:  # Connection closed
                            break
                        response_chunks.append(chunk)
                    except socket.timeout:
                        # No more data available
                        break
                
                if response_chunks:
                    response = b''.join(response_chunks)
            
            # Send data for UDP
            elif protocol.upper() == "UDP":
                sock.sendto(data, (host, port))
                
                # Try to receive response
                try:
                    response, addr = sock.recvfrom(4096)
                except socket.timeout:
                    # No response within timeout is not an error
                    pass
            
            # Record successful replay in history
            replay_record = {
                "timestamp": timestamp,
                "mode": "direct",
                "protocol": protocol,
                "host": host,
                "port": port,
                "success": True,
                "response": response.hex() if response and isinstance(response, bytes) else None,
                "response_hex": response.hex() if response and isinstance(response, bytes) else None
            }
            packet.replay_history.append(replay_record)
            
            # Update last replayed timestamp
            packet.last_edited_at = timestamp
            
            # Save state
            save_repeater_state()
            
            # Log the success
            response_size = len(response) if response else 0
            repeater_console_window.add_log(
                LogLevel.INFO,
                f"Packet sent successfully via {protocol}. Response size: {response_size} bytes",
                packet_id=packet_id
            )
            
            return True
            
        finally:
            # Always close the socket
            sock.close()
    
    except Exception as e:
        print(f"Error replaying packet with direct connection: {e}")
        import traceback
        print(traceback.format_exc())
        
        # Log the error
        repeater_console_window.add_log(
            LogLevel.ERROR,
            f"Error replaying packet with direct connection: {str(e)}",
            packet_id=packet_id
        )
        
        # Record error in history
        replay_record = {
            "timestamp": time.time(),
            "mode": "direct",
            "protocol": connection_params.get("protocol", "TCP"),
            "host": connection_params.get("host", ""),
            "port": connection_params.get("port", 0),
            "success": False,
            "error": str(e)
        }
        packet.replay_history.append(replay_record)
        save_repeater_state()
        
        return False


def replay_sequence_frida(sequence_id):
    """
    Replay a sequence of packets using Frida.
    
    Args:
        sequence_id: ID of the RepeaterSequence to replay
    
    Returns:
        list: Results of each packet replay operation
    """
    global repeater_sequences, is_running
    
    # Check if sequence exists
    if sequence_id not in repeater_sequences:
        print(f"Repeater sequence with ID {sequence_id} not found")
        repeater_console_window.add_log(
            LogLevel.ERROR,
            f"Sequence with ID {sequence_id} not found",
            sequence_id=sequence_id
        )
        return [{"success": False, "error": f"Sequence with ID {sequence_id} not found"}]
    
    # Check if Frida is running
    if not is_running:
        print("Frida is not running")
        repeater_console_window.add_log(
            LogLevel.ERROR,
            "Cannot replay sequence: Frida is not running",
            sequence_id=sequence_id
        )
        return [{"success": False, "error": "Frida is not running"}]
    
    # Get the sequence
    sequence = repeater_sequences[sequence_id]
    results = []
    
    # Log the start of sequence replay
    repeater_console_window.add_log(
        LogLevel.INFO,
        f"Starting replay of sequence '{sequence.name}' with {len(sequence.packet_ids)} packets via Frida",
        sequence_id=sequence_id
    )
    
    # Replay each packet in the sequence
    for packet_id in sequence.packet_ids:
        result = replay_packet_frida(packet_id)
        results.append({"success": result, "packet_id": packet_id})
        
        # Small delay between packets
        time.sleep(0.1)
    
    # Update last replayed timestamp
    sequence.last_replayed_at = time.time()
    
    # Save state
    save_repeater_state()
    
    # Log completion of sequence replay
    success_count = sum(1 for r in results if r["success"])
    repeater_console_window.add_log(
        LogLevel.INFO,
        f"Completed replay of sequence '{sequence.name}': {success_count}/{len(results)} packets successful",
        sequence_id=sequence_id
    )
    
    return results

def replay_sequence_direct(sequence_id, connection_params):
    """
    Replay a sequence of packets using direct socket connection.
    
    Args:
        sequence_id: ID of the RepeaterSequence to replay
        connection_params: Dictionary with connection parameters
    
    Returns:
        list: Results of each packet replay operation
    """
    global repeater_sequences
    
    # Check if sequence exists
    if sequence_id not in repeater_sequences:
        print(f"Repeater sequence with ID {sequence_id} not found")
        repeater_console_window.add_log(
            LogLevel.ERROR,
            f"Sequence with ID {sequence_id} not found",
            sequence_id=sequence_id
        )
        return [{"success": False, "error": f"Sequence with ID {sequence_id} not found"}]
    
    # Get the sequence
    sequence = repeater_sequences[sequence_id]
    results = []
    
    # Validate connection parameters
    if not connection_params.get("host") and not connection_params.get("port"):
        # We'll try to get connection info from each packet, so continue
        repeater_console_window.add_log(
            LogLevel.WARNING,
            "No host/port specified in connection parameters, will try to use packet-specific connection info",
            sequence_id=sequence_id
        )
    
    # Log the start of sequence replay
    protocol = connection_params.get("protocol", "TCP")
    repeater_console_window.add_log(
        LogLevel.INFO,
        f"Starting replay of sequence '{sequence.name}' with {len(sequence.packet_ids)} packets via direct {protocol} connection",
        sequence_id=sequence_id
    )
    
    # Replay each packet in the sequence
    for packet_id in sequence.packet_ids:
        result = replay_packet_direct(packet_id, connection_params)
        results.append({"success": result, "packet_id": packet_id})
        
        # Small delay between packets
        time.sleep(0.1)
    
    # Update last replayed timestamp
    sequence.last_replayed_at = time.time()
    
    # Save state
    save_repeater_state()
    
    # Log completion of sequence replay
    success_count = sum(1 for r in results if r["success"])
    repeater_console_window.add_log(
        LogLevel.INFO,
        f"Completed replay of sequence '{sequence.name}': {success_count}/{len(results)} packets successful",
        sequence_id=sequence_id
    )
    
    return results

def save_repeater_state():
    """Save repeater state to JSON file"""
    try:
        # Convert RepeaterPacket objects to dictionaries
        packets_dict = {}
        for packet_id, packet in repeater_packets.items():
            # Ensure hex_data and modified_hex_data are strings
            hex_data = packet.hex_data
            if isinstance(hex_data, bytes):
                hex_data = hex_data.hex()
                
            modified_hex_data = packet.modified_hex_data
            if isinstance(modified_hex_data, bytes):
                modified_hex_data = modified_hex_data.hex()
            
            # Process replay history to ensure all bytes are converted to strings
            processed_history = []
            for entry in packet.replay_history:
                processed_entry = entry.copy()
                # Convert response to hex string if it's bytes
                if 'response' in processed_entry and isinstance(processed_entry['response'], bytes):
                    processed_entry['response'] = processed_entry['response'].hex()
                processed_history.append(processed_entry)
            
            packets_dict[packet_id] = {
                "id": packet.id,
                "original_id": packet.original_id,
                "sequence_id": packet.sequence_id,
                "hex_data": hex_data,
                "modified_hex_data": modified_hex_data,
                "metadata": packet.metadata,
                "is_modified": packet.is_modified,
                "created_at": packet.created_at,
                "last_edited_at": packet.last_edited_at,
                "replay_history": processed_history
            }
        
        # Convert RepeaterSequence objects to dictionaries
        sequences_dict = {}
        for seq_id, sequence in repeater_sequences.items():
            sequences_dict[seq_id] = {
                "id": sequence.id,
                "name": sequence.name,
                "packet_ids": sequence.packet_ids,
                "created_at": sequence.created_at,
                "last_replayed_at": sequence.last_replayed_at
            }
        
        # Create state dictionary
        repeater_state = {
            "packets": packets_dict,
            "sequences": sequences_dict,
            "connection_mode": repeater_connection_mode,
            "connection_params": repeater_connection_params,
            "current_packet_id": current_repeater_packet_id,
            "current_sequence_id": current_repeater_sequence_id
        }
        
        # Save to file
        with open('repeater_state.json', 'w') as f:
            json.dump(repeater_state, f, indent=2)
        
        return True
    
    except Exception as e:
        print(f"Error saving repeater state: {e}")
        import traceback
        print(traceback.format_exc())
        return False

def load_repeater_state():
    """Load repeater state from JSON file"""
    global repeater_packets, repeater_sequences, repeater_connection_mode
    global repeater_connection_params, current_repeater_packet_id, current_repeater_sequence_id
    
    try:
        with open('repeater_state.json', 'r') as f:
            repeater_state = json.load(f)
        
        # Load packets
        packets_dict = repeater_state.get("packets", {})
        repeater_packets = {}
        for packet_id, packet_data in packets_dict.items():
            repeater_packets[packet_id] = RepeaterPacket(
                id=packet_data["id"],
                original_id=packet_data["original_id"],
                sequence_id=packet_data["sequence_id"],
                hex_data=packet_data["hex_data"],
                modified_hex_data=packet_data["modified_hex_data"],
                metadata=packet_data["metadata"],
                is_modified=packet_data["is_modified"],
                created_at=packet_data["created_at"],
                last_edited_at=packet_data["last_edited_at"],
                replay_history=packet_data["replay_history"]
            )
        
        # Load sequences
        sequences_dict = repeater_state.get("sequences", {})
        repeater_sequences = {}
        for seq_id, seq_data in sequences_dict.items():
            repeater_sequences[seq_id] = RepeaterSequence(
                id=seq_data["id"],
                name=seq_data["name"],
                packet_ids=seq_data["packet_ids"],
                created_at=seq_data["created_at"],
                last_replayed_at=seq_data["last_replayed_at"]
            )
        
        # Load other state
        repeater_connection_mode = repeater_state.get("connection_mode", "frida")
        repeater_connection_params = repeater_state.get("connection_params", {
            "host": "",
            "port": 0,
            "protocol": "TCP",
            "timeout": 5.0,
            "custom_params": {}
        })
        current_repeater_packet_id = repeater_state.get("current_packet_id")
        current_repeater_sequence_id = repeater_state.get("current_sequence_id")
        
        return True
    
    except (FileNotFoundError, json.JSONDecodeError):
        # Initialize with empty state if file doesn't exist or is invalid
        repeater_packets = {}
        repeater_sequences = {}
        repeater_connection_mode = "frida"
        repeater_connection_params = {
            "host": "",
            "port": 0,
            "protocol": "TCP",
            "timeout": 5.0,
            "custom_params": {}
        }
        current_repeater_packet_id = None
        current_repeater_sequence_id = None
        return False
    
    except Exception as e:
        print(f"Error loading repeater state: {e}")
        import traceback
        print(traceback.format_exc())
        return False

def update_repeater_packet_regions(sequence_id, regions):
    """Update markers for a repeater packet"""
    global repeater_packets
    
    # Check if packet exists
    if sequence_id not in repeater_packets:
        return
    
    # Get the packet
    packet = repeater_packets[sequence_id]
    
    # Update markers
    packet.metadata["markers"] = [
        {
            'start_offset': r.start_offset,
            'end_offset': r.end_offset,
            'tag_name': r.tag_name,
            'tag_type': r.tag_type,
            'properties': r.properties
        }
        for r in regions
    ]
    
    # Mark as modified
    packet.is_modified = True
    packet.last_edited_at = time.time()
    
    # Save repeater state
    save_repeater_state()

def update_repeater_packet_data(sequence_id, hex_data):
    """Update the hex data of a repeater packet"""
    global repeater_packets
    
    # Check if packet exists
    if sequence_id not in repeater_packets:
        return
    
    # Get the packet
    packet = repeater_packets[sequence_id]
    
    # Update hex data - ensure it's a string
    if isinstance(hex_data, bytes):
        packet.modified_hex_data = hex_data.hex()
    else:
        packet.modified_hex_data = hex_data
    
    # Mark as modified
    packet.is_modified = True
    packet.last_edited_at = time.time()
    
    # Save repeater state
    save_repeater_state()

def update_repeater_ui():
    """Update the Repeater UI with the current state"""
    try:
        # Update sequences list
        update_repeater_sequences_list()
        
        # Update connection mode radio button
        if repeater_connection_mode == "frida":
            dpg.set_value("repeater_connection_mode", 0)  # Frida
            dpg.configure_item("repeater_direct_connection_settings", show=False)
        else:
            dpg.set_value("repeater_connection_mode", 1)  # Direct Socket
            dpg.configure_item("repeater_direct_connection_settings", show=True)
        
        # Update connection settings inputs
        dpg.set_value("repeater_host_input", repeater_connection_params["host"])
        dpg.set_value("repeater_port_input", repeater_connection_params["port"])
        dpg.set_value("repeater_protocol_input", repeater_connection_params["protocol"])
        dpg.set_value("repeater_timeout_input", repeater_connection_params["timeout"])
        
        # If there's a current packet selected, update the editor
        if current_repeater_packet_id and current_repeater_packet_id in repeater_packets:
            select_repeater_packet(None, None, current_repeater_packet_id)
        
        # If there's a current sequence selected, update the sequence view
        if current_repeater_sequence_id and current_repeater_sequence_id in repeater_sequences:
            select_repeater_sequence(None, None, current_repeater_sequence_id)
    except Exception as e:
        print(f"Error updating repeater UI: {e}")
        import traceback
        print(traceback.format_exc())

def update_repeater_sequences_list():
    """Update the list of sequences in the Repeater UI"""
    try:
        # Clear existing items
        dpg.delete_item("repeater_sequences_list", children_only=True)
        
        # Add each sequence to the list
        for seq_id, sequence in repeater_sequences.items():
            # Create a button for each sequence
            btn_id = dpg.add_button(
                label=f"{sequence.name} ({len(sequence.packet_ids)} packets)",
                callback=select_repeater_sequence,
                user_data=seq_id,
                width=-1,
                parent="repeater_sequences_list"
            )
            
            # Highlight the currently selected sequence
            if seq_id == current_repeater_sequence_id:
                dpg.bind_item_theme(btn_id, "selected_item_theme")
    except Exception as e:
        print(f"Error updating repeater sequences list: {e}")
        import traceback
        print(traceback.format_exc())

def update_repeater_packets_list():
    """Update the list of packets in the currently selected sequence"""
    try:
        # Clear existing items
        dpg.delete_item("repeater_packets_list", children_only=True)
        
        # If no sequence is selected, return
        if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
            return
        
        # Get the current sequence
        sequence = repeater_sequences[current_repeater_sequence_id]
        
        # Add each packet in the sequence to the list
        for packet_id in sequence.packet_ids:
            if packet_id in repeater_packets:
                packet = repeater_packets[packet_id]
                
                # Get packet metadata
                packet_type = packet.metadata.get("packet_type", "undefined")
                buffer_length = packet.metadata.get("buffer_length", 0)
                
                # Create a button for each packet
                btn_id = dpg.add_button(
                    label=f"{packet_type} ({buffer_length} bytes)",
                    callback=select_repeater_packet,
                    user_data=packet_id,
                    width=-1,
                    parent="repeater_packets_list"
                )
                
                # Highlight the currently selected packet
                if packet_id == current_repeater_packet_id:
                    dpg.bind_item_theme(btn_id, "selected_item_theme")
    except Exception as e:
        print(f"Error updating repeater packets list: {e}")
        import traceback
        print(traceback.format_exc())

def select_repeater_sequence(sender, app_data, user_data):
    """Handle selection of a sequence in the Repeater UI"""
    global current_repeater_sequence_id
    
    # Set the current sequence ID
    current_repeater_sequence_id = user_data
    
    # Enable the sequence replay button
    dpg.configure_item("replay_sequence_btn", enabled=True)
    dpg.configure_item("delete_repeater_sequence_btn", enabled=True)
    
    # Update the packets list
    update_repeater_packets_list()
    
    # Save repeater state
    save_repeater_state()

def select_repeater_packet(sender, app_data, user_data):
    """Handle selection of a packet in the Repeater UI"""
    global current_repeater_packet_id
    
    # Set the current packet ID
    current_repeater_packet_id = user_data
    
    # Get the packet
    packet = repeater_packets[user_data]
    
    # Update the packet editor
    try:
        # Get the hex data to display (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        
        # Convert hex_data to bytes, handling both string and bytes types
        if isinstance(hex_data, bytes):
            data = hex_data
        else:
            data = bytes.fromhex(hex_data)
        
        # Update the hexdump widget
        repeater_hexdump_widget.set_data(data, user_data, packet.metadata.get("markers", []))
        
        # Update the packet editor title
        packet_type = packet.metadata.get("packet_type", "undefined")
        buffer_length = packet.metadata.get("buffer_length", 0)
        dpg.set_value("repeater_packet_editor_title", f"Packet Editor - {packet_type} ({buffer_length} bytes)")
        
        # Enable the packet replay button
        dpg.configure_item("replay_packet_btn", enabled=True)
        
        # If there's a response in the history, display it
        if packet.replay_history:
            last_replay = packet.replay_history[-1]
            if last_replay.get("response"):
                try:
                    response_data = bytes.fromhex(last_replay["response"])
                    repeater_response_hexdump_widget.set_data(response_data, None)
                    
                    # Update response title with timestamp
                    import datetime
                    timestamp = datetime.datetime.fromtimestamp(last_replay["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    dpg.set_value("repeater_response_title", f"Response - {timestamp}")
                except ValueError:
                    print("Invalid hex data in response")
    except Exception as e:
        print(f"Error selecting repeater packet: {e}")
        import traceback
        print(traceback.format_exc())
    
    # Save repeater state
    save_repeater_state()

def set_repeater_connection_mode(sender, app_data):
    """Set the connection mode for the Repeater"""
    global repeater_connection_mode
    
    # Set the connection mode based on radio button value
    if app_data == 0:
        repeater_connection_mode = "frida"
        dpg.configure_item("repeater_direct_connection_settings", show=False)
    else:
        repeater_connection_mode = "direct"
        dpg.configure_item("repeater_direct_connection_settings", show=True)
    
    # Save repeater state
    save_repeater_state()

def update_repeater_connection_settings(sender, app_data):
    """Update the connection settings for direct socket mode"""
    global repeater_connection_params
    
    # Get values from UI
    host = dpg.get_value("repeater_host_input")
    port = dpg.get_value("repeater_port_input")
    protocol = dpg.get_value("repeater_protocol_input")
    timeout = dpg.get_value("repeater_timeout_input")
    
    # Update connection params
    repeater_connection_params["host"] = host
    repeater_connection_params["port"] = port
    repeater_connection_params["protocol"] = protocol
    repeater_connection_params["timeout"] = timeout
    
    # Save repeater state
    save_repeater_state()

def create_new_repeater_sequence():
    """Create a new empty sequence in the Repeater"""
    global repeater_sequences
    
    # Generate a unique ID
    sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    sequence = RepeaterSequence(
        id=sequence_id,
        name=f"Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=time.time(),
        last_replayed_at=0
    )
    
    # Add to sequences dictionary
    repeater_sequences[sequence_id] = sequence
    
    # Update UI
    update_repeater_sequences_list()
    
    # Select the new sequence
    select_repeater_sequence(None, None, sequence_id)
    
    # Save repeater state
    save_repeater_state()

def delete_repeater_sequence():
    """Delete the currently selected sequence"""
    global repeater_sequences, current_repeater_sequence_id, current_repeater_packet_id
    
    # Check if a sequence is selected
    if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
        return
    
    # Get the sequence
    sequence = repeater_sequences[current_repeater_sequence_id]
    
    # Remove all packets in the sequence
    for packet_id in sequence.packet_ids:
        if packet_id in repeater_packets:
            del repeater_packets[packet_id]
    
    # Remove the sequence
    del repeater_sequences[current_repeater_sequence_id]
    
    # Reset current selections
    if current_repeater_sequence_id == current_repeater_sequence_id:
        current_repeater_sequence_id = None
    if current_repeater_packet_id in sequence.packet_ids:
        current_repeater_packet_id = None
    
    # Update UI
    update_repeater_sequences_list()
    update_repeater_packets_list()
    
    # Disable buttons
    dpg.configure_item("replay_sequence_btn", enabled=False)
    dpg.configure_item("delete_repeater_sequence_btn", enabled=False)
    
    # Save repeater state
    save_repeater_state()

def replay_current_repeater_packet():
    """Replay the currently selected packet"""
    # Check if a packet is selected
    if not current_repeater_packet_id or current_repeater_packet_id not in repeater_packets:
        return
    
    # Replay based on connection mode
    if repeater_connection_mode == "frida":
        success = replay_packet_frida(current_repeater_packet_id)
    else:
        # Validate connection parameters before direct replay
        if not repeater_connection_params.get("host") or not repeater_connection_params.get("port"):
            print("Please set valid host and port in connection settings before replaying")
            # Show a message to the user
            dpg.set_value("status", "Error: Please set valid host and port in connection settings")
            return
        success = replay_packet_direct(current_repeater_packet_id, repeater_connection_params)
    
    # Update UI after replay
    if success:
        # Refresh the packet view to show the response
        select_repeater_packet(None, None, current_repeater_packet_id)

def replay_current_repeater_sequence():
    """Replay the currently selected sequence"""
    # Check if a sequence is selected
    if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
        return
    
    # Replay based on connection mode
    if repeater_connection_mode == "frida":
        success = replay_sequence_frida(current_repeater_sequence_id)
    else:
        # Validate connection parameters before direct replay
        if not repeater_connection_params.get("host") or not repeater_connection_params.get("port"):
            print("Please set valid host and port in connection settings before replaying")
            # Show a message to the user
            dpg.set_value("status", "Error: Please set valid host and port in connection settings")
            return
        success = replay_sequence_direct(current_repeater_sequence_id, repeater_connection_params)
    
    # Update UI after replay
    if success and current_repeater_packet_id:
        # Refresh the packet view to show the response
        select_repeater_packet(None, None, current_repeater_packet_id)

def setup_repeater_tab_ui():
    """Set up the repeater tab UI components"""
    global repeater_hexdump_widget, repeater_response_hexdump_widget
    
    # Main layout with three panels
    with dpg.group(horizontal=True, parent="repeater_tab"):
        # Left panel - Sequences Panel
        with dpg.child_window(width=300, height=500, tag="repeater_sequences_panel"):
            dpg.add_text("Repeater Sequences")
            
            # Add buttons for sequence management
            with dpg.group(horizontal=True):
                dpg.add_button(label="New Sequence", callback=lambda s, a: create_new_repeater_sequence(), tag="new_repeater_sequence_btn")
                dpg.add_button(label="Delete", callback=lambda s, a: delete_repeater_sequence(), tag="delete_repeater_sequence_btn", enabled=False)
            
            # Sequences list
            dpg.add_text("Sequences:")
            dpg.add_child_window(tag="repeater_sequences_list", height=150)
            
            # Packets in selected sequence
            dpg.add_separator()
            dpg.add_text("Packets in Sequence:")
            dpg.add_child_window(tag="repeater_packets_list", height=250)
        
        # Middle panel - Packet Editor Panel
        with dpg.child_window(width=500, height=500, tag="repeater_packet_editor_panel"):
            dpg.add_text("Packet Editor", tag="repeater_packet_editor_title")
            
            # Create hexdump widget for packet editing
            repeater_hexdump_widget = HexdumpWidget(
                packet_type_manager=packet_type_manager,
                tag="repeater_hexdump_view",
                width=480,
                height=450,
                on_regions_changed=update_repeater_packet_regions,
                on_data_changed=update_repeater_packet_data,
                marker_editor_window_tag="repeater_marker_editor_window",
                marker_editor_tag_suffix="_repeater"
            )
        
        # Right panel - Response Panel
        with dpg.child_window(width=400, height=500, tag="repeater_response_panel"):
            dpg.add_text("Response", tag="repeater_response_title")
            
            # Response hexdump widget
            repeater_response_hexdump_widget = HexdumpWidget(
                packet_type_manager=packet_type_manager,
                tag="repeater_response_hexdump_view",
                width=380,
                height=450,
                marker_editor_window_tag="repeater_response_marker_editor_window",
                marker_editor_tag_suffix="_repeater_resp"
            )
    
    # Bottom panel - Connection Controls Panel
    with dpg.child_window(height=150, parent="repeater_tab", tag="repeater_connection_panel"):
        with dpg.group(horizontal=True):
            # Connection mode selection
            dpg.add_text("Connection Mode:")
            dpg.add_radio_button(
                items=["Frida", "Direct Socket"],
                horizontal=True,
                callback=set_repeater_connection_mode,
                tag="repeater_connection_mode"
            )
            
            # Replay buttons
            dpg.add_button(label="Replay Packet", callback=lambda s, a: replay_current_repeater_packet(), tag="replay_packet_btn", enabled=False)
            dpg.add_button(label="Replay Sequence", callback=lambda s, a: replay_current_repeater_sequence(), tag="replay_sequence_btn", enabled=False)
            dpg.add_button(label="Toggle Console", callback=lambda s, a: repeater_console_window.toggle_visibility(), tag="toggle_console_btn")
        
        # Direct connection settings (hidden by default)
        with dpg.group(tag="repeater_direct_connection_settings", show=False):
            with dpg.group(horizontal=True):
                dpg.add_input_text(label="Host", tag="repeater_host_input", width=150, default_value=repeater_connection_params["host"])
                dpg.add_input_int(label="Port", tag="repeater_port_input", width=100, default_value=repeater_connection_params["port"])
                dpg.add_combo(label="Protocol", items=["TCP", "UDP"], default_value=repeater_connection_params["protocol"], tag="repeater_protocol_input", width=100)
                dpg.add_input_float(label="Timeout (s)", tag="repeater_timeout_input", width=100, default_value=repeater_connection_params["timeout"])
            
            # Apply connection settings button
            dpg.add_button(label="Apply Connection Settings", callback=update_repeater_connection_settings, tag="apply_connection_settings_btn")

def update_repeater_packet_data(sequence_id, hex_data):
    """Update the hex data of a repeater packet"""
    global repeater_packets
    
    # Check if packet exists
    if sequence_id not in repeater_packets:
        return
    
    # Get the packet
    packet = repeater_packets[sequence_id]
    
    # Update hex data - ensure it's a string
    if isinstance(hex_data, bytes):
        packet.modified_hex_data = hex_data.hex()
    else:
        packet.modified_hex_data = hex_data
    
    # Mark as modified
    packet.is_modified = True
    packet.last_edited_at = time.time()
    
    # Save repeater state
    save_repeater_state()

def update_repeater_ui():
    """Update the Repeater UI with the current state"""
    try:
        # Update sequences list
        update_repeater_sequences_list()
        
        # Update connection mode radio button
        if repeater_connection_mode == "frida":
            dpg.set_value("repeater_connection_mode", 0)  # Frida
            dpg.configure_item("repeater_direct_connection_settings", show=False)
        else:
            dpg.set_value("repeater_connection_mode", 1)  # Direct Socket
            dpg.configure_item("repeater_direct_connection_settings", show=True)
        
        # Update connection settings inputs
        dpg.set_value("repeater_host_input", repeater_connection_params["host"])
        dpg.set_value("repeater_port_input", repeater_connection_params["port"])
        dpg.set_value("repeater_protocol_input", repeater_connection_params["protocol"])
        dpg.set_value("repeater_timeout_input", repeater_connection_params["timeout"])
        
        # If there's a current packet selected, update the editor
        if current_repeater_packet_id and current_repeater_packet_id in repeater_packets:
            select_repeater_packet(None, None, current_repeater_packet_id)
        
        # If there's a current sequence selected, update the sequence view
        if current_repeater_sequence_id and current_repeater_sequence_id in repeater_sequences:
            select_repeater_sequence(None, None, current_repeater_sequence_id)
    except Exception as e:
        print(f"Error updating repeater UI: {e}")
def update_repeater_sequences_list():
    """Update the list of sequences in the Repeater UI"""
    try:
        # Clear existing items
        dpg.delete_item("repeater_sequences_list", children_only=True)
        
        # Add each sequence to the list
        for seq_id, sequence in repeater_sequences.items():
            # Create a button for each sequence
            btn_id = dpg.add_button(
                label=f"{sequence.name} ({len(sequence.packet_ids)} packets)",
                callback=select_repeater_sequence,
                user_data=seq_id,
                width=-1,
                parent="repeater_sequences_list"
            )
            
            # Highlight the currently selected sequence
            if seq_id == current_repeater_sequence_id:
                dpg.bind_item_theme(btn_id, "selected_item_theme")
    except Exception as e:
        print(f"Error updating repeater sequences list: {e}")
        import traceback
        print(traceback.format_exc())

def update_repeater_packets_list():
    """Update the list of packets in the currently selected sequence"""
    try:
        # Clear existing items
        dpg.delete_item("repeater_packets_list", children_only=True)
        
        # If no sequence is selected, return
        if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
            return
        
        # Get the current sequence
        sequence = repeater_sequences[current_repeater_sequence_id]
        
        # Add each packet in the sequence to the list
        for packet_id in sequence.packet_ids:
            if packet_id in repeater_packets:
                packet = repeater_packets[packet_id]
                
                # Get packet metadata
                packet_type = packet.metadata.get("packet_type", "undefined")
                buffer_length = packet.metadata.get("buffer_length", 0)
                
                # Create a button for each packet
                btn_id = dpg.add_button(
                    label=f"{packet_type} ({buffer_length} bytes)",
                    callback=select_repeater_packet,
                    user_data=packet_id,
                    width=-1,
                    parent="repeater_packets_list"
                )
                
                # Highlight the currently selected packet
                if packet_id == current_repeater_packet_id:
                    dpg.bind_item_theme(btn_id, "selected_item_theme")
    except Exception as e:
        print(f"Error updating repeater packets list: {e}")
        import traceback
        print(traceback.format_exc())
def select_repeater_sequence(sender, app_data, user_data):
    """Handle selection of a sequence in the Repeater UI"""
    global current_repeater_sequence_id
    
    # Set the current sequence ID
    current_repeater_sequence_id = user_data
    
    # Enable the sequence replay button
    dpg.configure_item("replay_sequence_btn", enabled=True)
    dpg.configure_item("delete_repeater_sequence_btn", enabled=True)
    
    # Update the packets list
    update_repeater_packets_list()
    
    # Save repeater state
    save_repeater_state()

def select_repeater_packet(sender, app_data, user_data):
    """Handle selection of a packet in the Repeater UI"""
    global current_repeater_packet_id
    
    # Set the current packet ID
    current_repeater_packet_id = user_data
    
    # Get the packet
    packet = repeater_packets[user_data]
    
    # Update the packet editor
    try:
        # Get the hex data to display (use modified if available)
        hex_data = packet.modified_hex_data if packet.is_modified else packet.hex_data
        
        # Convert hex_data to bytes, handling both string and bytes types
        if isinstance(hex_data, bytes):
            data = hex_data
        else:
            data = bytes.fromhex(hex_data)
        
        # Update the hexdump widget
        repeater_hexdump_widget.set_data(data, user_data, packet.metadata.get("markers", []))
        
        # Update the packet editor title
        packet_type = packet.metadata.get("packet_type", "undefined")
        buffer_length = packet.metadata.get("buffer_length", 0)
        dpg.set_value("repeater_packet_editor_title", f"Packet Editor - {packet_type} ({buffer_length} bytes)")
        
        # Enable the packet replay button
        dpg.configure_item("replay_packet_btn", enabled=True)
        
        # If there's a response in the history, display it
        if packet.replay_history:
            last_replay = packet.replay_history[-1]
            if last_replay.get("response"):
                try:
                    response_data = bytes.fromhex(last_replay["response"])
                    repeater_response_hexdump_widget.set_data(response_data, None)
                    
                    # Update response title with timestamp
                    import datetime
                    timestamp = datetime.datetime.fromtimestamp(last_replay["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    dpg.set_value("repeater_response_title", f"Response - {timestamp}")
                except ValueError:
                    print("Invalid hex data in response")
    except Exception as e:
        print(f"Error selecting repeater packet: {e}")
        import traceback
        print(traceback.format_exc())
    
    # Save repeater state
    save_repeater_state()

def set_repeater_connection_mode(sender, app_data):
    """Set the connection mode for the Repeater"""
    global repeater_connection_mode
    
    # Set the connection mode based on radio button value
    if app_data == 0:
        repeater_connection_mode = "frida"
        dpg.configure_item("repeater_direct_connection_settings", show=False)
    else:
        repeater_connection_mode = "direct"
        dpg.configure_item("repeater_direct_connection_settings", show=True)
    
    # Save repeater state
    save_repeater_state()

def update_repeater_connection_settings(sender, app_data):
    """Update the connection settings for direct socket mode"""
    global repeater_connection_params
    
    # Get values from UI
    host = dpg.get_value("repeater_host_input")
    port = dpg.get_value("repeater_port_input")
    protocol = dpg.get_value("repeater_protocol_input")
    timeout = dpg.get_value("repeater_timeout_input")
    
    # Update connection params
    repeater_connection_params["host"] = host
    repeater_connection_params["port"] = port
    repeater_connection_params["protocol"] = protocol
    repeater_connection_params["timeout"] = timeout
    
    # Save repeater state
    save_repeater_state()

def create_new_repeater_sequence():
    """Create a new empty sequence in the Repeater"""
    global repeater_sequences
    
    # Generate a unique ID
    sequence_id = str(uuid.uuid4())
    
    # Create a new sequence
    sequence = RepeaterSequence(
        id=sequence_id,
        name=f"Sequence {len(repeater_sequences) + 1}",
        packet_ids=[],
        created_at=time.time(),
        last_replayed_at=0
    )
    
    # Add to sequences dictionary
    repeater_sequences[sequence_id] = sequence
    
    # Update UI
    update_repeater_sequences_list()
    
    # Select the new sequence
    select_repeater_sequence(None, None, sequence_id)
    
    # Save repeater state
    save_repeater_state()

def delete_repeater_sequence():
    """Delete the currently selected sequence"""
    global repeater_sequences, current_repeater_sequence_id, current_repeater_packet_id
    
    # Check if a sequence is selected
    if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
        return
    
    # Get the sequence
    sequence = repeater_sequences[current_repeater_sequence_id]
    
    # Remove all packets in the sequence
    for packet_id in sequence.packet_ids:
        if packet_id in repeater_packets:
            del repeater_packets[packet_id]
    
    # Remove the sequence
    del repeater_sequences[current_repeater_sequence_id]
    
    # Reset current selections
    if current_repeater_sequence_id == current_repeater_sequence_id:
        current_repeater_sequence_id = None
    if current_repeater_packet_id in sequence.packet_ids:
        current_repeater_packet_id = None
    
    # Update UI
    update_repeater_sequences_list()
    update_repeater_packets_list()
    
    # Disable buttons
    dpg.configure_item("replay_sequence_btn", enabled=False)
    dpg.configure_item("delete_repeater_sequence_btn", enabled=False)
    
    # Save repeater state
    save_repeater_state()

def replay_current_repeater_packet():
    """Replay the currently selected packet"""
    # Check if a packet is selected
    if not current_repeater_packet_id or current_repeater_packet_id not in repeater_packets:
        return
    
    # Replay based on connection mode
    if repeater_connection_mode == "frida":
        success = replay_packet_frida(current_repeater_packet_id)
    else:
        # Validate connection parameters before direct replay
        if not repeater_connection_params.get("host") or not repeater_connection_params.get("port"):
            print("Please set valid host and port in connection settings before replaying")
            # Show a message to the user
            dpg.set_value("status", "Error: Please set valid host and port in connection settings")
            return
        success = replay_packet_direct(current_repeater_packet_id, repeater_connection_params)
    
    # Update UI after replay
    if success:
        # Refresh the packet view to show the response
        select_repeater_packet(None, None, current_repeater_packet_id)

def replay_current_repeater_sequence():
    """Replay the currently selected sequence"""
    # Check if a sequence is selected
    if not current_repeater_sequence_id or current_repeater_sequence_id not in repeater_sequences:
        return
    
    # Replay based on connection mode
    if repeater_connection_mode == "frida":
        success = replay_sequence_frida(current_repeater_sequence_id)
    else:
        # Validate connection parameters before direct replay
        if not repeater_connection_params.get("host") or not repeater_connection_params.get("port"):
            print("Please set valid host and port in connection settings before replaying")
            # Show a message to the user
            dpg.set_value("status", "Error: Please set valid host and port in connection settings")
            return
        success = replay_sequence_direct(current_repeater_sequence_id, repeater_connection_params)
    
    # Update UI after replay
    if success and current_repeater_packet_id:
        # Refresh the packet view to show the response
        select_repeater_packet(None, None, current_repeater_packet_id)

def setup_repeater_tab_ui():
    """Set up the repeater tab UI components"""
    global repeater_hexdump_widget, repeater_response_hexdump_widget
    
    # Main layout with three panels
    with dpg.group(horizontal=True, parent="repeater_tab"):
        # Left panel - Sequences Panel
        with dpg.child_window(width=300, height=500, tag="repeater_sequences_panel"):
            dpg.add_text("Repeater Sequences")
            
            # Add buttons for sequence management
            with dpg.group(horizontal=True):
                dpg.add_button(label="New Sequence", callback=lambda s, a: create_new_repeater_sequence(), tag="new_repeater_sequence_btn")
                dpg.add_button(label="Delete", callback=lambda s, a: delete_repeater_sequence(), tag="delete_repeater_sequence_btn", enabled=False)
            
            # Sequences list
            dpg.add_text("Sequences:")
            dpg.add_child_window(tag="repeater_sequences_list", height=150)
            
            # Packets in selected sequence
            dpg.add_separator()
            dpg.add_text("Packets in Sequence:")
            dpg.add_child_window(tag="repeater_packets_list", height=250)
        
        # Middle panel - Packet Editor Panel
        with dpg.child_window(width=500, height=500, tag="repeater_packet_editor_panel"):
            dpg.add_text("Packet Editor", tag="repeater_packet_editor_title")
            
            # Create hexdump widget for packet editing
            repeater_hexdump_widget = HexdumpWidget(
                packet_type_manager=packet_type_manager,
                tag="repeater_hexdump_view",
                width=480,
                height=450,
                on_regions_changed=update_repeater_packet_regions,
                on_data_changed=update_repeater_packet_data,
                marker_editor_window_tag="repeater_marker_editor_window",
                marker_editor_tag_suffix="_repeater"
            )
        
        # Right panel - Response Panel
        with dpg.child_window(width=400, height=500, tag="repeater_response_panel"):
            dpg.add_text("Response", tag="repeater_response_title")
            
            # Response hexdump widget
            repeater_response_hexdump_widget = HexdumpWidget(
                packet_type_manager=packet_type_manager,
                tag="repeater_response_hexdump_view",
                width=380,
                height=450,
                marker_editor_window_tag="repeater_response_marker_editor_window",
                marker_editor_tag_suffix="_repeater_resp"
            )
    
    # Bottom panel - Connection Controls Panel
    with dpg.child_window(height=150, parent="repeater_tab", tag="repeater_connection_panel"):
        with dpg.group(horizontal=True):
            # Connection mode selection
            dpg.add_text("Connection Mode:")
            dpg.add_radio_button(
                items=["Frida", "Direct Socket"],
                horizontal=True,
                callback=set_repeater_connection_mode,
                tag="repeater_connection_mode"
            )
            
            # Replay buttons
            dpg.add_button(label="Replay Packet", callback=lambda s, a: replay_current_repeater_packet(), tag="replay_packet_btn", enabled=False)
            dpg.add_button(label="Replay Sequence", callback=lambda s, a: replay_current_repeater_sequence(), tag="replay_sequence_btn", enabled=False)
            dpg.add_button(label="Toggle Console", callback=lambda s, a: repeater_console_window.toggle_visibility(), tag="toggle_console_btn")
        
        # Direct connection settings (hidden by default)
        with dpg.group(tag="repeater_direct_connection_settings", show=False):
            with dpg.group(horizontal=True):
                dpg.add_input_text(label="Host", tag="repeater_host_input", width=150, default_value=repeater_connection_params["host"])
                dpg.add_input_int(label="Port", tag="repeater_port_input", width=100, default_value=repeater_connection_params["port"])
                dpg.add_combo(label="Protocol", items=["TCP", "UDP"], default_value=repeater_connection_params["protocol"], tag="repeater_protocol_input", width=100)
                dpg.add_input_float(label="Timeout (s)", tag="repeater_timeout_input", width=100, default_value=repeater_connection_params["timeout"])
            
            # Apply connection settings button
            dpg.add_button(label="Apply Connection Settings", callback=update_repeater_connection_settings, tag="apply_connection_settings_btn")