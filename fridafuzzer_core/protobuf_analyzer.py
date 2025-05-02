import dearpygui.dearpygui as dpg
from typing import Dict, List, Tuple, Optional, Any, Callable, Union
import struct
import binascii
import io
from traceback import format_exc

class ProtobufAnalyzer:
    """Class for analyzing and visualizing Protocol Buffer data."""
    
    # Wire types in protobuf encoding
    WIRE_VARINT = 0
    WIRE_64BIT = 1
    WIRE_LENGTH_DELIMITED = 2
    WIRE_START_GROUP = 3  # Deprecated
    WIRE_END_GROUP = 4    # Deprecated
    WIRE_32BIT = 5
    
    # Field type names for display (simplified without dependency)
    WIRE_TYPE_NAMES = {
        WIRE_VARINT: "varint",
        WIRE_64BIT: "64bit",
        WIRE_LENGTH_DELIMITED: "bytes/string/message",
        WIRE_START_GROUP: "start_group",
        WIRE_END_GROUP: "end_group",
        WIRE_32BIT: "32bit"
    }
    
    # Type registry for specialized parsers
    TYPE_REGISTRY = {
        WIRE_VARINT: ["varint", "sint32", "sint64", "int32", "int64", "uint32", "uint64", "enum", "bool"],
        WIRE_64BIT: ["fixed64", "sfixed64", "double"],
        WIRE_LENGTH_DELIMITED: ["bytes", "string", "message", "packed"],
        WIRE_32BIT: ["fixed32", "sfixed32", "float"]
    }
    
    # Formatting settings
    DEFAULT_INDENT = " " * 4
    COMPACT_MAX_LINE_LENGTH = 35
    COMPACT_MAX_LENGTH = 70
    BYTES_PER_LINE = 24
    
    @staticmethod
    def parse_protobuf(data: bytes) -> Tuple[Dict[str, Any], Dict[str, Tuple[int, int]], Optional[str]]:
        """
        Attempt to parse binary data as a protobuf message.
        
        Args:
            data: Binary data to parse
            
        Returns:
            Tuple containing:
            - Dictionary of parsed fields
            - Dictionary mapping field paths to byte ranges (start, end)
            - Error message if parsing failed, None otherwise
        """
        if not data:
            return {}, {}, "No data provided"
            
        try:
            # Convert bytes to BytesIO for easier handling
            data_io = io.BytesIO(data)
            
            # Since we don't know the message type, we'll try to parse it as a generic protobuf
            parsed_fields = {}
            field_offsets = {}
            errors = []
            
            while True:
                field_start = data_io.tell()
                if field_start >= len(data):
                    break
                
                # Parse field header (tag and wire type)
                field_number, wire_type = ProtobufAnalyzer._read_identifier(data_io)
                if field_number is None:
                    break
                
                # Parse field value based on wire type
                field_name = f"field_{field_number}"
                field_value = ProtobufAnalyzer._read_value(data_io, wire_type)
                
                if field_value is None:
                    errors.append(f"Failed to read value for field {field_number} with wire type {wire_type}")
                    continue
                
                # Process the field value based on wire type
                if wire_type == ProtobufAnalyzer.WIRE_VARINT:  # Varint
                    # Try to interpret as different varint types
                    parsed_fields[field_name] = {
                        "type": "varint",
                        "value": field_value,
                        "interpretations": {
                            "int32": ProtobufAnalyzer._interpret_int32(field_value),
                            "int64": ProtobufAnalyzer._interpret_int64(field_value),
                            "uint32": field_value & 0xFFFFFFFF,
                            "uint64": field_value,
                            "sint32": ProtobufAnalyzer._zigzag_decode(field_value),
                            "bool": bool(field_value)
                        }
                    }
                    
                elif wire_type == ProtobufAnalyzer.WIRE_64BIT:  # 64-bit
                    # Interpret as different 64-bit types
                    parsed_fields[field_name] = {
                        "type": "fixed64",
                        "value": field_value,
                        "interpretations": {
                            "fixed64": struct.unpack("<Q", field_value)[0],
                            "sfixed64": struct.unpack("<q", field_value)[0],
                            "double": struct.unpack("<d", field_value)[0]
                        }
                    }
                    
                elif wire_type == ProtobufAnalyzer.WIRE_LENGTH_DELIMITED:  # Length-delimited
                    # Try to interpret as string, bytes, message, or packed repeated
                    chunk = field_value.read()
                    
                    # First check if it's a valid string
                    if ProtobufAnalyzer._is_probable_string(chunk):
                        try:
                            string_value = chunk.decode('utf-8')
                            parsed_fields[field_name] = {"type": "string", "value": string_value}
                        except UnicodeDecodeError:
                            # Not a valid UTF-8 string, continue to other checks
                            pass
                    
                    # If not a string, try to parse as a nested message
                    if field_name not in parsed_fields:
                        nested_fields, nested_offsets, nested_error = ProtobufAnalyzer.parse_protobuf(chunk)
                        if nested_fields and not nested_error:
                            parsed_fields[field_name] = {
                                "type": "message",
                                "nested": nested_fields
                            }
                            
                            # Adjust nested offsets to be relative to the parent message
                            current_pos = data_io.tell() - len(chunk)
                            for nested_path, (nested_start, nested_end) in nested_offsets.items():
                                field_offsets[f"{field_name}.{nested_path}"] = (current_pos + nested_start, current_pos + nested_end)
                        else:
                            # Try to parse as packed repeated field
                            packed_values = ProtobufAnalyzer._try_parse_packed(chunk)
                            if packed_values:
                                parsed_fields[field_name] = {
                                    "type": "packed",
                                    "value": packed_values
                                }
                            else:
                                # Default to bytes
                                hex_value = binascii.hexlify(chunk).decode('ascii')
                                parsed_fields[field_name] = {"type": "bytes", "value": hex_value}
                                
                                # Add hex dump for better visualization
                                parsed_fields[field_name]["hex_dump"] = ProtobufAnalyzer._hex_dump(chunk)
                    
                elif wire_type == ProtobufAnalyzer.WIRE_32BIT:  # 32-bit
                    # Interpret as different 32-bit types
                    parsed_fields[field_name] = {
                        "type": "fixed32",
                        "value": field_value,
                        "interpretations": {
                            "fixed32": struct.unpack("<I", field_value)[0],
                            "sfixed32": struct.unpack("<i", field_value)[0],
                            "float": struct.unpack("<f", field_value)[0]
                        }
                    }
                else:
                    # Skip unsupported wire types (like deprecated group types)
                    errors.append(f"Unsupported wire type {wire_type} at offset {field_start}")
                    continue
                
                # Record field byte range
                field_end = data_io.tell() - 1
                field_offsets[field_name] = (field_start, field_end)
            
            error_msg = None
            if errors:
                error_msg = "; ".join(errors)
            
            return parsed_fields, field_offsets, error_msg
            
        except Exception as e:
            return {}, {}, f"Error parsing protobuf: {str(e)}\n{format_exc()}"
    
    @staticmethod
    def _read_identifier(file: io.BytesIO) -> Tuple[Optional[int], Optional[int]]:
        """
        Read a field identifier from the stream.
        
        Args:
            file: BytesIO object to read from
            
        Returns:
            Tuple of (field_number, wire_type) or (None, None) if EOF
        """
        id_value = ProtobufAnalyzer._read_varint(file)
        if id_value is None:
            return None, None
        return id_value >> 3, id_value & 0x07
    
    @staticmethod
    def _read_value(file: io.BytesIO, wire_type: int) -> Any:
        """
        Read a field value based on its wire type.
        
        Args:
            file: BytesIO object to read from
            wire_type: Wire type of the field
            
        Returns:
            The parsed value, or None if EOF
        """
        if wire_type == ProtobufAnalyzer.WIRE_VARINT:
            return ProtobufAnalyzer._read_varint(file)
            
        elif wire_type == ProtobufAnalyzer.WIRE_64BIT:
            data = file.read(8)
            if not data or len(data) < 8:
                return None
            return data
            
        elif wire_type == ProtobufAnalyzer.WIRE_LENGTH_DELIMITED:
            length = ProtobufAnalyzer._read_varint(file)
            if length is None:
                return None
            data = file.read(length)
            if len(data) != length:
                return None
            return io.BytesIO(data)
            
        elif wire_type == ProtobufAnalyzer.WIRE_START_GROUP or wire_type == ProtobufAnalyzer.WIRE_END_GROUP:
            return wire_type == ProtobufAnalyzer.WIRE_START_GROUP
            
        elif wire_type == ProtobufAnalyzer.WIRE_32BIT:
            data = file.read(4)
            if not data or len(data) < 4:
                return None
            return data
            
        return None
    
    @staticmethod
    def _read_varint(file: io.BytesIO) -> Optional[int]:
        """
        Read a varint from the stream.
        
        Args:
            file: BytesIO object to read from
            
        Returns:
            The parsed varint value, or None if EOF
        """
        value = 0
        shift = 0
        
        while True:
            b = file.read(1)
            if not b:
                if shift == 0:  # EOF at the start
                    return None
                raise ValueError("Unexpected EOF in varint")
                
            b = b[0]
            value |= ((b & 0x7F) << shift)
            shift += 7
            
            if not (b & 0x80):
                break
                
            if shift > 64:
                raise ValueError("Varint too long")
                
        return value
    
    @staticmethod
    def _parse_varint(data: bytes) -> Tuple[int, int]:
        """
        Parse a varint from the given data (legacy method for compatibility).
        
        Args:
            data: Bytes to parse
            
        Returns:
            Tuple of (parsed value, number of bytes read)
        """
        value = 0
        shift = 0
        bytes_read = 0
        
        for b in data:
            bytes_read += 1
            value |= ((b & 0x7F) << shift)
            if not (b & 0x80):
                break
            shift += 7
            
            if shift > 64:
                raise ValueError("Varint too long")
        
        return value, bytes_read
    
    @staticmethod
    def _zigzag_decode(value: int) -> int:
        """
        Decode a zigzag-encoded value.
        
        Args:
            value: Zigzag-encoded integer
            
        Returns:
            Decoded signed integer
        """
        return (value >> 1) ^ (-(value & 1))
    
    @staticmethod
    def _interpret_int32(value: int) -> int:
        """
        Interpret a value as an int32.
        
        Args:
            value: Value to interpret
            
        Returns:
            int32 interpretation
        """
        value &= 0xFFFFFFFF
        if value >= 0x80000000:
            value -= 0x100000000
        return value
    
    @staticmethod
    def _interpret_int64(value: int) -> int:
        """
        Interpret a value as an int64.
        
        Args:
            value: Value to interpret
            
        Returns:
            int64 interpretation
        """
        if value >= 0x8000000000000000:
            value -= 0x10000000000000000
        return value
    
    @staticmethod
    def _is_probable_string(data: bytes) -> bool:
        """
        Check if the data is likely to be a UTF-8 string.
        
        Args:
            data: Bytes to check
            
        Returns:
            True if the data is likely a string, False otherwise
        """
        if not data:
            return False
            
        # Check for common string patterns
        control_chars = 0
        alnum_chars = 0
        total_chars = len(data)
        
        for b in data:
            if b < 0x20 or b == 0x7F:  # Control characters
                control_chars += 1
            if (ord('A') <= b <= ord('Z')) or (ord('a') <= b <= ord('z')) or (ord('0') <= b <= ord('9')):
                alnum_chars += 1
        
        # Heuristics for string detection
        if control_chars / total_chars > 0.1:
            return False
        if alnum_chars / total_chars < 0.5:
            return False
            
        # Try to decode as UTF-8
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False
    
    @staticmethod
    def _try_parse_packed(data: bytes) -> Optional[List[Any]]:
        """
        Try to parse data as a packed repeated field.
        
        Args:
            data: Bytes to parse
            
        Returns:
            List of parsed values if successful, None otherwise
        """
        if not data:
            return None
            
        # Try to parse as packed varints first (most common)
        try:
            values = []
            data_io = io.BytesIO(data)
            while data_io.tell() < len(data):
                value = ProtobufAnalyzer._read_varint(data_io)
                if value is None:
                    break
                values.append(value)
            
            if values and data_io.tell() == len(data):
                return values
        except Exception:
            pass
            
        # Try to parse as packed 32-bit values
        if len(data) % 4 == 0 and len(data) > 0:
            try:
                values = []
                for i in range(0, len(data), 4):
                    values.append(struct.unpack("<I", data[i:i+4])[0])
                return values
            except Exception:
                pass
                
        # Try to parse as packed 64-bit values
        if len(data) % 8 == 0 and len(data) > 0:
            try:
                values = []
                for i in range(0, len(data), 8):
                    values.append(struct.unpack("<Q", data[i:i+8])[0])
                return values
            except Exception:
                pass
                
        return None
    
    @staticmethod
    def _hex_dump(data: bytes, bytes_per_line: int = None) -> str:
        """
        Create a hex dump of binary data.
        
        Args:
            data: Bytes to dump
            bytes_per_line: Number of bytes per line
            
        Returns:
            Formatted hex dump string
        """
        if bytes_per_line is None:
            bytes_per_line = ProtobufAnalyzer.BYTES_PER_LINE
            
        if not data:
            return "empty"
            
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            
            # Add ASCII representation
            ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            
            lines.append(f"{i:04X}:  {hex_part:<{bytes_per_line*3}}  {ascii_part}")
            
        return "\n".join(lines)
    
    @staticmethod
    def setup_tree(tag: str) -> None:
        """
        Create a DearPyGui tree for protobuf visualization.
        
        Args:
            tag: Base tag for the tree
        """
        try:
            # Create a tree node for displaying the protobuf structure
            dpg.add_tree_node(
                label="Protobuf Structure",
                tag=f"{tag}_tree",
                default_open=True
            )
        except Exception as e:
            print(f"Error setting up protobuf tree: {e}")
            raise
    
    @staticmethod
    def update_tree(tag: str, parsed_fields: Dict[str, Any], field_offsets: Dict[str, Tuple[int, int]], parent_tag: str = None) -> None:
        """
        Update the protobuf tree with parsed data.
        
        Args:
            tag: Base tag for the tree components
            parsed_fields: Dictionary of parsed protobuf fields
            field_offsets: Dictionary mapping field paths to byte ranges
            parent_tag: Tag of the parent node (for nested fields)
        """
        try:
            tree_tag = f"{tag}_tree" if parent_tag is None else parent_tag
            
            # Clear existing tree items if this is the root call
            if parent_tag is None and dpg.does_item_exist(tree_tag):
                dpg.delete_item(tree_tag, children_only=True)
                
            # If tree doesn't exist, we can't proceed
            if not dpg.does_item_exist(tree_tag):
                print(f"Error: Tree {tree_tag} does not exist!")
                return
                
            # Add fields to the tree
            for field_name, field_info in parsed_fields.items():
                field_type = field_info.get("type", "unknown")
                field_value = field_info.get("value", "")
                field_tag = f"{tree_tag}_{field_name}"
                
                # Handle different field types
                if field_type == "bytes":
                    # Create a tree node for bytes with hex dump
                    display_value = f"{field_value[:16]}..." if len(str(field_value)) > 16 else f"{field_value}"
                    with dpg.tree_node(label=f"{field_name}: {field_type} ({display_value})", tag=field_tag, parent=tree_tag):
                        if "hex_dump" in field_info:
                            dpg.add_text(field_info["hex_dump"], parent=field_tag)
                        
                        # Add selectable for highlighting
                        dpg.add_selectable(
                            label="Select to highlight in hexdump",
                            tag=f"{field_tag}_select",
                            parent=field_tag,
                            callback=lambda s, a, u: ProtobufAnalyzer._on_field_selected(s, a, u, field_offsets),
                            user_data=field_name
                        )
                
                elif field_type == "string":
                    # Format string display
                    display_value = f"\"{field_value[:32]}\"" if len(str(field_value)) > 32 else f"\"{field_value}\""
                    
                    # Add a selectable for this field
                    dpg.add_selectable(
                        label=f"{field_name}: {field_type} ({display_value})",
                        tag=field_tag,
                        parent=tree_tag,
                        callback=lambda s, a, u: ProtobufAnalyzer._on_field_selected(s, a, u, field_offsets),
                        user_data=field_name
                    )
                
                elif field_type == "packed":
                    # Display packed repeated field
                    with dpg.tree_node(label=f"{field_name}: packed repeated ({len(field_value)} items)", tag=field_tag, parent=tree_tag):
                        # Show the first few values
                        max_display = 10
                        for i, val in enumerate(field_value[:max_display]):
                            dpg.add_text(f"[{i}]: {val}", parent=field_tag)
                        
                        if len(field_value) > max_display:
                            dpg.add_text(f"... {len(field_value) - max_display} more items", parent=field_tag)
                        
                        # Add selectable for highlighting
                        dpg.add_selectable(
                            label="Select to highlight in hexdump",
                            tag=f"{field_tag}_select",
                            parent=field_tag,
                            callback=lambda s, a, u: ProtobufAnalyzer._on_field_selected(s, a, u, field_offsets),
                            user_data=field_name
                        )
                
                elif "interpretations" in field_info:
                    # Create a tree node for fields with multiple interpretations
                    with dpg.tree_node(label=f"{field_name}: {field_type}", tag=field_tag, parent=tree_tag):
                        # Add each interpretation
                        for interp_type, interp_value in field_info["interpretations"].items():
                            dpg.add_text(f"{interp_type}: {interp_value}", parent=field_tag)
                        
                        # Add selectable for highlighting
                        dpg.add_selectable(
                            label="Select to highlight in hexdump",
                            tag=f"{field_tag}_select",
                            parent=field_tag,
                            callback=lambda s, a, u: ProtobufAnalyzer._on_field_selected(s, a, u, field_offsets),
                            user_data=field_name
                        )
                
                elif "nested" in field_info:
                    # Handle nested message
                    with dpg.tree_node(label=f"{field_name}: message", tag=field_tag, parent=tree_tag):
                        # Recursively add nested fields
                        ProtobufAnalyzer.update_tree(tag, field_info["nested"], field_offsets, field_tag)
                        
                        # Add selectable for highlighting the entire message
                        dpg.add_selectable(
                            label="Select to highlight entire message",
                            tag=f"{field_tag}_select",
                            parent=field_tag,
                            callback=lambda s, a, u: ProtobufAnalyzer._on_field_selected(s, a, u, field_offsets),
                            user_data=field_name
                        )
                
                else:
                    # Default case for simple fields
                    display_value = str(field_value)
                    if len(display_value) > 32:
                        display_value = display_value[:32] + "..."
                    
                    # Add a selectable for this field
                    dpg.add_selectable(
                        label=f"{field_name}: {field_type} ({display_value})",
                        tag=field_tag,
                        parent=tree_tag,
                        callback=lambda s, a, u: ProtobufAnalyzer._on_field_selected(s, a, u, field_offsets),
                        user_data=field_name
                    )
        except Exception as e:
            print(f"Error updating protobuf tree: {e}")
            raise
    
    @staticmethod
    def _on_field_selected(sender, app_data, user_data, field_offsets):
        """
        Handle field selection in the tree.
        
        Args:
            sender: Sender widget ID
            app_data: Application data
            user_data: Field name
            field_offsets: Dictionary mapping field paths to byte ranges
        """
        field_name = user_data
        if field_name in field_offsets:
            start_offset, end_offset = field_offsets[field_name]
            
            # Get parent window to access the hexdump widget
            parent_id = dpg.get_item_parent(dpg.get_item_parent(sender))
            while parent_id and not dpg.get_item_label(parent_id).startswith("Protobuf Analysis"):
                parent_id = dpg.get_item_parent(parent_id)
            
            if parent_id:
                # Extract window tag to get the parent widget reference
                window_tag = dpg.get_item_alias(parent_id)
                if window_tag and "_window" in window_tag:
                    parent_tag = window_tag.split("_window")[0]
                    
                    # Find the parent widget in the global registry
                    # This is a bit of a hack, but it works for our purpose
                    import builtins
                    for obj in vars(builtins).values():
                        if hasattr(obj, "tag") and obj.tag == parent_tag and hasattr(obj, "parent"):
                            # Call the highlight method on the parent hexdump widget
                            if hasattr(obj.parent, "highlight_protobuf_field"):
                                obj.parent.highlight_protobuf_field(start_offset, end_offset)
                            break