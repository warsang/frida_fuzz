import json
from dataclasses import dataclass
from typing import List, Optional, Dict
from .ksy_manager import KsyManager

@dataclass
class PacketTypeCriteria:
    """
    Criteria for identifying a specific packet type.

    Attributes:
        hex_value: Hex string to match within the packet data.
        hex_offset: Byte offset where hex_value should be matched (if specified).
        packet_size: Expected size of the packet in bytes.
        callstack: Expected callstack signature as a string.
    """
    hex_value: Optional[str] = None  # Hex value to match anywhere
    hex_offset: Optional[int] = None  # Offset for hex value match
    packet_size: Optional[int] = None  # Expected packet size
    callstack: Optional[str] = None  # Expected callstack

@dataclass
class PacketType:
    """
    Represents a packet type definition.

    Attributes:
        name: Name of the packet type.
        description: Description of the packet type.
        criteria: Criteria used to identify packets of this type.
    """
    name: str
    description: str
    criteria: PacketTypeCriteria

class PacketTypeManager:
    """
    Manages packet type definitions, including loading, saving, matching packets,
    and generating Kaitai Struct (KSY) files for packet parsing.
    """
    def __init__(self):
        self.types: List[Dict] = []
        self.ksy_manager = KsyManager()  # Initialize KSY manager
        self.load_types()
    
    def load_types(self):
        """Load packet types from JSON file"""
        try:
            with open('packet_types.json', 'r') as f:
                data = json.load(f)
                self.types = data.get('types', [])
        except (FileNotFoundError, json.JSONDecodeError):
            self.types = []
    
    def save_types(self):
        """Save packet types to JSON file"""
        with open('packet_types.json', 'w') as f:
            json.dump({'types': self.types}, f, indent=2)
    
    def create_type(self, name: str, description: str, criteria: PacketTypeCriteria, sample_data: Optional[bytes] = None) -> bool:
        """
        Create a new packet type and generate its KSY definition
        
        Args:
            name: Name of the packet type
            description: Description of the packet type
            criteria: Criteria for identifying this packet type
            sample_data: Optional sample packet data to analyze for KSY generation
        """
        # Check if type with this name already exists
        if any(t['name'] == name for t in self.types):
            return False
            
        type_data = {
            'name': name,
            'description': description,
            'criteria': {
                'hex_value': criteria.hex_value,
                'hex_offset': criteria.hex_offset,
                'packet_size': criteria.packet_size,
                'callstack': criteria.callstack
            }
        }
        
        # Always create a KSY file
        try:
            # If no sample data, create empty bytes of the specified size or a default size
            if not sample_data and criteria.packet_size:
                sample_data = bytes(criteria.packet_size)
            elif not sample_data:
                sample_data = bytes(16)  # Default minimal size if no size criteria
                
            ksy_path = self.ksy_manager.create_minimal_ksy(name, sample_data)
            if ksy_path:
                type_data['ksy_file'] = ksy_path
                print(f"Created KSY file for {name} at {ksy_path}")
            else:
                print(f"Warning: Failed to create KSY file for {name}")
        except Exception as e:
            print(f"Warning: Failed to create KSY file: {e}")
        
        self.types.append(type_data)
        self.save_types()
        return True
    
    def delete_type(self, name: str) -> bool:
        """Delete a packet type by name"""
        initial_len = len(self.types)
        self.types = [t for t in self.types if t['name'] != name]
        if len(self.types) < initial_len:
            self.save_types()
            return True
        return False
    
    def get_type(self, name: str) -> Optional[Dict]:
        """Get a packet type by name"""
        for t in self.types:
            if t['name'] == name:
                return t
        return None
    
    def matches_type(self, packet_data: bytes, packet_size: int, callstack: str) -> Optional[str]:
        """Check if a packet matches any defined type and return the type name if it does"""
        hex_data = packet_data.hex()
        
        for t in self.types:
            criteria = t['criteria']
            matches = True
            
            # Check hex value
            if criteria['hex_value']:
                if criteria['hex_offset'] is not None:
                    # Check at specific offset
                    offset = criteria['hex_offset']
                    if offset + len(criteria['hex_value'])//2 > len(packet_data):
                        matches = False
                    else:
                        packet_hex = hex_data[offset*2:(offset + len(criteria['hex_value'])//2)*2]
                        if packet_hex != criteria['hex_value']:
                            matches = False
                else:
                    # Check anywhere in packet
                    if criteria['hex_value'] not in hex_data:
                        matches = False
            
            # Check packet size
            if criteria['packet_size'] is not None:
                if packet_size != criteria['packet_size']:
                    matches = False
            
            # Check callstack
            if criteria['callstack']:
                if criteria['callstack'] not in callstack:
                    matches = False
            
            if matches:
                return t['name']
        
        return None

    def get_ksy_path(self, name: str) -> Optional[str]:
        """Get the KSY file path for a packet type"""
        packet_type = self.get_type(name)
        if packet_type and 'ksy_file' in packet_type:
            return packet_type['ksy_file']
        return None

    def mark_field_fuzzable(self, packet_type: str, field_path: str) -> bool:
        """Mark a field as fuzzable in the KSY definition"""
        return self.ksy_manager.mark_field_fuzzable(packet_type, field_path)

    def get_fuzzable_fields(self, packet_type: str) -> List[str]:
        """Get list of fuzzable fields for a packet type"""
        return self.ksy_manager.get_fuzzable_fields(packet_type)