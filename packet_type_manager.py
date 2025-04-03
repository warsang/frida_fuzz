import json
from dataclasses import dataclass
from typing import List, Optional, Dict

@dataclass
class PacketTypeCriteria:
    hex_value: Optional[str] = None  # Hex value to match anywhere
    hex_offset: Optional[int] = None  # Offset for hex value match
    packet_size: Optional[int] = None  # Expected packet size
    callstack: Optional[str] = None  # Expected callstack

@dataclass
class PacketType:
    name: str
    description: str
    criteria: PacketTypeCriteria

class PacketTypeManager:
    def __init__(self):
        self.types: List[Dict] = []
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
    
    def create_type(self, name: str, description: str, criteria: PacketTypeCriteria) -> bool:
        """Create a new packet type"""
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