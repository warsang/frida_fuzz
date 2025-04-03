import json
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

@dataclass
class MarkerType:
    name: str
    display_name: str
    color: str
    is_builtin: bool
    default_properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MarkerRegion:
    start_offset: int
    end_offset: int
    tag_name: str
    tag_type: str
    properties: Dict[str, Any] = field(default_factory=dict)

class MarkerManager:
    def __init__(self):
        self.marker_types: Dict[str, MarkerType] = {}
        self.load_marker_types()
    
    def load_marker_types(self):
        """Load marker types from JSON file"""
        try:
            with open('marker_types.json', 'r') as f:
                data = json.load(f)
                for marker_type in data.get('marker_types', []):
                    self.marker_types[marker_type['name']] = MarkerType(
                        name=marker_type['name'],
                        display_name=marker_type['display_name'],
                        color=marker_type['color'],
                        is_builtin=marker_type['is_builtin'],
                        default_properties=marker_type.get('default_properties', {})
                    )
        except (FileNotFoundError, json.JSONDecodeError):
            # If file doesn't exist or is invalid, initialize with empty types
            self.marker_types = {}
    
    def save_marker_types(self):
        """Save marker types to JSON file"""
        data = {
            'marker_types': [
                {
                    'name': mt.name,
                    'display_name': mt.display_name,
                    'color': mt.color,
                    'is_builtin': mt.is_builtin,
                    'default_properties': mt.default_properties
                }
                for mt in self.marker_types.values()
            ]
        }
        with open('marker_types.json', 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_marker_type(self, name: str, display_name: str, color: str, 
                         default_properties: Dict[str, Any] = None) -> bool:
        """Create a new custom marker type"""
        if name in self.marker_types:
            return False
        
        self.marker_types[name] = MarkerType(
            name=name,
            display_name=display_name,
            color=color,
            is_builtin=False,
            default_properties=default_properties or {}
        )
        self.save_marker_types()
        return True
    
    def delete_marker_type(self, name: str) -> bool:
        """Delete a custom marker type"""
        if name not in self.marker_types or self.marker_types[name].is_builtin:
            return False
        
        del self.marker_types[name]
        self.save_marker_types()
        return True
    
    def update_marker_type(self, name: str, display_name: Optional[str] = None,
                          color: Optional[str] = None, 
                          default_properties: Optional[Dict[str, Any]] = None) -> bool:
        """Update an existing marker type"""
        if name not in self.marker_types:
            return False
        
        marker_type = self.marker_types[name]
        if marker_type.is_builtin:
            return False
            
        if display_name is not None:
            marker_type.display_name = display_name
        if color is not None:
            marker_type.color = color
        if default_properties is not None:
            marker_type.default_properties = default_properties
            
        self.save_marker_types()
        return True
    
    def get_marker_type(self, name: str) -> Optional[MarkerType]:
        """Get a marker type by name"""
        return self.marker_types.get(name)
    
    def get_all_marker_types(self) -> List[MarkerType]:
        """Get all marker types"""
        return list(self.marker_types.values())
    
    def get_builtin_marker_types(self) -> List[MarkerType]:
        """Get all built-in marker types"""
        return [mt for mt in self.marker_types.values() if mt.is_builtin]
    
    def get_custom_marker_types(self) -> List[MarkerType]:
        """Get all custom marker types"""
        return [mt for mt in self.marker_types.values() if not mt.is_builtin]