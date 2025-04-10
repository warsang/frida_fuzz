import json
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

@dataclass
class MarkerType:
    """
    Represents a marker type used to annotate regions in packet data.

    Attributes:
        name: Internal name of the marker type.
        display_name: User-friendly display name.
        color: Color code (hex or string) for visualization.
        is_builtin: True if this is a built-in marker type.
        default_properties: Default properties dictionary for this marker type.
    """
    name: str
    display_name: str
    color: str
    is_builtin: bool
    default_properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MarkerRegion:
    """
    Represents a marked region within packet data.

    Attributes:
        start_offset: Start byte offset of the region.
        end_offset: End byte offset of the region.
        tag_name: Name of the marker/tag.
        tag_type: Type/category of the marker.
        properties: Additional properties associated with the region.
        marker_id: Unique identifier for this marker.
        size_definition_mode: 'direct' or 'read_offset'.
        size_read_offset: If size is read from offset, the offset value.
        offset_definition_mode: 'direct', 'read_offset', or 'byte_sequence'.
        offset_read_offset: If offset is read from another offset, the offset value.
        offset_byte_sequence: If offset is found by byte sequence, the hex string.
        related_marker_id: ID of a related marker, if any.
    """
    start_offset: int
    end_offset: int
    tag_name: str
    tag_type: str
    properties: Dict[str, Any] = field(default_factory=dict)

    marker_id: str = ""
    size_definition_mode: str = "direct"
    size_read_offset: Optional[int] = None

    offset_definition_mode: str = "direct"
    offset_read_offset: Optional[int] = None
    offset_byte_sequence: Optional[str] = None

    related_marker_id: Optional[str] = None
class MarkerManager:
    """
    Manages marker types and marked regions, including loading from and saving to JSON files.
    """
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
        print(f"[DEBUG] get_marker_type called with name: '{name}'")
        marker_type = self.marker_types.get(name)
        print(f"[DEBUG] get_marker_type returning: {marker_type}")
        return marker_type

    def get_all_marker_types(self) -> List[MarkerType]:
        """Get all marker types"""
        return list(self.marker_types.values())

    def get_builtin_marker_types(self) -> List[MarkerType]:
        """Get all built-in marker types"""
        return [mt for mt in self.marker_types.values() if mt.is_builtin]

    def get_custom_marker_types(self) -> List[MarkerType]:
        """Get all custom marker types"""
        return [mt for mt in self.marker_types.values() if not mt.is_builtin]

    # ---------------- MarkerRegion serialization ----------------

    @staticmethod
    def marker_to_dict(marker: MarkerRegion) -> dict:
        """Convert MarkerRegion to dict for JSON serialization"""
        print(f"[DEBUG] marker_to_dict: marker_id={marker.marker_id}, properties={marker.properties}")
        return {
            'start_offset': marker.start_offset,
            'end_offset': marker.end_offset,
            'tag_name': marker.tag_name,
            'tag_type': marker.tag_type,
            'properties': marker.properties,
            'marker_id': marker.marker_id,
            'size_definition_mode': marker.size_definition_mode,
            'size_read_offset': marker.size_read_offset,
            'offset_definition_mode': marker.offset_definition_mode,
            'offset_read_offset': marker.offset_read_offset,
            'offset_byte_sequence': marker.offset_byte_sequence,
            'related_marker_id': marker.related_marker_id
        }

    @staticmethod
    def marker_from_dict(data: dict) -> MarkerRegion:
        """Create MarkerRegion from dict"""
        props = data.get('properties', {})
        # Ensure 'color' property is set
        if 'color' not in props or props['color'] is None:
            props['color'] = '#FFFFFF'
            print(f"[DEBUG] marker_from_dict: 'color' missing or None, set to default {props['color']}")
        else:
            print(f"[DEBUG] marker_from_dict: existing color is {props['color']}")
        print(f"[DEBUG] marker_from_dict: marker_id={data.get('marker_id', '')}, properties={props}")
        return MarkerRegion(
            start_offset=data['start_offset'],
            end_offset=data['end_offset'],
            tag_name=data['tag_name'],
            tag_type=data['tag_type'],
            properties=props,
            marker_id=data.get('marker_id', ''),
            size_definition_mode=data.get('size_definition_mode', 'direct'),
            size_read_offset=data.get('size_read_offset'),
            offset_definition_mode=data.get('offset_definition_mode', 'direct'),
            offset_read_offset=data.get('offset_read_offset'),
            offset_byte_sequence=data.get('offset_byte_sequence'),
            related_marker_id=data.get('related_marker_id')
        )

    def save_markers_for_type(self, packet_type: str, markers: List[MarkerRegion]):
        """Save list of markers for a given packet type to JSON file"""
        try:
            with open('packet_type_markers.json', 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        # Serialize markers
        data[packet_type] = [self.marker_to_dict(m) for m in markers]

        with open('packet_type_markers.json', 'w') as f:
            json.dump(data, f, indent=2)

    def load_markers_for_type(self, packet_type: str) -> List[MarkerRegion]:
        """Load list of markers for a given packet type from JSON file"""
        try:
            with open('packet_type_markers.json', 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

        marker_dicts = data.get(packet_type, [])
        for md in marker_dicts:
            props = md.get('properties', {})
            color = props.get('color')
            print(f"[DEBUG] Loaded marker dict properties: {props}")
            print(f"[DEBUG] Loaded marker color: '{color}'")
        return [self.marker_from_dict(md) for md in marker_dicts]
        return [mt for mt in self.marker_types.values() if not mt.is_builtin]