import os
import yaml
from typing import Dict, Optional, List
from dataclasses import dataclass

@dataclass
class KsyField:
    """Represents a field in a KSY file"""
    id: str
    type: str
    doc: Optional[str] = None
    size: Optional[int] = None
    size_eos: bool = False
    is_fuzzable: bool = False

class KsyManager:
    """Manages KSY file operations and generation"""

    def __init__(self):
        """Initialize KsyManager with ksy_definitions directory"""
        self.ksy_dir = "ksy_definitions"
        # Ensure directory exists
        os.makedirs(self.ksy_dir, exist_ok=True)
        print(f"KsyManager initialized with directory: {os.path.abspath(self.ksy_dir)}")  # Debug print

    def create_minimal_ksy(self, packet_type: str, sample_data: bytes) -> str:
        """
        Create a minimal KSY file for a new packet type

        Args:
            packet_type: Name of the packet type
            sample_data: Sample packet data to analyze for initial structure

        Returns:
            Path to the created KSY file
        """
        ksy_content = {
            "meta": {
                "id": f"{packet_type}_packet",
                "title": f"{packet_type} Packet Structure",
                "endian": "le",  # Default to little endian
                "fuzzable_fields": []  # List of field paths that are fuzzable
            },
            "seq": [
                {
                    "id": "header",
                    "type": "u4",
                    "doc": "Packet header"
                },
                {
                    "id": "payload",
                    "size-eos": True,
                    "doc": "Packet payload"
                }
            ]
        }

        # Create KSY file path
        ksy_path = os.path.join(self.ksy_dir, f"{packet_type}_packet.ksy")

        try:
            # Write KSY file
            with open(ksy_path, 'w') as f:
                yaml.dump(ksy_content, f, default_flow_style=False)
            print(f"Created KSY file at: {os.path.abspath(ksy_path)}")  # Debug print
            return ksy_path
        except Exception as e:
            print(f"Error creating KSY file: {e}")
            return None

    def mark_field_fuzzable(self, packet_type: str, field_path: str) -> bool:
        """
        Mark a field as fuzzable in the KSY file

        Args:
            packet_type: Name of the packet type
            field_path: Path to the field (e.g. "header.length")

        Returns:
            True if field was marked as fuzzable, False otherwise
        """
        ksy_path = os.path.join(self.ksy_dir, f"{packet_type}_packet.ksy")

        try:
            with open(ksy_path, 'r') as f:
                ksy_data = yaml.safe_load(f)

            # Ensure meta and fuzzable_fields keys exist
            if 'meta' not in ksy_data:
                ksy_data['meta'] = {}
            if 'fuzzable_fields' not in ksy_data['meta']:
                ksy_data['meta']['fuzzable_fields'] = []

            # Add field path if not already present
            if field_path not in ksy_data['meta']['fuzzable_fields']:
                ksy_data['meta']['fuzzable_fields'].append(field_path)

                # Save the updated KSY data
                with open(ksy_path, 'w') as f:
                    yaml.dump(ksy_data, f, default_flow_style=False)
                return True
            else:
                # Field already marked
                return True # Indicate success even if no change needed

        except FileNotFoundError:
             print(f"Error: KSY file not found at {ksy_path}")
             return False
        except Exception as e:
            print(f"Error marking field '{field_path}' as fuzzable in {ksy_path}: {e}")
            return False

    def add_field(self, packet_type: str, field: KsyField, index: Optional[int] = None) -> bool:
        """
        Add a new field to the KSY file

        Args:
            packet_type: Name of the packet type
            field: KsyField object describing the new field
            index: Optional index where to insert the field (None = append)

        Returns:
            True if field was added successfully, False otherwise
        """
        ksy_path = os.path.join(self.ksy_dir, f"{packet_type}_packet.ksy")

        try:
            with open(ksy_path, 'r') as f:
                ksy_data = yaml.safe_load(f)

            # Ensure 'seq' list exists
            if 'seq' not in ksy_data:
                ksy_data['seq'] = []
            target_seq_list = ksy_data['seq'] # Work directly with the list in ksy_data

            # Prepare new field data early for simulation
            new_size = field.size if field.size else 0
            new_field_data = {
                "id": field.id,
                "type": field.type
            }
            if field.doc:
                new_field_data["doc"] = field.doc
            if new_size > 0:
                new_field_data["size"] = new_size
            if field.size_eos:
                new_field_data["size-eos"] = True

            # Add a unique marker to identify the new field in the simulated sequence
            new_field_data["_is_new_field"] = True

            # Simulate the new sequence with the new field inserted
            simulated_seq = list(target_seq_list)  # shallow copy
            if new_size > 0:
                if index is not None:
                    simulated_seq.insert(index, new_field_data)
                else:
                    simulated_seq.append(new_field_data)

                # Recompute offsets and check for overlaps
                offsets = []
                current_offset = 0

                # First, compute start/end offsets for all fields (do NOT skip any)
                for i, existing in enumerate(simulated_seq):
                    size = existing.get('size', 0)
                    size = size if isinstance(size, (int, float)) else 0
                    start = current_offset
                    end = start + size
                    offsets.append((i, start, end))
                    current_offset += size

                # Identify new field's offset range
                new_start = None
                new_end = None
                new_field_index = None
                for idx, item in enumerate(simulated_seq):
                    if item.get("_is_new_field"):
                        new_field_index = idx
                        _, new_start, new_end = offsets[idx]
                        break

                if new_field_index is None or new_start is None or new_end is None:
                    raise RuntimeError("Failed to locate new field offsets in simulated sequence")

                # Check overlap with all other user-defined fields
                for idx, (i, start, end) in enumerate(offsets):
                    if i < 2 or i == new_field_index or start is None or end is None:
                        continue
                    if (new_start < end) and (new_end > start):
                        existing_id = simulated_seq[i].get('id')
                        raise ValueError(f"New field '{field.id}' ({new_start}-{new_end}) overlaps with existing field '{existing_id}' ({start}-{end})")

            # Prepare the new field data
            field_data = {
                "id": field.id,
                "type": field.type
            }
            if field.doc:
                field_data["doc"] = field.doc
            # Use new_size which handles None case for field.size
            if new_size > 0:
                field_data["size"] = new_size
            if field.size_eos:
                field_data["size-eos"] = True

            # Add the field to the sequence (using the same list reference)
            # Insert the new field at the specified index or append
            if index is not None:
                ksy_data['seq'].insert(index, field_data)
            else:
                ksy_data['seq'].append(field_data)

            # Mark as fuzzable if needed
            if field.is_fuzzable:
                if 'fuzzable_fields' not in ksy_data['meta']:
                    ksy_data['meta']['fuzzable_fields'] = []
                ksy_data['meta']['fuzzable_fields'].append(field.id)

            with open(ksy_path, 'w') as f:
                yaml.dump(ksy_data, f, default_flow_style=False)

            return True

        except FileNotFoundError as e:
             # Re-raise if file not found during initial read
             print(f"Error adding field: KSY file not found at {ksy_path}")
             raise e
        except Exception as e:
            print(f"Error adding field: {e}")
            return False

    def unmark_field_fuzzable(self, packet_type: str, field_path: str) -> bool:
        """
        Unmark a field as fuzzable in the KSY file

        Args:
            packet_type: Name of the packet type
            field_path: Path to the field to unmark

        Returns:
            True if field was unmarked or was already not marked, False otherwise
        """
        ksy_path = os.path.join(self.ksy_dir, f"{packet_type}_packet.ksy")

        try:
            with open(ksy_path, 'r') as f:
                ksy_data = yaml.safe_load(f)

            # Check if meta and fuzzable_fields exist
            if 'meta' in ksy_data and 'fuzzable_fields' in ksy_data['meta']:
                if field_path in ksy_data['meta']['fuzzable_fields']:
                    ksy_data['meta']['fuzzable_fields'].remove(field_path)

                    # Save the updated KSY data
                    with open(ksy_path, 'w') as f:
                        yaml.dump(ksy_data, f, default_flow_style=False)
                    return True
                else:
                    # Field was not marked, consider it success
                    return True
            else:
                 # Meta or fuzzable_fields list doesn't exist, so field wasn't marked
                 return True

        except FileNotFoundError:
             print(f"Error: KSY file not found at {ksy_path}")
             return False
        except Exception as e:
            print(f"Error unmarking field '{field_path}' as fuzzable in {ksy_path}: {e}")
            return False

    def get_fuzzable_fields(self, packet_type: str) -> List[str]:
        """
        Get list of fuzzable fields for a packet type

        Args:
            packet_type: Name of the packet type

        Returns:
            List of field paths that are marked as fuzzable
        """
        ksy_path = os.path.join(self.ksy_dir, f"{packet_type}_packet.ksy")

        try:
            with open(ksy_path, 'r') as f:
                ksy_data = yaml.safe_load(f)

            return ksy_data.get('meta', {}).get('fuzzable_fields', [])
        except FileNotFoundError:
             # If file doesn't exist, return empty list
             return []
        except Exception as e:
            print(f"Error getting fuzzable fields from {ksy_path}: {e}")
            return []
