meta:
  endian: le
  fuzzable_fields: []
  id: a_packet
  title: a Packet Structure
seq:
- doc: Packet header
  id: header
  type: u4
- doc: Packet payload
  id: payload
  size-eos: true
