# Active Context

2025-04-06 22:36:20 - Initialized Memory Bank.

---

## Current Focus

* Integrate interactive KSY editing into the hexdump widget
* Maintain offset-accurate KSY definitions with skip fields
* Enable marking fields as fuzzable
* Synchronize KSY edits with packet type manager

## Recent Changes

* Removed separate KSY editor button
* Added context menu for define/modify/remove KSY fields
* Implemented offset-aware insertion and skip merging
* Initialized Memory Bank

## Open Questions/Issues

* How to best support nested types and complex KSY features interactively
* How to visualize fuzzable fields more clearly
* How to handle KSY validation errors gracefully