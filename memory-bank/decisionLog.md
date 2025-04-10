# Decision Log

2025-04-06 22:36:39 - Initialized Memory Bank.

---

## Decision

Use interactive context menu in the hexdump widget for defining, modifying, and removing KSY fields, instead of a separate KSY editor window.

## Rationale 

* Provides immediate visual feedback
* Maintains offset-accurate KSY definitions
* Simplifies user workflow
* Enables future integration with fuzzing features

## Implementation Details

* Context menu options: Define, Modify, Remove KSY Field
* Offset-aware insertion with skip fields
* Skip merging on removal
* Immediate reload of KSY after edits
* Memory Bank tracks architecture, progress, and decisions