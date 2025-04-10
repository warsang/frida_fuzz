# Product Context

This file provides a high-level overview of the project and the expected product that will be created. Initially it is based upon projectBrief.md (if provided) and all other available project-related information in the working directory. This file is intended to be updated as the project evolves, and should be used to inform all other modes of the project's goals and context.

2025-04-06 22:36:10 - Initialized Memory Bank.

---

## Project Goal

Enable interactive, offset-accurate editing of Kaitai Struct (KSY) definitions directly from the hexdump view, integrated with packet type management and fuzzing workflows.

## Key Features

* Context menu-driven creation, modification, and removal of KSY fields
* Automatic insertion of skip fields to maintain correct offsets
* Immediate reloading of KSY after edits
* Packet type manager integration for KSY file association
* Support for marking fields as fuzzable
* Memory Bank to track architecture, progress, and decisions

## Overall Architecture

* `hexdump_widget.py` provides interactive hex view and KSY editing
* `packet_type_manager.py` manages packet type definitions and KSY paths
* `ksy_manager.py` handles KSY file creation and manipulation
* Memory Bank maintains project context, progress, and design rationale