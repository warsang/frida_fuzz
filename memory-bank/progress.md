# Progress

2025-04-06 22:36:29 - Initialized Memory Bank.

---

## Completed Tasks

* Removed separate KSY editor button
* Added context menu for define/modify/remove KSY fields
* Implemented offset-aware insertion with skip fields
* Implemented skip merging on removal
* Initialized Memory Bank
* Created comprehensive documentation for biodiff algorithms (2025-04-12)
* Updated README.md to include biodiff capabilities (2025-04-12)
* Fixed Frida mode replay error by updating status widget references (2025-04-30)

## Current Tasks

* Design Memory Bank structure
* Document architecture and design decisions
* Plan next steps for nested types and fuzzable visualization

## Next Steps

* Implement modify KSY field functionality
* Improve error handling and validation
* Integrate fuzzing workflows with KSY editing
* Enhance visualization of fuzzable fields
[2025-05-06 12:00:00] - Implemented process selection dropdown feature

**Changes made:**
1. Added `get_process_list()` function to `fridafuzzer_core/frida_handler.py` to retrieve a list of running processes using Frida's API.
2. Added a global `process_map` variable in `app.py` to map display strings to PIDs.
3. Replaced the text input with a dropdown and added a refresh button in the UI.
4. Implemented `populate_process_dropdown()` and `refresh_process_list()` functions.
5. Updated `start_intercepting()` and `stop_intercepting()` functions to work with the new dropdown.
6. Added code to populate the process dropdown when the application starts.

**Benefits:**
- Improved user experience by providing a list of available processes
- Reduced errors by eliminating manual PID entry
- Added ability to refresh the process list without restarting the application