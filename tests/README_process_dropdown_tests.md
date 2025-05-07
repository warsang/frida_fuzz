# Process Selection Dropdown Feature Tests

This directory contains test files for the process selection dropdown feature implemented in `app.py` and `fridafuzzer_core/frida_handler.py`.

## Overview

The process selection dropdown feature allows users to:
1. View a list of running processes in a dropdown
2. Refresh the list of processes
3. Select a process for interception
4. Start and stop interception with the selected process

## Test Files

- **`test_process_dropdown.py`**: Unit tests for the process dropdown functionality
- **`run_process_dropdown_tests.py`**: Script to run the automated tests
- **`manual_test_process_dropdown.md`**: Manual test plan with step-by-step instructions
- **`process_dropdown_test_report_template.md`**: Template for documenting test results

## Running Automated Tests

To run the automated tests:

```bash
python tests/run_process_dropdown_tests.py
```

Or:

```bash
cd tests
python run_process_dropdown_tests.py
```

## Performing Manual Tests

1. Review the manual test plan in `manual_test_process_dropdown.md`
2. Launch the application and follow the test steps
3. Document your findings using the report template in `process_dropdown_test_report_template.md`

## Test Coverage

The tests cover the following scenarios:

### Automated Tests
- Process list population
  - Success case with sorted list
  - Empty list case
  - Exception handling
- Refresh functionality
  - Success case
  - Empty list case
  - Failure case
- Interception start/stop
  - Success case
  - No selection case
  - Error selection case
  - Invalid selection case
  - Stop interception case
- Frida handler functionality
  - Get process list success
  - Transport error handling
  - General exception handling

### Manual Tests
- UI state verification
- Visual elements and tooltips
- Edge cases that are difficult to automate
- Performance and usability observations

## Notes for Testers

- Some test cases may require modifying code temporarily to simulate error conditions
- Screenshots are helpful when documenting UI-related issues
- Pay special attention to error handling and edge cases
- Note any performance issues or usability concerns

## Reporting Issues

When reporting issues:
1. Be specific about which test case failed
2. Provide steps to reproduce
3. Include expected vs. actual behavior
4. Add screenshots if applicable
5. Note the environment details (OS, Frida version, etc.)