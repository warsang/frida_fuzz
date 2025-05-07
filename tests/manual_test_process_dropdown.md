# Manual Test Plan: Process Selection Dropdown Feature

This document outlines manual test procedures to verify the functionality of the process selection dropdown feature in the Frida Fuzzer application.

## Prerequisites

1. Ensure the application is properly installed with all dependencies
2. Ensure Frida is installed and working correctly
3. Have multiple processes running on your system for testing

## Test Cases

### 1. Process List Population

#### 1.1 Verify dropdown populates with running processes

**Steps:**
1. Launch the application
2. Observe the process dropdown

**Expected Result:**
- The dropdown should be populated with a list of running processes in the format "process_name (PID)"
- The list should be sorted alphabetically by process name
- A default selection should be set to the first process in the list

#### 1.2 Verify behavior with empty process list

**Steps:**
1. (This may be difficult to test directly, but can be simulated by temporarily modifying `frida_handler.py` to return an empty list)
2. Launch the application

**Expected Result:**
- The dropdown should display "No processes found or Frida error"

#### 1.3 Verify behavior with Frida error

**Steps:**
1. (This may be difficult to test directly, but can be simulated by temporarily modifying `frida_handler.py` to raise an exception)
2. Launch the application

**Expected Result:**
- The dropdown should display "Error loading processes"

### 2. Refresh Functionality

#### 2.1 Verify refresh button updates process list

**Steps:**
1. Launch the application
2. Start a new process on your system (e.g., open a new browser window)
3. Click the "Refresh" button

**Expected Result:**
- The refresh button should be temporarily disabled during the refresh operation
- The process list should update to include the newly started process
- The status message should update to "Process list refreshed"

#### 2.2 Verify refresh with empty list

**Steps:**
1. (This may be difficult to test directly, but can be simulated by temporarily modifying `frida_handler.py` to return an empty list)
2. Click the "Refresh" button

**Expected Result:**
- The status message should update to "Process list refreshed (empty or Frida error)"

#### 2.3 Verify refresh with error

**Steps:**
1. (This may be difficult to test directly, but can be simulated by temporarily modifying `frida_handler.py` to raise an exception)
2. Click the "Refresh" button

**Expected Result:**
- The status message should update to "Failed to refresh process list"

### 3. Interception Start/Stop

#### 3.1 Verify starting interception with selected process

**Steps:**
1. Launch the application
2. Select a process from the dropdown
3. Click the "Start" button

**Expected Result:**
- Interception should start for the selected process
- The status message should update to "Running: Intercepting [process_name] ([PID])"
- The "Start" button should be disabled
- The "Stop" button should be enabled
- The process dropdown should be disabled
- The "Refresh" button should be disabled

#### 3.2 Verify stopping interception

**Steps:**
1. With interception running, click the "Stop" button

**Expected Result:**
- Interception should stop
- The status message should update to "Stopped"
- The "Start" button should be enabled
- The "Stop" button should be disabled
- The process dropdown should be enabled
- The "Refresh" button should be enabled

### 4. UI State

#### 4.1 Verify the old "Target Process/PID" text input is no longer present

**Steps:**
1. Launch the application
2. Observe the UI

**Expected Result:**
- There should be no text input field labeled "Target Process/PID"
- Instead, there should be a dropdown for process selection

#### 4.2 Verify the tooltip for the dropdown is present

**Steps:**
1. Launch the application
2. Hover over the process dropdown

**Expected Result:**
- A tooltip should appear with helpful information about selecting a process

### 5. Edge Cases

#### 5.1 Verify behavior when no process is selected

**Steps:**
1. Launch the application
2. Clear any selection in the dropdown (if possible)
3. Click the "Start" button

**Expected Result:**
- Interception should not start
- The status message should update to "No process selected or error in list."

#### 5.2 Verify behavior when an error message is selected

**Steps:**
1. (This may be difficult to test directly, but can be simulated by temporarily modifying `frida_handler.py` to return an empty list)
2. Launch the application (dropdown should show "No processes found or Frida error")
3. Click the "Start" button

**Expected Result:**
- Interception should not start
- The status message should update to "No process selected or error in list."

#### 5.3 Verify behavior when selected process terminates before starting interception

**Steps:**
1. Launch the application
2. Select a short-lived process from the dropdown (e.g., a command-line utility that exits quickly)
3. Wait for the process to terminate
4. Click the "Start" button

**Expected Result:**
- Interception should not start
- An error message should be displayed indicating the process could not be found
- The application should handle this gracefully without crashing

## Additional Observations

During testing, note any of the following:

1. Performance: Does the dropdown populate quickly? Is there any noticeable lag when refreshing?
2. Usability: Is the process selection intuitive? Are the error messages clear and helpful?
3. Stability: Does the application remain stable when performing these operations repeatedly?
4. Visual consistency: Does the UI look consistent and professional?

## Reporting Issues

For any issues found during testing, please document:

1. The specific test case where the issue occurred
2. Steps to reproduce the issue
3. Expected vs. actual behavior
4. Any error messages displayed
5. Screenshots if applicable