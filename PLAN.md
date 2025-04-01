# Frida Network Interceptor UI - Plan

This document outlines the plan for creating a Streamlit UI for intercepting network traffic using Frida, saving sequences, and providing a diffing feature.

**Core Requirements:**

*   Intercept `send`/`sendto` calls using Frida.
*   Display captured data (hexdumps, socket info) in a Streamlit UI.
*   Store captured data as numbered sequences.
*   Allow users to configure the target process name or PID.
*   Persist captured sequences to a file (`sequences.json`).
*   Provide a side-by-side diff view for comparing two selected sequences.

**Phased Implementation:**

**Phase 1: Refactoring and Basic Structure**

1.  **Separate Concerns:**
    *   Modify Frida JS to send structured JSON (function name, socket info, raw hex string) to Python.
    *   Create `app.py` for Streamlit UI.
    *   Create `frida_handler.py` for Frida interaction logic.
2.  **Create Streamlit App (`app.py`):**
    *   Import `streamlit`, `frida`, `json`, `difflib`, `pathlib`, `queue`.
    *   Define `SAVE_FILE = pathlib.Path("sequences.json")`.
    *   Use `st.session_state` for: `sequences`, `frida_session`, `frida_script`, `is_running`, `target_process`, `message_queue`.
3.  **Basic UI Layout (`app.py`):**
    *   Title: "Frida Network Interceptor".
    *   Input: `st.text_input("Target Process Name or PID:", key="target_process_input")`.
    *   Buttons: Start/Stop in columns.
    *   Status indicator.

**Phase 2: Frida Integration & Persistence**

1.  **Loading Sequences (`app.py`):**
    *   `load_sequences()` function called on startup. Reads `SAVE_FILE` if exists, populates `st.session_state.sequences`, handles errors. Initializes empty list otherwise.
2.  **Frida Control Logic (`app.py` calling `frida_handler.py`):**
    *   "Start" button -> `start_frida(target, message_queue)`: Attaches Frida, loads script, sets up `on_message` to use queue, stores session/script in state, updates `is_running`.
    *   "Stop" button -> `stop_frida()`: Detaches session, updates `is_running`.
3.  **Message Handling & Saving (`frida_handler.py` and `app.py`):**
    *   Python `on_message(message, data)` (in `frida_handler`): Parses JSON, adds timestamp/ID, puts dict into `st.session_state.message_queue`.
    *   Main loop (`app.py`): Checks queue periodically. If items exist, get them, append to `st.session_state.sequences`, call `save_sequences()`.
    *   `save_sequences()` (`app.py`): Writes `st.session_state.sequences` to `SAVE_FILE` as JSON.
    *   Use `st.experimental_rerun()` after processing queue items.

**Phase 3: Displaying Captured Sequences (`app.py`)**

1.  **Sequence List:**
    *   Iterate `st.session_state.sequences`.
    *   Use `st.expander` for each sequence (e.g., `f"Sequence {seq['id']}: {seq['function']} ({len(seq['hex_data']) // 2} bytes)"`).
    *   Inside: Display Timestamp, Socket Info, Full Hexdump (`st.code(seq['hex_data'])`).

**Phase 4: Implementing Diffing (`app.py`)**

1.  **Sequence Selection:**
    *   Two `st.selectbox` widgets in columns for "Sequence A" and "Sequence B", populated from `st.session_state.sequences`.
2.  **Diff Logic:**
    *   Retrieve `hex_data` for selected sequences.
    *   Use `difflib.ndiff` or similar.
    *   Helper function to format `ndiff` output into two strings for side-by-side view.
3.  **Display Diff:**
    *   Use `st.columns(2)`.
    *   Left column: Sequence A diff view (`st.code` or `st.text_area`).
    *   Right column: Sequence B diff view (`st.code` or `st.text_area`).

**Mermaid Diagram:**

```mermaid
graph TD
    subgraph Streamlit UI (app.py)
        A[User Input: Target Process] --> B{Start Button};
        B -- Click --> C[Call start_frida];
        F{Stop Button} -- Click --> G[Call stop_frida];

        P[load_sequences() on Startup] --> W[st.session_state.sequences];
        Y[Main Loop: Check Queue] --> Y1[Get from Queue];
        Y1 -- Updates --> W;
        Y1 --> Q[Call save_sequences()];
        Y1 --> J[st.experimental_rerun];


        I[Sequence Display Area] <-- J;
        K[Diff Selection] --> L[Select Seq A & B];
        L --> M[Retrieve Hexdumps from W];
        M --> N[Format Diff (Side-by-Side)];
        N --> O[Display Diff Result in Columns] --> J;

    end

    subgraph Frida Handling (frida_handler.py)
        C --> D[Attach Frida];
        D --> E[Load JS Script w/ on_message];
        E --> R(Target Process);
        G --> H[Detach Frida];

        V[Python on_message Callback] -- Puts --> X[st.session_state.message_queue];
    end

    subgraph Frida JS
        R -- Intercepts --> S[send/sendto];
        S -- Data --> T(JS Script);
        T -- Formats Data (JSON) --> U[JS send()];
        U -- Message --> V;
    end

    subgraph Data Flow & State
        X <-- V;
        Y1 --> X;
        W <--> Z[sequences.json File];
        P --> Z;
        Q --> Z;
    end
```

**Future Considerations:**

*   Fuzzy diffing.
*   Ability to define relationships between hex blocks within the diff view.