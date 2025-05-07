import frida
import sys
import threading
import time
from queue import Queue
import json # Import json for parsing messages

# Global variables to hold Frida session and script
# These might be better managed within a class if complexity grows
_session = None
_script = None
_message_queue = None
_console_queue = Queue()  # Queue for console logs
_stop_event = threading.Event() # To signal the message processing thread to stop

def _on_message(message, data):
    """
    Internal callback function for Frida messages.
    Parses the message and puts it into the shared queue.
    """
    global _message_queue
    if _message_queue is None:
        print("Error: Message queue not initialized.", file=sys.stderr)
        return

    try:
        if message['type'] == 'send':
            # The payload should already be a JSON object from our JS
            payload = message['payload']
            # Make sure type field is preserved for Streamlit
            if 'type' not in payload:
                payload['type'] = 'sequence'  # Default to sequence type for data messages
            # Add a timestamp from the Python side
            payload['timestamp'] = time.time()
            # Format and store console log
            console_log = json.dumps(payload, indent=2)
            print(console_log)  # Print to console
            _console_queue.put(console_log)  # Store for Streamlit
            # Put in queue for Streamlit sequence processing
            _message_queue.put(payload)
            print(f"Queue size after put: {_message_queue.qsize()}")
        elif message['type'] == 'error':
            # Format error message
            error_msg = f"[Frida JS Error] {message.get('source', 'unknown')}: {message.get('description', str(message))}"
            # Log to stderr
            print(error_msg, file=sys.stderr)
            # Add to console queue for UI
            _console_queue.put(error_msg)
            # Put error messages in the queue for UI notifications
            _message_queue.put({'type': 'error', 'description': message.get('description', str(message)), 'stack': message.get('stack')})
    except Exception as e:
        print(f"Error processing Frida message: {e}", file=sys.stderr)
        print(f"Original message: {message}", file=sys.stderr)


def start_frida(target_process, message_queue: Queue) -> tuple[bool, Queue]:
    """
    Attaches Frida to the target process, loads the script, and starts listening.

    Args:
        target_process (str or int): The process name (str) or PID (int).
        message_queue (Queue): The queue to put received messages into.

    Returns:
        bool: True if successful, False otherwise.
    """
    global _session, _script, _message_queue, _stop_event
    _message_queue = message_queue
    print(f"Message queue initialized. Queue object: {_message_queue}, Queue size: {_message_queue.qsize()}")
    _stop_event.clear() # Ensure stop event is clear before starting

    try:
        print(f"Attempting to attach to target: {target_process}")
        device = frida.get_local_device()

        # Try attaching by PID first if target is an integer
        if isinstance(target_process, int):
            print(f"Attaching by PID: {target_process}")
            _session = device.attach(target_process)
        # Otherwise, try attaching by process name
        elif isinstance(target_process, str):
            print(f"Attaching by name: {target_process}")
            # Find the process PID - use enumerate_processes for better matching
            processes = device.enumerate_processes()
            target_pid = None
            for process in processes:
                if target_process.lower() in process.name.lower():
                    target_pid = process.pid
                    print(f"Found process '{process.name}' with PID: {target_pid}")
                    break
            if target_pid is None:
                 raise frida.ProcessNotFoundError(f"Process matching '{target_process}' not found.")
            _session = device.attach(target_pid)
        else:
            raise ValueError("target_process must be a string (name) or integer (PID)")

        print("Attached successfully.")

        # Define the Frida JavaScript code directly
        frida_script_js = """
    // Helper function to convert ArrayBuffer to hex string
    function arrayBufferToHex(buffer) {
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    }

    // Function to format backtrace (simplified for JSON)
    function formatBacktrace(backtrace) {
        return backtrace
            .map(DebugSymbol.fromAddress)
            .map(symbol => `${symbol.address} -> ${symbol.name || "???"}`); // Return as an array of strings
    }

    // Function to get hex string from buffer
    function getHexData(ptr, length) {
        if (length <= 0) {
            return ""; // Return empty string for zero length
        }
        try {
            const buffer = ptr.readByteArray(length);
            return arrayBufferToHex(buffer);
        } catch (e) {
            // Send error back to Python side if reading fails
            send({ type: 'error', source: 'getHexData', message: `Error reading buffer: ${e.message}` });
            return ""; // Return empty string on error
        }
    }

    function getSocketInfo(socket) {
        try {
            const addrSize = 16;
            const sockAddr = Memory.alloc(addrSize);
            const lenPtr = Memory.alloc(4);
            Memory.writeU32(lenPtr, addrSize);

            const getpeername = new NativeFunction(
                Module.getExportByName(null, 'getpeername'),
                'int',
                ['int', 'pointer', 'pointer']
            );

            const result = getpeername(socket, sockAddr, lenPtr);

            if (result === 0) {
                const family = sockAddr.readU16();
                const port = ((sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8());
                let addr = '';

                if (family === 2) { // AF_INET
                    addr = [4, 5, 6, 7].map(i => sockAddr.add(i).readU8()).join('.');
                    return `${addr}:${port}`;
                } else if (family === 23) { // AF_INET6
                    // Handle IPv6 if needed
                    return 'IPv6 address';
                }
            }
            return 'Unable to get peer address';
        } catch (e) {
            return `Error getting socket info: ${e.message}`;
        }
    }

    var sendFunctions = ['send', 'sendto'];
    var recvFunctions = ['recv', 'recvfrom'];

    sendFunctions.forEach(function(funcName) {
        Interceptor.attach(Module.getExportByName(null, funcName), {
            onEnter: function(args) {
                try {
                    var socket = args[0].toInt32();
                    var buf = args[1];
                    var len = args[2].toInt32();
                    var flags = args[3].toInt32();

                    var socketInfo = getSocketInfo(socket);
                    var backtrace_raw = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    const hexData = getHexData(buf, len); // Use the new function

                    // Construct JSON payload
                    const payload = {
                        type: 'sequence', // Indicate this is sequence data
                        function_name: funcName,
                        socket_id: socket,
                        socket_info: socketInfo,
                        buffer_length: len,
                        flags: flags,
                        hex_data: hexData, // Send raw hex string
                        backtrace: formatBacktrace(backtrace_raw) // Send formatted backtrace array
                    };
                    send(payload); // Send the JSON object
                } catch (e) {
                    // Send error back to Python side
                    send({ type: 'error', source: 'onEnter', message: `Error in ${funcName}: ${e.message}` });
                }
            },
            onLeave: function(retval) {
                // Optionally send return value info (can be filtered in Python)
                send({ type: 'return', function_name: funcName, retval: retval.toInt32() });
            }
        });
    });

    // Hook receive functions
    recvFunctions.forEach(function(funcName) {
        Interceptor.attach(Module.getExportByName(null, funcName), {
            onEnter: function(args) {
                try {
                    // Store arguments for use in onLeave
                    this.socket = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                    this.flags = args[3].toInt32();
                    this.socketInfo = getSocketInfo(this.socket);
                    this.backtrace_raw = Thread.backtrace(this.context, Backtracer.ACCURATE);
                } catch (e) {
                    send({ type: 'error', source: 'onEnter', message: `Error in ${funcName}: ${e.message}` });
                }
            },
            onLeave: function(retval) {
                try {
                    const bytesReceived = retval.toInt32();
                    if (bytesReceived > 0) {
                        // Only get data if we actually received something
                        const hexData = getHexData(this.buf, bytesReceived);
                        
                        // Construct JSON payload
                        const payload = {
                            type: 'sequence',
                            function_name: funcName,
                            socket_id: this.socket,
                            socket_info: this.socketInfo,
                            buffer_length: bytesReceived,
                            flags: this.flags,
                            hex_data: hexData,
                            backtrace: formatBacktrace(this.backtrace_raw),
                            direction: 'receive' // Add direction to distinguish from send
                        };
                        send(payload);
                    }
                    // Send return value info
                    send({ type: 'return', function_name: funcName, retval: bytesReceived });
                } catch (e) {
                    send({ type: 'error', source: 'onLeave', message: `Error in ${funcName}: ${e.message}` });
                }
            }
        });
    });
    """

        _script = _session.create_script(frida_script_js)
        print("Script created.")

        # Set the message handler
        _script.on('message', _on_message)
        print("Message handler set.")

        # Load the script
        _script.load()
        print("Script loaded and running.")

        # Optional: Start a separate thread to process messages if needed,
        # but Streamlit's loop might be sufficient if checked frequently.

        return True, _console_queue

    except frida.ProcessNotFoundError as e:
        print(f"Error attaching to process: {e}", file=sys.stderr)
        _session = None
        _script = None
        return False
    except frida.TransportError as e:
         print(f"Frida transport error (is frida-server running?): {e}", file=sys.stderr)
         _session = None
         _script = None
         return False
    except Exception as e:
        print(f"An unexpected error occurred during Frida setup: {e}", file=sys.stderr)
        if _session:
            try:
                _session.detach()
            except Exception as detach_err:
                 print(f"Error detaching session during cleanup: {detach_err}", file=sys.stderr)
        _session = None
        _script = None
        return False

def stop_frida():
    """
    Detaches Frida from the process.
    """
    global _session, _script, _stop_event, _console_queue
    _stop_event.set() # Signal any background threads to stop
    
    # Clear any remaining console messages
    while not _console_queue.empty():
        try:
            _console_queue.get_nowait()
        except:
            pass

    if _session:
        try:
            print("Detaching Frida session...")
            _session.detach()
            print("Session detached.")
        except frida.InvalidOperationError:
             print("Session already detached or invalid.", file=sys.stderr)
        except Exception as e:
            print(f"Error detaching Frida session: {e}", file=sys.stderr)
        finally:
            _session = None
            _script = None
            # _message_queue = None # Keep queue reference for Streamlit? Or clear? Let Streamlit manage it.
    else:
        print("No active Frida session to detach.")

# Example of how a background thread could process the queue if needed
# (Not strictly necessary if Streamlit checks the queue in its main loop)
# def _process_messages():
#     global _message_queue, _stop_event
#     while not _stop_event.is_set():
#         try:
#             message = _message_queue.get(timeout=0.1) # Timeout to allow checking stop_event
#             # Process the message here or notify the main thread
#             print(f"Processed message: {message}")
#             _message_queue.task_done()
#         except queue.Empty:
#             continue
#         except Exception as e:
#             print(f"Error in message processing thread: {e}", file=sys.stderr)

def get_process_list():
    """
    Get a list of running processes that Frida can attach to.
    
    Returns:
        list: A list of tuples (process_name, pid, display_string)
              Returns an empty list if an error occurs.
    """
    try:
        device = frida.get_local_device()
        processes = device.enumerate_processes()
        process_list = []
        for process in processes:
            display_string = f"{process.name} ({process.pid})"
            process_list.append((process.name, process.pid, display_string))
        process_list.sort(key=lambda x: x[0].lower())  # Sort alphabetically by process name
        return process_list
    except frida.TransportError as e:
        print(f"Frida transport error: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error getting process list: {e}", file=sys.stderr)
        return []