import frida
import sys

def on_message(message, data):
    """
    Callback function to handle messages received from the Frida script.

    Args:
        message: Dictionary containing the message from Frida.
        data: Optional binary data sent with the message.
    """
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"Error: {message['stack']}")

def main():
    """
    Entry point for running the standalone Frida script.

    Attaches to the target process, injects the Frida JavaScript code,
    and sets up message handling.
    """
    device = frida.get_local_device()
    pid = device.get_process("TL-Win64-Test.exe").pid

    session = device.attach(pid)

    script = session.create_script("""
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
    """)

    script.on('message', on_message)
    script.load()

    print("Press Enter to stop...")
    sys.stdin.read()

    session.detach()

if __name__ == '__main__':
    main()
