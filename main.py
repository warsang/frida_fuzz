import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"Error: {message['stack']}")

def main():
    device = frida.get_local_device()
    pid = device.get_process("TL-Win64-Test.exe").pid

    session = device.attach(pid)

    script = session.create_script("""
    function formatBacktrace(backtrace) {
        return backtrace
            .map(DebugSymbol.fromAddress)
            .map(function(symbol) {
                var name = symbol.name || "???";
                return `\\t${symbol.address} -> ${name}`;
            })
            .join('\\n');
    }

     function formatHexdump(ptr, length) {
        try {
            const arr = new Uint8Array(ptr.readByteArray(length));
            let result = '';
            let ascii = '';
            let offset = 0;

            for (let i = 0; i < arr.length; i++) {
                if (i % 16 === 0) {
                    if (i !== 0) {
                        result += '  ' + ascii + '\\n';
                        ascii = '';
                    }
                    offset = i.toString(16).padStart(4, '0');
                    result += offset + '  ';
                }
                
                const byte = arr[i];
                result += byte.toString(16).padStart(2, '0') + ' ';
                ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                
                if ((i + 1) % 16 === 0 || i === arr.length - 1) {
                    const padding = '   '.repeat(15 - (i % 16));
                    result += padding + '  ' + ascii;
                    if (i !== arr.length - 1) {
                        result += '\\n';
                    }
                }
            }
            return result;
        } catch (e) {
            return `Error reading buffer: ${e.message}`;
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
                    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    const hexDump = (len > 0) ? formatHexdump(buf, len) : "Empty buffer";

                    send(funcName + '() called:\\n' +
                         '  Socket: ' + socket + '\\n' +
                         '  Remote: ' + socketInfo + '\\n' +
                         '  Buffer Length: ' + len + ' bytes\\n' +
                         '  Flags: ' + flags + '\\n' +
                         '\\nBuffer Contents:\\n' + hexDump + '\\n' +
                         '\\nCallstack (address -> function):\\n' + formatBacktrace(backtrace));
                } catch (e) {
                    send(`Error in onEnter: ${e.message}`);
                }
            },
            onLeave: function(retval) {
                send(funcName + '() returned: ' + retval);
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
