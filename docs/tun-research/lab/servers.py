# Runs inside "the internet" namespace B: HTTP + UDP echo that report who connected.
import socket, threading, sys, http.server, socketserver
HOST = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"peer={self.client_address[0]}\n".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True; allow_reuse_address = True
threading.Thread(target=TS((HOST, 8080), H).serve_forever, daemon=True).start()


class H204(http.server.BaseHTTPRequestHandler):
    """connectivitycheck.gstatic.com/generate_204 stand-in for elf-gate's connection check."""

    def do_GET(self):
        self.send_response(204); self.end_headers()

    def log_message(self, *a): pass


try:
    threading.Thread(target=TS((HOST, 80), H204).serve_forever, daemon=True).start()
except OSError:
    pass
def echo(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((HOST, port))
    while True:
        data, peer = u.recvfrom(65535)
        u.sendto(f"peer={peer[0]}:{peer[1]}|".encode() + data, peer)
threading.Thread(target=echo, args=(443,), daemon=True).start()
echo(5000)
