"""
A pretend robot for the development compose stack - deliberately insecure:

  9090  rosbridge (WebSocket handshake accepted without a token)
  23    a telnet-style plaintext login prompt
  8080  an HTTP JSON API that needs no login

Started as `python fake_robot.py [name]`. Only for the isolated `robotnet`
network in compose.dev.yaml.
"""

import base64
import hashlib
import json
import re
import socketserver
import sys
import threading

NAME = sys.argv[1] if len(sys.argv) > 1 else "fake-robot"


class Logged(socketserver.BaseRequestHandler):
    def setup(self):
        print(f"{NAME}: connection from {self.client_address[0]} to port {self.server.server_address[1]}", flush=True)


class Rosbridge(Logged):
    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        key = re.search(rb"(?i)sec-websocket-key:\s*(\S+)", data)
        if key:
            accept = base64.b64encode(hashlib.sha1(key.group(1) + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            self.request.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                 b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        else:
            body = b'Can "Upgrade" only to "WebSocket".'
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nServer: TornadoServer/6.1\r\nContent-Length: "
                                 + str(len(body)).encode() + b"\r\n\r\n" + body)


class Telnet(Logged):
    def handle(self):
        self.request.sendall(f"{NAME} controller\r\nlogin: ".encode())


class Api(Logged):
    def handle(self):
        self.request.recv(4096)
        body = json.dumps({"robot": NAME, "state": "idle", "battery": 87}).encode()
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\n\r\n" + body)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    servers = [Server(("0.0.0.0", 9090), Rosbridge), Server(("0.0.0.0", 23), Telnet), Server(("0.0.0.0", 8080), Api)]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"{NAME}: rosbridge 9090, telnet 23, api 8080", flush=True)
    servers[0].serve_forever()
