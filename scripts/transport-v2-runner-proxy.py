#!/usr/bin/env python3

import argparse
import ipaddress
import selectors
import socket
import socketserver


MAX_LINE = 4096
ALLOWED_HOSTS = frozenset()


class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline(MAX_LINE + 1)
        if len(request_line) > MAX_LINE:
            return
        parts = request_line.decode("ascii", "strict").strip().split()
        if len(parts) != 3 or parts[0] != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            return
        host, separator, port = parts[1].rpartition(":")
        if separator != ":" or host not in ALLOWED_HOSTS or port != "443":
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            return
        while True:
            header = self.rfile.readline(MAX_LINE + 1)
            if len(header) > MAX_LINE or not header:
                return
            if header in (b"\r\n", b"\n"):
                break
        with socket.create_connection((host, 443), timeout=5) as upstream:
            self.request.setblocking(False)
            upstream.setblocking(False)
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            selector = selectors.DefaultSelector()
            selector.register(self.request, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, self.request)
            try:
                while True:
                    events = selector.select(timeout=10)
                    if not events:
                        return
                    for key, _ in events:
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        key.data.sendall(data)
            finally:
                selector.close()


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--allow-host", action="append", required=True)
    args = parser.parse_args()
    ipaddress.ip_address(args.listen_host)
    if not 1 <= args.listen_port <= 65535:
        parser.error("listen port is outside 1..65535")
    if any(not host or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for character in host) for host in args.allow_host):
        parser.error("allow-host must be a DNS hostname")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    ALLOWED_HOSTS = frozenset(arguments.allow_host)
    with ProxyServer((arguments.listen_host, arguments.listen_port), ProxyHandler) as server:
        server.serve_forever()
