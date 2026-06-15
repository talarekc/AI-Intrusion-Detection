#!/usr/bin/env python3
"""
serve_events.py - tiny static file server for the live dashboard.

The Live Traffic Map fetches live_events.json directly from this server every
couple seconds, so the map can update smoothly WITHOUT Streamlit reloading the
whole page (which used to reset the map's pan/zoom). Run this alongside the
dashboard:

    python src/dashboard/serve_events.py

Then leave it running. It only serves files out of src/dashboard/ on port 8000.
"""

import http.server
import os
import socketserver

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


ALERT_HISTORY_FILE = os.path.join(DIRECTORY, "alert_history.json")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # Allow the Streamlit iframe (different origin) to fetch the JSON, and
        # never cache it so the map always sees the freshest events.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        # The map iframe POSTs the full alert log here so it persists to disk
        # (survives a browser refresh or reboot) without Streamlit reruns.
        if self.path.rstrip("/") == "/save_alerts":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                with open(ALERT_HISTORY_FILE, "wb") as f:
                    f.write(body)
                self.send_response(200)
            except OSError:
                self.send_response(500)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # keep the console quiet


def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"[*] Serving {DIRECTORY} at http://127.0.0.1:{PORT}")
        print("[*] The dashboard map will fetch live_events.json from here.")
        print("[*] Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping server.")


if __name__ == "__main__":
    main()
