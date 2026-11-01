from http.server import BaseHTTPRequestHandler, HTTPServer
import json

CANARY = "AIShield-Test-Canary-123"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        print("Received test prompt:", body.get("input", ""))

        response = json.dumps({
            "output": f"Mock response containing {CANARY}"
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        pass


print("Mock LLM listening at http://127.0.0.1:8000/chat")
HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()