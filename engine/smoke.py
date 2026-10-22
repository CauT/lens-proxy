"""Local real-network smoke; no system proxy or trust-store changes."""
import http.client
import http.server
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"lens-smoke")

    def log_message(self, *args):
        pass


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory() as data:
        process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("engine.py")), "--proxy-port", str(port),
                                    "--data-dir", data], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            event = json.loads(process.stdout.readline())
            assert event["event"] == "ready", event
            assert Path(event["ca_cert"]).is_file(), event
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            client.request("GET", f"http://127.0.0.1:{server.server_port}/hello")
            response = client.getresponse()
            assert response.status == 200 and response.read() == b"lens-smoke"
            client.close()
            process.stdin.write(json.dumps({"command": "export_har", "command_id": "smoke"}) + "\n")
            process.stdin.flush()
            capture_id = None
            while True:
                event = json.loads(process.stdout.readline())
                if event.get("event") == "flow":
                    capture_id = event["flow"]["id"]
                if event.get("command_id") == "smoke":
                    assert len(event["value"]["log"]["entries"]) == 1, event
                    break
            process.stdin.write(json.dumps({"command": "repeat", "command_id": "repeat", "id": capture_id,
                                             "count": 3, "concurrency": 2}) + "\n")
            process.stdin.flush()
            while True:
                event = json.loads(process.stdout.readline())
                if event.get("event") == "repeat_done":
                    assert event["completed"] == 3 and event["failed"] == 0, event
                    break
            process.stdin.write(json.dumps({"command": "repeat", "command_id": "cancel-job", "id": capture_id,
                                             "count": 1000, "concurrency": 2, "interval_ms": 100}) + "\n")
            process.stdin.flush()
            while True:
                event = json.loads(process.stdout.readline())
                if event.get("event") == "repeat_progress" and event["completed"] >= 1:
                    process.stdin.write(json.dumps({"command": "cancel_repeat", "command_id": "cancel",
                                                     "job_id": event["job_id"]}) + "\n")
                    process.stdin.flush()
                    break
            while True:
                event = json.loads(process.stdout.readline())
                if event.get("event") == "repeat_done":
                    assert event["state"] == "cancelled" and event["cancelled"] > 0, event
                    assert event["completed"] + event["failed"] + event["cancelled"] == 1000, event
                    break
            process.stdin.write(json.dumps({"command": "shutdown", "command_id": "stop"}) + "\n")
            process.stdin.flush()
            process.wait(timeout=5)
            assert process.returncode == 0
            # Listener must be closed as part of shutdown.
            with socket.socket() as probe:
                assert probe.connect_ex(("127.0.0.1", port)) != 0
            print("PASS real HTTP forwarding, isolated CA, HAR, JSONL, repeat/cancel, shutdown/listener cleanup")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            errors = process.stderr.read()
            if errors:
                print(errors, file=sys.stderr)
            server.shutdown()


if __name__ == "__main__":
    main()
