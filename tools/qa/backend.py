"""
A backend that tells you exactly what it was asked.

Every proxy test needs to know the request nginx actually made, not the one it
was supposed to make.  A static file cannot tell you whether a path prefix was
removed before the request was forwarded, which Host header arrived, or whether
the upgrade headers for a websocket survived the hop.  This can, because it
echoes the request line and every header back as json.

Two ports.  The data port is the web server under test, and it runs as a child
process so it can be killed outright: a failover test needs a backend that
refuses connections, and closing a listening socket is not that, because nginx
holds idle upstream connections open and an already accepted request carries on
being answered.  The control port stays up in the parent so the test can give
the backend back afterwards.

Health is kept in a file rather than in memory, because the parent and the
child do not share memory and the control port lives in the parent.

    BACKEND_NAME=backend1 BACKEND_PORT=9101 python3 backend.py

The control port is the data port plus 100:

    /stop      kill the data server, so it refuses connections
    /start     give it back
    /sick      answer /health with 503, while still serving everything else
    /well      answer /health with 200 again
    /delay=N   wait N seconds before answering anything
"""
import http.server
import json
import multiprocessing
import os
import pathlib
import socketserver
import time

NAME = os.environ.get("BACKEND_NAME", "backend")
PORT = int(os.environ.get("BACKEND_PORT", "9101"))
STATE_FILE = pathlib.Path(f"/tmp/qa-backend-{PORT}.json")


def state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"healthy": True, "delay": 0.0}


def set_state(**kw):
    s = state()
    s.update(kw)
    STATE_FILE.write_text(json.dumps(s))
    return s


PAGE = """<!doctype html>
<html><head><title>%(name)s</title>
<link rel="stylesheet" href="/static/site.css">
</head><body>
<h1>%(name)s</h1>
<p>served by %(name)s at %(path)s</p>
<a href="/deep/page.html">relative link</a>
<a href="/absolute/page.html">root relative link</a>
<a href="https://origin.example.net/elsewhere">absolute link</a>
<img src="/static/logo.png">
<form action="/submit" method="post"><button>go</button></form>
</body></html>
"""


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _out(self, body=b"", code=200, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend", NAME)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _echo(self, extra=None):
        payload = {
            "backend": NAME,
            "method": self.command,
            "path": self.path,
            "http_version": self.request_version,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        payload.update(extra or {})
        self._out(json.dumps(payload, indent=1).encode(), ctype="application/json")

    def handle_one(self):
        st = state()
        if st.get("delay"):
            time.sleep(float(st["delay"]))
        path = self.path

        if path.startswith("/health"):
            if st.get("healthy", True):
                return self._out(b"ok", ctype="text/plain")
            return self._out(b"sick", code=503, ctype="text/plain")

        if path.startswith("/echo") or self.headers.get("X-Qa-Echo"):
            return self._echo()

        if path.startswith("/redirect-abs"):
            # The shape a real backend produces for a directory without its
            # trailing slash: an absolute URL built from the Host header.
            host = self.headers.get("Host", "localhost")
            return self._out(b"", code=301,
                             extra={"Location": f"http://{host}/landed/"})
        if path.startswith("/redirect-here"):
            return self._out(b"", code=302, extra={"Location": "/landed"})
        if path.startswith("/redirect-me"):
            return self._out(b"", code=302,
                             extra={"Location": "http://origin.example.net/moved"})
        if path.startswith("/set-cookie"):
            return self._out(b"cookie set", ctype="text/plain",
                             extra={"Set-Cookie": "sid=abc; Path=/app; HttpOnly"})
        if path.startswith("/big/"):
            n = int(path.rsplit("/", 1)[-1].split("?")[0] or 1024)
            return self._out(b"x" * n, ctype="text/plain")
        if path.startswith("/status/"):
            return self._out(b"forced status",
                             code=int(path.split("/status/")[1].split("?")[0]),
                             ctype="text/plain")
        if path.startswith("/static/site.css"):
            return self._out(b"body { color: #123456 }", ctype="text/css")
        if path.startswith("/page.html") or path.startswith("/new/"):
            return self._out((PAGE % {"name": NAME, "path": path}).encode())
        if path.startswith("/cacheable-page"):
            return self._out(b"<html><body>a page worth caching</body></html>")
        if path.startswith("/compressible"):
            return self._out(("hello " * 500).encode(), ctype="text/plain")
        if path.startswith("/slow"):
            time.sleep(float(path.split("/slow/")[1]) if "/slow/" in path else 5)
            return self._out(b"slow done", ctype="text/plain")

        return self._out((PAGE % {"name": NAME, "path": path}).encode())

    def do_GET(self):
        self.handle_one()

    def do_HEAD(self):
        self.handle_one()

    def do_DELETE(self):
        self.handle_one()

    def do_OPTIONS(self):
        self.handle_one()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = b""
        remaining = n
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        self._echo({"bytes_received": len(data)})

    def do_PUT(self):
        self.do_POST()


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve():
    S(("0.0.0.0", PORT), H).serve_forever()


CHILD = {"proc": None}


def start_main():
    if CHILD["proc"] and CHILD["proc"].is_alive():
        return "already up"
    pr = multiprocessing.Process(target=_serve, daemon=True)
    pr.start()
    CHILD["proc"] = pr
    time.sleep(0.4)
    return "up"


def stop_main():
    pr = CHILD["proc"]
    if not pr or not pr.is_alive():
        return "already down"
    pr.terminate()
    pr.join(5)
    CHILD["proc"] = None
    return "down"


class Ctl(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/stop"):
            out = stop_main()
        elif self.path.startswith("/start"):
            out = start_main()
        elif self.path.startswith("/sick"):
            set_state(healthy=False); out = "sick"
        elif self.path.startswith("/well"):
            set_state(healthy=True); out = "well"
        elif self.path.startswith("/delay="):
            set_state(delay=float(self.path.split("=")[1])); out = "delay set"
        else:
            alive = bool(CHILD["proc"] and CHILD["proc"].is_alive())
            out = json.dumps({"listening": alive, **state()})
        body = out.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    set_state(healthy=True, delay=0.0)
    start_main()
    print(f"{NAME} on {PORT}, control on {PORT + 100}", flush=True)
    S(("0.0.0.0", PORT + 100), Ctl).serve_forever()
