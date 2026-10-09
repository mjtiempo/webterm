#!/usr/bin/env python3
"""
webterm - a browser terminal in front of a local shell, protected by a password.

Standard library only. One password per instance, session cookie auth, one PTY
per terminal, output pushed to the browser over Server-Sent Events and
keystrokes POSTed back. Nothing here parses terminal traffic, so long-lived
streams (a build, top, an editor) work through proxies and TLS-terminating
tunnels such as opentunnel.

    ./server.py --port 7681                    # prints a generated passphrase
    ./server.py --port 7681 --password-hash "$(./server.py --print-hash)"

Then open http://127.0.0.1:7681/. Bind defaults to loopback; put TLS in front
(a tunnel, a reverse proxy) if you want to reach it from elsewhere.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import pty
import random
import secrets
import select
import signal
import struct
import sys
import termios
import threading
import time
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# --- tuning -----------------------------------------------------------------

COOKIE = "webterm_session"
MAX_CHUNK = 128 * 1024          # largest payload in one SSE event
MAX_BUFFER = 1 << 20            # scrollback kept per terminal
HEARTBEAT = 15.0                # seconds between SSE keepalives
VENDOR_CACHE = "public, max-age=604800"   # fonts and js are big; let browsers keep them
MAX_BODY = 2 << 20              # request body cap
SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32, maxmem=64 << 20)
LOGIN_FAILURES = 5              # per IP, per minute

# Unambiguous alphanumerics (no 0/O/I/l) plus specials that stay safe when
# single-quoted on a shell, so a generated passphrase survives being read aloud
# and pasted into --password, WEBTERM_PASSWORD or a password manager.
PASSPHRASE_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
PASSPHRASE_LOWER = "abcdefghijkmnopqrstuvwxyz"
PASSPHRASE_DIGITS = "23456789"
PASSPHRASE_SPECIAL = "!@#$%^&*()-_=+[]{}?"
PASSPHRASE_ALPHABET = PASSPHRASE_UPPER + PASSPHRASE_LOWER + PASSPHRASE_DIGITS + PASSPHRASE_SPECIAL
PASSPHRASE_LENGTH = 24          # 24 x log2(76) ≈ 150 bits


def generate_passphrase(length: int = PASSPHRASE_LENGTH) -> str:
    """A random passphrase holding at least one of every character class."""
    pools = (PASSPHRASE_UPPER, PASSPHRASE_LOWER, PASSPHRASE_DIGITS, PASSPHRASE_SPECIAL)
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(PASSPHRASE_ALPHABET) for _ in range(max(0, length - len(pools)))]
    random.SystemRandom().shuffle(chars)   # otherwise the classes would sit in fixed order
    return "".join(chars)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return hmac.compare_digest(digest, expected)


# --- sessions ---------------------------------------------------------------


class Sessions:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self.lock = threading.Lock()
        self.tokens: dict[str, dict] = {}

    def create(self, ip: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.tokens[token] = {"ip": ip, "expires": time.time() + self.ttl}
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self.lock:
            entry = self.tokens.get(token)
            if entry is None:
                return False
            if entry["expires"] < time.time():
                del self.tokens[token]
                return False
            return True

    def drop(self, token: str | None) -> None:
        if token:
            with self.lock:
                self.tokens.pop(token, None)

    def reap(self) -> None:
        now = time.time()
        with self.lock:
            for token in [t for t, e in self.tokens.items() if e["expires"] < now]:
                del self.tokens[token]


# --- the PTY ----------------------------------------------------------------


class Terminal:
    """A shell on a PTY with a byte ring buffer any number of readers share."""

    def __init__(self, argv: list[str], cwd: str, cols: int, rows: int, session: str):
        self.id = secrets.token_hex(8)
        self.session = session
        self.shell = argv[0]
        self.argv = argv
        self.cols, self.rows = cols, rows
        self.cond = threading.Condition()
        self.buffer = bytearray()     # buffer[0] is absolute offset base_offset
        self.base_offset = 0
        self.seq = 0                  # absolute bytes ever produced
        self.closed = False
        self.exit_code: int | None = None
        self.closed_at: float | None = None
        self.subscribers = 0
        self.last_seen = time.monotonic()

        pid, fd = pty.fork()
        if pid == 0:  # child: becomes the session leader on the pty
            try:
                env = dict(os.environ)
                env["TERM"] = "xterm-256color"
                env["COLORTERM"] = "truecolor"
                env["WEBTERM"] = "1"
                env.pop("WEBTERM_PASSWORD", None)
                env.pop("WEBTERM_PASSWORD_HASH", None)
                os.chdir(cwd)
                os.execvpe(argv[0], argv, env)
            except BaseException:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.resize(cols, rows)
        self.thread = threading.Thread(target=self._read_loop, name=f"pty-{self.id}", daemon=True)
        self.thread.start()

    # -- pty side ------------------------------------------------------------

    def _read_loop(self) -> None:
        """Copy pty output into the shared buffer, batching bursts a little so a
        command that writes many small chunks becomes a few SSE events."""
        while True:
            try:
                ready, _, _ = select.select([self.fd], [], [], 1.0)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            batch = bytearray()
            while len(batch) < MAX_CHUNK:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:  # EIO once the child's pty is gone
                    ready = False
                    break
                if not data:
                    ready = False
                    break
                batch += data
                # 5 ms of quiet, or a full batch, ends the burst
                try:
                    more, _, _ = select.select([self.fd], [], [], 0.005)
                except (OSError, ValueError):
                    more = []
                if not more:
                    break
            if not ready:
                if batch:
                    self._publish(bytes(batch))
                break
            self._publish(bytes(batch))

        status = None
        try:
            status = os.waitpid(self.pid, 0)[1]
        except (ChildProcessError, OSError):
            pass
        with self.cond:
            self.closed = True
            self.closed_at = time.monotonic()
            if status is not None:
                self.exit_code = os.waitstatus_to_exitcode(status)
            self.cond.notify_all()
        try:
            os.close(self.fd)
        except OSError:
            pass

    def _publish(self, data: bytes) -> None:
        with self.cond:
            self.buffer += data
            self.seq += len(data)
            overflow = len(self.buffer) - MAX_BUFFER
            if overflow > 0:
                del self.buffer[:overflow]
                self.base_offset += overflow
            self.cond.notify_all()

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    def write(self, data: bytes) -> bool:
        self.last_seen = time.monotonic()
        if self.closed:
            return False
        try:
            os.write(self.fd, data)
            return True
        except OSError:
            return False

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def close(self) -> None:
        if self.closed:
            return
        try:
            os.killpg(self.pid, signal.SIGHUP)
        except OSError:
            pass


# --- application state ------------------------------------------------------


class TooManyTerminals(Exception):
    pass


class App:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.verbose = args.verbose
        self.password_hash = resolve_password(args)
        self.sessions = Sessions(args.session_ttl)
        self.terminals: dict[str, Terminal] = {}
        self.lock = threading.Lock()
        self.failures: dict[str, deque[float]] = {}
        self.stopping = False

    # -- auth ----------------------------------------------------------------

    def login_allowed(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            attempts = self.failures.setdefault(ip, deque())
            while attempts and attempts[0] < now - 60:
                attempts.popleft()
            return len(attempts) < LOGIN_FAILURES

    def record_failure(self, ip: str) -> None:
        with self.lock:
            self.failures.setdefault(ip, deque()).append(time.time())

    def clear_failures(self, ip: str) -> None:
        with self.lock:
            self.failures.pop(ip, None)

    # -- terminals -----------------------------------------------------------

    def spawn(self, session: str, cols: int, rows: int) -> Terminal:
        argv = [self.args.shell, "-l"]
        with self.lock:
            live = sum(1 for t in self.terminals.values() if t.session == session)
            if live >= self.args.max_terminals_per_session:
                raise TooManyTerminals("too many terminals for this session")
            if len(self.terminals) >= self.args.max_terminals:
                raise TooManyTerminals("server terminal limit reached")
        term = Terminal(argv, self.args.cwd, cols, rows, session)
        with self.lock:
            self.terminals[term.id] = term
        return term

    def terminal(self, tid: str, session: str) -> Terminal | None:
        with self.lock:
            term = self.terminals.get(tid)
        if term is None or term.session != session:
            return None
        return term

    def kill_terminal(self, term: Terminal) -> None:
        term.close()
        with self.lock:
            self.terminals.pop(term.id, None)

    def drop_session(self, token: str) -> None:
        with self.lock:
            doomed = [t for t in self.terminals.values() if t.session == token]
        for term in doomed:
            self.kill_terminal(term)
        self.sessions.drop(token)

    def reap_loop(self) -> None:
        idle = self.args.idle_timeout
        while not self.stopping:
            time.sleep(10)
            now = time.monotonic()
            self.sessions.reap()
            with self.lock:
                doomed = [
                    t for t in self.terminals.values()
                    if (t.closed and t.closed_at and now - t.closed_at > 120)
                    or (not t.closed and t.subscribers == 0 and now - t.last_seen > idle)
                ]
            for term in doomed:
                self.kill_terminal(term)

    def shutdown(self) -> None:
        self.stopping = True
        with self.lock:
            terms = list(self.terminals.values())
        for term in terms:
            self.kill_terminal(term)


def resolve_password(args: argparse.Namespace) -> str:
    if args.password_hash:
        return args.password_hash
    if args.password:
        return hash_password(args.password)
    generated = generate_passphrase()
    print(f"webterm: generated password for this run: {generated}", file=sys.stderr)
    print("webterm: set it with --password, WEBTERM_PASSWORD or --password-hash to pin your own",
          file=sys.stderr)
    return hash_password(generated)


# --- HTTP -------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "webterm"
    disable_nagle_algorithm = True

    STATIC = {
        "/": ("index.html", "text/html; charset=utf-8", "no-cache"),
        "/index.html": ("index.html", "text/html; charset=utf-8", "no-cache"),
        "/vendor/xterm.js": ("vendor/xterm.js", "text/javascript; charset=utf-8", VENDOR_CACHE),
        "/vendor/xterm.css": ("vendor/xterm.css", "text/css; charset=utf-8", VENDOR_CACHE),
        "/vendor/addon-fit.js": ("vendor/addon-fit.js", "text/javascript; charset=utf-8", VENDOR_CACHE),
        "/vendor/addon-web-links.js": ("vendor/addon-web-links.js", "text/javascript; charset=utf-8", VENDOR_CACHE),
        "/vendor/JetBrainsMonoNerdFontMono-Regular.woff2": (
            "vendor/JetBrainsMonoNerdFontMono-Regular.woff2", "font/woff2", VENDOR_CACHE),
        "/vendor/JetBrainsMonoNerdFontMono-Bold.woff2": (
            "vendor/JetBrainsMonoNerdFontMono-Bold.woff2", "font/woff2", VENDOR_CACHE),
    }

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        if self.app.verbose:
            sys.stderr.write(f"{self.address_string()} - {format % args}\n")

    def log_error(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write(f"webterm: {self.address_string()} - {format % args}\n")

    # -- plumbing ------------------------------------------------------------

    def send_json(self, code: int, obj=None, cookie: str | None = None,
                  extra: dict | None = None) -> None:
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def send_file(self, name: str, content_type: str, cache: str = "no-cache") -> None:
        path = os.path.join(self.server.static_root, name)  # type: ignore[attr-defined]
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except OSError:
            return self.send_json(404, {"error": "not found"})
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return None

    def cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value or None
        return None

    def session(self) -> str | None:
        token = self.cookie(COOKIE)
        return token if self.app.sessions.valid(token) else None

    def require_session(self) -> str | None:
        token = self.session()
        if token is None:
            self.send_json(401, {"error": "not authenticated"})
        return token

    def same_origin(self) -> bool:
        """Cookie is SameSite=Strict; this closes the rest of the CSRF door."""
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl and same-origin navigations
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https"):
            return False
        return parts.netloc == (self.headers.get("Host") or "")

    def terminal_from_path(self, session: str) -> Terminal | None:
        parts = self.path.split("?")[0].strip("/").split("/")
        # api / terminals / <id> / <action>
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "terminals":
            self.send_json(404, {"error": "not found"})
            return None
        tid = parts[2]
        if not tid or not all(c in "0123456789abcdef" for c in tid):
            self.send_json(400, {"error": "bad terminal id"})
            return None
        term = self.app.terminal(tid, session)
        if term is None:
            self.send_json(404, {"error": "no such terminal"})
            return None
        return term

    # -- routes --------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urlsplit(self.path).path
            if path == "/favicon.ico":
                return self.send_json(204)
            if path in self.STATIC:
                return self.send_file(*self.STATIC[path])
            if path == "/api/session":
                token = self.session()
                return self.send_json(200, {"authenticated": token is not None})
            if path == "/api/terminals":
                session = self.require_session()
                if session is None:
                    return
                with self.app.lock:
                    terms = [
                        {
                            "id": t.id,
                            "shell": t.shell,
                            "pid": t.pid,
                            "closed": t.closed,
                            "exitCode": t.exit_code,
                            "subscribers": t.subscribers,
                        }
                        for t in self.app.terminals.values() if t.session == session
                    ]
                return self.send_json(200, {"terminals": terms})
            if path.startswith("/api/terminals/"):
                session = self.require_session()
                if session is None:
                    return
                term = self.terminal_from_path(session)
                if term is None:
                    return
                if path.endswith("/stream"):
                    return self.stream(term)
                return self.send_json(404, {"error": "not found"})
            return self.send_json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.send_json(500, {"error": "internal error"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self.same_origin():
                return self.send_json(403, {"error": "bad origin"})
            path = urlsplit(self.path).path
            if path == "/api/login":
                return self.login()
            if path == "/api/logout":
                token = self.cookie(COOKIE)
                if token:
                    self.app.drop_session(token)
                return self.send_json(204, cookie=f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            if path == "/api/terminals":
                return self.create_terminal()
            if path.startswith("/api/terminals/"):
                session = self.require_session()
                if session is None:
                    return
                term = self.terminal_from_path(session)
                if term is None:
                    return
                if path.endswith("/input"):
                    return self.input(term)
                if path.endswith("/resize"):
                    return self.resize(term)
                return self.send_json(404, {"error": "not found"})
            return self.send_json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.send_json(500, {"error": "internal error"})

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            if not self.same_origin():
                return self.send_json(403, {"error": "bad origin"})
            path = urlsplit(self.path).path
            if path.startswith("/api/terminals/"):
                session = self.require_session()
                if session is None:
                    return
                term = self.terminal_from_path(session)
                if term is None:
                    return
                self.app.kill_terminal(term)
                return self.send_json(204)
            return self.send_json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.send_json(500, {"error": "internal error"})

    # -- handlers ------------------------------------------------------------

    def login(self) -> None:
        ip = self.client_address[0]
        if not self.app.login_allowed(ip):
            return self.send_json(429, {"error": "too many attempts, wait a minute"},
                                  extra={"Retry-After": "60"})
        body = self.read_json() or {}
        password = body.get("password")
        if not isinstance(password, str) or not verify_password(password, self.app.password_hash):
            self.app.record_failure(ip)
            sys.stderr.write(f"webterm: failed login from {ip}\n")
            return self.send_json(401, {"error": "invalid password"})
        self.app.clear_failures(ip)
        token = self.app.sessions.create(ip)
        cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={self.app.args.session_ttl}"
        if self.app.args.secure_cookies:
            cookie += "; Secure"
        sys.stderr.write(f"webterm: login from {ip}\n")
        self.send_json(204, cookie=cookie)

    def create_terminal(self) -> None:
        session = self.require_session()
        if session is None:
            return
        body = self.read_json() or {}
        cols = clamp_int(body.get("cols"), 2, 1000, 80)
        rows = clamp_int(body.get("rows"), 2, 1000, 24)
        try:
            term = self.app.spawn(session, cols, rows)
        except TooManyTerminals as error:
            return self.send_json(429, {"error": str(error)})
        self.send_json(201, {"id": term.id, "pid": term.pid, "shell": term.shell})

    def input(self, term: Terminal) -> None:
        body = self.read_json() or {}
        data = body.get("data")
        if not isinstance(data, str):
            return self.send_json(400, {"error": "data must be base64"})
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error):
            return self.send_json(400, {"error": "bad base64"})
        if not term.write(raw):
            return self.send_json(410, {"error": "terminal is closed"})
        self.send_json(204)

    def resize(self, term: Terminal) -> None:
        body = self.read_json() or {}
        cols = clamp_int(body.get("cols"), 2, 1000, term.cols)
        rows = clamp_int(body.get("rows"), 2, 1000, term.rows)
        term.resize(cols, rows)
        term.touch()
        self.send_json(204)

    def stream(self, term: Terminal) -> None:
        query = parse_qs(urlsplit(self.path).query)
        try:
            cursor = int(query.get("cursor", ["-1"])[0])
        except ValueError:
            cursor = -1

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        term.subscribers += 1
        term.touch()
        try:
            with term.cond:
                if cursor < 0 or cursor < term.base_offset or cursor > term.seq:
                    cursor = term.base_offset
                    self.sse("reset", json.dumps({"cursor": cursor}))
                self.sse("ready", json.dumps({
                    "cursor": cursor, "pid": term.pid, "shell": term.shell,
                    "closed": term.closed, "exitCode": term.exit_code,
                    "cols": term.cols, "rows": term.rows,
                }))

            idle = False
            while True:
                chunk = None
                with term.cond:
                    if cursor < term.seq:
                        start = cursor - term.base_offset
                        chunk = bytes(term.buffer[start:start + MAX_CHUNK])
                        cursor += len(chunk)
                        idle = False
                    elif term.closed:
                        self.sse("exit", json.dumps({"code": term.exit_code}))
                        break
                    else:
                        # wait() is True when notified and False on timeout, so
                        # only a timeout means "send a keepalive".
                        idle = not term.cond.wait(HEARTBEAT)
                if chunk is not None:
                    self.sse("output", base64.b64encode(chunk).decode())
                elif idle:
                    self.sse(None, None, raw=b": keepalive\n\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            term.subscribers -= 1

    def sse(self, event: str | None, data: str | None, raw: bytes | None = None) -> None:
        if raw is None:
            buf = bytearray()
            if event:
                buf += f"event: {event}\n".encode()
            if data is not None:
                buf += f"data: {data}\n".encode()
            buf += b"\n"
            raw = bytes(buf)
        self.wfile.write(raw)
        self.wfile.flush()


def clamp_int(value, low: int, high: int, default: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, app: App, static_root: str):
        super().__init__(address, handler)
        self.app = app
        self.static_root = static_root


# --- entry point ------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="webterm",
        description="Serve a shell in the browser, behind a password.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=7681, help="bind port (default 7681)")
    parser.add_argument("--shell", default=os.environ.get("SHELL") or "/bin/sh",
                        help="shell to run (default $SHELL)")
    parser.add_argument("--cwd", default=os.getcwd(), help="working directory for the shell")
    parser.add_argument("--password", default=os.environ.get("WEBTERM_PASSWORD"),
                        help="password (or WEBTERM_PASSWORD); omit and a 16-character passphrase is generated")
    parser.add_argument("--password-hash", default=os.environ.get("WEBTERM_PASSWORD_HASH"),
                        help="scrypt hash, see --print-hash")
    parser.add_argument("--print-hash", action="store_true",
                        help="read a password on stdin, print its hash, and exit")
    parser.add_argument("--secure-cookies", action="store_true",
                        help="add Secure to the session cookie (use when served over HTTPS)")
    parser.add_argument("--session-ttl", type=int, default=12 * 3600,
                        help="session lifetime in seconds (default 43200)")
    parser.add_argument("--idle-timeout", type=int, default=1800,
                        help="kill a terminal with no browser attached after N seconds (default 1800)")
    parser.add_argument("--max-terminals", type=int, default=8, help="server-wide terminal cap")
    parser.add_argument("--max-terminals-per-session", type=int, default=4,
                        help="terminals per session cap")
    parser.add_argument("--static-root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"),
                        help="directory holding index.html and vendor/")
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args(argv)

    if args.print_hash:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            print("webterm: empty password", file=sys.stderr)
            return 1
        print(hash_password(password))
        return 0

    if not os.path.exists(os.path.join(args.static_root, "index.html")):
        print(f"webterm: no index.html under {args.static_root}", file=sys.stderr)
        return 1
    if not os.path.exists(args.shell):
        print(f"webterm: shell not found: {args.shell}", file=sys.stderr)
        return 1
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print("webterm: warning: binding beyond loopback; serve it over TLS and use a strong password",
              file=sys.stderr)

    app = App(args)
    server = Server((args.host, args.port), Handler, app, args.static_root)

    reaper = threading.Thread(target=app.reap_loop, name="reaper", daemon=True)
    reaper.start()

    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    shown = args.host if args.host not in ("0.0.0.0", "::") else "127.0.0.1"
    print(f"webterm: http://{shown}:{args.port}/  shell={args.shell}  cwd={args.cwd}", file=sys.stderr)
    try:
        server.serve_forever()
    finally:
        app.shutdown()
        server.server_close()
        print("webterm: stopped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
