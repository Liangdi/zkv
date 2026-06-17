#!/usr/bin/env python3
"""PTY end-to-end tests for the `zkv` binary (drives src/main.rs + ui::run).

Runs the real `target/debug/zkv` under a pseudo-terminal (80x24) and asserts on
the rendered screen text and the process exit code. This covers the layers the
unit tests can't reach: clap CLI wiring, terminal setup/teardown (raw mode +
alternate screen + TerminalGuard/panic-hook), the ui::run main loop, and real
rendering.

Not part of `cargo test` — invoke via `just e2e` (which builds first) or:

    python3 tests/e2e_pty.py -v

Only the Python standard library is used (no `pip install`). Linux/macOS.
"""

import errno
import os
import re
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import fcntl
import pty
import termios

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "target" / "debug" / "zkv"
ROWS, COLS = 24, 80

# ioctl constants (termios exposes TIOCSWINSZ; TIOCSCTTY is platform-specific).
TIOCSWINSZ = termios.TIOCSWINSZ
TIOCSCTTY = getattr(termios, "TIOCSCTTY", 0x540E)  # 0x540E is the Linux value.

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\x1b\][^\x07]*\x07")


def _normalize(s: str) -> str:
    """Strip ANSI sequences AND all whitespace.

    ratatui's diff renderer writes each word with explicit cursor positioning and
    skips unchanged inter-word space cells, so a rendered "unlock failed" can arrive
    as the bytes "unlockfailed" (no space). Matching on whitespace-normalized text
    makes assertions robust to that, on both first-frame (spaces present) and
    subsequent (spaces omitted) renders.
    """
    return re.sub(r"\s", "", _ANSI.sub("", s))


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    """Set the PTY window size via TIOCSWINSZ (struct: rows, cols, xpix, ypix)."""
    fcntl.ioctl(fd, TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _exitcode(status: int) -> int:
    if hasattr(os, "waitstatus_to_exitcode"):
        return os.waitstatus_to_exitcode(status)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return status


# --------------------------------------------------------------------------- #
# PTY harness
# --------------------------------------------------------------------------- #


class Pty:
    """A child process running under a pseudo-terminal.

    Output written by the child (to its stdout/stderr, both the PTY slave) is
    read from the master into a string buffer; bytes we write to the master
    arrive as the child's stdin (crossterm parses them as key events in raw
    mode).
    """

    def __init__(self, argv, cwd=None, rows=ROWS, cols=COLS, env_extra=None):
        env = dict(os.environ)
        env["TERM"] = "xterm-256color"
        if env_extra:
            env.update(env_extra)

        # pty.fork() handles openpty + setsid + controlling-tty + dup2 to 0/1/2.
        pid, master_fd = pty.fork()
        if pid == 0:
            # ---- child ----
            try:
                if cwd:
                    os.chdir(cwd)
                os.execvpe(argv[0], argv, env)
            except Exception:
                os._exit(127)

        # ---- parent ----
        # Set window size immediately; crossterm reads it lazily on first draw,
        # well after this point, so there is no race in practice.
        _set_winsize(master_fd, rows, cols)
        self.master = master_fd
        self.pid = pid
        self.buf = ""
        self.raw = b""  # 原始字节(含 ANSI 转义),供截图脚本喂给真终端渲染
        self.matched_through = 0  # consume cursor (offset into normalized buffer)
        self._closed = False

    # -- low-level read ---------------------------------------------------- #
    def _read_some(self, timeout: float):
        """Read available bytes into self.buf.

        Returns True if bytes were read, False on idle (no data within timeout),
        None on EOF (child closed the slave).
        """
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            data = os.read(self.master, 4096)
        except OSError as e:
            # Linux raises EIO once the slave side is gone; treat as EOF.
            if e.errno == errno.EIO:
                return None
            raise
        if not data:
            return None
        self.raw += data
        self.buf += data.decode("utf-8", errors="replace")
        return True

    # -- high-level ops ---------------------------------------------------- #
    def send(self, data: bytes) -> None:
        os.write(self.master, data)

    def expect(self, substr: str, timeout: float = 15.0) -> None:
        """Block until `substr` appears (whitespace-normalized; consumed through match).

        Searches the normalized buffer starting at the previous match's end, so the
        same token rendered twice is matched in order.
        """
        needle = _normalize(substr)
        if not needle:
            raise ValueError("expected substring is empty after normalization")
        deadline = time.monotonic() + timeout
        while True:
            hay = _normalize(self.buf)
            idx = hay.find(needle, self.matched_through)
            if idx >= 0:
                self.matched_through = idx + len(needle)
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"timeout ({timeout}s) waiting for {substr!r}\n"
                    f"--- captured (ansi-stripped, tail) ---\n{self._visible()}\n---"
                )
            rc = self._read_some(min(remaining, 0.25))
            if rc is None:
                raise AssertionError(
                    f"EOF before seeing {substr!r}\n"
                    f"--- captured (ansi-stripped, tail) ---\n{self._visible()}\n---"
                )

    def drain(self, timeout: float = 0.5) -> None:
        """Read until idle/EOF; appends to buffer (used to settle a frame)."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            rc = self._read_some(min(remaining, 0.1))
            if rc is not True:
                return

    def wait_exit(self, timeout: float = 10.0) -> int:
        """Read remaining output until EOF, then reap and return the exit code."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            rc = self._read_some(min(remaining, 0.1))
            if rc is None:
                break
        try:
            _, status = os.waitpid(self.pid, 0)
            return _exitcode(status)
        except ChildProcessError:
            return -1

    def close(self) -> None:
        """Close the master and ensure the child is reaped (kill if still alive)."""
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self.master)
        except OSError:
            pass
        # If the child already exited, reap is a no-op/ChildProcessError.
        for _ in range(50):  # up to ~5s
            try:
                wpid, _ = os.waitpid(self.pid, os.WNOHANG)
                if wpid == self.pid:
                    return
            except ChildProcessError:
                return
            time.sleep(0.1)
        # Still alive — terminate.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(self.pid, sig)
            except OSError:
                return
            try:
                os.waitpid(self.pid, 0)
                return
            except ChildProcessError:
                return
            time.sleep(0.2)

    def _visible(self) -> str:
        # ANSI-stripped raw text (spaces kept for readability); tail to keep dumps short.
        return _ANSI.sub("", self.buf)[-1500:]

    # context-manager sugar
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

PASSPHRASE = "correct-horse-battery-staple"


def require_bin() -> None:
    if not BIN.exists():
        raise RuntimeError(
            f"zkv binary not found at {BIN} — run `cargo build` (or `just e2e`) first."
        )


def spawn(args) -> Pty:
    return Pty([str(BIN), *args], cwd=str(REPO))


def make_vault(path: str, passphrase: str = PASSPHRASE) -> None:
    """Create a real vault file by driving `zkv new` through the PTY."""
    with spawn(["new", path]) as p:
        p.expect("Create New Vault", 10)
        p.send(passphrase.encode() + b"\r")
        p.expect("vault created", 25)  # create+unlock run the (slow) default KDF.
        p.send(b"q")
        code = p.wait_exit(10)
    assert code == 0, f"fixture vault creation exited {code}"


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


class E2E(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        require_bin()
        cls.tmpdir = tempfile.mkdtemp(prefix="zkv_e2e_")
        cls.fixture = os.path.join(cls.tmpdir, "fixture.zkv")
        # One slow create, reused read-only by every `open` test below.
        make_vault(cls.fixture)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # --- CLI surface (no PTY needed) -------------------------------------- #
    def test_help_lists_subcommands(self):
        r = subprocess.run([str(BIN), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("new", r.stdout)
        self.assertIn("open", r.stdout)

    # --- startup smokes (Esc before passphrase => zero KDF) -------------- #
    def test_new_shows_create_screen_esc_exits(self):
        path = os.path.join(self.tmpdir, "new_smoke.zkv")
        with spawn(["new", path]) as p:
            p.expect("Create New Vault", 10)
            p.send(b"\x1b")  # Esc -> quit from prompt
            self.assertEqual(p.wait_exit(10), 0)

    def test_open_shows_unlock_screen_esc_exits(self):
        with spawn(["open", self.fixture]) as p:
            p.expect("Unlock Vault", 10)
            p.send(b"\x1b")
            self.assertEqual(p.wait_exit(10), 0)

    # --- unlock flow ------------------------------------------------------ #
    def test_open_wrong_passphrase_stays_locked(self):
        with spawn(["open", self.fixture]) as p:
            p.expect("Unlock Vault", 10)
            p.send(b"definitely-wrong\r")
            p.expect("unlock failed", 15)  # one KDF derivation on the fixture
            # Still in the passphrase prompt -> Esc quits cleanly.
            p.send(b"\x1b")
            self.assertEqual(p.wait_exit(10), 0)

    def test_open_correct_unlocks(self):
        with spawn(["open", self.fixture]) as p:
            p.expect("Unlock Vault", 10)
            p.send(PASSPHRASE.encode() + b"\r")
            # "unlocked" message shows in the header bar.
            p.expect("unlocked", 15)
            p.send(b"q")
            self.assertEqual(p.wait_exit(10), 0)

    # --- full create + edit + persist + reopen --------------------------- #
    def test_full_create_edit_persist_reopen(self):
        path = os.path.join(self.tmpdir, "persist.zkv")

        # 1) create + add a password item, then quit.
        with spawn(["new", path]) as p:
            p.expect("Create New Vault", 10)
            p.send(PASSPHRASE.encode() + b"\r")
            p.expect("vault created", 25)  # create+unlock done (message in header)

            p.send(b"n")  # open NewItem editor (Password)
            p.expect("Editor", 5)
            # title
            p.send(b"github")
            # Tab -> username field
            p.send(b"\t")
            p.send(b"bob")
            # Enter -> save (insert + vault::save runs the default KDF)
            p.send(b"\r")
            # After save we're back in the list; anchor on "[PW]" — the list-only
            # item tag (freshly written, never shown in the editor) — then the
            # saved title, to confirm the item landed and rules out a stale hit
            # from the editor's title field.
            p.expect("[PW]", 25)
            p.expect("github", 10)
            p.send(b"q")
            self.assertEqual(p.wait_exit(10), 0)

        # 2) reopen the same vault; the item must persist.
        with spawn(["open", path]) as p:
            p.expect("Unlock Vault", 10)
            p.send(PASSPHRASE.encode() + b"\r")
            p.expect("unlocked", 25)
            p.expect("github", 10)
            p.send(b"q")
            self.assertEqual(p.wait_exit(10), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
