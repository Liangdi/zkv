#!/usr/bin/env python3
"""Capture PNG screenshots of the zkv TUI into ./screenshot — via a REAL terminal.

Pipeline (no more custom rasterizer — the result matches a real terminal):
  1. Drive the real `zkv` binary under a PTY (reusing `tests/e2e_pty.Pty`) to a
     given screen state, capturing the **raw ANSI byte stream** it emits
     (alternate-screen, cursor moves, truecolor SGR, the works).
  2. `cat` that byte stream into a real **xterm** (Source Code Pro, dark bg)
     running under a headless **Xvfb** display. xterm is a true terminal
     emulator, so it renders the stream's *final frame* exactly as a terminal
     would — real font, real anti-aliasing, real colors.
  3. `import` (ImageMagick) grabs that xterm window (found via `xdotool`) → PNG.

Why this and not Pillow: a real terminal render is the only thing that looks
like a real terminal. The earlier pyte+Pillow approximation diverged in font,
line height, anti-aliasing and background.

External deps (Linux): Xvfb, xterm, xdotool, ImageMagick `import`.
Run:  python3 tests/screenshot.py   (or: just shots)
"""

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))
from e2e_pty import BIN, PASSPHRASE, REPO, Pty, make_vault  # noqa: E402

OUT = REPO / "screenshot"

# Terminal look (match a typical dark terminal; tweak to taste / your profile).
TERM_FONT = "Source Code Pro"
TERM_SIZE = 14
TERM_BG = "#0b0e14"
TERM_FG = "#d4d4dc"
COLS, ROWS = 82, 26  # 80×24 zkv frame + a 1-cell breathing margin


# --------------------------------------------------------------------------- #
# External-tool checks
# --------------------------------------------------------------------------- #
def require_tools():
    missing = [t for t in ("Xvfb", "xterm", "xdotool", "import") if not shutil.which(t)]
    if missing:
        raise SystemExit(
            "missing tools: " + ", ".join(missing)
            + "\n  Fedora: sudo dnf install xorg-x11-server-Xvfb xterm xdotool ImageMagick"
        )


# --------------------------------------------------------------------------- #
# Headless X server
# --------------------------------------------------------------------------- #
class Xvfb:
    """A private headless X display for the lifetime of the script."""

    def __init__(self, display=":99", w=960, h=680):
        self.display = display
        self.w, self.h = w, h
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["Xvfb", self.display, "-screen", "0", f"{self.w}x{self.h}x24", "-ac"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.2)  # let the server come up
        return self

    def env(self):
        return {**os.environ, "DISPLAY": self.display}

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --------------------------------------------------------------------------- #
# Render one ANSI stream → PNG via xterm + import
# --------------------------------------------------------------------------- #
def render_ansi_to_png(ansi: bytes, out_path: str, xvfb: Xvfb) -> None:
    with tempfile.NamedTemporaryFile(suffix=".ansi", delete=False) as f:
        f.write(ansi)
        ansi_path = f.name
    try:
        cmd = (
            f"cat {shlex.quote(ansi_path)}; sleep 8  # hold the final alt-screen frame"
        )
        xterm = subprocess.Popen(
            [
                "xterm",
                f"-geometry", f"{COLS}x{ROWS}+0+0",
                "+sb",                              # no scrollbar
                "-fa", TERM_FONT, "-fs", str(TERM_SIZE),
                "-bg", TERM_BG, "-fg", TERM_FG,
                "-xrm", "xterm*allowBoldFonts: true",
                "-e", "bash", "-c", cmd,
            ],
            env=xvfb.env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wid = _wait_window(xvfb, xterm.pid)
            time.sleep(1.0)  # let xterm finish rendering the streamed frame
            subprocess.run(
                ["import", "-window", wid, out_path],
                env=xvfb.env(),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            xterm.terminate()
            try:
                xterm.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xterm.kill()
    finally:
        os.unlink(ansi_path)


def _wait_window(xvfb: Xvfb, pid: int, tries: int = 40) -> str:
    """Return the xterm top-level window id (xdotool search by pid)."""
    for _ in range(tries):
        r = subprocess.run(
            ["xdotool", "search", "--pid", str(pid)],
            env=xvfb.env(),
            capture_output=True,
            text=True,
        )
        wids = [w for w in r.stdout.split() if w]
        if wids:
            return wids[0]
        time.sleep(0.1)
    raise RuntimeError(f"no xterm window for pid {pid}")


def capture(p: Pty, name: str, xvfb: Xvfb) -> None:
    p.drain(0.4)
    render_ansi_to_png(p.raw, str(OUT / name), xvfb)
    print(f"  wrote {name}")


# --------------------------------------------------------------------------- #
# TUI driving helpers
# --------------------------------------------------------------------------- #
def add_password(p: Pty, title: str, username: str) -> None:
    p.send(b"n")
    p.expect("Editor", 5)
    p.send(title.encode("utf-8"))
    p.send(b"\t")
    p.send(username.encode("utf-8"))
    p.send(b"\r")
    p.expect("[PW]", 25)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    if not BIN.exists():
        raise SystemExit(f"zkv binary not found at {BIN} — run `cargo build` first.")
    require_tools()
    OUT.mkdir(exist_ok=True)

    tmp = tempfile.mkdtemp(prefix="zkv_shots_")
    print(f"temp dir: {tmp}")
    with Xvfb() as xvfb:
        print(f"Xvfb on {xvfb.display} ({xvfb.w}x{xvfb.h})")
        try:
            # 1) Create-vault passphrase screen.
            with Pty([str(BIN), "new", os.path.join(tmp, "a.zkv")], cwd=str(REPO)) as p:
                p.expect("Create New Vault", 8)
                capture(p, "01-create-vault.png", xvfb)

            fixture = os.path.join(tmp, "fixture.zkv")
            make_vault(fixture)

            # 2) Unlock passphrase screen.
            with Pty([str(BIN), "open", fixture], cwd=str(REPO)) as p:
                p.expect("Unlock Vault", 8)
                capture(p, "02-unlock-vault.png", xvfb)

            # 3) Empty vault browse view.
            with Pty([str(BIN), "open", fixture], cwd=str(REPO)) as p:
                p.expect("Unlock Vault", 8)
                p.send(PASSPHRASE.encode() + b"\r")
                p.expect("unlocked", 15)
                capture(p, "03-empty-vault.png", xvfb)

            # 4) Populated vault tour.
            vault = os.path.join(tmp, "demo.zkv")
            with Pty([str(BIN), "new", vault], cwd=str(REPO)) as p:
                p.expect("Create New Vault", 8)
                p.send(PASSPHRASE.encode() + b"\r")
                p.expect("vault created", 25)
                add_password(p, "Gmail", "bob@gmail.com")
                add_password(p, "AWS Console", "root")
                add_password(p, "GitHub", "bob")

                p.drain(0.3)
                capture(p, "04-list.png", xvfb)

                p.send(b"n")
                p.expect("Editor", 5)
                p.drain(0.3)
                capture(p, "05-new-item-editor.png", xvfb)
                p.send(b"\x1b")
                p.drain(0.3)

                p.send(b"/")
                p.send(b"git")
                p.drain(0.3)
                capture(p, "06-search.png", xvfb)
                p.send(b"\x1b")
                p.drain(0.3)

                p.send(b"x")
                p.expect("Confirm Delete", 5)
                p.drain(0.3)
                capture(p, "07-confirm-delete.png", xvfb)
                p.send(b"n")
                p.drain(0.3)

                p.send(b"q")
                p.wait_exit(10)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print(f"\ndone — {len(list(OUT.glob('*.png')))} PNGs in {OUT}/")


if __name__ == "__main__":
    main()
