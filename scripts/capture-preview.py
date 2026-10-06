#!/usr/bin/env python3
"""Capture the real piddigger TUI to an SVG for documentation.

Documentation-only dependency: pip install pyte

A full repaint is forced with a resize before the frame is read, because the
TUI renders incrementally and a naive pty capture would miss unchanged cells.
"""
import fcntl
import html
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pyte

COLS, ROWS = 160, 48


def capture(keys, out_path):
    master, slave = pty.openpty()
    winsize = lambda c: struct.pack("HHHH", ROWS, c, 0, 0)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize(COLS))
    screen = pyte.Screen(COLS, ROWS)
    stream = pyte.ByteStream(screen)
    env = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"}
    proc = subprocess.Popen(
        ["target/release/piddigger", "--demo", "--theme", "thugsred"],
        stdin=slave, stdout=slave, stderr=slave, env=env,
    )

    def pump(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    stream.feed(os.read(master, 65536))
                except OSError:
                    return

    try:
        pump(2.0)
        for key in keys:
            os.write(master, key.encode())
            pump(0.4)
        # Force a full repaint (SIGWINCH) so every cell is emitted.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize(COLS - 1))
        pump(0.3)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize(COLS))
        pump(0.6)
        render_svg(screen, out_path)
    finally:
        os.write(master, b"q")
        time.sleep(0.2)
        if proc.poll() is None:
            proc.kill()
        os.close(master)
        os.close(slave)


def render_svg(screen, out_path):
    cw, ch = 9, 18
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{COLS*cw+32}" '
        f'height="{ROWS*ch+32}" role="img" aria-label="piddigger terminal capture">',
        '<rect width="100%" height="100%" fill="#0a0a0c"/>',
        '<style>text{font-family:"JetBrains Mono","DejaVu Sans Mono",monospace;font-size:15px}</style>',
    ]
    for y in range(ROWS):
        for x in range(COLS):
            cell = screen.buffer[y][x]
            px, py = 16 + x * cw, 16 + y * ch
            if cell.bg != "default":
                parts.append(f'<rect x="{px}" y="{py}" width="{cw}" height="{ch}" fill="#{cell.bg}"/>')
            data = cell.data
            if data and data.strip():
                fg = "#d6d8e0" if cell.fg == "default" else f"#{cell.fg}"
                weight = ' font-weight="bold"' if cell.bold else ""
                parts.append(f'<text x="{px}" y="{py+14}" fill="{fg}"{weight}>{html.escape(data)}</text>')
    parts.append("</svg>")
    Path(out_path).write_text("\n".join(parts))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    os.makedirs("assets/screenshots", exist_ok=True)
    # (keys to press, output file)
    shots = [
        ("", "assets/screenshots/overview.svg"),
        ("0", "assets/screenshots/findings.svg"),
        ("R", "assets/screenshots/trace.svg"),
    ]
    if len(sys.argv) > 1:
        shots = [(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "assets/screenshots/custom.svg")]
    for keys, out in shots:
        capture(keys, out)
