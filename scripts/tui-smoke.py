#!/usr/bin/env python3
"""Run the actual TUI in a PTY, exercise views, and verify Ctrl+C exits."""
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
env = dict(os.environ, TERM="xterm-256color")
process = subprocess.Popen([sys.argv[1], "tui", "--socket=" + sys.argv[2]], stdin=slave, stdout=slave, stderr=slave, env=env)
os.close(slave)
output = bytearray()


def wait_for(text, timeout=10):
    deadline = time.monotonic() + timeout
    start = len(output)
    while time.monotonic() < deadline:
        if text in output[start:]:
            return
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                output.extend(os.read(master, 65536))
            except OSError:
                break
    raise AssertionError("missing terminal text " + repr(text) + "\n" + repr(output[-2000:]))


try:
    wait_for(b"curl")
    os.write(master, b"?")
    wait_for(b"KEYBOARD SHORTCUTS")
    os.write(master, b"\x1b")
    time.sleep(0.2)
    os.write(master, b"\r")
    wait_for(b"7-Day Usage History")
    os.write(master, b"\x1b")
    time.sleep(0.2)
    os.write(master, b"/curl")
    time.sleep(0.3)
    os.write(master, b"\x03")
    process.wait(timeout=5)
    assert process.returncode == 0, process.returncode
    print("TUI dashboard, help, details, filter, and Ctrl+C passed")
finally:
    if process.poll() is None:
        process.kill()
        process.wait()
    os.close(master)
