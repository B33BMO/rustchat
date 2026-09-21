#!/usr/bin/env python3
"""Plays the other half of the conversation while VHS records one client.

A chat demo with one participant isn't a demo. This joins the same room in a
pty that nothing is recording, and each line it sends is triggered by a word
appearing from the recorded side. Reacting rather than sleeping means the two
halves stay in step no matter how long the render takes to start up, which a
fixed schedule does not.

Reads the invite from RUSTCHAT_INVITE and the binary from RUSTCHAT_BIN.
"""

import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import fcntl
import time

ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b[()][A-Z0-9]|\x1b[=>]|\r")

NAME = os.environ.get("DEMO_PARTNER_NAME", "sam")
BIN = os.environ.get("RUSTCHAT_BIN", "rustchat")
TIMEOUT = 60.0

# (word to wait for from the other side, pause after seeing it, what to say).
# A `None` trigger sends immediately, which seeds the room so the recording
# opens on a conversation already in progress rather than an empty pane.
#
# Triggers are single words on purpose: the TUI redraws by patching cells, so
# the raw stream has cursor moves where the spaces would be and a multi-word
# pattern will not match it.
SCRIPT = [
    (None, 0.0, "relay's live on your box now?"),
    ("tunnel", 1.1, "and it can't read a single byte of it?"),
    ("ciphertext", 4.0, "ha. perfect"),
]


class Partner:
    """A rustchat client in a pty, driven by what it sees."""

    def __init__(self):
        self.buf = ""
        master, slave = pty.openpty()
        # Without a window size the pty reports 0x0 and ratatui renders
        # nothing, so nothing would ever match a trigger.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        os.set_blocking(master, False)
        self.master = master
        self.proc = subprocess.Popen(
            [BIN, "--no-vault", "-u", NAME],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "TERM": "xterm-256color"},
        )
        os.close(slave)

    def pump(self, seconds):
        deadline = time.time() + seconds
        while time.time() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if not ready:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return
            if not data:
                return
            self.buf += data.decode("utf-8", "replace")

    def seen(self):
        """Everything received so far, with whitespace removed."""
        return re.sub(r"\s+", "", ANSI.sub("", self.buf))

    def wait_for(self, needle, timeout=TIMEOUT):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.pump(0.2)
            if needle in self.seen():
                return True
        return False

    def say(self, line):
        os.write(self.master, (line + "\r").encode())
        self.pump(0.4)

    def close(self):
        os.write(self.master, b"\x03")
        self.pump(0.8)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main():
    if not os.environ.get("RUSTCHAT_INVITE"):
        sys.exit("RUSTCHAT_INVITE is not set")

    partner = Partner()
    if not partner.wait_for("online"):
        partner.close()
        sys.exit(f"{NAME} could not reach the relay")
    print(f"{NAME}: connected", flush=True)

    for trigger, pause, line in SCRIPT:
        if trigger is not None:
            if not partner.wait_for(trigger):
                print(f"{NAME}: gave up waiting for {trigger!r}", flush=True)
                break
            time.sleep(pause)
        partner.say(line)
        print(f"{NAME}: {line}", flush=True)

    # Stay in the room so the recording keeps showing two occupants, and so
    # the closing frames do not include a "sam left" notice.
    partner.pump(20.0)
    partner.close()


if __name__ == "__main__":
    main()
