"""Drop a host file through a PTY and check its read-only guest copy."""

import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time


GUEST = r"""
set -eu
stty -echo
printf '\033[?2004hAIRLOCK_DROP_READY\n'
IFS= read -r pasted
start=$(printf '\033[200~')
end=$(printf '\033[201~')
path=${pasted#"$start"}
path=${path%"$end"}
case "$path" in /airlock/imports/*) ;; *) echo BAD_PATH; exit 1;; esac
[ "$(cat "$path")" = "airlock attachment fixture" ]
if (printf changed > "$path") 2>/dev/null; then echo WRITABLE; exit 1; fi
if chmod u+w "$path" 2>/dev/null; then echo CHMOD_ALLOWED; exit 1; fi
printf 'AIRLOCK_DROP_OK\n'
"""


def stop(process):
    if process is None or process.poll() is not None:
        return
    # Signalling the group would kill VM helpers before Airlock finishes cleanup.
    process.terminate()
    try:
        # Airlock allows up to 30 seconds for guest shutdown before teardown.
        process.wait(timeout=45)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def run(binary, mode, root):
    home, project = root / "home", root / "project"
    home.mkdir()
    project.mkdir()
    (home / ".airlock").mkdir()
    (home / ".airlock/settings.toml").write_text('[vault]\nstorage = "disabled"\n')
    (project / "airlock.toml").write_text('[vm]\nimage = "alpine:3"\n')
    source = root / "external screenshot 猫.png"
    source.write_text("airlock attachment fixture")
    env = dict(os.environ, HOME=str(home), TERM="xterm-256color")
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    owner = process = None
    transcript = bytearray()
    try:
        if mode == "exec":
            with (root / "owner.log").open("wb") as log:
                owner = subprocess.Popen(
                    [binary, "start", "--", "sleep", "300"], cwd=project, env=env,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                )
            deadline = time.monotonic() + 120
            while not (project / ".airlock/sandbox/cli.sock").exists():
                if owner.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError((root / "owner.log").read_text())
                time.sleep(0.1)
            command = [binary, "exec", "sh", "-c", GUEST]
        else:
            command = [binary, "start"]
            if mode == "monitor":
                command.append("--monitor")
            command.extend(["--", "sh", "-c", GUEST])
        process = subprocess.Popen(
            command, cwd=project, env=env, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True,
        )
        os.close(slave)
        slave = None
        sent = False
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                transcript.extend(data)
                if not sent and b"AIRLOCK_DROP_READY" in transcript:
                    os.write(master, b"\x1b[200~" + shlex.quote(str(source)).encode() + b"\x1b[201~\r")
                    sent = True
            elif process.poll() is not None:
                break
        assert process.wait(timeout=10) == 0, transcript.decode(errors="replace")
        assert b"AIRLOCK_DROP_OK" in transcript, transcript.decode(errors="replace")
        assert source.read_text() == "airlock attachment fixture"
        stop(owner)
        leftovers = list((home / ".cache/airlock/imports").glob("*/run-*"))
        assert not leftovers, f"attachment snapshots survived shutdown: {leftovers}"
    finally:
        stop(process)
        stop(owner)
        os.close(master)
        if slave is not None:
            os.close(slave)


if __name__ == "__main__":
    temp_root = Path(__file__).resolve().parents[2] / "dev/tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attachments-vm-", dir=temp_root) as directory:
        run(str(Path(sys.argv[1]).resolve()), sys.argv[2], Path(directory))
