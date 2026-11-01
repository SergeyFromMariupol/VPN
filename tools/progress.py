#!/usr/bin/env python3
"""A disposable terminal renderer. It never reads phase logs or signals workers."""
import errno
import os
from pathlib import Path
import stat
import sys
import time


def owner_alive(pid, ticks):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return fields[0] not in ('Z', 'X') and fields[19] == ticks
    except (OSError, IndexError):
        return False


def control_alive(path, identity):
    try:
        info = os.lstat(path)
        actual = f'{info.st_uid}:{info.st_gid}:{stat.S_IMODE(info.st_mode):o}:{info.st_nlink}:{info.st_dev}:{info.st_ino}'
        return stat.S_ISREG(info.st_mode) and actual == identity
    except OSError:
        return False


def main():
    if len(sys.argv) not in (8, 9):
        return
    path, identity, pid, ticks, count, label, term = sys.argv[1:8]
    total = sys.argv[8] if len(sys.argv) == 9 else '12'
    if total not in ('8', '12'):
        return
    total = int(total)
    if not pid.isdecimal() or not ticks.isdecimal() or not (count == '-' or count.isdecimal()):
        return
    count = None if count == '-' else int(count)
    if (count is not None and not 0 <= count <= total) or not owner_alive(pid, ticks) or not control_alive(path, identity):
        return
    # A fresh open file description is essential: changing inherited stdout's
    # blocking flags would also change the installer's terminal descriptor.
    try:
        fd = os.open('/dev/tty', os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError:
        return
    dumb = term == 'dumb'
    started = time.monotonic()
    next_frame = started
    frame = 0
    width = 0

    def write(value):
        try:
            os.write(fd, value.encode('utf-8'))
            return True
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                return True  # Cosmetic frames may be dropped under backpressure.
            return False

    try:
        while control_alive(path, identity) and owner_alive(pid, ticks):
            now = time.monotonic()
            if now >= next_frame:
                elapsed = int(now - started)
                clock = f'{elapsed // 60:02}:{elapsed % 60:02}'
                spinner = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'[frame % 10]
                if count is None:
                    line = f'{spinner} {label} · {clock}'
                else:
                    filled = count * 12 // total
                    bar = '█' * filled + '░' * (12 - filled)
                    line = f'Общий прогресс: [{bar}] {count * 100 // total}% [{count}/{total}] {spinner} {label} · {clock}'
                width = max(width, len(line))
                if not write(line + '\n' if dumb else '\r' + line.ljust(width)):
                    break
                frame += 1
                next_frame = now + (10 if dumb else 1)
            time.sleep(0.1)
    finally:
        if not dumb and width:
            write('\r' + ' ' * width + '\r')
        os.close(fd)


if __name__ == '__main__':
    main()
