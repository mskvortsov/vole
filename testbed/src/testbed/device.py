import fcntl
import os
import struct
import termios
import time
from datetime import datetime


def ts() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


_TIOCMBIS = 0x5416
_TIOCMBIC = 0x5417
_TIOCM_RTS = struct.pack("I", 0x004)
_TIOCM_DTR = struct.pack("I", 0x002)


def open_device(path: str) -> int:
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
    attrs = termios.tcgetattr(fd)
    attrs[0] &= ~(termios.IXON | termios.IXOFF | termios.IXANY | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.ISTRIP)
    attrs[1] &= ~termios.OPOST
    attrs[2] = (
        (attrs[2] & ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS)) | termios.CS8 | termios.CREAD | termios.CLOCAL
    )
    attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ECHOE | termios.ISIG | termios.IEXTEN)
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    attrs[6][termios.VMIN] = 1
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    return fd


def reset_device(fd: int, on_release=None) -> None:
    """Hard-reset the device into firmware (RTS=EN, DTR=IO0/BOOT)."""
    fcntl.ioctl(fd, _TIOCMBIS, _TIOCM_RTS)  # EN low (hold in reset)
    fcntl.ioctl(fd, _TIOCMBIC, _TIOCM_DTR)  # IO0 high (firmware boot mode)
    termios.tcflush(fd, termios.TCIFLUSH)  # discard tail from previous run
    if on_release:
        on_release()
    time.sleep(0.1)
    fcntl.ioctl(fd, _TIOCMBIC, _TIOCM_RTS)  # EN high (release reset)
    fcntl.ioctl(fd, _TIOCMBIC, _TIOCM_DTR)  # IO0 high (keep)


def read_device_log(fd: int, log_path: str = "device.log") -> None:
    buf = b""
    with open(log_path, "wb") as log_file:
        while True:
            try:
                chunk = os.read(fd, 256)
            except OSError:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                t = ts()
                log_file.write(t.encode() + b" " + line + b"\n")
                log_file.flush()
                print(t, "[device]", line.rstrip(b"\r").decode(errors="replace"), flush=True)
