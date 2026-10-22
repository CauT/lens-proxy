"""Cancelable, bounded reads of explicitly selected certificate files."""
import errno
import os
from pathlib import Path
import stat
import sys

from owned_commands import OwnedCommands
from bounds import BODY_BYTES


def selected_certificate_path(path):
    if not isinstance(path, str) or "\0" in path or not Path(path).expanduser().is_absolute():
        raise ValueError("Certificate path must be absolute")
    return Path(path).expanduser()


def read_certificate_file(path, remaining):
    if type(remaining) is not int or not 0 <= remaining <= BODY_BYTES:
        raise ValueError("Certificate read budget must be between 0 and 32 MiB")
    descriptor = os.open(selected_certificate_path(path), os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        identity = os.fstat(stream.fileno())
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError("Certificate input must be a regular file")
        if identity.st_size > remaining:
            raise ValueError("Client certificate inputs exceed the 32 MiB aggregate budget")
        payload = stream.read(remaining + 1)
        if len(payload) > remaining:
            raise ValueError("Client certificate inputs exceed the 32 MiB aggregate budget")
        return payload


class CertificateInputs:
    def __init__(self):
        self.commands = OwnedCommands()

    async def read(self, path, remaining):
        selected = selected_certificate_path(path)
        # Raw bytes plus one tag avoid base64/JSON expansion of private keys.
        # The error branch contains only fixed admission text or an errno name.
        raw = await self.commands.run([sys.executable, str(Path(__file__).resolve()),
                                       str(selected), str(remaining)], max(remaining + 1, 4096))
        if raw[:1] == b"\1":
            raise ValueError(raw[1:].decode("utf-8", "strict"))
        if raw[:1] != b"\0" or len(raw) - 1 > remaining:
            raise ValueError("Certificate reader returned an invalid bounded result")
        return raw[1:]

    async def close(self):
        await self.commands.close()


if __name__ == "__main__":
    try:
        payload = b"\0" + read_certificate_file(sys.argv[1], int(sys.argv[2]))
    except ValueError as exc:
        payload = b"\1" + str(exc).encode("utf-8")
    except OSError as exc:
        reason = errno.errorcode.get(exc.errno, "IO_ERROR")
        payload = b"\1Certificate file could not be opened or read (" + reason.encode("ascii") + b")."
    sys.stdout.buffer.write(payload)
