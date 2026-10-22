"""Map Local URL interpretation and bounded, descriptor-owned file reads."""
import mimetypes
import os
from pathlib import Path
import re
import stat
from urllib.parse import unquote, urlsplit, urlunsplit

from mitmproxy import http
from bounds import BODY_BYTES
from http_urls import mapping_path_prefix


def selected_local_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or "\0" in value:
        raise ValueError("Map Local requires an absolute file or directory path")
    return path


def local_url(url):
    """Query parameters select neither a mapping nor a local filename."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def relative_parts(url, pattern):
    prefix = mapping_path_prefix(pattern)
    path = urlsplit(url).path
    if not path.startswith(prefix):
        raise ValueError("Map Local URL does not have the mapping's directory prefix")
    parts = []
    for encoded in path[len(prefix):].split("/"):
        if not encoded:
            continue
        if re.search(r"%(?![0-9a-fA-F]{2})", encoded):
            raise ValueError("Map Local URL contains an invalid percent escape")
        segment = unquote(encoded, encoding="utf-8", errors="strict")
        if segment in (".", "..") or any(c in segment for c in ("/", "\\", "\0")):
            raise ValueError("Map Local URL contains an unsafe path component")
        parts.append(segment)
    # A trailing slash still denotes a directory. Do not turn '/file.txt/'
    # into the regular file '/file.txt' while removing empty components.
    return [] if path.endswith("/") else parts


def read_regular(descriptor):
    identity = os.fstat(descriptor)
    if not stat.S_ISREG(identity.st_mode):
        raise ValueError("Map Local input must be a regular file")
    if identity.st_size > BODY_BYTES:
        raise ValueError("Local mapping exceeds 32 MiB")
    # fstat alone cannot bound a file that grows after admission.
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        body = stream.read(BODY_BYTES + 1)
    if len(body) > BODY_BYTES:
        raise ValueError("Local mapping exceeds 32 MiB")
    return body


def local_response(url, pattern, value):
    """None means a genuine local miss: preserve the normal upstream pipeline.

    The selected root may itself be a symlink. Descendants are opened relative
    to owned directory descriptors without following links, including at the
    final open. Concurrent renames cannot redirect a validated path outside it.
    """
    path = selected_local_path(value)
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        filename = path.name
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            parts = relative_parts(url, pattern)
            if not parts:
                return None  # No implicit index file or directory listing.
            for index, part in enumerate(parts):
                flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                if index < len(parts) - 1:
                    flags |= os.O_DIRECTORY
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                return None
            filename = parts[-1]
        body = read_regular(descriptor)
        return http.Response.make(200, body, {
            "Content-Type": mimetypes.guess_type(filename)[0] or "application/octet-stream"})
    except (FileNotFoundError, NotADirectoryError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
