"""Atomic, private HAR persistence for explicitly selected absolute paths."""
import json
from contextlib import contextmanager
import os
import stat
from pathlib import Path
import tempfile
import threading
from har import export_flow, import_entry
from har_metadata import document_metadata
from bounds import ImportBudget, HAR_FILE_BYTES, METADATA_BYTES, STORE_BYTES, metadata_size


def selected_path(value):
    if not isinstance(value, str):
        raise ValueError("path must be an absolute path string")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    return path


def prepare_import(document, max_flows, max_bytes):
    entries = document["log"]["entries"]
    if not isinstance(entries, list) or len(entries) > max_flows:
        raise ValueError(f"HAR must contain at most {max_flows} entries")
    budget = ImportBudget(max_flows, max_bytes)
    envelope = {**document, "log": {key: value for key, value in document["log"].items() if key != "entries"}}
    budget.metadata = metadata_size(envelope, METADATA_BYTES, path=("document",))
    flows = []
    for entry in entries:
        prepared = budget.prepare(entry)
        flow = import_entry(entry, prepared)
        budget.account_encoded(flow, prepared)
        flows.append(flow)
    return flows


class LimitedWriter:
    def __init__(self, stream, limit=None, label="HAR"):
        self.stream, self.bytes, self.limit, self.label = stream, 0, HAR_FILE_BYTES if limit is None else limit, label

    def write(self, text):
        # All emitted HAR text uses ensure_ascii=True, so characters equal bytes.
        if self.bytes + len(text) > self.limit:
            raise ValueError(f"Serialized {self.label} exceeds {self.limit} byte file budget")
        self.bytes += len(text)
        return self.stream.write(text)


_stage_lock = threading.Lock()
_stages = set()


class OwnedStage:
    """Retain inode/path authority after failed cleanup, including write failures."""
    def __init__(self, path, descriptor):
        self.path, self.pending, self.consumed = path, False, False
        self.proof = os.fdopen(descriptor, "rb", buffering=0)
        identity = os.fstat(descriptor)
        self.identity = (identity.st_dev, identity.st_ino)
        with _stage_lock:
            _stages.add(self)

    def check(self):
        # The held descriptor prevents inode reuse until our name is consumed
        # or removed. A path/inode number alone would lose that proof on close.
        held = os.fstat(self.proof.fileno())
        identity = self.path.lstat()
        if (held.st_dev, held.st_ino) != self.identity or not stat.S_ISREG(identity.st_mode) or (identity.st_dev, identity.st_ino) != self.identity:
            raise RuntimeError(f"Session stage identity changed; retained for review: {self.path}")

    def commit(self, target):
        with _stage_lock:
            self.check()
            os.replace(self.path, target)
            self.consumed = True
            self.proof.close()
            _stages.remove(self)

    def cleanup(self):
        with _stage_lock:
            if self not in _stages:
                return  # successful replace consumed the owned name
            self.pending = True
            if not self.consumed:
                try:
                    self.check()
                except FileNotFoundError:
                    pass
                else:
                    self.path.unlink()
            self.proof.close()
            _stages.remove(self)


def cleanup_pending_stages():
    with _stage_lock:
        pending = [stage for stage in _stages if stage.pending]
    errors = []
    for stage in pending:
        try:
            stage.cleanup()
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise RuntimeError("Session stage cleanup remains pending; retry Stop: " + "; ".join(errors))


@contextmanager
def atomic_text(path):
    """Own a private stage until fsync/replace or failed-write cleanup completes."""
    cleanup_pending_stages()  # do not accumulate stages behind a failed owner
    descriptor, stage_name = tempfile.mkstemp(prefix=f".{path.name}.lens-", suffix=".tmp", dir=path.parent)
    stage = OwnedStage(Path(stage_name), descriptor)
    try:
        with os.fdopen(os.dup(stage.proof.fileno()), "w", encoding="utf-8") as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        stage.commit(path)
    finally:
        stage.cleanup()


def save_snapshot(path, flows):
    """A failed serialization/write never replaces the user's previous file."""
    budget = ImportBudget(2000, STORE_BYTES)
    header = document_metadata()
    budget.metadata = metadata_size({"log": header}, METADATA_BYTES, path=("document",))
    with atomic_text(path) as file:
        stream = LimitedWriter(file)
        stream.write('{"log":{')
        for index, (key, value) in enumerate(header.items()):
            if index:
                stream.write(",")
            json.dump(key, stream, ensure_ascii=True)
            stream.write(":")
            json.dump(value, stream, ensure_ascii=True, allow_nan=False)
        stream.write(',"entries":[')
        for index, flow in enumerate(flows):
            if index:
                stream.write(",")
            entry = export_flow(flow)
            budget.prepare(entry)
            json.dump(entry, stream, ensure_ascii=True, allow_nan=False)
        stream.write("]}}")
    return {"path": str(path), "entries": len(flows)}


def read_document(path, max_bytes=None, label="HAR", unique_keys=False):
    max_bytes = HAR_FILE_BYTES if max_bytes is None else max_bytes
    # Opening a selected FIFO in blocking mode could wait forever before fstat
    # and strand shutdown's owned worker. Nonblocking open permits type checks
    # first; symlinks to ordinary files retain normal caller-selected semantics.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        identity = os.fstat(stream.fileno())
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError(f"{label} input must be a regular file")
        if identity.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} byte file budget before parsing")
        payload = stream.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} byte file budget before parsing")
    def invalid_constant(value):
        raise ValueError(f"Invalid JSON number: {value}")
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"Duplicate {label} JSON field: {key}")
            value[key] = item
        return value
    document = json.loads(payload, parse_constant=invalid_constant,
                          object_pairs_hook=unique_object if unique_keys else None)
    del payload
    return document


def load_snapshot(path, max_flows, max_bytes):
    return prepare_import(read_document(path), max_flows, max_bytes)
