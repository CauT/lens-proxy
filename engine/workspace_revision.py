"""One event-loop owner for persistent workspace mutations and snapshot cuts."""
import asyncio
import uuid


class WorkspaceRevision:
    def __init__(self, emit):
        self.emit = emit
        self.epoch = str(uuid.uuid4())
        self.generation = 0
        self.published = 0
        self.enabled = False
        self.pending = None

    def current(self):
        # The generation is an opaque decimal string, not a JSON/JS integer.
        return {"epoch": self.epoch, "generation": str(self.generation)}

    def changed(self):
        self.generation += 1
        if self.enabled and self.pending is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                self.flush()
            else:
                # State is updated immediately, independently of raw capture's
                # summary throttle. One timer bounds native status traffic.
                self.pending = loop.call_later(.1, self.flush)

    def enable(self):
        self.enabled = True
        self.published = self.generation  # Ready publishes this exact cut.

    def published_frame(self):
        if self.pending is not None:
            self.pending.cancel()
            self.pending = None
        self.published = self.generation
        return self.current()

    def flush(self):
        if self.pending is not None:
            self.pending.cancel()
            self.pending = None
        if self.enabled and self.published != self.generation:
            self.published = self.generation
            self.emit("workspace_state", workspace_revision=self.current())

    def close(self):
        self.flush()
        self.enabled = False
