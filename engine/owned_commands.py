"""Retained child-process ownership shared by certificate reads and socket lookup."""
import asyncio
from dataclasses import dataclass, field


@dataclass(eq=False)
class Child:
    process: object
    waiter: object
    output: object
    spawn: object = None
    cleanup_lock: object = field(default_factory=asyncio.Lock)


class OwnedCommands:
    """Own child objects, I/O and shielded exit waiters through final cleanup."""
    def __init__(self):
        self.children = set()
        self.stopped = False
        self.cleanup_pending = False

    async def run(self, arguments, limit):
        if self.stopped or self.cleanup_pending:
            raise ValueError("command_cleanup_pending")
        child = Child(None, None, None)
        # Register before awaiting creation. A late Process handshake remains
        # owned even when the connecting task is cancelled during launch.
        self.children.add(child)
        child.spawn = asyncio.create_task(self.start(child, arguments, limit))
        child.spawn.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        try:
            await asyncio.shield(child.spawn)
            return await asyncio.shield(child.output)
        finally:
            try:
                await self.cleanup(child)
            finally:
                if child in self.children:
                    self.cleanup_pending = True  # fail closed before admitting more helpers

    async def start(self, child, arguments, limit):
        process = await asyncio.create_subprocess_exec(*arguments, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=64 * 1024)
        waiter = asyncio.create_task(process.wait())
        async def read(stream, budget):
            data, overflow = bytearray(), False
            while chunk := await stream.read(4096):
                if not overflow and len(data) + len(chunk) <= budget:
                    data.extend(chunk)
                else:
                    if not overflow and process.returncode is None:
                        try: process.terminate()
                        except ProcessLookupError: pass
                    overflow = True
                # Keep draining owned pipes after the cap; cancellation/timeout
                # cleanup terminates the child rather than deadlocking wait().
            return bytes(data), overflow
        async def collect():
            out, err = await asyncio.gather(read(process.stdout, limit), read(process.stderr, 16 * 1024))
            await asyncio.shield(waiter)
            if out[1] or err[1]: raise ValueError("command_output_limit")
            if process.returncode: raise ValueError("command_failed")
            return out[0]
        child.process, child.waiter, child.output = process, waiter, asyncio.create_task(collect())
        # A cancelled caller can leave this owned task pending for Stop retry.
        # Retrieve errors even if final cleanup itself is interrupted.
        child.output.add_done_callback(lambda task: None if task.cancelled() else task.exception())

    async def cleanup(self, child):
        async with child.cleanup_lock:
            await self._cleanup(child)

    async def _cleanup(self, child):
        if child.spawn is not None:
            try:
                await asyncio.wait_for(asyncio.shield(child.spawn), 1)
            except asyncio.TimeoutError:
                raise RuntimeError("Owned command launch cleanup remains pending; retry Stop") from None
            except Exception:
                if child.process is None:
                    self.children.discard(child)
                    return  # launch failed before a Process object existed
                raise
        process = child.process
        if process.returncode is None:
            try: process.terminate()
            except ProcessLookupError: pass
        try:
            await asyncio.wait_for(asyncio.shield(child.waiter), .25)
        except asyncio.TimeoutError:
            if process.returncode is None:
                try: process.kill()
                except ProcessLookupError: pass
            # Owned CPython 3.13 subprocess transport: close our pipe ends too,
            # so inherited/blocked output cannot strand a completed child wait.
            process._transport.close()
            try:
                await asyncio.wait_for(asyncio.shield(child.waiter), 1)
            except asyncio.TimeoutError:
                raise RuntimeError("Owned command child cleanup remains pending; retry Stop") from None
        # Process exit and pipe completion are separate boundaries: a descendant
        # can inherit stdout after the direct child has exited. Close only our
        # pipe ends; never signal an unidentified descendant.
        process._transport.close()
        try:
            await asyncio.wait_for(asyncio.shield(child.output), 1)
        except asyncio.TimeoutError:
            raise RuntimeError("Owned command output cleanup remains pending; retry Stop") from None
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise
            raise RuntimeError("Owned command output waiter was cancelled; cleanup remains pending") from None
        except Exception:
            pass  # collected command failure, not a cleanup failure
        self.children.discard(child)

    async def close(self):
        self.stopped = True
        results = await asyncio.gather(*(self.cleanup(child) for child in list(self.children)), return_exceptions=True)
        if self.children:
            raise RuntimeError("Owned command cleanup remains pending; retry Stop")
        for result in results:
            if isinstance(result, BaseException):
                raise result
