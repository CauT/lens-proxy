"""Gate only SDK hook timing; all sockets, sends and ownership are production.

This test-only JSONL adapter is never copied into the application resources.
"""
import asyncio
import os
import inspect
from pathlib import Path
import sys

sys.path.insert(0, str(Path(os.environ['LENS_LATE_ENGINE']).resolve().parent))
import engine


class GatedLens(engine.Lens):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.probe_next = None
        self.probe_gates = {}

    async def requestheaders(self, flow):
        await self.gated(flow, super().requestheaders, "before")

    async def request(self, flow):
        await self.gated(flow, super().request, "after")

    async def gated(self, flow, operation, phase):
        gate = self.probe_next
        if gate and gate['phase'] == phase and flow.request.path == gate['path']:
            self.probe_next = None
            release = asyncio.Event()
            self.probe_gates[flow.id] = release
        else:
            gate = None
        async def wait():
            engine.emit('probe_entered', id=flow.id, phase=gate['phase'],
                        fields=list(flow.request.headers.items(multi=True)))
            await asyncio.wait_for(release.wait(), 15)
        try:
            if gate and gate['phase'] == 'before':
                await wait()
            result = operation(flow)
            if inspect.isawaitable(result):
                await result
            if gate and gate['phase'] == 'after':
                await wait()
            if gate:
                engine.emit('probe_completed', id=flow.id,
                    fields=list(flow.request.headers.items(multi=True)),
                    replayed=flow.metadata.get('lens_replayed', False),
                    error=str(flow.error) if flow.error else None)
        finally:
            self.probe_gates.pop(flow.id, None)

    async def command(self, cmd):
        if cmd['command'] == 'probe_arm':
            self.probe_next = {'path': cmd['path'], 'phase': cmd['phase']}
            return {}
        if cmd['command'] == 'probe_release':
            for identity, release in list(self.probe_gates.items()):
                if cmd.get('id') in (None, identity):
                    release.set()
            return {}
        if cmd['command'] == 'probe_pending':
            return {'pending': len(self.pending_requests),
                    'bound': sum(pending.flow is not None for pending in self.pending_requests.values())}
        return await super().command(cmd)


engine.Lens = GatedLens
asyncio.run(engine.main())
