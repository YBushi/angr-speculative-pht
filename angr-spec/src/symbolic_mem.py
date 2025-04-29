import claripy
import angr
from angr.state_plugins.symbolic_memory import SimSymbolicMemory

class FullySymbolicMemory(SimSymbolicMemory):
    def __init__(self, endness=None):
        super().__init__(memory_backer=None, permissions_backer=None, endness=endness, memory_id="mem")

    def _store(self, req):
        super()._store(req)

    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        try:
            return super()._load(addr, size, condition, fallback, inspect, events, ret_on_segv)
        except SimMemoryError:
            # If memory access fails (because of symbolic address), create a fresh symbolic variable
            return claripy.BVS(f"uninitialized_{addr}", size * 8)
    def copy(self, memo):
        return FullySymbolicMemory(endness=self._endness)
