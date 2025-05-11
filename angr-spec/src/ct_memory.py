from angr.storage.memory import SimMemory
from angr.state_plugins.symbolic_memory import SimSymbolicMemory
from angr.state_plugins.fully_symbolic_memory import FullySymbolicMemory
from angr.errors import SimUnsatError
import claripy


from IPython import embed


class CTMemory(SimMemory):

    _angr_sections_ranges = []

    @staticmethod
    def _set_memsight_ranges(project):
        for obj in project.loader.all_elf_objects:
            for section in obj.sections:
                # All non-writable sections are handled by angr's memory, i.e.,
                # the memory backer. It's faster for constant, concrete values.
                # NOTE: We ignore .init_array and .finit_array
                if not (
                    section.is_writable
                    and section.type in ["SHT_PROGBITS", "SHT_NOBITS"]
                ):
                    if not (
                        section.name.startswith(".debug")
                        or section.name.startswith(".symtab")
                        or section.name.startswith(".strtab")
                        or section.name.startswith(".init_array")
                        or section.name.startswith(".finit_array")
                    ):
                        CTMemory._angr_sections_ranges.append(
                            (section.min_addr, section.max_addr)
                        )


    def _memory(self, addr):
        if not isinstance(addr, int):
            if addr.concrete:
                addr = addr.args[0]
            else:
                if self.state.solver.unique(addr):
                    addr = self.state.solver.eval(addr)
                else: # Fully symbolic address -> memsight
                    return self.mem_memsight

        # Loop is faster (here) than list comprehensions and generators
        for start, end in CTMemory._angr_sections_ranges:
            if addr >= start and addr <= end:
                return self.mem_angr

        # If in doubt use memsight, to be on the safe site
        return self.mem_memsight

    def __init__(self,
                 memory_backer=None,
                 permissions_backer=None,
                 endness=None,
                 mem_angr=None,
                 mem_memsight=None,
                 *args,
                 **kwargs,
                 ):

        SimMemory.__init__(self,
                           endness=endness,
                           abstract_backer=False,
                           stack_region_map=None,
                           generic_region_map=None
                           )

        self.id = 'mem'
        self._endness = endness
        self._memory_backer = memory_backer
#        self._permissions_backer = permissions_backer

        if mem_angr is None:
            self.mem_angr = SimSymbolicMemory(
                memory_backer=self._memory_backer,
                permissions_backer=None,
                endness=endness,
                memory_id='mem'
            )

        else:
            self.mem_angr = mem_angr

        if mem_memsight is None:
            self.mem_memsight = FullySymbolicMemory(
                # Data stored to memsight is not backed by anything. Backing is
                # only the file content.
                memory_backer=None,
                # Technically, we only need the permissions for the relevant
                # sections but apparently no harm done by passing them.
                permissions_backer=None,
                endness=endness
            )
        else:
            self.mem_memsight = mem_memsight

    @SimMemory.memo
    def copy(self, _):
        return CTMemory(
            memory_backer=self._memory_backer,
            mem_angr=self.mem_angr.copy(),
            mem_memsight=self.mem_memsight.copy(),
        )

    @property
    def mem(self):
        return self

    def set_state(self, state):
        super().set_state(state)
        # We don't have to always set both states but maybe this is good enough
        self.mem_angr.set_state(state)
        self.mem_memsight.set_state(state)

    def _store(self, req):
        # All writable sections are in memsight
        return self.mem_memsight._store(req)
#        return self._memory(req.addr)._store(req)

    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        return self._memory(addr)._load(addr, size, condition, fallback, inspect, events, ret_on_segv)

    def map_region(self, addr, length, permissions):
        self.mem_memsight.map_region(addr, length, permissions)

    def unmap_region(self, addr, length):
        self.mem_memsight.unmap_region(addr, length)

    def permissions(self, addr):
        raise NotImplementedError()

    def merge(self, others, merge_conditions, common_ancestor=None):
        raise NotImplementedError()

    def __contains__(self, addr):

        mem = self._memory(addr)
        if mem.__contains__(addr):
            return True

        # Memsight has no memory backer. When asked if it contains elf sections
        # that have not been touched yet. It they are not in memory. This breaks
        # SimEngineVEX._load_bytes(), so we fix it here.
        # TODO optimize as needed
        # if isinstance(mem, FullySymbolicMemory):
        #     for section in CTMemory._mem_memsight_sections:
        #         if section.contains_addr(addr):
        #             return True

        return False