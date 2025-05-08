import angr
import claripy
import time
import csv
import sys
import re
import capstone
from collections import defaultdict
from angr.state_plugins.fully_symbolic_memory import FullySymbolicMemory
import logging
import warnings
from angr.sim_state import SimState
from ct_memory import CTMemory

# uncomment only for presenting results!!!
warnings.filterwarnings("ignore")
logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.ERROR)

# suppress warnings from memsight
logging.getLogger("memsight").setLevel(logging.ERROR)

# suppress angr's unconstrained successor warnings
logging.getLogger("angr.engines.successors").setLevel(logging.ERROR)

# load the binary and optionally a specific case name
# if a specific case is not provided, all case_ functions will be run
if len(sys.argv) < 2:
    print("❌ Usage: python3 run_analysis.py <path_to_binary> [case_name]")
    sys.exit(1)

binary_path = sys.argv[1]
binary_label = binary_path.split('/')[-1]
specific_case = sys.argv[2] if len(sys.argv) >= 3 else None

# number of instruction that can be executed in a speculative state
SPECULATIVE_WINDOW = 200

# create an angr project from the binary
proj = angr.Project(binary_path, auto_load_libs=False)

# create a symbolic memory from memsightpp
CTMemory._set_memsight_ranges(proj)

# initialize a CFG and map addresses to function names
cfg = proj.analyses.CFGFast(normalize=True)

# gather all functions to analyze
if specific_case:
    case_names = [specific_case]
else:
    case_names = sorted(f.name for f in cfg.kb.functions.values() if f.name.startswith("case_"))

# create a dictionary for results of functions
results = defaultdict(lambda: {
    "speculative": False,
    "leakage": False,
    "leak_depth": None,
    "inputs": [],
    "addrs": set(),
    "I": None,
    "Iunr": None,
    "Time": None
})

# run the whole process for every case sequentially
for case_name in case_names:
    func = cfg.kb.functions.function(name=case_name)

    # check whether there is a conditional branch in this case
    def has_branching(func):
        for block_addr in func.block_addrs_set:
            block = proj.factory.block(block_addr)
            for insn in block.capstone.insns:
                if capstone.CS_GRP_JUMP in insn.groups:
                    return True
        return False

    # if there is not a branch, skip this case
    if not has_branching(func):
        results[case_name]["speculative"] = False
        results[case_name]["leakage"] = False
        results[case_name]["I"] = 0
        results[case_name]["Iunr"] = 0
        results[case_name]["Time"] = 0.0
        continue

    # create symbolic input + taint sources
    sym_input = claripy.BVS("input", 72) # 72-bit symbolic input
    taint_sources = set(sym_input.variables)
    
    # create a set for branches that we have already speculated on
    speculated_branches = set()

    idx = sym_input[:64] # actual input
    selector = sym_input[64:] # extra input to differentiate runs

    SimState.register_default('memory', CTMemory)

    # initialize call (entry) state
    state = state = proj.factory.call_state(func.addr, idx)
    block = proj.factory.block(state.addr)

    # rewrite the memory to be fully symbolic
    ct_mem = CTMemory(endness=proj.arch.memory_endness)
    ct_mem.set_state(state)
    state.register_plugin('memory', ct_mem)
    
    # create the simulation manager
    simgr = proj.factory.simulation_manager(state)

    # flags set the same way as in memsightpp
    # add simulation options
    state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.sim_options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.sim_options.CONSERVATIVE_WRITE_STRATEGY)
    state.options.add(angr.sim_options.SYMBOLIC_INITIAL_VALUES)

    # remove simplification
    state.options.discard(angr.options.KEEP_IP_SYMBOLIC)
    state.options.discard(angr.options.SIMPLIFY_MEMORY_WRITES)
    state.options.discard(angr.options.SIMPLIFY_REGISTER_WRITES)
    state.options.discard(angr.options.SIMPLIFY_MEMORY_READS)
    state.options.discard(angr.options.SIMPLIFY_REGISTER_READS)
    state.options.discard(angr.options.SIMPLIFY_EXIT_GUARD)
    state.options.discard(angr.options.SIMPLIFY_EXIT_STATE)
    state.options.discard(angr.options.SIMPLIFY_EXIT_TARGET)
    state.options.discard(angr.options.SIMPLIFY_RETS)
    state.options.discard(angr.options.SIMPLIFY_EXPRS)
    state.options.discard(angr.options.SIMPLIFY_CONSTRAINTS)

    # create a metadata which tracks tainted variables
    state.globals["taint_vars"] = set(taint_sources)
    
    # get the address of the secretarray and determine its size
    secret_sym = proj.loader.main_object.get_symbol("secretarray")
    secret_addr = secret_sym.rebased_addr
    secret_size = secret_sym.size
    state.globals["secretarray_base"] = secret_addr
    state.globals["secretarray_size"] = secret_size

   # get the address of the publicarray and determine its size
    public_sym = proj.loader.main_object.get_symbol("publicarray")
    public_addr = public_sym.rebased_addr
    public_size = public_sym.size
    state.globals["publicarray_size"] = public_size

    # put symbolic secret values in secretarray
    for i in range(secret_size):
        symb = claripy.BVS(f"secret_{i}", 8)
        state.memory.store(secret_addr + i, symb)
    
    # make public array symbolic
    for i in range(public_size):
        public_byte = claripy.BVS(f"public_{i}", 8)
        state.memory.store(public_addr + i, public_byte)

    # create a set of secret symbols that we have to check for
    secret_symbols = {f"secret_{i}" for i in range (secret_size)}

    # set a time limit for solving constraints
    state.solver.timeout = 1000

    def on_branch(state):
        # get the branch condition and address for the current state
        cond = state.inspect.exit_guard
        addr = state.addr

        # continue only if the state wasn't already speculated 
        if cond is None or addr in speculated_branches:
            return
        speculated_branches.add(addr)

        # retrieve the tainted variables
        taint_vars = state.globals.get("taint_vars", set())

        # get the variables of the condition
        cond_vars = {strip_suffix(var) for var in cond.variables}
        
        # fork the current state and mark it as speculative
        speculative = state.copy()
        speculative.globals["speculative"] = True

        # mark the state as not speculative
        results[case_name]["speculative"] = True
        results[case_name]["addrs"].add(speculative.addr)

        #TODO: in this hook, I have to check whether the condition isn't dependent on a secret or secret-tainted value

        # always take the mispredicted path
        state.globals["defer_speculation_cond"] = claripy.Not(cond)
        
        # add the new speculative state to the active states
        simgr.active.append(speculative)


    def mem_read(state):
        '''
        On memory read, detect whether we have read a secret symbol value that was put into the secret array during
        initialization
        '''
        # if we are not in a speculative state don't proceed
        if not state.globals.get('speculative'):
            return 
        
        # get the address from which memory will be read
        addr = state.inspect.mem_read_address

        # get the value being read
        expr = state.inspect.mem_read_expr

        # get the tainted variables
        taint_vars = state.globals.get("taint_vars", set())

        # check whether they exist
        if addr is None or expr is None:
            return

        # if a secret was used to determine the address of memory read, mark as leaky
        if any(strip_suffix(var) in secret_symbols for var in addr.variables):
            mark_as_leaky(state, addr)
        
        # if we have read a secret, mark all the variables of the read expression as tainted
        if any(strip_suffix(var) in secret_symbols for var in expr.variables):
            for var in expr.variables:
                stripped_var = strip_suffix(var)
                state.globals["taint_vars"].add(stripped_var)
        
        # if the address contains tainted variables, taint all the variables from the read expression 
        if any(strip_suffix(var) in taint_vars for var in addr.variables):
            for var in expr.variables:
                stripped_var = strip_suffix(var)
                state.globals["taint_vars"].add(stripped_var)
        
        # if the address was tainted, mark as leaky
        if any(strip_suffix(var) in taint_vars for var in addr.variables):
            mark_as_leaky(state, addr)

    def on_reg_write(state):
        # if we are not in a speculative state don't proceed
        if not state.globals.get('speculative'):
            return 
        
        # retrieve the expression that is going to be written to a register
        expr = state.inspect.reg_write_expr

        # check whether the expression exists
        if expr is None:
            return

        # retrieve the offset of the target register
        reg_offset = state.inspect.reg_write_offset

        # based on the register offset, get the register name
        reg_name = state.arch.translate_register_name(reg_offset, size=8)

        # get the tainted variables
        taint_vars = state.globals.get("taint_vars", set())
        
        # proceed only if the expression includes a tainted value
        if is_tainted(expr, taint_vars):

            # taint the target register
            state.globals["taint_vars"].add(reg_name)

            # the expression is tainted, so taint every symbolic variable
            for var in expr.variables:
                stripped_var = strip_suffix(var)
                state.globals["taint_vars"].add(stripped_var)

    # function to propagate the speculative flag from parents to successors
    def propagate_speculative_flag(state):
        parent_state = state.history.parent.state if state.history.parent is not None else None
        if parent_state:
            # inherit speculative flag from parent state
            if parent_state.globals.get('speculative', False):
                state.globals['speculative'] = True
            # inherit taint variables from parent state
            state.globals["taint_vars"] = set(parent_state.globals.get("taint_vars", set()))
        else:
            # initialize taint variables from attacker input
            state.globals["taint_vars"] = set(sym_input.variables)
    
    def inject_constraint(state):
        '''
        After a condition branch is resolved an angr goes into the branch, inject the mispredicted constraint
        '''
        # only inject misprediction constraint in speculative states
        if not state.globals.get("speculative", False):
            return

        # only inject misprediction if previously flagged
        if "defer_speculation_cond" in state.globals:
            cond = state.globals.pop("defer_speculation_cond")
            state.add_constraints(cond)
            # print(f"\n🧩 [on_irsb] Adding misprediction constraint at {hex(state.addr)}:")
            # print(f"  → Constraint being added: {cond}")  
            # print(f"  → Total constraints in path now: {len(state.solver.constraints)}")
            # for i, c in enumerate(state.solver.constraints):
            #     print(f"    [{i}] {c}")

    def count_speculative_instructions(state):
        if state.globals.get("speculative"):
            speculative_instruction_count = state.globals.get("spec_instr_count", 0)
            block = proj.factory.block(state.addr)
            speculative_instruction_count += len(block.capstone.insns)
            state.globals["spec_instr_count"] = speculative_instruction_count

    # determine if the address is tainted
    def is_tainted(expr, taint_vars):
        return any(var in taint_vars for var in expr.variables)
        
    # mark the state as leaky
    def mark_as_leaky(state, addr):
        leak_key = (state.addr, str(addr))

        # we only have to determine if the function is leaky only once, if it's already leaky just skip
        if leak_key not in results[case_name]["addrs"]:
            results[case_name]["addrs"].add(leak_key)
            results[case_name]["leakage"] = True
            results[case_name]["speculative"] = state.globals.get("speculative", False)
            state.globals['leakage'] = True

    # keep only the first secret symbol description
    def strip_suffix(var):
        return "_".join(var.split("_")[:2])
    
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=propagate_speculative_flag) # triggers before basic block execution
    state.inspect.b('exit', when=angr.BP_AFTER, action=inject_constraint) # triggers after branch is resolved
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=count_speculative_instructions) # triggers before basic block execution
    state.inspect.b('exit', when=angr.BP_BEFORE, action=on_branch) # triggers before a branch or conditional jump
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read) # triggers before a memory read
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=on_reg_write) # triggers after writing to a register

    start_time = time.time()
    speculative_instruction_count = 0

    # execute while there are active states
    while simgr.active:
        # advance states
        simgr.step()

        # for every active speculative state check whether it hasn't exceed the speculative window
        for state in simgr.active:
            if state.globals.get("spec_instr_count", 0) >= SPECULATIVE_WINDOW:
                    # if the speculative window has been exceeded, discard the state
                    state.globals["speculative"] = False
            if not state.globals.get("speculative", False):
                simgr.deadended.append(state)
        
        # if we have already detected a leakage, halt the execution
        if results[case_name]["leakage"]:
            simgr.deadended.extend(simgr.active)
            simgr.active.clear()

    end_time = time.time()
    results[case_name]["Time"] = end_time - start_time

    # loop for every terminal state
    for state in simgr.deadended:
        static_insns = set() # unique instructions
        total_insns = 0 # total number of instructions
        for addr in state.history.bbl_addrs:
            block = proj.factory.block(addr)
            total_insns += len(block.capstone.insns)
            static_insns.update(insn.address for insn in block.capstone.insns)
        results[case_name]["I"] = len(static_insns)
        results[case_name]["Iunr"] = total_insns
        try:
            concrete_input = state.solver.eval(idx, cast_to=int)
            hex_input = hex(concrete_input)
            if hex_input not in results[case_name]["inputs"]:
                results[case_name]["inputs"].append(hex_input)
        except:
            pass

# print out the summary for each test case
print("\n📊 === Summary by Function ===")
for func_name in sorted(results):
    res = results[func_name]
    print(f"\n📌 {func_name}")
    print(f"   - Speculative branch: {'✅' if res['speculative'] else '❌'}")
    print(f"   - Leakage detected:   {'✅' if res['leakage'] else '❌'}")
    if res["inputs"]:
        for i, inp in enumerate(res["inputs"]):
            print(f"     Input {i+1}: {inp}")

print(f"⏱️ Total combined analysis time: {sum(res['Time'] for res in results.values()):.2f} seconds")

# write merged CSV output
# this collects all case results into a single CSV file for easier comparison
output_csv = f"/workspace/results/{binary_label}_results.csv"
with open(output_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Binary", "I", "Iunr", "Time", "Result"])

    # summary row
    total_I = 0
    total_Iunr = 0
    total_time = 0.0
    has_insecure = False
    for case_name in sorted(results, key=lambda x: int(re.search(r'\d+', x).group()) if re.search(r'\d+', x) else float('inf')):
        res = results[case_name]
        verdict = "Insecure" if res["leakage"] or res["speculative"] else "Secure"
        input_val = res["inputs"][0] if res["inputs"] else "-"
        result = "Insecure" if res["leakage"] or res["speculative"] else "Secure"
        I = res.get("I", 0)
        Iunr = res.get("Iunr", 0)
        time_val = round(res.get("Time", 0), 2)

        total_I += I if isinstance(I, int) else 0
        total_Iunr += Iunr if isinstance(Iunr, int) else 0
        total_time += time_val
        if result == "Insecure":
            has_insecure = True

        writer.writerow([
            case_name,
            I,
            Iunr,
            time_val,
            result
        ])

    # write the final summary row with binary name
    binary_label = binary_path.split('/')[-1]
    summary_result = "Insecure" if has_insecure else "Secure"
    writer.writerow([
        binary_label,
        total_I,
        total_Iunr,
        round(total_time, 2),
        summary_result
    ])