import angr
import claripy
import time
import csv
import sys
import re
from collections import defaultdict
from angr.concretization_strategies import SimConcretizationStrategyAny
import logging
import warnings

# uncomment only for presenting results!!!
warnings.filterwarnings("ignore")
logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.ERROR)

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

    # create symbolic input + taint sources
    sym_input = claripy.BVS("input", 72) # 72-bit symbolic input
    taint_sources = set(sym_input.variables)
    
    # create a set for branches that we have already speculated on
    speculated_branches = set()

    idx = sym_input[:64] # actual input
    selector = sym_input[64:] # extra input to differentiate runs

    # initialize call (entry) state
    state = proj.factory.call_state(func.addr, idx)

    # create a metadata which tracks tainted variables
    state.globals["taint_vars"] = set(taint_sources)
    
    # get the address of the secretarray and determine its size
    secret_sym = proj.loader.main_object.get_symbol("secretarray")
    secret_addr = secret_sym.rebased_addr
    secret_size = secret_sym.size

    # get the address of the publicarray and determine its size
    public_sym = proj.loader.main_object.get_symbol("publicarray")
    public_addr = public_sym.rebased_addr
    public_size = public_sym.size

    # read both arrays
    public_bytes = [proj.loader.memory.load(public_addr + i, 1)[0] for i in range(public_size)]
    secret_bytes = [proj.loader.memory.load(secret_addr + i, 1)[0] for i in range(secret_size)]

    # turn the lists into a set and find the intersection so we know which secret values are in publicarray
    public_vals = set(public_bytes)
    secret_vals = set(secret_bytes)
    leaky_values = public_vals.intersection(secret_vals)
    # print(f"These are the leaky values: {leaky_values}")

    # put symbolic secret values in secretarray
    for i in range(secret_size):
        symb = claripy.BVS(f"secret_{i}", 8)
        state.memory.store(secret_addr + i, symb)
    
    # create a set of secret symbols that we have to check for
    secret_symbols = {f"secret_{i}" for i in range (secret_size)}

    # put symbolic secret values in publicarray 
    for i in range(public_size):
        val = public_bytes[i]

        # only if the value is secret
        if isinstance(val, int) and val in leaky_values:
            # print(f"Adding secret_{val} to public array!")
            symb = claripy.BVS(f"secret_{val}", 8)
            state.memory.store(public_addr + i, symb)
            
            # add the secret value to the set of secret symbols
            secret_symbols.add(f"secret_{val}")
    

    # allow angr to pick any possible value, helps with resolving when accessing symbolic memory
    state.memory.read_strategies = [SimConcretizationStrategyAny()]
    state.memory.write_strategies = [SimConcretizationStrategyAny()]

    # pick any possible value when reading and don't access unmapped memory
    state.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    state.options.add(angr.options.STRICT_PAGE_ACCESS)

    # returns 0 from uninitialized memory/registers
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # enable automatic simplification
    state.options.add(angr.options.SIMPLIFY_EXPRS)
    
    # set a time limit for solving constraints
    state.solver.timeout = 10000

    def on_branch(state):
        # get the branch condition and address for the current state 
        cond = state.inspect.exit_guard
        addr = state.addr

        # continue only if the state wasn't already speculated
        if cond is None or addr in speculated_branches:
            return

        # check whether the current condition is symbolic
        is_symbolic = state.solver.symbolic(cond)

        # check whether the condition is tainted by attacker input
        is_tainted_branch = any(var in taint_sources for var in cond.variables)

        # don't model speculation unless current condition is both symbolic and tainted
        if not (is_symbolic and is_tainted_branch):
            return
        
        speculated_branches.add(addr)
        func_name = case_name
        
        # fork the current state and mark it as speculative
        speculative_state = state.copy()
        speculative_state.globals['speculative'] = True

        # save the condition and set the speculative flag so the state doesn't get prune
        # before the condition is retrieved in an irsb hook 
        state.globals["defer_speculation_cond"] = cond
        state.globals["speculative"] = True

        results[func_name]["speculative"] = True
        results[func_name]["addrs"].add(speculative_state.addr)

        # Replace current state with the speculative fork
        simgr.active.append(speculative_state)

    def mem_read(state):
        # get the address from which memory will be read
        addr = state.inspect.mem_read_address

        # get the value being read
        val = state.inspect.mem_read_expr

        # check whether they exist
        if addr is None or val is None:
            return

        # if we are not in a speculative state don't proceed
        if not state.globals.get('speculative'):
            return

        accessed_secret = False
        taint_vars = state.globals.get("taint_vars", set())

        # determine whether we have accessed any secret value
        if any(strip_suffix(var) in secret_symbols for var in val.variables):
            accessed_secret = True

        # determine whether the attacker has accessed memory that contains secret value
        if is_addr_attacker_controled(addr, taint_vars):
            accessed_secret = True

        # if we have accessed a secret mark as leaky
        if accessed_secret:
            func_name = case_name
            leak_key = (state.addr, str(addr))

            # we only have to determine if the function is leaky only once, if it's already leaky just skip
            if leak_key not in results[func_name]["addrs"]:
                results[func_name]["addrs"].add(leak_key)
                state.globals['leakage'] = True
                results[func_name]["leakage"] = True
    
    def on_reg_write(state):
        # retrieve the expression that is going to be written to a register
        expr = state.inspect.reg_write_expr

        # retrieve the offset of the target register
        reg_offset = state.inspect.reg_write_offset
        
        # proceed only if the expression includes a tainted value
        if expr is not None and is_tainted(expr, state):
            
            # based on the register offset, get the register name
            reg_name = state.arch.translate_register_name(reg_offset, size=8)

            # taint the target register
            state.globals["taint_vars"].add(reg_name)

            # the expression is tainted, so taint every symbolic variable
            for var in expr.variables:
                var = strip_suffix(var)
                state.globals["taint_vars"].add(var)

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
    
    # after an instruction block, inject the misprediction to the constraints
    def on_irsb(state):
        # only inject misprediction if previously flagged
        if "defer_speculation_cond" in state.globals:
            cond = state.globals.pop("defer_speculation_cond")
            state.add_constraints(state.solver.Not(cond))

            # set the flag to false, so this state can be pruned
            state.globals["speculative"] = False 
    
    # after an instruction block, add the number of instruction that were executed to the counter
    def count_speculative_instructions(state):
        if state.globals.get("speculative"):
            speculative_instruction_count = state.globals.get("spec_instr_count", 0)
            block = proj.factory.block(state.addr)
            speculative_instruction_count += len(block.capstone.insns)
            state.globals["spec_instr_count"] = speculative_instruction_count

    # keep only the first secret symbol description
    def strip_suffix(var):
        return "_".join(var.split("_")[:2])

    # check whether an expression is tainted
    def is_tainted(expr, state):
        return any(var in state.globals["taint_vars"] for var in expr.variables)

    # check whether the address depends on a secret
    def is_addr_attacker_controled(addr, taint_vars):
        # check whether the adress is dependent on tainted variable
        is_attacker_controlled = any(var in taint_vars for var in addr.variables)

        if is_attacker_controlled:
            # get the concerte address of the state
            concrete_addr = state.solver.eval(addr, cast_to=int)

            # determine whether we are inside publicarray
            is_inside_public = (public_addr <= concrete_addr < public_addr + public_size)
            if is_inside_public:
                offset = concrete_addr - public_addr
                byte = public_bytes[offset]
                # determine whether there is a secret symbol in publicarray
                is_secret_byte = isinstance(byte, int) and f"secret_{byte}" in secret_symbols

                # publicarray is accessed based on the tainted variable and has a secret value
                if is_secret_byte:
                    return True
        return False



    
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=propagate_speculative_flag) # triggers before basic block execution
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=on_irsb) # triggers before basic block execution
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=count_speculative_instructions) # triggers before basic block execution
    state.inspect.b('exit', when=angr.BP_BEFORE, action=on_branch) # triggers before a branch or conditional jump
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read) # triggers before a memory read
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=on_reg_write) # triggers after writing to a register

    start_time = time.time()
    simgr = proj.factory.simulation_manager(state)
    speculative_instruction_count = 0
    steps = 0
    step_limit = 10000
    # execute while there are active states
    while simgr.active and steps < step_limit:
        # advance all active states
        simgr.step()
        steps += 1

        # for every active speculative state check whether it hasn't exceed the speculative window
        for state in simgr.active:
            if state.globals.get("speculative"):
                if state.globals.get("spec_instr_count", 0) >= SPECULATIVE_WINDOW:
                    # if the speculative window has been exceeded, discard the state
                    simgr.active.remove(state)
        
        # if we have already detected a leakage, prune all non-speculative states
        if results[case_name]["leakage"]:
            simgr.stash(
                    filter_func=lambda s: not s.globals.get("speculative", False),
                    from_stash='active',
                    to_stash='pruned'
                )
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
            results[case_name]["inputs"].append(hex(concrete_input))
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