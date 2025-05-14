import angr
import claripy
import time
import csv
import sys
import re
import capstone
import copy
from collections import defaultdict
from angr.state_plugins.fully_symbolic_memory import FullySymbolicMemory
import logging
import warnings
from angr.sim_state import SimState
from ct_memory import CTMemory
from claripy import UGE, ULT

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
proj = angr.Project(binary_path, auto_load_libs=False, default_analysis_mode='symbolic', use_sim_procedures=False)

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

# initialize public memory data
public_sym = proj.loader.main_object.get_symbol("publicarray")
public_array_sym = proj.loader.main_object.get_symbol("publicarray_size")
mask_sym = proj.loader.main_object.get_symbol("publicarray_mask")
public_addr = public_sym.rebased_addr
public_size = public_sym.size
public_size_addr = public_array_sym.rebased_addr

# initialize secret memory data
secret_sym = proj.loader.main_object.get_symbol("secretarray")
secret_array_sym = proj.loader.main_object.get_symbol("publicarray_size")
secret_addr = secret_sym.rebased_addr
secret_size = secret_sym.size
secret_size_addr = secret_array_sym.rebased_addr

def build_sec_mem_predicate(state, idx):
    """Build the predicate that needs to be satisfied for idx to reach secret memory"""
    secret_addr = state.globals["secretarray_addr"]
    secret_size = state.globals["secretarray_size"]
    public_addr = state.globals["publicarray_addr"]

    offset = secret_addr - public_addr
    idx_width = idx.size()
    delta = claripy.BVV(offset, idx_width)
    delta_end = claripy.BVV(offset + secret_size, idx_width)
    in_secret = claripy.And(
        claripy.UGE(idx,      delta), 
        claripy.ULT(idx,      delta_end),
        )
    state.globals["leak_pred"] = in_secret

def has_branching(func):
    """Check whether the test case has a conditional jump, which can be mis-predicted
       This is a precondition for speculative execution 
    """
    for block_addr in func.block_addrs_set:
        block = proj.factory.block(block_addr)
        for insn in block.capstone.insns:
            if capstone.CS_GRP_JUMP in insn.groups:
                return True
    return False

def record_branch_count(state):
    """Record the number of constraints before the conditional branch
        Save the original exit guard that will then determine which state is speculative
        Mark the current condition as True so we enter the branch
    """
    # get the current condition
    cond = state.inspect.exit_guard
    
    if cond is None:
        return
    
    state.globals["guard"] = cond
    state.globals["_pre_branch_count"] = len(state.solver.constraints)
    state.inspect.exit_guard = claripy.BoolV(True)

def on_branch(state):
    """After the conditional branch remove the added constraint
        Detect whether the condition was dependent on a secret
    """
    # get the branch condition and address for the current state
    cond = state.globals["guard"]
    addr = state.addr

    # continue only if the branch wasn't already speculated on
    if cond is None or addr in speculated_branches:
        return
    speculated_branches.add(addr)

    # the actual target addr that this state has jumped to
    target = state.solver.eval(state.history.jump_target) 

    # the addr of the successor the branch should have taken
    true_target = state.solver.eval(state.inspect.exit_target)

    # retrieve the path predicates and create a new reference
    old_path_predicates = state.globals.get("path_predicates", [])
    new_path_pred = list(old_path_predicates)
    # print("Path predicates before adding:")
    # print_path_pred(old_path_predicates)

    # if this state represents true branch
    if target == true_target:
        pred = cond
    
    # if this state represent the false branch
    else:
        pred = claripy.Not(cond)
    
    # append the new predicate and save it to globals
    new_path_pred.append(pred)
    # print("Path predicates after adding")
    # print_path_pred(new_path_pred)
    # print("END OF PREDICATES\n\n")
    state.globals["path_predicates"] = new_path_pred

    # remove the constraint that was added by the conditional branch
    pre_count = state.globals.get("_pre_branch_count", 0)        
    state.solver._solver.constraints= state.solver._solver.constraints[:pre_count]

    # if the condition is not dependent on a secret, we can return
    if check_secret_dependency(state, cond):
        mark_as_leaky(state, addr)
        return

def mem_read(state):
    """Before a memory read, check whether secret memory can be accessed
        If secret memory was accessed mark the read expression as dependent on a secret
        If secret dependent variables were used as an address, report leakage
    """
    # get the address from which memory will be read
    addr = state.inspect.mem_read_address

    # get the value being read
    expr = state.inspect.mem_read_expr

    if addr is None or expr is None:
        return
    
    # if we can access secret memory, taint the expression being read
    in_secret = state.globals["leak_pred"]
    if state.solver.satisfiable(extra_constraints=[in_secret]):
        taint(state, expr)

    # if we have an expression dependent on secret, taint the expression
    if check_secret_dependency(state, expr):
        taint(state, expr)
    
    # if the address isn't secret dependent we can return
    if not check_secret_dependency(state, addr):
        return

    # if the leak has occurred in a speculative state, mark as leaky and halt the execution
    if is_speculative_leak(state):
        mark_as_leaky(state, addr)
        return
    
def on_irsb(state):
    """Retrieve the publicarray mask and if this state is masking the index add is as a constraint"""
    addr = state.addr
    irsb = proj.factory.block(addr).vex
    mask = state.globals.get('publicarray_mask')
    
    # if there is no musk declared in the file don't add any constraints
    if mask is None:
        return 
    
    for stmt in irsb.statements:
        # check if there is a binary operation
        if stmt.tag == 'Ist_WrTmp' and stmt.data.tag == 'Iex_Binop':
            operator = stmt.data

            # if there is a bitwiseAnd operation, add the constraint
            if operator.op in ('Iop_And32', 'Iop_And64'):
                mask_bvv = claripy.BVV(mask, idx.size())
                constraint = (idx & ~mask_bvv) == 0
                state.add_constraints(constraint)

def check_secret_dependency(state, expr):
    """Check whether an expression is dependent on a secret"""
    if len(secret_symbols) > 0:
        renamed_secrets = {secret.cache_key:
                           state.solver.BVV(0, secret.size()) for secret in secret_symbols}

        expr_renamed = expr.replace_dict(renamed_secrets)
        return state.solver.satisfiable(extra_constraints=[expr != expr_renamed], exact=True)

def count_speculative_instructions(state):
    """Count the number of speculative instruction executed"""
    speculative_instruction_count = state.globals.get("spec_instr_count", 0)
    block = proj.factory.block(state.addr)
    speculative_instruction_count += len(block.capstone.insns)
    state.globals["spec_instr_count"] = speculative_instruction_count
    
def mark_as_leaky(state, addr):
    """Mark the state as leaky and determine the attacker input that lead to this leakage"""
    leak_key = (state.addr, str(addr))

    # we only have to determine if the function is leaky only once, if it's already leaky just skip
    if leak_key not in results[case_name]["addrs"]:
        results[case_name]["leakage"] = True
        results[case_name]["speculative"] = True
        results[case_name]["addrs"].add(state.addr)
        concrete_idx = state.solver.eval(idx)
        results[case_name].setdefault("inputs", []).append(hex(concrete_idx))
        simgr.move('active', 'deadended', lambda s: True)

def taint(state, expr):
    """Add symbolic variables to the secret symbols"""
    # get the secret symbols
    secret_symbols = state.globals.get("secret_symbols", set())

    # add symbolic variables that were tainted into the secret_symbols
    for var in expr.variables:
        stripped = strip_suffix(var)
        sym = claripy.BVS(stripped, 8)
        if sym is not None and sym not in secret_symbols:
            secret_symbols.add(sym)

def is_speculative_leak(state):
    """Determine whether we are in a speculative state"""
    predicates = state.globals.get("path_predicates", [])
    in_secret = state.globals["leak_pred"]
    # build conjunction of predicates
    if predicates:
        path_cond = predicates[0]
        for predicate in predicates[1:]:
            path_cond = state.solver.And(path_cond, predicate)
    else:
        path_cond = state.solver.true

    # if the constraints are not satisfiable, we are in a speculative state
    return not state.solver.satisfiable(extra_constraints=[path_cond, in_secret])

# keep only the first secret symbol description
def strip_suffix(var):
    return "_".join(var.split("_")[:2])

# FOR DEBUG!
def print_path_pred(pred_list):
    if len(pred_list) == 0:
        print("[]")
        print("-------------------------------------------------------------")
    counter = 0
    for pred in pred_list:
        print(f"Predicate [{counter}: {pred}]")
        print("-------------------------------------------------------------")
        counter+=1

# run the whole process for every case sequentially
for case_name in case_names:
    func = cfg.kb.functions.function(name=case_name)

    # if there is no conditional jump, skip the test case
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

    idx      = sym_input[63:] # attacker input
    selector = sym_input[:64] # input for specific case

    SimState.register_default('memory', CTMemory)

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

    # create a set for variables that are secret dependent
    state.globals["secret_dependent_vars"] = set()

    # get the address of the secretarray and determine its size
    state.globals["secretarray_addr"] = secret_addr
    state.globals["secretarray_size"] = secret_size

    # get the address of the publicarray and determine its size, retrieve publicarray mask
    state.globals["publicarray_addr"] = public_addr
    state.globals["publicarray_size"] = public_size

    # TODO for now this is a primitive solution, should make it more robust
    if mask_sym is not None:
        state.globals["publicarray_mask"] = public_size-1
    
    state.memory.store(public_size_addr,
                   claripy.BVV(public_size, 64), endness=proj.arch.memory_endness)
    state.memory.store(secret_size_addr,
                    claripy.BVV(secret_size, 64), endness=proj.arch.memory_endness)

    # initialize the path predicate
    state.globals["path_predicates"] = []
    
    # initialize the secret_symbols set and populate it
    state.globals["secret_symbols"] = set()
    secret_symbols = state.globals["secret_symbols"]
    for i in range(secret_size):
        symb = claripy.BVS(f"secret_{i}", 8)
        secret_symbols.add(symb)
        state.memory.store(secret_addr + i, symb)
    
    # put symbolic values in publicarray
    for i in range(public_size):
        public_byte = claripy.BVS(f"public_{i}", 8)
        state.memory.store(public_addr + i, public_byte)

    # set a time limit for solving constraints
    state.solver.timeout = 1000

    # build the predicate for reading from secret memory
    build_sec_mem_predicate(state, idx)

    # Hooks
    state.inspect.b('exit', when=angr.BP_BEFORE, action=record_branch_count) # triggers after branch is resolved
    state.inspect.b('exit', when=angr.BP_AFTER, action=on_branch) # triggers after branch is resolved
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=count_speculative_instructions) # triggers before basic block execution
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read) # triggers before a memory read
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=on_irsb) # triggers before an instruction block is executed

    start_time = time.time()
    speculative_instruction_count = 0

    # execute while there are active states
    while simgr.active:
        # advance states
        simgr.step()

        # move the unsat states to deadended so I can check them manually
        simgr.move('unsat', 'deadended', lambda s: True)

        # for every active speculative state check whether it hasn't exceed the speculative window
        for state in simgr.active:
            # if the state has exceeded the speculative window move it to deadened
            spec_inst_count = state.globals.get("spec_instr_count", 0)
            if state.globals.get("spec_instr_count", 0) >= SPECULATIVE_WINDOW:
                preds = state.globals.get("path_predicates", [])

                # build conjunction (or “true” if empty)
                if preds:
                    path_cond = preds[0]
                    for p in preds[1:]:
                        path_cond = state.solver.And(path_cond, p)
                else:
                    path_cond = state.solver.true

                # if the state predicate is not satisfiable, we are in a speculative state
                if not state.solver.satisfiable(extra_constraints=[path_cond]):                    
                    # move the state to deadended
                    simgr.move(from_stash='active', to_stash='deadended',
                            filter_func=lambda s: s is state)
                else:
                    # this is the path taken by normal execution, reset the speculative window
                    state.globals["path_predicates"] = []
                    state.globals["spec_instr_count"] = 0
            
            # go through deadended states, and check whether a leakage was reported
            for state in simgr.deadended:
                preds = state.globals.get("path_predicates", [])
                if preds:
                    path_cond = preds[0]
                    for p in preds[1:]:
                        path_cond = state.solver.And(path_cond, p)
                else:
                    path_cond = state.solver.true

                if not state.solver.satisfiable(extra_constraints=[path_cond]):
                    # check if we have found a leakage in this state
                    if state.globals.get("leakage", False):
                        results[case_name]["leakage"] = True
                        for inp in state.globals.get("leak_inputs", []):
                            results[case_name]("inputs", []).append(inp)
                        break

            # if we have already detected a leakage, halt the execution
            if results[case_name]["leakage"]:
                simgr.move(
                    from_stash='active',
                    to_stash='deadended',
                    filter_func=lambda s: True
                )
                break

    end_time = time.time()
    results[case_name]["Time"] = end_time - start_time

    # print("=== stash summary ===")
    # for stash_name, stash_list in simgr.stashes.items():
    #     print(f"  {stash_name:10s}: {len(stash_list)} state(s)")

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