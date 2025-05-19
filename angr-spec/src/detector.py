import angr
import claripy
import time
import csv
import sys
import re
import capstone
import copy
import json
from collections import defaultdict
from angr.state_plugins.fully_symbolic_memory import FullySymbolicMemory
import logging
import warnings
from angr.sim_state import SimState
from ct_memory import CTMemory
from claripy import UGE, ULT
import pyvex

# number of instruction that can be executed in a speculative state
SPECULATIVE_WINDOW = 200
counter = 0

def parse_symbol(proj, name):
    """Parses a symbol to match name of a symbol against its name in memory"""
    # try to simply match the name in the cfg against memory
    sym = proj.loader.main_object.get_symbol(name)
    if sym is not None:
        return sym
    
    # if the compiler added some suffix, try to find the original 
    for sym in proj.loader.main_object.symbols:
        if sym.name.startswith(name + "."):
            return sym
    
    # if we haven't found it
    return None

def get_case_names(proj, specific_case=None):
    """Collects the name of all the cases, if the user wants to analyze
       only a specific case, return that one"""
    all_cases = [
        sym.name
        for sym in proj.loader.main_object.symbols
        if sym.name and sym.name.startswith("case_")
    ]
    if specific_case:
        return [specific_case]
    return sorted(all_cases)

def parse_config(proj, cfg):
    """Populate the dictionary with data from the config file"""
    symbol_info = {}
    mem_sections = ["public", "private"]
    
    # for both memory sections in config
    for mem in mem_sections:
        for entry in cfg[mem]:
            # get the symbol from the memory
            sym = parse_symbol(proj, entry["name"])
            if sym is None:
                raise RuntimeError(f"{mem} symbol `{entry['name']}` not found")
            if entry["type"].endswith("[]"):
                elem_size = {"uint8[]": 1}[entry["type"]]
                length    = entry["length"]
            else:
                elem_size = {"uint8":1, "uint64":8}[entry["type"]]
                length    = None

            # populate the symbol info dictionary
            symbol_info[entry["name"]] = {
                "addr":       sym.rebased_addr,
                "elem_size":  elem_size,
                "length":     length,
                "kind":       mem,
                "value":      entry.get("value", None)
            }
    return symbol_info

def dump_memory():
    """Debug function for dumping memory"""
    print("=== GLOBAL SYMBOLS ===")
    for sym in proj.loader.main_object.symbols:
        # only show symbols with a valid address
        if sym.rebased_addr is not None:
            print(f"{sym.name:30s} @ {hex(sym.rebased_addr)}")

def has_branching(addr):
    """Determine whether the case has conditional jumps"""
    # disassemble the one block at addr and look for any jump opcodes
    block = proj.factory.block(addr)
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

    speculated_branches = state.globals["speculated_branches"]
    # continue only if the branch wasn't already speculated on
    if cond is None or addr in speculated_branches:
        return
    speculated_branches.add(addr)

    # the actual target addr that this state has jumped to
    target = state.solver.eval(state.history.jump_target) 

    # the addr of the successor the branch should have taken
    true_target = state.solver.eval(state.inspect.exit_target)

    # retrieve the path predicates and create a new reference
    old_path_pred = state.globals["path_predicates"]
    new_path_pred = list(old_path_pred)

    # if this state represents true branch
    if target == true_target:
        pred = cond
    
    # if this state represent the false branch
    else:
        pred = claripy.Not(cond)
    
    # if this is the first branch
    if not state.globals["spec_started"]:
        state.globals["spec_started"] = True
        state.globals["spec_instr_count"] = 0

    # if this is not the first branch
    instr_count = state.globals["spec_instr_count"]
    new_path_pred.append({
        "pred":       pred,
        "count":      instr_count,
    })
    state.globals["path_predicates"] = new_path_pred

    # remove the constraint that was added by the conditional branch
    pre_count = state.globals.get("_pre_branch_count", 0)        
    state.solver._solver.constraints= state.solver._solver.constraints[:pre_count]

    # if the condition is not dependent on a secret, we can return
    if check_secret_dependency(state, cond):
        mark_as_leaky(state, addr)
        return
    
def add_mask(state):
    addr = state.inspect.mem_read_address
    mask = state.globals.pop("pending_mask", None)
    if not mask:
        return
    
    tmp_name, mask_val = mask

    # if the idx is not used as a part of mem_read addr return
    if not contains_idx(addr, state.globals["idx"]):
        return
    
    # add the mask
    idx = state.globals["idx"]
    mask_bvv = claripy.BVV(mask_val, idx.size())
    state.add_constraints((idx & ~mask_bvv) == 0)

def mem_read(state):
    """Before a memory read, check whether secret memory can be accessed
       If secret memory was accessed mark the read expression as dependent on a secret
       If secret dependent variables were used as an address, report leakage
    """
    # before memory read, add a mask if there is one
    add_mask(state)
    
    # get the address from which memory will be read
    addr = state.inspect.mem_read_address

    # get the value being read
    expr = state.inspect.mem_read_expr

    if addr is None or expr is None:
        return
    
    idx = state.globals.get("idx")
    if not contains_idx(addr, idx):
       return

    base = state.globals["secretarray_addr"]
    size = state.globals["secretarray_size"]
    w    = addr.size()
    lo   = claripy.BVV(base, w)
    hi   = claripy.BVV(base + size, w)
    
    # if we can access secret memory, taint the expression being read
    in_secret = claripy.And(addr.UGE(lo), addr.ULT(hi))
    if state.solver.satisfiable(extra_constraints=[in_secret]):
        taint(state, expr)
        """TODO: In here I have to check which addr has been tainted, after that 
           when I am in is_speculative_leak I should check if that saved addr is used 
           if yes then retrieve that in_secret predicate.
        """
        if "first_leak" not in state.globals:
            state.globals["first_leak"] = (addr, in_secret)

    # if we have an expression dependent on secret, taint the expression
    if check_secret_dependency(state, expr):
        taint(state, expr)
        if "first_leak" not in state.globals:
            state.globals["first_leak"] = (addr, in_secret)
    
    # if the address isn't secret dependent we can return
    if not check_secret_dependency(state, addr):
        return

    # if the leak has occurred in a speculative state, mark as leaky and halt the execution
    if is_speculative_leak(state, addr):
        mark_as_leaky(state, addr)
        return

def check_secret_dependency(state, expr):
    """Check whether an expression is dependent on a secret"""
    secret_symbols = state.globals["secret_symbols"]
    if len(secret_symbols) > 0:
        renamed_secrets = {secret.cache_key:
                           state.solver.BVV(0, secret.size()) for secret in secret_symbols}

        expr_renamed = expr.replace_dict(renamed_secrets)
        return state.solver.satisfiable(extra_constraints=[expr != expr_renamed], exact=True)

def count_speculative_instructions(state):
    """Count the number of speculative instruction executed"""
    if not state.globals["spec_started"]:
        return
    speculative_instruction_count = state.globals.get("spec_instr_count", 0)
    block = proj.factory.block(state.addr)
    speculative_instruction_count += len(block.capstone.insns)
    state.globals["spec_instr_count"] = speculative_instruction_count
    
def mark_as_leaky(state, addr):
    """Mark the state as leaky and determine the attacker input that lead to this leakage
       Afterwards, halt the execution of this state by moving it to deadended
    """
    leak_key = (state.addr, str(addr))
    case_name = state.globals["case_name"]
    simgr = state.globals["simgr"]
    idx = state.globals["idx"]
    results_map = state.globals["results"]
    leak = state.globals.get("first_leak")
    if leak is None:
        return
    addr, in_secret = leak

    print(f"{case_name}_IN_SEC: {in_secret}")

    s = claripy.Solver()
    s.add(in_secret)

    # get the per‐case record
    results = results_map[case_name]

    # we only have to determine if the function is leaky only once, if it's already leaky just skip
    if leak_key in results["addrs"]:
        return
    
    results["leakage"] = True
    results["speculative"] = True
    results["addrs"].add(state.addr)
    concrete_idx = s.eval(idx, 1)[0]
    results.setdefault("inputs", []).append(hex(concrete_idx))
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

def is_speculative_leak(state, addr):
    """Determine whether we are in a speculative state"""
    predicates = state.globals.get("path_predicates", [])
    base = state.globals["secretarray_addr"]
    size = state.globals["secretarray_size"]
    w = addr.size()
    lo = claripy.BVV(base, w)
    hi = claripy.BVV(base + size, w)
    in_secret = claripy.And(addr.UGE(lo), addr.ULT(hi))
    init_constraints = state.globals.get("init_constraints", [])
    
    # get the predicates from the dict
    preds = []
    for entry in predicates:
        # only dicts with a "pred" key
        if isinstance(entry, dict) and "pred" in entry:
            preds.append(entry["pred"])
        else:
            # in case you ever accidentally append a raw BoolRef
            preds.append(entry)

    # build conjunction of predicates and initial constraints
    if preds:
        path_cond = preds[0]
        for predicate in preds[1:] + init_constraints:
            path_cond = state.solver.And(path_cond, predicate)
    else:
        path_cond = state.solver.true
    # print(path_cond, in_secret)

    # if the constraints are not satisfiable, we are in a speculative state
    return not state.solver.satisfiable(extra_constraints=[path_cond, in_secret])

def on_tmp_write(state):
        """Triggers on write into temp. Used for detecting masking"""
        # get the expression written to temp
        expr = state.inspect.tmp_write_expr  

        # get the name of the idx
        idx = state.globals.get("idx")

        if expr.size() != idx.size():
            return

        # determine whether this is a bitwiseAND operation
        if expr.op != "__and__":
            return

        # check if there are 2 arguments in the operation
        if len(expr.args) != 2:
            return
        
        arg0, arg1 = expr.args
    
        # arg0 is input, so arg1 is the mask
        if contains_idx(arg0, idx):
            mask_sym    = arg1
            tmp_name = state.inspect.tmp_write_num
        elif contains_idx(arg1, idx):
            mask_sym    = arg0
            tmp_name = state.inspect.tmp_write_num
        else:
            return
        
        # determine the mask val and add it as a pending mask that should be added later
        mask_val = state.solver.eval(mask_sym, extra_constraints = state.globals["init_constraints"])
        state.globals["pending_mask"] = (tmp_name, mask_val)

def contains_idx(node, target):
    """Check whether the AST node has idx inside it"""
    if node is target:
        return True
    for child in getattr(node, "args", ()):
        if contains_idx(child, target):
            return True
    return False

def strip_suffix(var):
    """Strip the suffix of a variable which is assigned by the compiler"""
    return "_".join(var.split("_")[:2])

def print_path_pred(pred_list):
    """Debug function that prints the predicates of a path"""
    if len(pred_list) == 0:
        print("[]")
        print("-------------------------------------------------------------")
    counter = 0
    for pred in pred_list:
        print(f"Predicate [{counter}: {pred}]")
        print("-------------------------------------------------------------")
        counter+=1

def analyze_case(proj, symbol_info, case_name, SPECULATIVE_WINDOW):
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
    sym = parse_symbol(proj, case_name)
    if sym is None:
        raise RuntimeError(f"Couldn’t resolve {case_name}")
    func_addr = sym.rebased_addr

    # if there is no conditional jump, skip the test case
    if not has_branching(func_addr):
        results[case_name]["speculative"] = False
        results[case_name]["leakage"] = False
        results[case_name]["I"] = 0
        results[case_name]["Iunr"] = 0
        results[case_name]["Time"] = 0.0
        return

    # create symbolic attacker input
    sym_input = claripy.BVS("input", 64) # 64-bit symbolic input
    idx = sym_input

    SimState.register_default('memory', CTMemory)

    state = state = proj.factory.call_state(func_addr, idx)
    block = proj.factory.block(state.addr)

    # rewrite the memory to be fully symbolic
    ct_mem = CTMemory(endness=proj.arch.memory_endness)
    ct_mem.set_state(state)
    state.register_plugin('memory', ct_mem)
    
    # create the simulation manager
    simgr = proj.factory.simulation_manager(state)

    # assign variables to state globals
    state.globals["case_name"] = case_name
    state.globals["simgr"] = simgr
    state.globals["idx"] = idx
    state.globals["results"] = results
    state.globals["spec_started"] = False
    state.globals["spec_instr_count"] = 0
    state.globals['leak_pred'] = claripy.false
    state.globals["mask"] = None

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

    # get the address of the secretarray and its size and assign globals
    secret_info = symbol_info["secretarray"] 
    state.globals["secretarray_addr"] = secret_info["addr"]
    state.globals["secretarray_size"] = secret_info["length"]

    # get the address of the publicarray and its size and assign globals
    public_info = symbol_info["publicarray"]
    state.globals["publicarray_addr"] = public_info["addr"]
    state.globals["publicarray_size"] = public_info["length"]

    # initialize secret symbols
    state.globals["secret_symbols"] = set()
    secret_symbols = state.globals["secret_symbols"]

    # keep track of which branches you’ve already speculated on
    state.globals["speculated_branches"] = set()
    state.globals["path_predicates"] = []
    state.globals["init_constraints"] = []

    """For every memory data that we were given in the config
       create symbolic variables and store them in memory
    """
    for name, info in symbol_info.items():
        addr      = info["addr"]
        elem_size = info["elem_size"]
        length    = info["length"]
        kind      = info["kind"]
        val       = info["value"]
        bits = elem_size * 8

        # simple variables
        if length is None:
            if kind == "public" and val is not None:
                sym = claripy.BVS(name, bits)
                state.memory.store(addr, sym, endness=proj.arch.memory_endness)
                concrete_bvv = claripy.BVV(val, bits)
                pred = (sym == concrete_bvv)
                if "mask" in name:
                    state.globals["mask"] = val
                
                # only add non-trivial predicates so we don't change the outcome if the symbol is not used
                if not pred.is_true() and not pred.is_false():
                    state.globals["init_constraints"].append(pred)
            elif kind == "public":
                # no concrete value given? fall back to symbolic
                bv = claripy.BVS(name, bits)
                state.memory.store(addr, bv, endness=proj.arch.memory_endness)
            else:
                # private scalar
                bv = claripy.BVS(f"_high_{name}", bits)
                state.memory.store(addr, bv, endness=proj.arch.memory_endness)
        # arrays
        else:
            for i in range(length):
                elem_addr = addr + i * elem_size
                if kind == "public":
                    symb = claripy.BVS(f"public_{i}", bits)
                    state.memory.store(elem_addr, symb, endness=proj.arch.memory_endness)
                else:
                    # private array element
                    symb = claripy.BVS(f"secret_{i}", bits)
                    secret_symbols.add(symb)
                    state.memory.store(elem_addr, symb, endness=proj.arch.memory_endness)
    
    # set a time limit for solving constraints
    state.solver.timeout = 1000
    
    # hooks
    state.inspect.b('exit', when=angr.BP_BEFORE, action=record_branch_count) # triggers after branch is resolved
    state.inspect.b('exit', when=angr.BP_AFTER, action=on_branch) # triggers after branch is resolved
    state.inspect.b('irsb', when=angr.BP_BEFORE, action=count_speculative_instructions) # triggers before basic block execution
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read) # triggers before a memory read
    state.inspect.b('tmp_write', when=angr.BP_BEFORE, action=on_tmp_write) # triggers before a write to tmp

    start_time = time.time()

    # execute while there are active states
    while simgr.active:
        # advance states
        simgr.step()
        for state in simgr.active:
            # if the state has exceeded the speculative window move it to deadened
            if state.globals.get("spec_instr_count", 0) > SPECULATIVE_WINDOW:
                predicate_dict = state.globals["path_predicates"]
                preds = [predicate["pred"] for predicate in predicate_dict]
                # build conjunction (or “true” if empty)
                if preds:
                    path_cond = preds[0]
                    for p in preds[1:]:
                        path_cond = state.solver.And(path_cond, p)
                else:
                    path_cond = state.solver.true

                """If the path predicate is unsatisfiable, we are in a speculative state
                   This state has passed it's speculative window and has been rolled back
                """
                if not state.solver.satisfiable(extra_constraints=[path_cond]):                    
                    # move the state to deadended
                    simgr.move(from_stash='active', to_stash='deadended',
                            filter_func=lambda s: s is state)
                else:
                    # this is the path taken by normal execution

                    # remove the oldest branch predicate and extend the speculative window
                    last = predicate_dict.pop(0)
                    refunded = last["count"] 
                    state.globals["spec_instr_count"] -= refunded

                    # if there are no predicates left, just reset the whole window
                    if not predicate_dict:
                        state.globals["spec_started"] = False

            # if we have already detected a leakage, halt the execution
            if results[case_name]["leakage"]:
                simgr.move(
                    from_stash='active',
                    to_stash='deadended',
                    filter_func=lambda s: True
                )
                break

    # dump_stashes(simgr)

    end_time = time.time()
    results[case_name]["Time"] = end_time - start_time

    # for every terminal state, populate results dict with the number of isnstruction executed
    for state in simgr.deadended:
        static_insns = set() # unique instructions
        total_insns = 0 # total number of instructions
        for addr in state.history.bbl_addrs:
            block = proj.factory.block(addr)
            total_insns += len(block.capstone.insns)
            static_insns.update(insn.address for insn in block.capstone.insns)
        results[case_name]["I"] = len(static_insns)
        results[case_name]["Iunr"] = total_insns
    return results[case_name]

def print_summary(results):
    # print out the summary for each test case
    print("\n📊 === Summary by Function ===")
    for func_name in sorted(results):
        res = results[func_name]
        print(f"\n📌 {func_name}")
        print(f"   - Speculative branch: {'✅' if res['speculative'] else '❌'}")
        print(f"   - Leakage detected:   {'✅' if res['leakage'] else '❌'}")
        inputs = res.get("inputs")
        if isinstance(inputs, list) and inputs:
            for i, inp in enumerate(inputs):
                print(f"     Input {i+1}: {inp}")
        else:
            print("     Input: -")

    # safely sum times, treating None as 0.0
    total_time = sum((res.get("Time") or 0.0) for res in results.values())
    print(f"⏱️ Total combined analysis time: {total_time:.2f} seconds")

def dump_stashes(simgr):
    print("=== Simulation Manager Stashes ===")
    for stash_name, states in simgr.stashes.items():
        print(f"\n• {stash_name!r} ({len(states)} state{'s' if len(states)!=1 else ''}):")
        for i, st in enumerate(states):
            # show the current instruction pointer and any other info you like
            addr = st.addr if hasattr(st, "addr") else st.state.addr
            print(f"    [{i:2}] 0x{addr:x}")

# write merged CSV output
# this collects all case results into a single CSV file for easier comparison
def write_results(binary_label, binary_path, results):
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

def main():
    global proj
    # check if there are enough arguments
    if len(sys.argv) < 3:
        print("Usage: python3 detector.py <binary> <config.json> [case_name]")
        sys.exit(1)


    binary_path  = sys.argv[1]
    binary_label = binary_path.split('/')[-1]
    config_path  = sys.argv[2]
    specific_case = sys.argv[3] if len(sys.argv) >= 4 else None

    # load up the config file
    with open(config_path) as file:
        cfg = json.load(file)

    proj = angr.Project(binary_path, auto_load_libs=False)
    CTMemory._set_memsight_ranges(proj)
    symbol_info = parse_config(proj, cfg)
    case_names  = get_case_names(proj, specific_case)
    results = {}

    # analyze every case sequentially
    for case_name in case_names:
        results[case_name] = analyze_case(proj, symbol_info, case_name, SPECULATIVE_WINDOW)
    
    # print the summary and create a csv file with the results
    print_summary(results)
    write_results(binary_label, binary_path, results)

if __name__ == "__main__":
    # uncomment only for presenting results!!!
    warnings.filterwarnings("ignore")
    logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.ERROR)
    logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.ERROR)

    # suppress warnings from memsight
    logging.getLogger("memsight").setLevel(logging.ERROR)

    # suppress angr's unconstrained successor warnings
    logging.getLogger("angr.engines.successors").setLevel(logging.ERROR)
    main()