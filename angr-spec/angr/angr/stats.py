# Dummy stats module to satisfy import in older angr versions
from contextlib import contextmanager
from decimal import Decimal

smt_eval_time = Decimal(0)
smt_solve_time = Decimal(0)
smt_total_time = Decimal(0)
solver_calls = 0
solver_successes = 0
solver_failures = 0

def tick(key):
    pass

def count(key):
    pass

def log(key, value):
    pass

def dump():
    pass

@contextmanager
def timed_block(key):
    yield
