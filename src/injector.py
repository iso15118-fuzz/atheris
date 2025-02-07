import builtins
import os
import sys
import types
from pathlib import Path

from bytecode import Bytecode, Instr


def singleton(cls):
  _instances = {}

  def get_instance(*args, **kwargs):
    if cls not in _instances:
      _instances[cls] = cls(*args, **kwargs)
    return _instances[cls]

  return get_instance


@singleton
class FuzzInjector:
  def __init__(self, base_dir: Path = Path(os.getcwd())):
    self.base_path = base_dir
    self.var_idx = 0
    self.mutation_list = []
    self.mutation_map = {}
    # set attr of builtins to let it globally accessible
    builtins.fuzz_mutation_list = self.mutation_list
    builtins.fuzz_mutation_map = self.mutation_map
    builtins.fuzz_mutate_var = self.mutate_var

  def mutate_var(self, var, idx):
    if isinstance(var, (int, bool)):
      # var = var ^ self.fuzz_mutation_list[idx] # TODO: mutate here
      var = var
    # elif isinstance(var, str): # TODO: mutate here
    #   var = var + str(self.fuzz_mutation_list[idx])
    return var

  def inject(self, code: types.CodeType) -> types.CodeType:
    if self.base_path not in Path(code.co_filename).parents:
      return code
    byte_code = Bytecode.from_code(code)
    modified = set(["self"])  # skip self by default

    def ensure_xor_compatibility(instr: Instr) -> list[Instr]:
      if instr.name == "LOAD_CONST":
        return [instr] # TODO: mutate some of LOAD_CONST
        # print("LOAD_CONST arg with type", instr.arg, type(instr.arg))
        if type(instr.arg) not in (int, bool):  # TODO: support str
          return [instr]
      elif instr.name == "LOAD_FAST" and instr.arg in modified:
        return [instr]
      sys.stderr.write(
        f"INFO: Injecting bytecode at "
        f"{code.co_filename}:"
        f"{instr.location.end_lineno}:"
        f"{instr.location.end_col_offset} "
        f"{instr.name} {instr.arg!r}\n"
      )
      instrs = [
        Instr("LOAD_GLOBAL", (True, "fuzz_mutate_var")),
        instr,
        Instr("LOAD_CONST", self.var_idx),
        Instr("PRECALL", 2),
        Instr("CALL", 2),  # Call fuzz_mutate_var(arg, var_idx)
      ]
      if instr.name == "LOAD_FAST":
        instrs += [
          Instr("STORE_FAST", instr.arg),
          Instr("LOAD_FAST", instr.arg),
        ]
      self.mutation_list.append(0) # TODO: other initialization
      self.mutation_map[self.var_idx] = (
        instr.name,
        instr.arg,
        f"{code.co_filename}:"
        f"{instr.location.end_lineno}:"
        f"{instr.location.end_col_offset}",
      )
      self.var_idx += 1
      return instrs

    instrs = []

    def process_instruction(instr, modified):
      if not isinstance(instr, Instr):
        return [instr]
      if not instr.name.startswith(("LOAD", "STORE")):
        return [instr]
      if instr.name not in ["LOAD_FAST", "LOAD_CONST"]:
        return [instr]
      result = ensure_xor_compatibility(instr)
      if instr.name == "LOAD_FAST":
        modified.add(instr.arg)
      return result

    instrs = []
    for instr in byte_code:
      instrs.extend(process_instruction(instr, modified))

    byte_code.clear()
    byte_code.extend(instrs)
    code = byte_code.to_code()
    return code

  def dump(self):
    sys.stderr.write(f"INFO: dumping injector data len: {len(self.mutation_list)}\n")
    for k, v in self.mutation_map.items():
      sys.stderr.write(f"INFO: mutation_list[{k}] = {self.mutation_list[k]}, tuple: {v}\n")
