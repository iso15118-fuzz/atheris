import builtins
from collections import Counter
import os
import sys
import types
from pathlib import Path
from dataclasses import dataclass
from bytecode import Bytecode, Instr
import jedi


@dataclass(frozen=True)
class Position:
  file: str
  line: int
  column: int
  _base_dir: Path | None = None

  def __str__(self):
    return f"{self.file}:{self.line}:{self.column}"

  def __repr__(self):
    return f"{self.file}:{self.line}:{self.column}"

  @classmethod
  def set_base_dir(cls, base_dir: Path):
      cls._base_dir = base_dir

  @classmethod
  def from_str(cls, path: str):
    file_part, line, column = path.rsplit(":", 2)
    full_path = os.path.join(cls._base_dir, file_part)
    return cls(full_path, int(line), int(column))


def singleton(cls):
  _instances = {}

  def get_instance(*args, **kwargs):
    if cls not in _instances:
      _instances[cls] = cls(*args, **kwargs)
    return _instances[cls]

  return get_instance


def is_inside_logger_call(position: Position) -> bool:
  with open(position.file, "r", encoding="utf-8") as f:
    code = f.read()

  script = jedi.Script(code=code, path=position.file)
  try:
    signatures = script.get_signatures(position.line, position.column)

    for sig in signatures:
      for definition in sig.infer():
        if _is_logger_method(definition):
          return True
  except Exception as e:
    pass
  return False


def _is_logger_method(definition):
  full_name = getattr(definition, "full_name", "")
  if full_name and full_name.startswith("logging.Logger."):
    return True

  parent = getattr(definition, "parent", None)
  if parent and getattr(parent, "type", "") == "class":
    parent_full_name = getattr(parent, "full_name", "")
    if parent_full_name == "logging.Logger":
      return True

  return False


def get_types(position: Position) -> list[str]:
  with open(position.file, "r", encoding="utf-8") as f:
    code = f.read()

  script = jedi.Script(code=code, path=position.file)
  try:
    inferences = script.infer(position.line, position.column)
    return [inference.description for inference in inferences]
  except Exception as e:
    pass
  return []


@singleton
class FuzzInjector:
  def __init__(self, base_dir: Path = Path(os.getcwd())):
    self.disabled = False
    self.base_dir = base_dir
    Position.set_base_dir(base_dir)
    self.var_idx = 0
    self.skip_positions = set(
      [
        Position.from_str("iso15118/evcc/transport/udp_client.py:68:86"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:382:24"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:413:37"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:418:49"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:516:45"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:504:36"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:536:48"),
        Position.from_str("iso15118/shared_evcc/messages/sdp.py:275:51"),
        Position.from_str("iso15118/shared_evcc/messages/sdp.py:174:15"),
        Position.from_str("iso15118/shared_evcc/messages/sdp.py:174:38"),
        Position.from_str("iso15118/shared_evcc/messages/v2gtp.py:127:27"),
        Position.from_str("iso15118/shared_evcc/messages/v2gtp.py:136:31"),
        Position.from_str("iso15118/shared_evcc/messages/v2gtp.py:94:28"),
        Position.from_str("iso15118/shared_evcc/messages/v2gtp.py:161:23"),
        Position.from_str("iso15118/shared_evcc/messages/v2gtp.py:148:25"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:191:21"),
        Position.from_str("iso15118/evcc/comm_session_handler.py:192:20"),
        Position.from_str("iso15118/shared_evcc/comm_session.py:490:29"),
      ]
    )
    self.skip_files = set(
      [
        os.path.join(base_dir, "iso15118/evcc/transport/udp_client.py"),
        os.path.join(base_dir, "iso15118/evcc/transport/tcp_client.py"),
        os.path.join(base_dir, "iso15118/evcc/evcc_settings.py"),
        os.path.join(base_dir, "iso15118/shared_evcc/notifications.py"),
      ]
    )
    self.mutation_list: list[int] = []
    self.mutation_map: dict[int, tuple] = {}
    self.instr_counter = Counter()
    # set attr of builtins to let it globally accessible
    builtins.fuzz_mutation_list = self.mutation_list
    builtins.fuzz_mutation_map = self.mutation_map
    builtins.fuzz_mutate_var = self.mutate_var

  def mutate_var(self, var, idx):
    res_var = var
    if type(var) is int or type(var) is bool:
      if type(var) is int:
        res_var = var ^ self.mutation_list[idx]  # TODO: mutate here
      elif type(var) is bool:
        res_var = bool(var ^ (self.mutation_list[idx] % 2))
      # elif isinstance(var, str):
      #   var = var + str(self.mutation_list[idx])
      print(f"{var} => {res_var} from {self.mutation_map[idx]}")
    return res_var

  def disable(self):
    self.disabled = True

  def enable(self):
    self.disabled = False

  def inject(self, code: types.CodeType) -> types.CodeType:
    if self.disabled:
      return code
    if self.base_dir not in Path(code.co_filename).parents:
      return code
    byte_code = Bytecode.from_code(code)
    modified = set(["self"])  # skip self by default

    def ensure_xor_compatibility(instr: Instr) -> list[Instr]:
      if instr.name == "LOAD_CONST":
        return [instr]  # TODO: mutate some of LOAD_CONST
        # print("LOAD_CONST arg with type", instr.arg, type(instr.arg))
        # if type(instr.arg) not in (int, bool):  # TODO: support str
        #   return [instr]
      elif instr.name == "LOAD_FAST" and instr.arg in modified:
        return [instr]
      position = Position(
        code.co_filename,
        instr.location.end_lineno,
        instr.location.end_col_offset,
      )
      if is_inside_logger_call(position):
        return [instr]
      arg_types = get_types(position)
      if len(arg_types) != 0 and not any(
        any(t in s for s in arg_types) for t in ["int", "bool", "bytes"]
      ):
        return [instr]
      if position in self.skip_positions:
        return [instr]
      if position.file in self.skip_files:
        return [instr]
      sys.stderr.write(
        f"INFO: Injecting bytecode at "
        f"{position} types {arg_types} instr: "
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
      self.mutation_list.append(0)  # TODO: other initialization
      self.mutation_map[self.var_idx] = (
        instr.name,
        instr.arg,
        position,
        arg_types,
      )
      self.var_idx += 1
      return instrs

    instrs = []

    def process_instruction(instr, modified):
      if not isinstance(instr, Instr):
        return [instr]
      if instr.name.startswith("LOAD"):
        self.instr_counter[instr.name] += 1
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
    sys.stderr.write(
      f"INFO: dumping injector data len: {len(self.mutation_list)}\n"
    )
    for k, v in self.mutation_map.items():
      sys.stderr.write(
        f"INFO: mutation_list[{k}] = {self.mutation_list[k]}, tuple: {v}\n"
      )
    sys.stderr.write(f"Instructions Counter: {self.instr_counter}\n")
