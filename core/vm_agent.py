# core/vm_agent.py
"""
VMAgent: loads custom bytecode (.bc/.bytecode) into a simple VM
and records both execution trace and printable output.
"""
import os
import logging
from enhanced_state_management import MaterialType

logger = logging.getLogger(__name__)

class VMAgent:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)

    def run(self, state):
        # scan for binary materials with .bc or .bytecode extension
        for mat in state.materials.values():
            if mat.material_type != MaterialType.BINARY:
                continue
            path = mat.file_path.lower()
            if not (path.endswith(".bc") or path.endswith(".bytecode")):
                continue

            data = open(mat.file_path, "rb").read()
            vm = _SimpleVM(data, verbose=self.verbose)
            output, trace = vm.execute()

            finding = {
                "source":      "vm_agent",
                "type":        "vm_execution",
                "material_id": mat.id,
                "output":      output,
                "trace":       trace
            }
            state.add_finding(finding)
            if self.verbose:
                self.logger.info(f"[VMAgent] {mat.id} → output={output!r}")
        return state

class _SimpleVM:
    """
    Minimal stack-based VM:
      0x01 NOP
      0x02 PUSH <4-byte big-endian int>
      0x03 POP
      0x10 ADD
      0x11 SUB
      0xFF HALT
    PUSHed ints in ASCII printable range (0x20–0x7E) are collected as output.
    """
    def __init__(self, data: bytes, verbose: bool = False):
        self.data = data
        self.pc = 0
        self.stack = []
        self.verbose = verbose
        self.trace = []
        self.output = []
        self.opcodes = {
            0x01: self._op_nop,
            0x02: self._op_push,
            0x03: self._op_pop,
            0x10: self._op_add,
            0x11: self._op_sub,
            0xFF: self._op_halt,
        }

    def fetch(self):
        if self.pc >= len(self.data):
            return None
        opcode = self.data[self.pc]
        self.pc += 1
        return opcode

    def read_imm(self, size: int):
        val = int.from_bytes(self.data[self.pc:self.pc+size], "big", signed=False)
        self.pc += size
        return val

    def execute(self):
        while True:
            op = self.fetch()
            if op is None:
                self.trace.append("EOF")
                break
            handler = self.opcodes.get(op)
            if not handler:
                self.trace.append(f"UNKNOWN_OPCODE 0x{op:02X}@{self.pc-1}")
                break
            done = handler()
            if done:
                break
        return "".join(self.output), self.trace

    def _op_nop(self):
        self.trace.append("NOP")
        return False

    def _op_push(self):
        val = self.read_imm(4)
        self.stack.append(val)
        self.trace.append(f"PUSH {val}")
        if 0x20 <= val <= 0x7E:
            self.output.append(chr(val))
        return False

    def _op_pop(self):
        if self.stack:
            v = self.stack.pop()
            self.trace.append(f"POP {v}")
        return False

    def _op_add(self):
        if len(self.stack) >= 2:
            b = self.stack.pop()
            a = self.stack.pop()
            res = a + b
            self.stack.append(res)
            self.trace.append(f"ADD {a}+{b}={res}")
        return False

    def _op_sub(self):
        if len(self.stack) >= 2:
            b = self.stack.pop()
            a = self.stack.pop()
            res = a - b
            self.stack.append(res)
            self.trace.append(f"SUB {a}-{b}={res}")
        return False

    def _op_halt(self):
        self.trace.append("HALT")
        return True
