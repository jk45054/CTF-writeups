# flareon 11 challenge 10 vm implementation
import sys
import struct
from binascii import hexlify, unhexlify
from string import printable


class vm:
    def init(self):
        # initialize a clean vm
        self.mem = [0] * 512
        self.stack = [0] * 256
        self.cpu_pc = 0
        self.cpu_sp = 0
        self.cpu_saved_sp = 0
        self.program = b""

    def reset(self):
        # keep the program as is but reset memory, stack and registers
        self.mem = [0] * 515
        self.stack = [0] * 256
        self.cpu_pc = 0
        self.cpu_sp = 0
        self.cpu_saved_sp = 0

    def load_program_from_vm_file(self, filename):
        with open(filename, "rb") as f:
            self.program = f.read()
        f.close()
        print(f"[*] Loaded {len(self.program)} bytes vm code from {filename}")

    def patch_key(self, key):
        prog = bytearray(self.program)
        if len(key) != 16:
            raise RuntimeError("Key has to be size 16")
        for counter in range(8):
            prog[5 + counter * 7] = key[counter * 2]
            prog[4 + counter * 7] = key[counter * 2 + 1]
        self.program = bytes(prog)

    def load_program_from_c4tb_file(self, filename, key=b"0123456789ABCDEF"):
        with open(filename, "rb") as f:
            f.seek(0x8)  # third dword = offset vm program
            self.program_offset = int.from_bytes(f.read(4), "little")
            f.seek(0xC)  # fourth dword = size vm program
            self.program_size = int.from_bytes(f.read(4), "little")
            f.seek(self.program_offset)
            self.program = f.read(self.program_size)
        f.close()
        print(
            f"[*] Loaded {len(self.program)} bytes vm code from {filename}, patching key {key}"
        )
        self.patch_key(key)

    def push(self, value):
        self.stack[self.cpu_sp] = value
        self.cpu_saved_sp = self.cpu_sp
        self.cpu_sp += 1
        if self.cpu_sp > 256:
            raise RuntimeError(f"Stack overflow at PC {self.cpu_pc}")

    def pop(self):
        val_on_stack = self.stack[self.cpu_saved_sp]
        self.cpu_sp = self.cpu_saved_sp
        self.cpu_saved_sp -= 1
        if self.cpu_sp < 0:
            raise RuntimeError(f"Stack underflow at PC {self.cpu_pc}")
        return val_on_stack

    def ror(self, n, c, bits=32):
        mask = (1 << bits) - 1
        return ((n >> c) | (n << (bits - c))) & mask

    def rol(self, n, c, bits=32):
        return self.ror(n, bits - c, bits)
    
    def mem_print(self, action, addr, val):
        mem_string = self.transform_number_to_printable_string(val)
        print(f"MEM {action:5}: MEM[{addr:02x}] = {val:x} (\"{mem_string}\")")

    def execute(self, pc, opcode):
        if opcode == 0x01:  # "PUSH_IMM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            self.push(operand)
        elif opcode == 0x02:  # "PUSH_MEM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            mem_val = self.mem[operand]
            self.mem_print("READ", operand, mem_val)
            self.push(mem_val)
        elif opcode == 0x03:  # "ADD_MEM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            mem_val = self.mem[operand]
            self.mem_print("READ", operand, mem_val)
            val_on_stack = self.pop()
            result = val_on_stack + mem_val
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ADD_MEM: {val_on_stack:x} + {mem_val:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x04:  # "POP_MEM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            val_on_stack = self.pop()
            self.mem_print("WRITE", operand, val_on_stack)
            self.mem[operand] = val_on_stack
        elif opcode == 0x05:  # "PUSH_IND_MEM"
            op_size = 1
            addr = self.pop()
            val_on_stack = self.mem[addr]
            self.mem_print("READ", addr, val_on_stack)
            self.push(val_on_stack)
        elif opcode == 0x06:  # "POP_IND_MEM"
            op_size = 1
            val_on_stack = self.pop()
            addr = self.pop()
            self.mem_print("WRITE", addr, val_on_stack)
            self.mem[addr] = val_on_stack
        elif opcode == 0x07:  # "DUP"
            op_size = 1
            val_on_stack = self.pop()
            self.push(val_on_stack)
            self.push(val_on_stack)
        elif opcode == 0x08:  # "POP0"
            op_size = 1
            self.pop()
        elif opcode == 0x09:  # "ADD"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b + a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ADD: {b:x} + {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x0A:  # "ADD_IMM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            a = self.pop()
            result = a + operand
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ADD_IMM: {a:x} + {operand:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x0B:  # "SUB"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b - a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC SUB: {b:x} - {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x0C:  # "DIV"
            op_size = 1
            a = self.pop()
            if a == 0:
                raise RuntimeError(f"Division by zero at PC {self.cpu_pc}")
            b = self.pop()
            result = b / a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC DIV: {b:x} / {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x0D:  # "MUL"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b * a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC MUL: {b:x} * {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x0E:  # "JMP"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            return operand  # next_pc
        elif opcode == 0x0F:  # "JZ"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            flag = self.pop()
            if flag == 1:
                print("[*] JUMP taken")
                return operand  # next_pc
            else:
                print("[*] JUMP NOT taken")
        elif opcode == 0x10:  # "JNZ"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            flag = self.pop()
            if flag == 0:
                print("[*] JUMP taken")
                return operand  # next_pc
            else:
                print("[*] JUMP NOT taken")
        elif opcode == 0x11:  # "CMP_EQ"
            op_size = 1
            a = self.pop()
            b = self.pop()
            a_str = self.transform_number_to_printable_string(a)
            b_str = self.transform_number_to_printable_string(b)
            if b == a:
                print(f"CMP: {b:x} (\"{b_str}\") == {a:x} (\"{a_str}\") yielded TRUE")
                self.push(1)
            else:
                print(f"CMP: {b:x} (\"{b_str}\") == {a:x} (\"{a_str}\") yielded FALSE")
                self.push(0)
        elif opcode == 0x12:  # "CMP_L"
            op_size = 1
            a = self.pop()
            b = self.pop()
            a_str = self.transform_number_to_printable_string(a)
            b_str = self.transform_number_to_printable_string(b)
            if b < a:
                print(f"CMP: {b:x} (\"{b_str}\") < {a:x} (\"{a_str}\") yielded TRUE")
                self.push(1)
            else:
                print(f"CMP: {b:x} (\"{b_str}\") < {a:x} (\"{a_str}\") yielded FALSE")
                self.push(0)
        elif opcode == 0x13:  # "CMP_LE"
            op_size = 1
            a = self.pop()
            b = self.pop()
            a_str = self.transform_number_to_printable_string(a)
            b_str = self.transform_number_to_printable_string(b)
            if b <= a:
                print(f"CMP: {b:x} (\"{b_str}\") <= {a:x} (\"{a_str}\") yielded TRUE")
                self.push(1)
            else:
                print(f"CMP: {b:x} (\"{b_str}\") <= {a:x} (\"{a_str}\") yielded FALSE")
                self.push(0)
        elif opcode == 0x14:  # "CMP_G"
            op_size = 1
            a = self.pop()
            b = self.pop()
            a_str = self.transform_number_to_printable_string(a)
            b_str = self.transform_number_to_printable_string(b)
            if b > a:
                print(f"CMP: {b:x} (\"{b_str}\") > {a:x} (\"{a_str}\") yielded TRUE")
                self.push(1)
            else:
                print(f"CMP: {b:x} (\"{b_str}\") > {a:x} (\"{a_str}\") yielded FALSE")
                self.push(0)
        elif opcode == 0x15:  # "CMP_GE"
            op_size = 1
            a = self.pop()
            b = self.pop()
            a_str = self.transform_number_to_printable_string(a)
            b_str = self.transform_number_to_printable_string(b)
            if b >= a:
                print(f"CMP: {b:x} (\"{b_str}\") >= {a:x} (\"{a_str}\") yielded TRUE")
                self.push(1)
            else:
                print(f"CMP: {b:x} (\"{b_str}\") >= {a:x} (\"{a_str}\") yielded FALSE")
                self.push(0)
        elif opcode == 0x16:  # "CMP_GE_IMM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
            a = self.pop()
            a_str = self.transform_number_to_printable_string(a)
            op_str = self.transform_number_to_printable_string(operand)
            if a >= operand:
                print(f"CMP: {a:x} (\"{a_str}\") >= {operand:x} (\"{op_str}\") yielded TRUE")
                self.push(1)
            else:
                print(f"CMP: {a:x} (\"{a_str}\") >= {operand:x} (\"{op_str}\") yielded FALSE")
                self.push(0)
        elif opcode == 0x17 or opcode == 0x19:  # "POP_VM_RESULT"
            op_size = 1
            a = self.pop()
            print(f"[*] VM RESULT set to {a:x}")
        elif opcode == 0x18:  # "EXIT"
            op_size = 1
            return -1  # next_pc
        elif opcode == 0x1A:  # "XOR"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b ^ a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC XOR: {b:x} ^ {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x1B:  # "OR"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b | a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC OR: {b:x} | {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x1C:  # "AND"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b & a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC AND: {b:x} & {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x1D:  # "MOD"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = b % a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC MOD: {b:x} % {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x1E:  # "SHL"
            op_size = 1
            a = self.pop() & 0x3f
            b = self.pop()
            result = b << a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC SHL: {b:x} << {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x1F:  # "SHR"
            op_size = 1
            a = self.pop() & 0x3f
            b = self.pop()
            result = b >> a
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC SHR: {b:x} >> {a:x} = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x20:  # "ROL32"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = self.rol(b, a, 32)
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ROL32: ROL32({b:x}, {a:x}) = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x21:  # "ROR32"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = self.ror(b, a, 32)
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ROR32: ROR32({b:x}, {a:x}) = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x22:  # "ROL16"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = self.rol(b, a, 16)
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ROL16: ROL16({b:x}, {a:x}) = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x23:  # "ROR16"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = self.ror(b, a, 16)
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ROR16: ROR16({b:x}, {a:x}) = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x24:  # "ROL8"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = self.rol(b, a, 8)
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ROL8: ROL8({b:x}, {a:x}) = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x25:  # "ROR8"
            op_size = 1
            a = self.pop()
            b = self.pop()
            result = self.ror(b, a, 8)
            result_string = self.transform_number_to_printable_string(result)
            print(f"CALC ROR8: ROR8({b:x}, {a:x}) = {result:x} (\"{result_string}\")")
            self.push(result)
        elif opcode == 0x26:  # "PUTCHAR"
            op_size = 1
            char = self.pop()
            print(f"{char}")
        else:
            raise RuntimeError(f"Unknown CPU opcode {opcode:x}")
        next_pc = self.cpu_pc + op_size
        return next_pc

    def decode(self, pc, opcode):
        if opcode == 0x01:
            mnemonic = "PUSH_IMM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x02:
            mnemonic = "PUSH_MEM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x03:
            mnemonic = "ADD_MEM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x04:
            mnemonic = "POP_MEM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x05:
            mnemonic = "PUSH_IND_MEM"
            op_size = 1
            operand = -1
        elif opcode == 0x06:
            mnemonic = "POP_IND_MEM"
            op_size = 1
            operand = -1
        elif opcode == 0x07:
            mnemonic = "DUP"
            op_size = 1
            operand = -1
        elif opcode == 0x08:
            mnemonic = "POP0"
            op_size = 1
            operand = -1
        elif opcode == 0x09:
            mnemonic = "ADD"
            op_size = 1
            operand = -1
        elif opcode == 0x0A:
            mnemonic = "ADD_IMM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x0B:
            mnemonic = "SUB"
            op_size = 1
            operand = -1
        elif opcode == 0x0C:
            mnemonic = "DIV"
            op_size = 1
            operand = -1
        elif opcode == 0x0D:
            mnemonic = "MUL"
            op_size = 1
            operand = -1
        elif opcode == 0x0E:
            mnemonic = "JMP"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x0F:
            mnemonic = "JZ"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x10:
            mnemonic = "JNZ"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x11:
            mnemonic = "CMP_EQ"
            op_size = 1
            operand = -1
        elif opcode == 0x12:
            mnemonic = "CMP_L"
            op_size = 1
            operand = -1
        elif opcode == 0x13:
            mnemonic = "CMP_LE"
            op_size = 1
            operand = -1
        elif opcode == 0x14:
            mnemonic = "CMP_G"
            op_size = 1
            operand = -1
        elif opcode == 0x15:
            mnemonic = "CMP_GE"
            op_size = 1
            operand = -1
        elif opcode == 0x16:
            mnemonic = "CMP_GE_IMM"
            op_size = 3
            operand = self.program[(pc + 1)] * 256 + self.program[(pc + 2)]
        elif opcode == 0x17 or opcode == 0x19:
            mnemonic = "POP_VM_RESULT"
            op_size = 1
            operand = -1
        elif opcode == 0x18:
            mnemonic = "EXIT"
            op_size = 1
            operand = -1
        elif opcode == 0x1A:
            mnemonic = "XOR"
            op_size = 1
            operand = -1
        elif opcode == 0x1B:
            mnemonic = "OR"
            op_size = 1
            operand = -1
        elif opcode == 0x1C:
            mnemonic = "AND"
            op_size = 1
            operand = -1
        elif opcode == 0x1D:
            mnemonic = "MOD"
            op_size = 1
            operand = -1
        elif opcode == 0x1E:
            mnemonic = "SHL"
            op_size = 1
            operand = -1
        elif opcode == 0x1F:
            mnemonic = "SHR"
            op_size = 1
            operand = -1
        elif opcode == 0x20:
            mnemonic = "ROL32"
            op_size = 1
            operand = -1
        elif opcode == 0x21:
            mnemonic = "ROR32"
            op_size = 1
            operand = -1
        elif opcode == 0x22:
            mnemonic = "ROL16"
            op_size = 1
            operand = -1
        elif opcode == 0x23:
            mnemonic = "ROR16"
            op_size = 1
            operand = -1
        elif opcode == 0x24:
            mnemonic = "ROL8"
            op_size = 1
            operand = -1
        elif opcode == 0x25:
            mnemonic = "ROR8"
            op_size = 1
            operand = -1
        elif opcode == 0x26:
            mnemonic = "PUTCHAR"
            op_size = 1
            operand = -1
        else:
            raise RuntimeError(f"Unknown CPU opcode {opcode:x}")
        return mnemonic, operand, op_size

    def disasm_one(self, ea):
        opcode = self.program[ea]
        mnemonic, operand, op_size = self.decode(ea, opcode)
        return opcode, mnemonic, operand, op_size

    def disasm(self, ea, num_instructions=65536):
        counter = 1
        opcode, mnemonic, operand, op_size = self.disasm_one(ea)
        operand_string = self.transform_number_to_printable_string(operand)
        if operand != -1:
            print(f"EA:{ea:3x} OP:{opcode:2x} {mnemonic:16} {operand:4x} (\"{operand_string}\")")
        else:
            print(f"EA:{ea:3x} OP:{opcode:2x} {mnemonic:16}")
        while mnemonic != "EXIT" and counter < num_instructions:
            ea += op_size
            counter += 1
            opcode, mnemonic, operand, op_size = self.disasm_one(ea)
            operand_string = self.transform_number_to_printable_string(operand)
            if operand != -1:
                print(f"EA:{ea:3x} OP:{opcode:2x} {mnemonic:16} {operand:4x} (\"{operand_string}\")")
            else:
                print(f"EA:{ea:3x} OP:{opcode:2x} {mnemonic:16}")

    def transform_number_to_printable_string(self, value):
        ascii = ""
        tmp_stack_value = value
        while tmp_stack_value > 0:
            cur_byte = tmp_stack_value & 0xff
            if cur_byte >= 0x20 and cur_byte <= 0x7e:
                ascii += chr(cur_byte)
            else:
                ascii += "."
            tmp_stack_value = tmp_stack_value >> 8
        return ascii[::-1]  # reverse the string as we processed from lowest byte to highest

    def dump_stack(self, num_items=0):
        counter = 0
        if num_items == 0:
            num_items = self.cpu_sp
        tmp_sp = self.cpu_saved_sp
        while tmp_sp >= 0 and counter < num_items:
            # try to convert bytes to printable chars
            stack_string = self.transform_number_to_printable_string(self.stack[tmp_sp])
            # debug print
            print(f"STACK[{tmp_sp:x}] = {self.stack[tmp_sp]:x} (\"{stack_string}\")")
            counter += 1
            tmp_sp -= 1

    def step(self):
        # print(f"[*] Executing one step at pc {self.cpu_pc:x}")
        # get instruction opcode at current pc
        opcode = self.program[self.cpu_pc]
        # decode instruction at current program counter pc
        mnemonic, operand, _ = self.decode(self.cpu_pc, opcode)
        operand_string = self.transform_number_to_printable_string(operand)
        # suppress output of certain instructions for high level readability
        # such as PUSH_IMM, POP_IND_MEM, PUSH_IND_MEM
        # mem access logging still happens for these in the opcode handlers that access memory
        silent_ops = ["PUSH_IMM", "POP_IND_MEM", "PUSH_IND_MEM"]
        if mnemonic not in silent_ops:
            print("-" * 40)
            if operand != -1:
                print(
                    f"PC:{self.cpu_pc:3x} OP:{opcode:2x} {mnemonic:16} {operand:4x} (\"{operand_string}\") SP:{self.cpu_sp:x}"
                    )
            else:
                print(
                    f"PC:{self.cpu_pc:3x} OP:{opcode:2x} {mnemonic:16} SP:{self.cpu_sp:x}"
                    )
        # execute instruction
        next_pc = self.execute(self.cpu_pc, opcode)
        # add debuf stuff, mem/stack dumps
        if mnemonic not in silent_ops:
            self.dump_stack()
        # update pc unless we reached the EXIT
        if next_pc != -1:
            self.cpu_pc = next_pc
            return True
        else:
            return False

    def run(self):
        # reset memory, stack and registers
        self.reset()
        # separator line
        # print("-" * 40)
        while self.step():
            # add debuf stuff, mem/stack dumps
            # self.dump_stack()
            # separator line
            # print("-" * 40)
            True


if __name__ == "__main__":
    v = vm()
    v.init()
    # v.load_program_from_vm_file(sys.argv[1])
    if len(sys.argv) > 2:
        v.load_program_from_c4tb_file(sys.argv[1], bytes(sys.argv[2], "UTF-8"))
    else:
        v.load_program_from_c4tb_file(sys.argv[1])
    # v.disasm(0)
    # v.step()
    # v.step()
    v.run()
