# flareon 11 challenge 10 vm implementation
import sys
import struct


class vm:
    def init(self):
        self.mem = [0] * 256
        self.stack = [0] * 256
        self.cpu_pc = 0
        self.cpu_sp = 0
        self.cpu_saved_sp = 0
        self.program = b""

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


if __name__ == "__main__":
    v = vm()
    v.init()
    # v.load_program_from_vm_file(sys.argv[1])
    v.load_program_from_c4tb_file(sys.argv[1])
    v.disasm(0)
