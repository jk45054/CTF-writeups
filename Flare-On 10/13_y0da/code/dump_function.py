# Flare-On 10, Challenge 13, y0da
#
# Produce deobfuscated function disassembly
# and save it to disk
#
# Example: functon 0x18001d361
# its a huge spaghetti and builds a rop chain on the stack
# params:
# rcx = ptr to buf with 0x39 bytes (possibly the flag)
# edx = 0x39 (len)
# r8 = ptr to buf with 0x3c rand bytes generate with MT19937 with seed 5D1FF27D
# r9 = ptr to RWX buf with 0x1c3 bytes of rop gadgets
#

import idautils
import idc
import idaapi
import ida_bytes
from binascii import hexlify

# ea = 0x18001D361
ea = idc.here()
dis_filename = hex(ea) + "_disassembly.txt"
dis = ""
func_bytes_filename = hex(ea) + "_bytes.bin"
func_bytes = b""
num_func_inst = 0
num_jmp = 0
DEBUG = 1  # 1 = a bit, 2 = spam

print(
    f"[*] De-jmp-fuscating function {ea:x}, let's hope there are no legit JMP instructions"
)
while True:
    # Get disassembly string the way IDA displays it
    # This only works on bytes already disassembled, it would return db xx and the likes otherwise
    disasm_line = idc.GetDisasm(ea)
    if disasm_line == "":
        print(f"[-] Could not get disasm_line at {ea:x}")

    # Decode instruction
    inst = idautils.DecodeInstruction(ea)
    if not inst:
        print(f"[-] Error decoding instruction at {ea:x}")

    # If current instruction is not a JMP
    # Get instruction bytes and disassembly, log them
    # And advance to the next instruction up until a RET
    if inst.itype != idaapi.NN_jmp:
        num_func_inst += 1
        inst_bytes = ida_bytes.get_bytes(ea, inst.size)
        # show opcode bytes similar to IDA, with space as seperator between each byte
        inst_bytes_pretty_str = hexlify(inst_bytes, " ").decode("UTF-8")
        if DEBUG > 1:
            print(f"{hex(ea)}: {hexlify(inst_bytes).decode('UTF-8'):22} {disasm_line}")
        dis += f"{hex(ea)} {inst_bytes_pretty_str:22} {disasm_line}\n"
        func_bytes += inst_bytes
        # stop condition: we hit a ret
        if inst.itype == idaapi.NN_retn:
            if DEBUG > 0:
                print(
                    f"[*] Found RET at {ea:x}, stopping after {num_func_inst} instructions and {num_jmp} JMPs."
                )
            break
        # move to next instruction
        ea += inst.size
    else:
        # we got a jmp, this could be obfuscated or not
        # for now assume all jmps are evil
        #
        # get jump address and do not log these
        num_jmp += 1
        jmp_target = inst[0].addr
        if DEBUG > 1:
            print(
                f"[*] Found JMP #{num_jmp} at {ea:x} to {jmp_target:x}, continuing there"
            )
        ea = jmp_target

# save disassembly to file
print(
    f"[*] Dumping disassembly to file {dis_filename}, size {len(dis)} with {num_func_inst} instructions"
)
with open(dis_filename, "w") as f:
    f.write(dis)
f.close()

# save function bytes to file
print(
    f"[*] Dumping function bytes to file {func_bytes_filename}, size {len(func_bytes)}"
)
with open(func_bytes_filename, "wb") as f:
    f.write(func_bytes)
f.close()
