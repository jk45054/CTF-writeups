# Flare-On 10, Challenge 13, y0da
#
# Func 0x18001d361 pushes ROP gadgets to the stack
#
# params:
# rcx = ptr to buf with 0x39 bytes (possibly the flag)
# edx = 0x39 (len)
# r8 = ptr to buf with 0x3c rand bytes generate with MT19937 with seed 5D1FF27D
# r9 = ptr to RWX buf with 0x1c3 bytes of rop gadgets
#
# the function / like all other functions / is jmp-fuscated
#
# identify each ROP gadget, these are luckily all 1 inst + ret each
# dump all ROP gadgets in execution order (reverse)
#
# execute this script during debugging on breakpoint hit @ 0x18001d361
#
# TODO:
# - generalize ROP reconstruction without debugging/breakpoint requirement
#

import idautils
import idc
import idaapi
import ida_bytes
import ida_dbg
import ida_ua
from binascii import hexlify

# the ROP chain creating function
ea = 0x18001D361
dbg_ea = 0
g_dis_filename = hex(ea) + "_ropchain_disassembly.asm"
g_dis = ""
g_bytes_filename = hex(ea) + "_ropchain_bytes.bin"
g_bytes = b""
num_func_inst = 0
num_add = 0
num_jmp = 0
gadget_list = []
gadget_dict = {}
DEBUG = 0  # 1 = a bit, 2 = more, 3 = spam

# check if debugger is running
if not ida_dbg.dbg_is_loaded():
    print("[-] Debugger is not running")
    exit()
# check if we are at target ea
dbg_ea = ida_dbg.get_reg_val("rip")
if dbg_ea != ea:
    print(f"[-] dbg_ea is at {dbg_ea:x}, expected ea is {ea:x}")
    exit()
# get reg value from r9, the buf with rop gadgets
rcx = ida_dbg.get_reg_val("rcx")
edx = ida_dbg.get_reg_val("edx")
r8 = ida_dbg.get_reg_val("r8")
r9 = ida_dbg.get_reg_val("r9")
print(f"[*] Got dbg reg vals: rcx = {rcx:x}, edx = {edx:x}, r8 = {r8:x}, r9 = {r9:x}")

# force make code for rop gadgets in r9 buf, so we can grab their disassembly later
# could also try to JIT check if at address x is_code(), if not MakeCode first
# delete all items, if there were any at r9, size 0x1c3
print(f"[*] Deleting items at gadget buffer r9 = {r9:x}, size = 0x1c3")
ida_bytes.del_items(r9, 0x1C3)

# now collect all gadgets as they are pushed onto the stack in this function
print(f"[*] Parsing function {ea:x} for ROP gadget pushing")
while True:
    # Get disassembly string the way IDA displays it
    # This only works on bytes already disassembled, it would return db xx and the likes otherwise
    disasm_line = idc.GetDisasm(ea)
    if disasm_line == "":
        print(f"[-] Could not get disasm_line at {ea:x}")
        exit()

    # Decode instruction
    inst = idautils.DecodeInstruction(ea)
    if not inst:
        print(f"[-] Error decoding instruction at {ea:x}")
        exit()

    if inst.itype != idaapi.NN_jmp:
        # if its not a jump, look for the following opcodes to push ROP gadgets on the stack
        # 0x180038551 49 8b f1               mov     rsi, r9
        # 0x18001aa0c 48 83 c6 3e            add     rsi, 3Eh ; '>'
        # 0x18002933c 56                     push    rsi
        #
        # luckily it looks like the order of opcodes and use of registers is strictly the same, makes this case a lot easier
        #
        # lazy approach:
        # - just look for add rsi, xx
        # - xx will be the offset into the ROP gadget RWX buf
        # - count all adds, save each xx in a list
        num_func_inst += 1
        inst_bytes = ida_bytes.get_bytes(ea, inst.size)
        # show opcode bytes similar to IDA, with space as seperator between each byte
        inst_bytes_pretty_str = hexlify(inst_bytes, " ").decode("UTF-8")
        if DEBUG > 2:
            print(f"{hex(ea)}: {hexlify(inst_bytes).decode('UTF-8'):22} {disasm_line}")
        # dis += f"{hex(ea)} {inst_bytes_pretty_str:22} {disasm_line}\n"
        # func_bytes += inst_bytes
        # parse each ADD rsi, x
        # extract x as gadget offset and append to gadget list (the chain)
        # if x was not already "known", add gadget disassembly and bytes to gadget dict
        if (inst.itype == idaapi.NN_add) and (inst[0] == idautils.procregs.rsi):
            # we could do more safeguards here, but since we only expect add rsi, xx... focus first
            # get op1 imm value
            num_add += 1
            gadget_offset = inst[1].value
            gadget_ea = r9 + gadget_offset
            gadget_list.append(gadget_offset)
            if DEBUG > 2:
                print(
                    f"[*] Found ADD RSI, IMM at {ea:x} with Op1.value == {gadget_offset:x}"
                )
            # check if at r9 + gadget offset there is already code defined
            gadget_ea_flags = idaapi.get_flags(gadget_ea)
            if not idaapi.is_code(gadget_ea_flags):
                if DEBUG > 2:
                    print(f"[*] Creating gadget instruction at {gadget_ea:x}")
                ida_ua.create_insn(gadget_ea)
            # stuff that assumes that there is disassembly / code defined now at gadget_ea
            gadget_dis = idc.GetDisasm(gadget_ea)
            if gadget_dis == "":
                print(f"[-] Error, could not get gadget_dis at {gadget_ea:x}")
                exit()
            # decode gadget instruction
            gadget_inst = idautils.DecodeInstruction(gadget_ea)
            if not gadget_inst:
                print(
                    f"[-] Error, could not decode gadget instruction at {gadget_ea:x}"
                )
                exit()
            # get the bytes
            gadget_bytes = ida_bytes.get_bytes(gadget_ea, gadget_inst.size)
            if DEBUG > 0:
                print(
                    f"[*] PUSH #{num_add:3} Gadget {gadget_offset:3x}: {hexlify(gadget_bytes).decode('UTF-8'):12} {gadget_dis}"
                )
            # put gadget disassembly and bytes into gadget_dict with key gadget_offset
            # if not already known
            if not gadget_offset in gadget_dict.keys():
                if DEBUG > 2:
                    print(f"[*] Adding gadget {gadget_offset:x} to gadget dict")
                gadget_dict[gadget_offset] = {
                    "offset": gadget_offset,
                    "dis": gadget_dis,
                    "bytes": gadget_bytes,
                }
            else:
                if DEBUG > 2:
                    print(
                        f"[*] Gadget {gadget_offset:x} is already known in gadget dict"
                    )

        # stop condition: we hit a ret
        if inst.itype == idaapi.NN_retn:
            if DEBUG > 0:
                print(
                    f"[*] Found RET at {ea:x}, stopping after {num_func_inst} instructions, {num_add} ADDs and {num_jmp} JMPs."
                )
            break
        # move to next instruction
        ea += inst.size
    else:
        # we got a jmp, this could be obfuscated or not (how would we judge?)
        # for now assume all jmps are evil
        #
        # get jump address and do not log these
        num_jmp += 1
        jmp_target = inst[0].addr
        if DEBUG > 2:
            print(
                f"[*] Found JMP #{num_jmp} at {ea:x} to {jmp_target:x}, continuing there"
            )
        ea = jmp_target

# now that we have collected all gadgets and their push order, we can reconstruct the ROP chain
# code by reverse iterating over the push list and concatenating the gadget disassemblies/bytes
if DEBUG > 1:
    print(f"ROP chain: {gadget_list}")
    print(f"Gadgets used: {gadget_dict.keys()}")

for gadget in gadget_list[::-1]:
    g_offset = gadget_dict[gadget]["offset"]
    g_bytes_gadget = gadget_dict[gadget]["bytes"]
    g_dis_line = gadget_dict[gadget]["dis"]
    g_dis += f"Gadget {g_offset:3x}: {hexlify(g_bytes_gadget).decode('UTF-8'):12} {g_dis_line}\n"
    g_bytes += g_bytes_gadget

##### done, save results to disk

# save ROP chain disassembly to file
print(
    f"[*] Dumping ROP chain disassembly to file {g_dis_filename}, size {len(g_dis)} with {len(gadget_list)} gadgets"
)
with open(g_dis_filename, "w") as f:
    f.write(g_dis)
f.close()

# save ROP chain bytes to file
print(f"[*] Dumping ROP chain bytes to file {g_bytes_filename}, size {len(g_bytes)}")
with open(g_bytes_filename, "wb") as f:
    f.write(g_bytes)
f.close()
