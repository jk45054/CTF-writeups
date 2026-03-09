import idaapi
import idc
import ida_dbg
import ida_ua  # To analyze instruction opcodes and mnemonics
import ida_bytes


def log_msg(msg):
    LOGFILE = "z:\\flareon11\\9_serpentine\\unwind.log"
    print(msg, end="")
    with open(LOGFILE, "a") as f:
        f.write(msg)
    f.close()
    return


def dump_runtime_function():
    # assert that we are at the right spot
    rip_value = idc.get_reg_value("rip")
    # are we at ntdll_RtlDispatchException+0x15C ?
    assert rip_value == 0x7FFEF27013BC

    # Get the value of RAX registers
    rax_value = idc.get_reg_value("rax")
    rcx_value = idc.get_reg_value("rcx")

    # Check if the RCX and RSI values are valid
    if rax_value == idc.BADADDR:
        print("Error: RAX register does not hold a valid address.")
        return 0
    if rcx_value == idc.BADADDR:
        print("Error: RDX register does not hold a valid address.")
        return 0

    # print(f"RAX points to: {hex(rax_value)} (RUNTIME_FUNCTION *)")
    # print(f"RDX points to: {hex(rdx_value)} (shellcode base)")

    # Read the first 32-bit value at offset 0, which is the relative offset to RSI
    RVA_function_start = idc.get_wide_dword(rax_value)
    # print(f"RVA function_start={hex(RVA_function_start)}")
    shellcode_base = rcx_value - RVA_function_start

    # Calculate the final address by adding the relative offset to RSI (for offset 0)
    VA_function_start = shellcode_base + RVA_function_start
    # print(f"VA function_start address: {hex(VA_function_start)} (sc address that caused exc)")

    # Disassemble and print the instruction at RSI + RCX[0x0]
    insn_0 = ida_ua.insn_t()
    if ida_ua.decode_insn(insn_0, VA_function_start):
        #disasm_0 = idc.generate_disasm_line(VA_function_start, 0)
        opcode_bytes = ida_bytes.get_bytes(VA_function_start, insn_0.size)
        #print(f"Instr at {hex(VA_function_start)}: {opcode_bytes.hex()} {disasm_0}")
    else:
        print(f"Error: Unable to decode instruction at {hex(VA_function_start)}")
        return 0

    # Read the second 32-bit value at offset 4
    RVA_function_end = idc.get_wide_dword(rax_value + 0x4)
    # print(f"RVA function_end: {hex(RVA_function_end)}")

    # Read the third 32-bit value at offset 8, which is another relative offset to RSI
    unwind_info = idc.get_wide_dword(rax_value + 0x8)
    # msg = f"Exc caused by instr at {hex(VA_function_start)}: {opcode_bytes.hex()}, VA function_start address: {hex(VA_function_start)}, UnwindInfo: {hex(unwind_info)}"
    msg = f"Exc caused by instr at {hex(VA_function_start)}: {opcode_bytes.hex()}, UnwindInfo: {hex(unwind_info)}, "
    log_msg(msg)
    return 1


    # Calculate the full address by adding the relative offset to RSI (for offset 8)
    #instruction_address_8 = rdx_value + unwind_info
    #print(f"Shellcode handler address (RSI + RCX[0x8]): {hex(instruction_address_8)}")

    # Disassemble and dump the first 3 instructions at RSI + RCX[0x8]
    #print(f"Disassembling 3 instructions at {hex(instruction_address_8)}:")
    #current_address = instruction_address_8
    #for i in range(3):
    #    insn = ida_ua.insn_t()
    #    # current_address = instruction_address_8 + i * ida_ua.get_item_size(instruction_address_8 + i)
    #    if ida_ua.decode_insn(insn, current_address):
    #        disasm = idc.generate_disasm_line(current_address, 0)
    #        size = insn.size
    #        opcode_bytes = ida_bytes.get_bytes(VA_function_start, size)
    #        print(f"Instruction {i+1} at {hex(current_address)}: {opcode_bytes.hex()} {disasm}")
    #        current_address = current_address + size
    #    else:
    #        print(f"Error: Unable to decode instruction at {hex(current_address)}")
    #        break

dump_runtime_function()