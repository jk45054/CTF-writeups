import idaapi
import idc
import ida_dbg
import ida_ua  # To analyze instruction opcodes and mnemonics
import ida_bytes

def dump_rcx_data():
    # assert that we are at the right spot
    rip_value = idc.get_reg_value("rip")
    assert rip_value == 0x140001164

    # Get the value of RCX and RSI registers
    rcx_value = idc.get_reg_value("rcx")
    rsi_value = idc.get_reg_value("rsi")

    # Check if the RCX and RSI values are valid
    if rcx_value == idc.BADADDR:
        print("Error: RCX register does not hold a valid address.")
        return
    if rsi_value == idc.BADADDR:
        print("Error: RSI register does not hold a valid address.")
        return

    print(f"RCX points to: {hex(rcx_value)} (struct_0xc)")
    print(f"RSI points to: {hex(rsi_value)} (shellcode base address)")

    # Read the first 32-bit value at offset 0, which is the relative offset to RSI
    relative_offset_0 = idc.get_wide_dword(rcx_value)
    print(f"Relative offset at RCX + 0x0: {hex(relative_offset_0)} (sc offset for opcode that caused exc)")

    # Calculate the final address by adding the relative offset to RSI (for offset 0)
    instruction_address_0 = rsi_value + relative_offset_0
    print(f"Instruction address (RSI + RCX[0x0]): {hex(instruction_address_0)} (sc address that caused exc)")

    # Disassemble and print the instruction at RSI + RCX[0x0]
    insn_0 = ida_ua.insn_t()
    if ida_ua.decode_insn(insn_0, instruction_address_0):
        disasm_0 = idc.generate_disasm_line(instruction_address_0, 0)
        opcode_bytes = ida_bytes.get_bytes(instruction_address_0, insn_0.size)
        print(f"Instruction at {hex(instruction_address_0)}: {opcode_bytes.hex()} {disasm_0}")
    else:
        print(f"Error: Unable to decode instruction at {hex(instruction_address_0)}")

    # Read the second 32-bit value at offset 4
    value_2 = idc.get_wide_dword(rcx_value + 0x4)
    print(f"Value at struct_0xc offset 0x4: {hex(value_2)}")

    # Read the third 32-bit value at offset 8, which is another relative offset to RSI
    relative_offset_8 = idc.get_wide_dword(rcx_value + 0x8)
    print(f"Relative offset at RCX + 0x8: {hex(relative_offset_8)}")

    # Calculate the full address by adding the relative offset to RSI (for offset 8)
    instruction_address_8 = rsi_value + relative_offset_8
    print(f"Shellcode handler address (RSI + RCX[0x8]): {hex(instruction_address_8)}")

    # Disassemble and dump the first 3 instructions at RSI + RCX[0x8]
    print(f"Disassembling 3 instructions at {hex(instruction_address_8)}:")
    current_address = instruction_address_8
    for i in range(3):
        insn = ida_ua.insn_t()
        # current_address = instruction_address_8 + i * ida_ua.get_item_size(instruction_address_8 + i)
        if ida_ua.decode_insn(insn, current_address):
            disasm = idc.generate_disasm_line(current_address, 0)
            size = insn.size
            opcode_bytes = ida_bytes.get_bytes(instruction_address_0, size)
            print(f"Instruction {i+1} at {hex(current_address)}: {opcode_bytes.hex()} {disasm}")
            current_address = current_address + size
        else:
            print(f"Error: Unable to decode instruction at {hex(current_address)}")
            break

dump_rcx_data()