import idaapi
import idc
import ida_ua
import ida_auto
import idautils
import ida_dbg
import ida_bytes


# Function to check if the current address is defined as code in IDA
def is_code(ea):
    flags = idc.get_full_flags(ea)
    return idc.is_code(flags)


# Function to log the full disassembled instruction to a file
def log_instruction(filename_base, ea, insn):
    # Get the raw opcode bytes
    size = insn.size
    opcode_bytes = idc.get_bytes(ea, size)
    opcodes_str = " ".join(f"{byte:02X}" for byte in opcode_bytes)

    # Get the full disassembled line (including address and operands)
    disasm_str = idc.generate_disasm_line(ea, 0)  # 0 = normal disassembly

    # Write the full disassembled line with opcode bytes to the log file
    with open(filename_base + ".asm", "a") as f:
        f.write(f"0x{ea:06X}: {opcodes_str:32} {disasm_str}\n")
    f.close()
    with open(filename_base + ".bin", "ab") as f:
        f.write(opcode_bytes)
    f.close()


def force_code(ea):
    ida_bytes.del_items(ea, 0, 0x20)
    insn_size = ida_ua.create_insn(ea)
    ida_auto.plan_and_wait(ea, ea + insn_size)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)


# Function to perform single-step debugging until a HLT (0xF4) instruction is found
def step_until_hlt(log_filename_base):
    log_trace = True
    # Begin single-step execution
    while True:
        # Get the current instruction address (RIP)
        ea = idc.get_reg_value("rip")
        # Decode the current instruction at the RIP address
        # insn = ida_ua.insn_t()  # Create an instruction object
        try:
            # length = ida_ua.decode_insn(insn, ea)  # Decode the instruction at ea
            inst = idautils.DecodeInstruction(ea)
            length = inst.size
        except Exception as e:
            print(f"Failed to decode insn at address {hex(ea)}, {e}")
            break
        if length == 0:
            print(f"Failed to decode instruction at {hex(ea)}")
            break
        
        # Check if the opcode is HLT (mnemonic "hlt")
        if inst.itype == idaapi.NN_hlt:
            print(f"HLT instruction encountered at address {hex(ea)}")
            break  # Stop the stepping when HLT is found
        # Log the disassembled instruction (full line with opcode bytes) to the file
        # only log legit code
        if log_trace:
            print(f"Logging legit instruction at {ea:x}")
            log_instruction(log_filename_base, ea, inst)
        # make sure the next instruction has been analyzed as code before step
        if not is_code(ea + length):
            # If it's not defined as code, try to define it as code
            print(f"Look-ahead Address {hex(ea + length)} is not defined as code. Attempting to make it code...")
            force_code(ea)
        # Print the current address and full disassembled instruction for tracing
        disasm_str = idc.generate_disasm_line(ea, 0)
        print(f"Stepping at {hex(ea)}: {disasm_str}")
        # Perform the single step
        idaapi.step_into()
        # sync script and debugger
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)


# get rip value, this script should only ever execute when bp is hit at
# ntdll_RtlpExecuteHandlerForException+14
assert idautils.cpu.Rip == 0x7FFEF275235D
# Start single-step debugging until the HLT instruction is found and log the instructions
step_until_hlt(f"z:\\flareon11\\9_serpentine\\trace_block_{idautils.cpu.Rax:x}")
