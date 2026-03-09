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
def log_instruction(shellcode_base, asm_log_file, bin_log_file, ea, insn):
    # Get the raw opcode bytes
    size = insn.size
    opcode_bytes = idc.get_bytes(ea, size)
    opcodes_str = " ".join(f"{byte:02X}" for byte in opcode_bytes)

    # Get the full disassembled line (including address and operands)
    disasm_str = idc.generate_disasm_line(ea, 0)  # 0 = normal disassembly

    # Write the full disassembled line with opcode bytes to the log file
    asm_log_file.write(f"0x{ea-shellcode_base:06X}: {opcodes_str:32} {disasm_str}\n")
    bin_log_file.write(opcode_bytes)


def force_code(ea):
    ida_bytes.del_items(ea, 0, 0x20)
    insn_size = ida_ua.create_insn(ea)
    ida_auto.plan_and_wait(ea, ea + insn_size)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)


# Function to perform single-step debugging until a HLT (0xF4) instruction is found
def dump_blocks(shellcode_base, RtlpExecuteHandlerForException, log_filename_base):
    try:
        with open("z:\\flareon11\\9_serpentine\\next_block.txt", "r") as f:
            saved_line = f.read().split("|")
            next_block = int(save_line[0])
            saved_rsp = int(save_line[1])
        f.close()
    except Exception as e:
        next_block = 0
        saved_rsp = 0
    # print(f"Last: {last_dumped_block}")
    # skip dumped blocks
    for i in range(next_block):
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        rax_value = idautils.cpu.Rax
        print(f"Skipping block {i} at {hex(rax_value)}")
        ida_dbg.continue_process()

    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    rax_value = idautils.cpu.Rax
    rax_rva = rax_value - shellcode_base
    block_counter = next_block
    print(f"-----\nBegin dumping block {block_counter} @ VA:{rax_value:x} RVA:{rax_rva:x}\n----")
    asm_log_file = open(f"{log_filename_base}{next_block:03}_rva_0x{rax_rva:06x}.asm", "a")
    bin_log_file = open(f"{log_filename_base}{next_block:03}_rva_0x{rax_rva:06x}.bin", "ab")

    log_trace = False
    skip_one = False
    inst_counter = 0
    # Begin single-step execution
    while True:
        # Get the current instruction address (RIP)
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        ea = idautils.cpu.Rip
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
        if (inst.itype == idaapi.NN_hlt) or (inst.itype == idaapi.NN_jmpni and inst[0].type == idaapi.o_reg and inst[0] == idautils.procregs.R12):
            # save any register values you want to compare between blocks
            saved_rsp = idautils.cpu.Rsp
            print(f"Block {block_counter} end at address {hex(ea)} after {inst_counter} instructions, RSP:{saved_rsp:x}")
            block_counter += 1
            # there are only 364 shellcode handlers, at least with a wrong input
            # stop then. last block is 364, but it ends with jmp r12, not hlt
            if block_counter == 364:
                # log the jmp r12
                log_instruction(shellcode_base, asm_log_file, bin_log_file, ea, inst)
                print(f"Dumped {block_counter} blocks. Good luck, you are on your own now!")
                asm_log_file.close()
                bin_log_file.close()
                return(-1)
            # write next block so the script can pick up here after ida crashes
            with open("z:\\flareon11\\9_serpentine\\next_block.txt", "w") as f:
                save_line = f"{block_counter}|{saved_rsp}"
                f.write(save_line)
            f.close()
            # close log files for this block
            asm_log_file.close()
            bin_log_file.close()
            # run forward to ntdll execution call
            ida_dbg.run_to(exec_handler)
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
            rax_value = idautils.cpu.Rax
            rax_rva = rax_value - shellcode_base
            print(f"-----\nBegin dumping block {block_counter} @ VA:{rax_value:x} RVA:{rax_rva:x}\n----")
            asm_log_file = open(f"{log_filename_base}{block_counter:03}_rva_0x{rax_rva:06x}.asm", "a")
            bin_log_file = open(f"{log_filename_base}{block_counter:03}_rva_0x{rax_rva:06x}.bin", "ab")
            # reset counters
            inst_counter = 0
            # skip the call from ntdll
            log_trace = False

        # Toggle log_trace based on filter logic
        # what is junk? what is legit code
        #disasm_str = idc.generate_disasm_line(ea, 0)
        #print(f"Current instruction at {hex(ea)}: {disasm_str}")
        # conditional bp starts at call rax, that is traced
        # instruction number 0, don't log this. activate logging at 1
        if inst_counter == 1:
            new_rsp = idautils.cpu.Rsp
            if new_rsp != saved_rsp:
                print(f"OH NOES! RSP changed between end of last block and here. Saved:{saved_rsp:x} New:{new_rsp:x}")
            log_trace = True

        # Log the disassembled instruction (full line with opcode bytes) to the file
        # only log legit code
        if log_trace:
            #print(f"Logging legit instruction #{legit_counter} at {ea:x}")
            log_instruction(shellcode_base, asm_log_file, bin_log_file, ea, inst)
        # make sure the next instruction has been analyzed as code before step
        if not is_code(ea + length):
            # If it's not defined as code, try to define it as code
            #print(f"Look-ahead Address {hex(ea + length)} is not defined as code. Attempting to make it code...")
            force_code(ea)
        # Perform the single step
        idaapi.step_into()
        # sync script and debugger
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        inst_counter += 1


# get rip value, this script should only ever execute when bp is hit at
# ntdll_RtlpExecuteHandlerForException+14
# assert idautils.cpu.Rip == 0x7FFEF275235D
# Start single-step debugging until the HLT instruction is found and log the instructions


# start debugging
if not ida_dbg.dbg_is_loaded():
    print("[-] Debugger is not configured")
    exit(-1)

# log base
log_base = "z:\\flareon11\\9_serpentine\\trace_block_"

# TlsCallback after VirtualAlloc
tls_alloc = 0x140001522

# ntdll_RtlpExecuteHandlerForException+14, call rax
exec_handler = 0x7FFEF275235D

# grab virtual alloc shellcode base address from tls function
ida_dbg.run_to(tls_alloc)
ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
shellcode_base = idautils.cpu.Rax
print(hex(shellcode_base))


# now run to the first exec handler call in ntdll
ida_dbg.run_to(exec_handler)
ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

dump_blocks(shellcode_base, exec_handler, log_base)
