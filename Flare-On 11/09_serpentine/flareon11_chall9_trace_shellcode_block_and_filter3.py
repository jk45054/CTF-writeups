import idaapi
import idc
import ida_ua
import ida_auto
import idautils
import ida_dbg
import ida_bytes
from sys import exit
from json import dump
from binascii import hexlify, unhexlify


def is_code(ea):
    flags = idc.get_full_flags(ea)
    return idc.is_code(flags)


def log_block(log_file_base, block_number, inst_log, next_block_file):
    # Function to log the full disassembled instruction to files and update next_block_file
    # log the block as disasm text and binary opcode bytes
    file_name = f"{log_file_base}{block_number:03}_rva_0x{inst_log['handler_rva']:06x}_unwind_{inst_log['runtime_function_unwindinfo']:06x}"
    asm_log_file = open(f"{file_name}.asm", "w")
    asm_deobf_log_file = open(f"{file_name}_deobf.asm", "w")
    bin_log_file = open(f"{file_name}.bin", "wb")
    bin_deobf_log_file = open(f"{file_name}_deobf.bin", "wb")
    json_log_file = open(f"{file_name}.json", "w")
    # traverse the instruction log and write each entry to both files
    for inst in sorted(inst_log["insts"].keys()):
        rva = inst_log['insts'][inst]['rva']
        disasm = inst_log['insts'][inst]['disasm']
        opcodes = unhexlify(inst_log['insts'][inst]['opcodes'])
        opcodes_str = "".join(f"{byte:02X}" for byte in opcodes)
        asm_log_file.write(f"0x{rva:06X}: {opcodes_str:32} {disasm}\n")
        bin_log_file.write(opcodes)
        if not inst_log["insts"][inst]["junk"]:
            asm_deobf_log_file.write(f"0x{rva:06X}: {opcodes_str:32} {disasm}\n")
            bin_deobf_log_file.write(opcodes)
    asm_log_file.close()
    bin_log_file.close()
    asm_deobf_log_file.close()
    bin_log_file.close()
    bin_deobf_log_file.close()
    # do a json dump too, because why not
    dump(inst_log, json_log_file)
    json_log_file.close()
    # update the next_block_file
    with open(next_block_file, "w") as f:
        runtime_function_start = inst_log["runtime_function_start"]
        runtime_function_end = inst_log["runtime_function_end"]
        runtime_function_unwindinfo = inst_log["runtime_function_unwindinfo"]
        save_line = f"{block_number}|{inst_log['saved_rsp']|runtime_function_start|runtime_function_end|runtime_function_unwindinfo}"
        f.write(save_line)
    f.close()


def get_instruction_bytes_and_disasm(inst):
    # TODO: resolve named locations for disasm instead of names
    # get the opcodes for this inst
    opcode_bytes = hexlify(ida_bytes.get_bytes(inst.ea, inst.size)).decode("utf-8")
    # opcodes_str = "".join(f"{byte:02X}" for byte in opcode_bytes)
    #
    # Get the full disassembled line (including address and operands)
    # might use ida_lines.generate_disassembly() too
    disasm_str = idc.generate_disasm_line(inst.ea, 0)  # 0 = normal disassembly
    return (opcode_bytes, disasm_str)


def deobfuscate_block(current_bock, inst_log):
    # judging from the first few blocks, this is possibly the logic to distinguish junk from code
    # 1. keep first line if it is a mov <reg>, [r9+28h], this might be a value passing from block to block
    # 2. keep all lines until and excluding the next call near ptr
    # 3. remove the call near ptr, the following pop cs: up until and including the next pop rax
    # 4. if the next instruction is a jmp near, skip everything from here to the end -> exit
    # 5. keep the next instruction
    # 6. the next instruction should be a mov dword ptr cs:. skip/discard this and the following lines
    #    up until and including xchg rax followed by retn
    # 7. goto 2
    sorted_keys = iter(sorted(inst_log["insts"].keys()))
    for inst in sorted_keys:
        disasm = inst_log['insts'][inst]['disasm']
        opcodes = unhexlify(inst_log['insts'][inst]['opcodes'])
        # if (inst == 0) and ("[r9+28h]" in disasm):  # this is legit, likely value passing
        #     inst_log['insts'][inst]['junk'] = 0
        #     continue
        if opcodes[0] == 0xe8: # call near
            try:
                inst_log['insts'][inst]['junk'] = 1  # mark the call
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be pop cs:
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be push rax
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be mov rax,
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be mov ah, byte ptr
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be lea eax, [eax...]
                inst = next(sorted_keys)         
                inst_log['insts'][inst]['junk'] = 1  # this should be mov cs:..., eax
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be pop rax
                continue
            except Exception as e:
                print(f"[-] deobfuscate call near...pop rax failed miserably for block {current_bock} at inst {inst}. {e}")
                return
        if (opcodes[0] == 0xc7) and (opcodes[1] == 0x05):  # junk move
            try:
                inst_log['insts'][inst]['junk'] = 1  # mark this move
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be a push rax
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be a move rax,
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be a lea rax, [rax...]
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be an xchg rax, [rsp...]
                inst = next(sorted_keys)
                inst_log['insts'][inst]['junk'] = 1  # this should be a retn
                continue
            except Exception as e:
                print(f"[-] deobfuscate mov...retn sequence failed miserably for block {current_bock} at inst {inst}, {e}")
                return
        if (opcodes[0] == 0xe9):  # jmp near
            inst_log['insts'][inst]['junk'] = 1
            continue
    return (inst_log)


def patch(patch_target, patch_file_offset, inst_log, block_index):
    # we know the shellcode blob file offset
    # we can use this as RVA 0
    # we need to make sure though that there is a hlt 0xf4 opcode at the very same location / preserve this
    # we may not use more space in each handler region to not overwrite the hlt
    # we can only pray that there are no backjumps from other handlers - crossing fingers
    # this may allow us to debug the deobfuscated code for each handler - still 364 of them!
    with open(patch_target, "r+b") as p:
        rva = inst_log["handler_rva"]
        current_patch_position = patch_file_offset + rva
        print(f"Seeking to {current_patch_position:x} = {patch_file_offset:x} + {rva:x}")
        p.seek(current_patch_position, 0)
        num_insts = len(inst_log["insts"])
        last_inst_rva = inst_log["insts"][num_insts - 1]["rva"]
        deadline = patch_file_offset + last_inst_rva
        bytes_left = deadline - current_patch_position
        print(f"[*] Patch area for block {block_index}: {current_patch_position:x} to {deadline:x} size {bytes_left}")
        # traverse the instructions, patch only non junk one after another
        for inst in sorted(inst_log["insts"].keys()):
            opcodes = unhexlify(inst_log['insts'][inst]['opcodes'])
            if inst_log["insts"][inst]["junk"] == 0:
                if bytes_left < len(opcodes):
                    print(f"[-] Ran out of space while patching block {block_index}")
                    return(-1)
                print(f"Writing {opcodes.hex()}")
                p.write(opcodes)
                bytes_left = bytes_left - len(opcodes)
        # fill up with nops until hlt
        print(f"[*] Patching block {block_index}: Got {bytes_left} bytes left until the rva of the last instruction, filling up with nops")
        p.write(b"\x90" * bytes_left)
    p.close()


def force_code_at(ea):
    ida_bytes.del_items(ea, 0, 0x20)
    # ida_ua.create_insn(ea)
    ida_auto.auto_make_code(ea)
    ida_auto.auto_wait()
    # ida_auto.plan_and_wait(ea, ea + insn_size)
    # ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)


def decode_inst_at_rip():
    # may want to sync here just to be safe than sorry
    ea = idautils.cpu.Rip
    try:
        # length = ida_ua.decode_insn(insn, ea)  # Decode the instruction at ea
        inst = idautils.DecodeInstruction(ea)
    except Exception as e:
        print(f"[-] Failed to decode insn at address {hex(ea)}, {e}")
        exit(-1)
    if inst.size == 0:
        print(f"[-] Failed to decode instruction at {hex(ea)}")
        exit(-1)
    return inst


def get_next_runtime_function(RtlLookupFunctionEntryReturn):
    # run to instruction just behind call to ntdll_RtlLookupFunctionEntry in ntdll_RtlDispatchException
    # grab return value rax, type PRUNTIME_FUNCTION
    # the values have been dynamically calucated by the installed custom callback function 10b0
    ida_dbg.run_to(RtlLookupFunctionEntryReturn)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    where_am_i = idautils.cpu.Rip
    assert where_am_i == RtlLookupFunctionEntryReturn
    pruntime_function = idautils.cpu.Rax
    # print(f"pruntime_function {pruntime_function:x}")
    # runtime_function = ida_bytes.get_64bit(pruntime_function)
    # print(f"runtime_function {runtime_function:x}")
    # fetch UnwindInfo address for possible future fun
    runtime_function_start = ida_bytes.get_wide_dword(pruntime_function)
    runtime_function_end = ida_bytes.get_wide_dword(pruntime_function + 0x4)
    runtime_function_unwindinfo = ida_bytes.get_wide_dword(pruntime_function + 0x8)
    # print(f"[+] First PRUNTIME_FUNCTION->UnwindInfo: {runtime_function_unwindinfo:x} for start: {runtime_function_end:x}")
    return runtime_function_start, runtime_function_end, runtime_function_unwindinfo


def run_to_next_RtlpExecuteHandlerForException(exec_handler, shellcode_base):
    # run to call rax @ ntdll_RtlpExecuteHandlerForException+14
    # where we expect a call rax to the exception handler
    ida_dbg.run_to(exec_handler)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    where_am_i = idautils.cpu.Rip
    assert where_am_i == exec_handler
    # grab rax value
    handler_va = idautils.cpu.Rax
    handler_rva = handler_va - shellcode_base
    return (handler_va, handler_rva)


def dump_blocks_new(shellcode_base, exec_handler, RtlLookupFunctionEntryReturn, log_base, next_block_file, patch_target, patch_file_offset):
    # parse next_block with block_number, saved_rsp
    # loop:
    # skip_blocks()
    # data_struct = process_block()
    # deobf(data_struct)
    # log_block(data_struct)
    # patch(data_struct)
    # check loop condition

    # advance behind the first RtlLookupFunctionEntry call
    runtime_function_start, runtime_function_end, runtime_function_unwindinfo = get_next_runtime_function(RtlLookupFunctionEntryReturn)

    # parse next_block file
    next_block, saved_rsp, rf_start, rf_end, rf_unwind = parse_next_block_file(next_block_file)
    if rf_unwind != 0:
        runtime_function_start, runtime_function_end, runtime_function_unwindinfo = rf_start, rf_end, rf_unwind
    print(f"[+] next_block {next_block} saved_rsp {saved_rsp:x} rf_start {runtime_function_start:x} rf_end {runtime_function_end:x} rf_unwind {runtime_function_unwindinfo:x}")

    # skip blocks - to make up for ida crashes
    # this function will use ida_dbg.run_to next_block times + 1
    handler_va, handler_rva = skip_blocks(shellcode_base, exec_handler, next_block)
    print(f"[+] handler VA {handler_va:x} RVA {handler_rva:x}")

    # process one block, possible done in a future loop
    current_bock = next_block
    hit_jmpni_r12 = False

    # TEST process 3 blocks
    # when polished, do a while not hit_jmpni_r12: and possibly safeguard with current_block != 364
    # while not hit_jmpni_r12 and current_bock <= 364:
    for i in range(3):
        hit_jmpni_r12, inst_log = process_block(shellcode_base, exec_handler, current_bock, saved_rsp, handler_va, handler_rva)
        # add the runtime_function values, because, we may need them in the future although we do seriously hope we don't
        inst_log["runtime_function_start"] = runtime_function_start
        inst_log["runtime_function_end"] = runtime_function_end
        inst_log["runtime_function_unwindinfo"] = runtime_function_unwindinfo
        # dump for debug purposes
        # print(inst_log)

        # TODO for pros
        # - now if we were real reverse engineers and had a proper clue, we could parse the unwind tables for each handler
        # - and then emulate or generate code to destroy/restore the stack frames and cpu context before each handler execution
        # - then we might even be able to remove the hlts in a patched target
        # - possibly even decompile the deobfuscated code
        inst_log = deobfuscate_block(current_bock, inst_log)
        
        # log the block and update the next_block file
        log_block(log_base, current_bock, inst_log, next_block_file)

        # patch the target shellcode area with the deobfuscated code
        patch(patch_target, patch_file_offset, inst_log, current_bock)

        # do some kind of end check - have we reached the end?
        if hit_jmpni_r12:
            print(f"[*] We reached jmpni r12, no idea what to do now, good luck!")
            exit(-1)
        
        # advance to next exception handling
        # - first get the PRUNTIME_FUNCTION returned from ntdll_RtlLookupFunctionEntry
        # - then adcance to ntdll_RtlpExecuteHandlerForException's call rax
        runtime_function_start, runtime_function_end, runtime_function_unwindinfo = get_next_runtime_function(RtlLookupFunctionEntryReturn)
        handler_va, handler_rva = run_to_next_RtlpExecuteHandlerForException(exec_handler, shellcode_base)
        current_bock += 1
        # end loop
    # are we done already, yippie!
    return


def parse_next_block_file(filename):
    # structure is block_numer|saved_rsp
    try:
        with open(filename, "r") as f:
            saved_line = f.read().split("|")
            next_block = int(saved_line[0])
            saved_rsp = int(saved_line[1])
            runtime_function_start = int(saved_line[2])
            runtime_function_end = int(saved_line[3])
            runtime_function_unwindinfo = int(saved_line[4])
        f.close()
    except Exception as e:
        print(f"[-] Exception opening {filename}: {e}, resetting next_block/saved_rsp to 0")
        next_block = 0
        saved_rsp = 0
        runtime_function_start = 0
        runtime_function_end = 0
        runtime_function_unwindinfo = 0
    return (next_block, saved_rsp, runtime_function_start, runtime_function_end, runtime_function_unwindinfo)


def skip_blocks(shellcode_base, exec_handler, next_block):
    # skip previously dumped blocks - likely because ida crashed again
    # run to first exec_handler
    handler_va, handler_rva = run_to_next_RtlpExecuteHandlerForException(exec_handler, shellcode_base)
    # start skipping
    for i in range(next_block):
        print(f"[+] Skipping block {i} at VA {handler_va:x} RVA {handler_rva:x}")
        # run to next exec_handler
        handler_va, handler_rva = run_to_next_RtlpExecuteHandlerForException(exec_handler, shellcode_base)
    # DOUBLE CHECK if we are at the right block after refactoring!
    # ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    return (handler_va, handler_rva)


def process_block(shellcode_base, exec_handler, next_block, saved_rsp, handler_va, handler_rva):
    # do stuff
    block_counter = next_block
    print(f"-----\nBegin dumping block {block_counter} @ VA:{handler_va:x} RVA:{handler_rva:x}\n----")
    # log_trace = False # may be used for logic to toggle skipping junk code and to only log legit code
    # skip_one = False

    # we should be on the call rax inside ntdll_RtlpExecuteHandlerForException
    # double check that before ida goes boom
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    where_am_i = idautils.cpu.Rip
    assert where_am_i == exec_handler
    # double check that rax target is actually where we want to go
    call_target = idautils.cpu.Rax
    assert call_target == handler_va
    # then single step into the handler
    ida_dbg.step_into()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    # we are inside the handler routine now, start processing that
    inst_counter = 0
    # in a completely weird scenario, the jmpni r12 could be the first instruction
    # but we don't care (yet) to check for that here
    hit_jmpni_r12 = False
    # the instruction log data structure
    # key = insts, value = dict with key inst_number, value shellcode rva, opcode (bytes), disasm (string)
    # key = saved_rsp, value = RSP at end of block
    # key = handler_rva, value = rva of in the shellcode block of first instruction
    # keys for runtime_function_start/end/unwindinfo with respective values, filled by caller after we return from this function
    inst_log = dict()
    inst_log["handler_rva"] = handler_rva
    inst_log["insts"] = dict()

    # log_trace = True
    # prefill the loop condition check by decoding the first instruction
    inst = decode_inst_at_rip()

    # Begin single-step loop
    # we are done with this block when the following occurs
    # - we hit the hlt instruction that causes the next exception
    # - we hit a jmp near r12 instruction demarking the end of part 1 block 364 which jumps to func wrong_key 1400011F0
    while (inst.itype != idaapi.NN_hlt) and not (hit_jmpni_r12):
        # TODO: possibly implement some logic for filtering of what is logged and what not
        # check RSP changes at start - yes, we know already what we feared...
        # each handler has a different stack frame setup and register context
        # likely set up by ntdll_RtlVirtualUnwind based on the RUNTIME_FUNCTION ptr returned from
        # the custom callback function 10b0

        # print(f"Processing instruction {inst_counter} at {inst.ea:x}")
        opcode_bytes, disasm_line = get_instruction_bytes_and_disasm(inst)
        # TODO: possibly decide here if we want to log or discard this instruction, could be tough though here
        inst_log["insts"][inst_counter] = {"rva": inst.ea - shellcode_base, "opcodes": opcode_bytes, "disasm": disasm_line}
        inst_log['insts'][inst_counter]['junk'] = 0
        # print(f"inst_no {inst_counter:03} rva {inst.ea-shellcode_base:06x} {opcode_bytes.hex():20} {disasm_line}")

        # make sure the next instruction has been analyzed as code before step
        if not is_code(inst.ea + inst.size):
            # If it's not defined as code, try to enforce that it becomes code
            # print(f"Look-ahead Address {hex(ea + length)} is not defined as code. Attempting to make it code...")
            force_code_at(inst.ea)

        # Perform a single step / f7
        idaapi.step_into()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        # decode the next instruction
        inst = decode_inst_at_rip()
        # do a pre-check for part 1 end condition as it is re-used
        if (inst.itype == idaapi.NN_jmpni and inst[0].type == idaapi.o_reg and inst[0] == idautils.procregs.R12):
            hit_jmpni_r12 = True
        inst_counter += 1
        # end single step while loop

    # process last instruction for completeness
    # print(f"Processing instruction {inst_counter} at {inst.ea:x}")
    opcode_bytes, disasm_line = get_instruction_bytes_and_disasm(inst)
    inst_log["insts"][inst_counter] = {"rva": inst.ea - shellcode_base, "opcodes": opcode_bytes, "disasm": disasm_line}
    inst_log['insts'][inst_counter]['junk'] = 1
    # print(f"inst_no {inst_counter:03} rva {inst.ea-shellcode_base:06x} {opcode_bytes.hex():20} {disasm_line}")
    # post processing once loop hit one of the exit conditions
    # save any register values you want to compare between blocks
    new_rsp = idautils.cpu.Rsp
    print(f"Block {block_counter} ends at address {hex(inst.ea)} with {inst.get_canon_mnem()} after {inst_counter + 1} instructions, RSP:{new_rsp:x}")
    inst_log["saved_rsp"] = new_rsp
    # return
    # - hit_jmpni_r12
    # - a data structure with all processed instructions such as disassembly, opcodes for this block
    return hit_jmpni_r12, inst_log


#########################################
# main
#########################################

# start debugging
if not ida_dbg.dbg_is_loaded():
    print("[-] Debugger is not configured")
    exit(-1)

# possibly enable batch mode processing, if i werent an ida noob
program = "z:\\flareon11\\9_serpentine\\serpentine.exe"
working_dir = "z:\\flareon11\\9_serpentine\\"
argument = "abcdefghijklmnopqrstuvwxyz123456"
ida_dbg.request_start_process(program, argument, working_dir)

# pass exceptions to debuggee? no idea
# ida_dbg.set_debugger_options()

# patch target and file offset of shellcode blob
patch_target = "z:\\flareon11\\9_serpentine\\target.exe"
patch_file_offset = 0x95ef0

# log base
log_base = "z:\\flareon11\\9_serpentine\\trace_block_"
next_block_file = "z:\\flareon11\\9_serpentine\\next_block.txt"

# TlsCallback after VirtualAlloc
tls_alloc = 0x140001522

# ntdll_RtlDispatchException+15c
# just behind call ntdll_RtlLookupFunctionEntry
RtlLookupFunctionEntryReturn = 0x7FFEF27013BC

# ntdll_RtlpExecuteHandlerForException+14, call rax
exec_handler = 0x7FFEF275235D

# grab virtual alloc shellcode base address from tls function
ida_dbg.run_to(tls_alloc)
ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
where_am_i = idautils.cpu.Rip
assert where_am_i == tls_alloc

shellcode_base = idautils.cpu.Rax
print(f"[+] Working with shellcode base address: {hex(shellcode_base)}")

# do the thing
dump_blocks_new(shellcode_base, exec_handler, RtlLookupFunctionEntryReturn, log_base, next_block_file, patch_target, patch_file_offset)

# stop debugging
ida_dbg.exit_process()
