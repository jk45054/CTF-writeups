from binascii import hexlify, unhexlify
import struct


def hexdump(data, length=16):
    """Prints data in hex and ASCII format."""
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        
        # Print the address (offset)
        print(f"{i:08x}  ", end="")
        
        # Print the hex bytes
        hex_bytes = ' '.join(f"{byte:02x}" for byte in chunk)
        print(f"{hex_bytes:<{length*3}}", end="  ")
        
        # Print the ASCII representation
        ascii_bytes = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)
        print(ascii_bytes)


def parse_unwind_info(ui_blob, ui_addr, image_base):
    # Mapping of opcode to names based on the Windows PE documentation
    unwind_opcodes = {
        0: "UWOP_PUSH_NONVOL",
        1: "UWOP_ALLOC_LARGE",
        2: "UWOP_ALLOC_SMALL",
        3: "UWOP_SET_FPREG",
        4: "UWOP_SAVE_NONVOL",
        5: "UWOP_SAVE_NONVOL_FAR",
        6: "UWOP_SAVE_XMM",
        7: "UWOP_SAVE_XMM_FAR",
        8: "UWOP_SAVE_XMM128",
        9: "UWOP_SAVE_XMM128_FAR",
        10: "UWOP_PUSH_MACHFRAME"
    }
    unwind_flags = {
        0: "UNW_FLAG_NHANDLER",
        1: "UNW_FLAG_EHANDLER",
        2: "UNW_FLAG_UHANDLER",
        3: "UNW_FLAG_FHANDLER",
        4: "UNW_FLAG_CHAININFO"
    }
    registers = {
        0: "RAX",
        1: "RCX",
        2: "RDX",
        3: "RBX",
        4: "RSP",
        5: "RBP",
        6: "RSI",
        7: "RDI",
        8: "R8",
        9: "R9",
        10: "R10",
        11: "R11",
        12: "R12",
        13: "R13",
        14: "R14",
        15: "R15",
    }
    xmm_registers = {
        0: "XMM0",
        1: "XMM1",
        2: "XMM2",
        3: "XMM3",
        4: "XMM4",
        5: "XMM5",
        6: "XMM6",
        7: "XMM7",
        8: "XMM8",
        9: "XMM9",
        10: "XMM10",
        11: "XMM11",
        12: "XMM12",
        13: "XMM13",
        14: "XMM14",
        15: "XMM15",
    }
    # ui_addr = image_base + ui_offset
    version_flags = ui_blob[0]
    version = version_flags & 0x07
    flags = version_flags >> 3
    size_of_prolog = ui_blob[1]
    count_unwind_codes = ui_blob[2]
    count_unwind_codes_orig = count_unwind_codes
    count_unwind_codes += count_unwind_codes & 0x1
    # skip frame register and frame register offset 
    frame_register_and_offset = ui_blob[3]
    frame_register_offset = frame_register_and_offset >> 4
    frame_register = frame_register_and_offset & 0x0F
    # skip unwind codes
    unwind_codes = []
    for i in range(count_unwind_codes_orig):
        offset_in_prolog = frame_register_and_offset = ui_blob[4 + i * 2]
        unwind_op_code_and_info = frame_register_and_offset = ui_blob[4 + i * 2 + 1]
        op_info = unwind_op_code_and_info >> 4
        op_code = unwind_op_code_and_info & 0x0F
        unwind_codes.append((offset_in_prolog, op_code, op_info))
    print('UNWIND_INFO at: ' + hex(ui_addr))
    print('version: ' + str(version))
    # flags
    print(f"flag: {unwind_flags[flags]}")
    print('Size of prolog: ' + str(size_of_prolog))
    print('Size of unwind codes: ' + str(count_unwind_codes_orig * 2) + ' bytes')
    print('Frame register: ' + hex(frame_register))
    print('Frame register offset: ' + hex(frame_register_and_offset))
    if len(unwind_codes) > 0:
        print('--- Unwind codes ---')
        for unwind_code in unwind_codes:
            print('unwind code offset in prolog: ' + hex(unwind_code[0]))
            if unwind_code[1] in unwind_opcodes:
                print('op code: ' + unwind_opcodes[unwind_code[1]])
            else:
                print('op code: UNKNOWN ' + str(unwind_code[1]))
            op_code = unwind_code[1]
            if (op_code == 0) | (op_code == 4) | (op_code == 5):
                print('op_info : ' + registers[unwind_code[2]])
            elif (op_code == 6) | (op_code == 7) | (op_code == 8) | (op_code == 9):
                print('op_info : ' + xmm_registers[unwind_code[2]])
            else:
                print('op info: ' + str(unwind_code[2]))
        
    # if ((flags & 0x3) == 0x2) | ((flags & 0x3) == 0x1):  #  flag UNW_FLAG_CHAININFO is clear and one of the flags UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER
    if (flags & 0x3): #  flag UNW_FLAG_CHAININFO is clear and one of the flags UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER
        exception_hdlr_addr = int.from_bytes(ui_blob[4 + count_unwind_codes * 2: 4 + count_unwind_codes * 2 + 4], 'little')
        print('Address of exception handler: ' + hex(exception_hdlr_addr))
    elif flags & 0x04:  # UNW_FLAG_CHAININFO
        print("flag: UNW_FLAG_CHAININFO set")
        # _get_runtime_function(ui_addr+4+count_unwind_codes*2)
        pass


shellcode_file_offset = 0x95ef0
# imaginary here
image_base = 0x6a20000

# first hlt RUNTIME_FUNCTION
runtime_function_start = 0x0
runtime_function_end = 0x1
# this is calculated by custom callback function based on byte value behind hlt instruction that caused the exception
# so for hlt at rva 0 and byte 0x46 at rva 1, callback yielded 0x48
runtime_function_unwindinfo = 0x48

first_handler_rva = 0x98
with open("z:\\flareon11\\9_serpentine\\serpentine.exe", "rb") as f:
    f.seek(shellcode_file_offset + runtime_function_unwindinfo)
    # we dont know the size yet, but for first handler, that is max 0x50
    unwind_blob = f.read(0x50)
f.close()

print("----- first runtime_function->UnwindInfo -----")
hexdump(unwind_blob)
parse_unwind_info(unwind_blob, runtime_function_unwindinfo, image_base)

# second hlt RUNTIME_FUNCTION
runtime_function_start = 0x107
runtime_function_end = 0x108
# this is calculated by custom callback function based on byte value behind hlt instruction that caused the exception
# so for hlt at rva x and byte 0x3D at rva x + 1, callback yielded 0x146
runtime_function_unwindinfo = 0x146

second_handler_rva = 0x1a7
with open("z:\\flareon11\\9_serpentine\\serpentine.exe", "rb") as f:
    f.seek(shellcode_file_offset + runtime_function_unwindinfo)
    # we dont know the size yet, but for first handler, that is max 0x50
    unwind_blob = f.read(0x80)
f.close()

print("\n----- second runtime_function->UnwindInfo -----")
hexdump(unwind_blob)
parse_unwind_info(unwind_blob, runtime_function_unwindinfo, image_base)
