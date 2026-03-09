import idaapi
import idc
import ida_dbg
import ida_ua  # To analyze instruction opcodes and mnemonics
import ida_bytes


def log_msg(msg):
    LOGFILE = "z:\\flareon11\\9_serpentine\\unwind.log"
    print(msg)
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")
    f.close()
    return


def dump_sc_handler_addr():
    rip_value = idc.get_reg_value("rip")
    # are we at ntdll_RtlDispatchException+0x198 ?
    # this is supposed to be the opcode just after
    # the call to ntdll_RtlVirtualUnwind 
    assert rip_value == 0x7FFEF27013F8

    # Get the value of RAX registers
    r15_value = idc.get_reg_value("r15")
    rax_value = idc.get_reg_value("rax")

    # Check if the RCX and RSI values are valid
    if r15_value == idc.BADADDR:
        print("Error: R15 register does not hold a valid address.")
        return 0
    if rax_value == idc.BADADDR:
        print("Error: RAX register does not hold a valid address.")
        return 0

    # msg = f"Exception @ {hex(r15_value)} is handled by {hex(rax_value)}"
    msg = f"Handler: {hex(rax_value)}"
    log_msg(msg)
    return 1


dump_sc_handler_addr()
