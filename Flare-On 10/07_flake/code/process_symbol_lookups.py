# Flare-On 10, Challenge 7, flake
#
# IDA Python script to list cross references to function
# lookup_metadata_for_symbol_1404BC0E0
#
# Most (but not all) calls to that function are located at the
# Beginning of the corresponding Nuitka compiled C function like this
#
# .text:140482CDF lea     r8, aMain       ; "__main__"
# .text:140482CE6 lea     rdx, main_metadata_14052EDB0 ; obj_ptr_or_stuff
# .text:140482CED call    lookup_metadata_for_symbol_1404BC0E0
# .text:140482CF2 mov     cs:main_res_lookup_done_14052EDA8, 1
#
# Goal is to iterate over all xrefs to this function
# Locate string value r8 before that
# And identify the function in which this call happens
# And dump that information out + rename
#

from idautils import CodeRefsTo, DecodePreviousInstruction, procregs
from ida_bytes import set_cmt
from ida_funcs import get_func, get_func_name
from ida_name import set_name, SN_NOCHECK
from idc import get_strlit_contents, STRTYPE_C
import idaapi


def get_prior_r8_string(ea):
    # Locate lea r8, global_string_offset
    # Prior to address ea
    # Seems to always be 2 instructions prior to lookup call
    # Decode first preceding instruction
    inst = DecodePreviousInstruction(ea)
    # Skip it and decode the one preceding that
    inst = DecodePreviousInstruction(inst.ea)
    # To be more resilient, we might want to add a "deeper"
    # lookback (todo)
    if inst.itype != idaapi.NN_lea:
        # print(f"[-] Error, instruction at {hex(inst.ea)} is not a LEA!")
        return ""
    if inst[0] != procregs.r8:
        # print(f"[-] Error, LEA at {hex(inst.ea)} does not load R8!")
        return ""
    # print(f"[+] Found LEA R8, {hex(inst[1].addr)}")
    r8_str = get_strlit_contents(inst[1].addr, strtype=STRTYPE_C).decode("UTF-8")
    return r8_str


def process_xref(ref):
    # Find and get the string value that is used as parameter r8
    r8_str = get_prior_r8_string(ref)
    func = get_func(ref)
    print(
        f"[*] Function {hex(func.start_ea)} called symbol lookup from {hex(ref)} with R8 = '{r8_str}'"
    )
    # Set comment at address of call with string value
    set_cmt(ref, f"with R8 = '{r8_str}'", 0)
    # If R8 string was empty or .bytecode, return here
    # __main__ is looked up twice, so its ambiguous. return as well
    # as we already identified main (see wrtie up)
    if r8_str == '' or r8_str == '.bytecode' or r8_str == '__main__':
        return
    # Get function name
    func_name = get_func_name(ref)
    # If function was already renamed, leave it alone
    if not func_name.startswith("sub_"):
        return
    # Rename function with what we think it is
    # i.e. the string of the looked up symbol
    set_name(func.start_ea, f"{r8_str}_{ref:x}", SN_NOCHECK)


# Main
if __name__ == "__main__":
    lookup_metadata_for_symbol = 0x1404BC0E0
    # Get all xrefs to this function
    refs = CodeRefsTo(lookup_metadata_for_symbol, 1)
    # Iterate over all xrefs
    for ref in refs:
        # print(f"[*] Processing ref {hex(ref)} with CodeRef to {hex(lookup_metadata_for_symbol)}")
        # Process this code xref
        process_xref(ref)
