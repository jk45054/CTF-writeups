# Flare-On 10, Challenge 7, flake
#
# IDA Python script to log (and possibly rename)
# Method initializations in order to identify all methods
# Of a module / class
#
# The init method is `method_init_1404A42F0`
# It takes 11 parameters, but the first three seems to be essential
# For our task:
#
# Most (but not all) calls to that function are located at the
# Beginning of the corresponding Nuitka compiled C module code like this
#
# .text:14048372A  lea     rcx, # main_method_read_ctr
# .text:140483731  mov     r9, cs:off_14052F658 ; a4
# .text:140483738  xor     r14d, r14d
# .text:14048373B  mov     rdx, cs:pu_read_config_14052F3D8 ; # funcname
# .text:140483742  xor     r8d, r8d        ; classname
# .text:140483745  mov     [rsp+0F0h+a11], r14 ; a11
# .text:14048374A  mov     [rsp+0F0h+a10], r14 ; a10
# .text:14048374F  mov     [rsp+0F0h+a9], rax ; a9
# .text:140483754  mov     rax, cs:main_PyModuletype_e_140532318
# .text:14048375B  mov     [rsp+0F0h+a8], rax ; a8
# .text:140483760  mov     [rsp+0F0h+a7], r14 ; a7
# .text:140483765  mov     [rsp+0F0h+a6], r14 ; a6
# .text:14048376A  mov     [rsp+0F0h+a5], r14 ; a5
# .text:14048376F  call    method_init_1404A42F0 ; read_config
#
# It's probably very hard to run this script statically
# As the strings are looked up dynamically/during run-time
# But we can use this script in IDA Pro with conditional execution
# On breakpoint 0x1404A42F0 to log calls (and possibly iteratively
# Rename functions) on the go.
#

from ida_funcs import get_func_name
from ida_name import set_name, SN_NOCHECK
from idc import get_strlit_contents, STRTYPE_C
from ida_dbg import dbg_is_loaded, get_reg_val


# Check if debugger is running
if not dbg_is_loaded():
    print("[-] Debugger is not running")
    return -1
# Check if we are at the correct address
# Entrypoint of sub `method_init_1404A42F0`
expected_ea = 0x1404A42F0
dbg_ea = get_reg_val("rip")
if dbg_ea != expected_ea:
    print(f"[-] dbg_ea is at {dbg_ea:x}, expected ea is {expected_ea:x}")
    return -1
# Debugger is running, RIP is at correct address
# Get values for registers RCX, RDX and R8
rcx = get_reg_val("rcx")
rdx = get_reg_val("rdx")
r8 = get_reg_val("r8")
# Skip this hit if rcx is 0
if rcx == 0:
    return 0
# Get the function name for RCX
rcx_fname = get_func_name(rcx)
# Try to dereference the PyUnicode_Type string RDX (method name)
rdx_str = ""
try:
    rdx_str = get_strlit_contents(rdx + 0x30, strtype=STRTYPE_C).decode("UTF-8")
except:
    pass
if rdx_str == "":
    # print(f"[-] Could not dereference RDX string at {rdx+0x30:x}")
    return 0
# Try to dereference the PyUnicode_Type string R8 (class name)
# If r8 has a value (for non-classes, it's null)
r8_str = ""
if r8 != 0:
    try:
        r8_str = get_strlit_contents(r8 + 0x30, strtype=STRTYPE_C).decode("UTF-8")
    except:
        pass
    if r8_str == "":
        # print(f"[-] Could not dereference R8 string at {r8+0x30:x}")
        return 0
# print(
#    f"[*] Function method_init bp hit, RCX = {rcx:x} ({rcx_fname}), RDX = {rdx:x} ('{rdx_str}'), R8 = {r8:x} ('{r8_str}')"
# )
# Check if the function in RCX starts with "sub_" (i.e. has not been
# renamed yet)
if not rcx_fname.startswith("sub_"):
    return 0
# Can we get the callee address from call stack
# To set a comment to the call to this method_init?
# TODO for future Flare-On
#
# Rename the RCX function to something senseful
# i.e. class name (if it exists) or func name
#
if r8_str == "":
    new_method_name = rdx_str
else:
    new_method_name = r8_str
# Would be awesome to get the module name from callee / call stack
# To use that as a prefix for the new method name
# print(f"[*] Debug: We could rename {rcx_fname} to {new_method_name}_{rcx:x}")
print(f"[*] Method init detected, renaming {rcx_fname} to {new_method_name}_{rcx:x}")
set_name(rcx, f"{new_method_name}_{rcx:x}", SN_NOCHECK)
