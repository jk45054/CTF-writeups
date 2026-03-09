import idaapi
import idc
import ida_dbg
import ida_ua  # To analyze instruction opcodes and mnemonics
import ida_bytes
import idautils


def do_stuff(filename):
    # check if we are at the right address when executing this
    # this is the call mempy instruction in the TlsCallback
    # that allocates RWX memory and copies the raw and obfuscated
    # shellcode into it
    rip = idautils.cpu.Rip
    assert rip == 0x14000155E
    # rcx = dest, rdx = src, r8d = size
    dest = idautils.cpu.Rcx
    src = idautils.cpu.Rdx
    size = idautils.cpu.R8d
    print(f"memcpy at {rip:x} with dst={dest:x}, src={src:x}, size={size:x} ", end="")
    with open(filename, "wb") as f:
        nbytes = f.write(ida_bytes.get_bytes(src, size))
    f.close()
    print(f"dumped to {filename} (nbytes={nbytes:x})")

do_stuff("z:\\flareon11\\9_serpentine\\raw_shellcode.bin")
