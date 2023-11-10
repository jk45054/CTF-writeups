# Flare-On 10, Challenge 12, HVM
#
# IDA Pro plugin for code decryption
# Set cursor (ScreenEA) to an IN/OUT instruction
# - IN: decrypt the code based on R8/R9 values
#   - r8: RC4 key
#   - r9: size
# - OUT: NOP it away (code re-encryption after execution)
#

import idaapi
from ida_ua import insn_t, decode_insn, decode_prev_insn, o_imm, o_reg, create_insn
from ida_kernwin import get_screen_ea
from ida_bytes import get_bytes, patch_bytes, set_cmt, del_items

PLUGIN_COMMENT = "42"
PLUGIN_HELP = "42"
PLUGIN_NAME = "FlareOn10-Ch12-Patching"
PLUGIN_WANTED_HOTKEY = "Alt-9"


class RC4:
    S = None
    i = 0
    j = 0
    dropped = 0

    # constructor for instance of class RC4
    # if n > 0, drop first n key bytes - alias RC4-drop[n]
    def __init__(self, key: bytes, n: int = 0):
        self.i = 0
        self.j = 0
        self.S = bytearray(256)
        self.KSA(key)
        while n > 0:
            self.PRGA()
            n = n - 1

    # Key Scheduling Algorithm (KSA)
    def KSA(self, key: bytes):
        for i in range(256):
            self.S[i] = i
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    # Pseudo-random generation algorithm (PRGA)
    def PRGA(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

    # Encrypt/decrypt bytes
    def crypt(self, data: bytes) -> bytes:
        result = bytearray()
        for b in data:
            result.append(b ^ self.PRGA())
        return bytes(result)


class do_io_patching_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    def patch_in(self, ea):
        # Patch for case opcode: in
        # for IN opcode -> hvm.exe applies XOR decrypt with key r8, fixed key_len 8, buf at VA_alloc + rip + 2 and buf_len r9
        # Decode the two instructions before the IN opcode to get r8 and r9 immed values
        #
        # Decode first instruction ahead of in = prev1_insn
        # This should yield r9d value
        print(f"[*] Found in instruction @ {hex(ea)}")
        prev1_insn = insn_t()
        len_prev1_insn = decode_prev_insn(prev1_insn, ea)
        print(f"[*] Decoding prev1 insn")
        if len_prev1_insn == 0:
            print(f"[-] Couldn't decode prev1 insn @ {hex(prev1_insn.ea)}")
            return ()
        if prev1_insn.get_canon_mnem() != "mov":
            print(
                f"[-] Prev1 instruction is a {prev1_insn.get_canon_mnem()}, expected mov r9d, immed"
            )
            return ()
        if prev1_insn.ops[0].type != o_reg:
            print(
                f"[-] Prev1 mov instruction operand 0 is of type {prev1_insn.ops[1].type}, expected o_reg"
            )
            return ()
        if prev1_insn.ops[1].type != o_imm:
            print(
                f"[-] Prev1 mov instruction operand 1 is of type {prev1_insn.ops[1].type}, expected o_imm"
            )
            return ()
        print(
            f"[*] Found prev1 insn: mov ops[0] reg number {prev1_insn.ops[0].reg}, immed value {hex(prev1_insn.ops[1].value64)}"
        )
        # Decode second instruction ahead of in = prev2_insn
        # This should yield r8 value
        prev2_insn = insn_t()
        len_prev2_insn = decode_prev_insn(prev2_insn, prev1_insn.ea)
        print(f"[*] Decoding prev2 insn @ {hex(prev2_insn.ea)}")
        if len_prev2_insn == 0:
            print(f"[-] Couldn't decode prev2 insn")
            return ()
        if prev2_insn.ops[0].type != o_reg:
            print(
                f"[-] Prev2 mov instruction operand 0 is of type {prev2_insn.ops[1].type}, expected o_reg"
            )
            return ()
        if prev2_insn.get_canon_mnem() != "mov":
            print(
                f"[-] Prev2 instruction is a {prev2_insn.get_canon_mnem()}, expected mov r8, immed"
            )
            return ()
        if prev2_insn.ops[1].type != o_imm:
            print(
                f"[-] Prev2 mov instruction operand 1 is of type {prev2_insn.ops[1].type}, expected o_imm"
            )
            return ()
        print(
            f"[*] Found prev2 insn: mov ops[0] reg number {prev2_insn.ops[0].reg}, immed value {hex(prev2_insn.ops[1].value64)}"
        )
        # Grab the bytes to be decrypted
        # - start: ea + 2 (rip + 2)
        # - len: r9d
        r9d = prev1_insn.ops[1].value64
        r8 = prev2_insn.ops[1].value64
        enc_code_bytes = get_bytes(ea + 2, r9d)
        print(f"[*] Encrypted bytes beginning at {hex(ea+2)}: {enc_code_bytes.hex()}")
        # Initialize RC4 cipher with prev2 immed value as RC4 key
        cipher = RC4(int.to_bytes(r8, 8, "little"))
        dec_code_bytes = cipher.crypt(enc_code_bytes)
        print(f"[*] Decrypted bytes: {dec_code_bytes.hex()} using key: {hex(r8)}")
        # Del items in the range -> make them unexplored
        del_items(ea, r9d)
        # Patch the bytes and NOP the IN
        patch_bytes(ea, b"\x90\x90")
        patch_bytes(ea + 2, dec_code_bytes)
        # Create instruction at patched address
        create_insn(ea)
        # Set comment
        self.in_counter += 1
        # set_cmt(ea, f"Counter: {self.counter}, decrypted @ {hex(ea+2)}, len {hex(r9d)}, before: {enc_code_bytes.hex()}, after: {dec_code_bytes.hex()}", 0)
        set_cmt(
            ea,
            f"IN-Counter: {self.in_counter}, decrypted @ {hex(ea+2)}, len {hex(r9d)}",
            0,
        )
        return ()

    def patch_out(self, ea):
        # Patch for case opcode: out
        # for OUT opcode -> applies XOR key r8, fixed key_len 8 at VA_alloc + rip - 16 - r9, for len r9
        # Decode the two instructions before the IN opcode to get r8 and r9 immed values
        print(f"[*] Found out instruction @ {hex(ea)}")
        # Del the out
        del_items(ea, 2)
        # Patch it with NOP
        patch_bytes(ea, b"\x90\x90")
        # Create instruction at patched address
        create_insn(ea)
        # Set comment
        self.out_counter += 1
        set_cmt(ea, f"OUT-Counter: {self.out_counter}, patched with NOPs", 0)
        return ()

    def init(self):
        try:
            idaapi.msg("do_io_patching init() called!\n")
            self.in_counter = 0
            self.out_counter = 0
            return idaapi.PLUGIN_OK
        except Exception as err:
            idaapi.msg("Exception during init: %s\n" % str(err))
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        try:
            # idaapi.msg("do_io_patching run() called with %d!\n" % arg)
            # Get current cursor location VA
            ea = get_screen_ea()
            # Decode instruction at ea
            insn = insn_t()
            len_inst = decode_insn(insn, ea)
            if len_inst == 0:
                print(f"[-] Couldn't decode insn @ {hex(ea)}")
                return ()
            print(
                f"do_io_patching: decoded insn @ {hex(ea)}, canon mnem = {insn.get_canon_mnem()}"
            )
            if insn.get_canon_mnem() == "in":
                self.patch_in(ea)
            elif insn.get_canon_mnem() == "out":
                self.patch_out(ea)
            else:
                print(f"[-] Neither in nor out opcode @ {hex(ea)}")
                return ()
        except Exception as err:
            idaapi.msg("Exception during run: %s\n" % str(err))
            raise
        idaapi.msg("do_io_patching run() complete!\n")

    def term(self):
        idaapi.msg("do_io_patching term() called!\n")


def PLUGIN_ENTRY():
    return do_io_patching_plugin_t()
