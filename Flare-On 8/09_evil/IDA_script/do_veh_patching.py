import idaapi
import idautils
import idaapi
import idc
import ida_bytes
import ida_ua

PLUGIN_COMMENT = "This is a shameless plug"
PLUGIN_HELP = "This is help"
PLUGIN_NAME = "do_veh_patching"
PLUGIN_WANTED_HOTKEY = "Alt-9"

class do_veh_patching_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_WANTED_HOTKEY

    def init(self):
        try:
            idaapi.msg("do_veh_patching init() called!\n")
            return idaapi.PLUGIN_OK
        except Exception as err:
            idaapi.msg("Exception during init: %s\n" % str(err))
        
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        try:
            idaapi.msg("do_veh_patching run() called with %d!\n" % arg)
            cur_ea = idc.get_screen_ea()
            orig = ida_bytes.get_bytes(cur_ea, 0x3)
            #print("Orig Bytes at {} are: {}".format(hex(cur_ea), orig))
            buf = b"\x90\xFF\xD0" # nop; call eax
            ida_bytes.patch_bytes(cur_ea, buf)
            print("Patching Orig: {} to: {} @ {}".format(orig, buf, hex(cur_ea)))
            ida_ua.create_insn(cur_ea)
            idaapi.msg("do_veh_patching run() done")
        except Exception as err:
            idaapi.msg("Exception during run: %s\n" % str(err))
            raise
            
        idaapi.msg("do_veh_patching run() complete!\n")

    def term(self):
        idaapi.msg("do_veh_patching term() called!\n")

def PLUGIN_ENTRY():
    return do_veh_patching_plugin_t()