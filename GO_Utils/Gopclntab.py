import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs
import ida_search
import Utils

info = idaapi.get_inf_structure()
try:
    is_be = info.is_be()
except:
    is_be = info.mf

lookup = "FF FF FF FB 00 00" if is_be else "FB FF FF FF 00 00"

def check_is_gopclntab(addr):
    ptr = Utils.get_bitness(addr)
    first_entry = ptr.ptr(addr+8+ptr.size)
    first_entry_off = ptr.ptr(addr+8+ptr.size*2)
    addr_func = addr+first_entry_off
    func_loc = ptr.ptr(addr_func)
    if func_loc == first_entry:
        return True
    return False


def findGoPcLn():
    pos = idautils.Functions().next() # Get some valid address in .text segment
    while True:
        end_ea = idc.get_segm_end(pos)
        possible_loc = ida_search.find_binary(pos, end_ea, lookup, 16, idc.SEARCH_DOWN) #header of gopclntab
        if possible_loc == idc.BADADDR:
            break
        if check_is_gopclntab(possible_loc):
            return possible_loc
        pos = possible_loc+1
    return None


def rename(beg, ptr, make_funcs = True):
    base = beg
    pos = beg + 8 #skip header
    size = ptr.ptr(pos)
    pos += ptr.size
    end = pos + (size * ptr.size * 2)
    print "%x" % end
    while pos < end:
        offset = ptr.ptr(pos + ptr.size)
        ptr.maker(pos)         #in order to get xrefs
        ptr.maker(pos+ptr.size)
        pos += ptr.size * 2
        ptr.maker(base+offset)
        func_addr = ptr.ptr(base+offset)
        if make_funcs == True:
            ida_bytes.del_items(func_addr, 1, ida_bytes.DELIT_SIMPLE)
            ida_funcs.add_func(func_addr)
        name_offset = idc.get_wide_dword(base+offset+ptr.size)
        name = idc.get_strlit_contents(base + name_offset)
        name = Utils.relaxName(name)
        Utils.rename(func_addr, name)