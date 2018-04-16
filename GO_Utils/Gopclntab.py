import idc
import idautils
import idaapi
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
        possible_loc = idc.FindBinary(pos, idc.SEARCH_DOWN, lookup) #header of gopclntab
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
            idc.MakeUnknown(func_addr, 1, idc.DOUNK_SIMPLE)
            idc.MakeFunction(func_addr)
        name_offset = idc.Dword(base+offset+ptr.size)
        name = idc.GetString(base + name_offset)
        name = Utils.relaxName(name)
        Utils.rename(func_addr, name)