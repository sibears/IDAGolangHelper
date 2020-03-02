import idc
import idaapi
import idautils
import ida_bytes

#Simple function to fix strings in current function
#Mostly based on "Tim 'diff' Strazzere" ideas

def parseOp(operand):
    if operand.type == idaapi.o_displ or operand.type == idaapi.o_phrase:
        if operand.reg == 4: #esp/rsp
            return True, operand.addr
    return False, 0

def convert_operand(operand, size, num, pos):
    if operand.type == idaapi.o_displ or operand.type == idaapi.o_phrase:
        if operand.reg == 4: #esp/rsp
            if operand.addr < size:
                idc.OpHex(pos, num)
            
#Well for now I don't know how determine ptr size ;[
def is_this_a_real_string(next_pos, instr, size_data):
    #Common scenario is when we mov offset into register
    #and after that either fill local string variable or push string as argument
    #so we just check that we use esp 
    next_instr = idautils.DecodeInstruction(next_pos)
    if next_instr.get_canon_mnem() == "mov":
        is_stack_used, ptr_addr = parseOp(next_instr.Op1)
        if is_stack_used is True:
            #Check if we really place our offset
            if next_instr.Op2.type == idaapi.o_reg and next_instr.Op2.reg == instr.Op1.reg: 
                next_pos += next_instr.size
                next_instr = idautils.DecodeInstruction(next_pos)
                if next_instr.get_canon_mnem() == "mov":
                    is_stack_used, size_addr = parseOp(next_instr.Op1)
                    #if we filling string or at least smthng looking very similar
                    if is_stack_used is True and (size_addr - ptr_addr == size_data):
                        #for now explicitly set 0x1000 as max string size
                        if next_instr.Op2.type == idaapi.o_imm and next_instr.Op2.value < 0x1000:
                            return True, next_instr.Op2.value
    return False, 0

def make_string(addr, siz):
    print("Creating string at %x %d size" % (addr, siz))
    idc.MakeUnknown(addr, siz, idc.DOUNK_SIMPLE)
    ida_bytes.create_strlit(addr, siz, -1)

def get_bitness_bytes(addr):
    if idc.GetSegmentAttr(addr, idc.SEGATTR_BITNESS) == 2:
        return 8
    return 4

def stringify():
    ea = idc.here()
    size_data = get_bitness_bytes(ea)
    f = idaapi.get_func(ea)
    frsize = idc.GetFrameLvarSize(ea)
    position = f.startEA
    size = 0
    while position < f.endEA:
        instr = idautils.DecodeInstruction(position)
        if instr is None:
            print("%x: Not and instruction found" % position)
            break
        mnem = instr.get_canon_mnem()
        if mnem == "mov":
            if instr.Op2.type == idaapi.o_imm and instr.Op1.type == idaapi.o_reg: #this may be string load
                is_string, size_s = is_this_a_real_string(position + instr.size, instr, size_data)
                if is_string is True:
                    make_string(instr.Op2.value, size_s)
        elif mnem == "lea":
            if instr.Op2.type == idaapi.o_mem and instr.Op1.type == idaapi.o_reg:
                is_string, size_s = is_this_a_real_string(position + instr.size, instr, size_data)
                if is_string is True:
                    make_string(instr.Op2.addr, size_s)
        position += instr.size
