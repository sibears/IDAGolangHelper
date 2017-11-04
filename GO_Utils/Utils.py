import idc
import string
import random

class bitZ(object):
    def __init__(self, ptr, size, maker):
        self.ptr = ptr
        self.size = size
        self.maker = maker


bits32 = bitZ(idc.Dword, 4, idc.MakeDword)
bits64 = bitZ(idc.Qword, 8, idc.MakeQword)


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def rename(offset, name):
    res = idc.MakeNameEx(offset, name, idc.SN_NOWARN)
    if res == 0:
        name = name+"_autogen_"+id_generator()
        idc.MakeNameEx(offset, name, idc.SN_NOWARN)


def relaxName(name):
    name = name.replace('.', '_').replace("<-", '_chan_left_').replace('*', '_ptr_').replace('-', '_').replace(';','').replace('"', '').replace('\\', '')
    name = name.replace('(', '').replace(')', '').replace('/', '_').replace(' ', '_').replace(',', 'comma').replace('{','').replace('}', '').replace('[', '').replace(']', '')
    return name


def get_bitness(addr):
    ptr = bits32
    if idc.GetSegmentAttr(addr, idc.SEGATTR_BITNESS) == 2:
        ptr = bits64
    return ptr


def is_hardcoded_slice(addr, bt_obj):
    #compiled slices will have valid ptr
    if bt_obj.ptr(bt_obj.ptr(addr)) == idc.BADADDR:
        return False
    addr = addr + bt_obj.size
    val1 = bt_obj.ptr(addr)
    val2 = bt_obj.ptr(addr + bt_obj.size)
    if val1 != val2:
        return False
    return True


class StructCreator(object):

    def __init__(self, bt_obj):
        self.types_id = {}
        if bt_obj.size == 8:
            self.uintptr = (idc.FF_QWRD|idc.FF_DATA, -1, bt_obj.size)
        else:
            self.uintptr = (idc.FF_DWRD | idc.FF_DATA, -1, bt_obj.size)

    def createStruct(self, name):
        sid = idc.GetStrucIdByName(name)
        if sid != -1:
            idc.DelStruc(sid)
        sid = idc.AddStrucEx(-1, name, 0)
        self.types_id['name'] = sid
        return sid

    def fillStruct(self, sid, data):
        for i in data:
            new_type = None
            #(i1, i2, i3) = self.stepper.parseField(i[1])
            name = i[1]
            if name[0] == "*":
                name = name[1:]
            if i[1] != "uintptr":
                i1,i2,i3 = (idc.FF_BYTE|idc.FF_DATA, -1, 1)
            else:
                i1, i2, i3 = self.uintptr
            if name == i[1]:
                new_type = i[1]
            else:
                new_type = name + " *"
            res = idc.AddStrucMember(sid, i[0], -1, i1, i2, i3)
            use_name = i[0]
            if res == -1: #Bad name
                #print "Bad name %s for struct member" % i[0]
                use_name = i[0] + "_autogen_"+id_generator()
                idc.AddStrucMember(sid, use_name, -1, i1, i2, i3)
            if new_type is not None:
                offset = idc.GetMemberOffset(sid, use_name)
                #print "Setting %s as %s" % (i[0], new_type)
                idc.SetType(idc.GetMemberId(sid, offset), new_type)

    def makeStruct(self, i):
        print "Creating structure %s" % (i[0])
        sid = self.createStruct(i[0])
        self.fillStruct(sid, i[1])

    def createTypes(self, types):
        for i in types:
            self.makeStruct(i)

    def createEnum(self, enum):
        eid = idc.AddEnum(-1, enum[0], 0x1100000) #what is this flag?
        idc.SetEnumBf(eid, 1)
        val = 0
        mask = 0x1f
        idc.SetEnumWidth(eid, 1)
        for i in enum[1]:
            idc.AddConstEx(eid, i, val, mask)
            val += 1

    def createEnums(self, enums):
        for i in enums:
            self.createEnum(i)

