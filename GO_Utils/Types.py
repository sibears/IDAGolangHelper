from . import Utils
import ida_bytes
import ida_struct
import idc

class GoTypes_BASE(object):
    def __init__(self, creator):
        self.standardTypes = [
                              ("string",[("ptr","*char"), ("len", "uintptr")]),
                              ("slice", [("data","*char"),("len", "uintptr"), ("cap", "uintptr")]),
                              ("__iface", [("itab","*char"),("ptr","*char")])
        ]

        self.commonTypes = [
                              ("arrayType",[
                                  ("type", "type"),
                                  ("elem", "*type"),
                                  ("slice", "*type"),
                                  ("len", "uintptr")
                              ]),
                              ("chanType", [
                                  ("type", "type"),
                                  ("elem", "*type"),
                                  ("dir", "uintptr")
                              ]),
                              ("ptrType", [
                                  ("type", "type"),
                                  ("elem", "*type")
                              ]),
                              ("sliceType", [
                                  ("type", "type"),
                                  ("elem", "*type")
                              ])
        ]
        self.standardEnums = [
            ("kind",[
            "INVALID", "BOOL","INT","INT8",
            "INT16","INT32","INT64","UINT",
            "UINT8","UINT16","UINT32","UINT64",
            "UINTPTR","FLOAT32","FLOAT64","COMPLEX64",
            "COMPLEX128","ARRAY","CHAN","FUNC","INTERFACE","MAP","PTR","SLICE",
            "STRING","STRUCT","UNSAFE_PTR"
            ])
        ]
        creator.createTypes(self.standardTypes)
        creator.createEnums(self.standardEnums)


class GoTypes_l7(GoTypes_BASE):

    def __init__(self, creator):
        super(GoTypes_l7, self).__init__(creator)
        self.standardTypes = [
                              ("uncommonType", [("name", "*string"), ("pkgPath", "*string"), ("methods", "slice")]),
        ]
        #this types depends on type structure so should be created after
        self.commonTypes += [
                            ("method__", [("name", "*string"),("pkgPath","*string"),("mtype","*type"),("typ","*type"),("ifn", "void *"),("tfn","void *")]),
                            ("structField",[
                                    ("Name",   "*string"),
                                    ("PkgPath","*string"),
                                    ("typ", "*type"),
                                    ("tag", "*string"),
                                    ("offset", "uintptr"),
                              ]),
                              ("structType", [
                                    ("type","type"),
                                    ("fields", "slice")
                              ]),
                              ("imethod", [
                                  ("name", "*string"),
                                  ("pkgPath", "*string"),
                                  ("typ", "*type")
                              ]),
                              ("interfaceType",[
                                  ("type", "type"),
                                  ("methods", "slice")
                              ]),
                              ("funcType",[("type","type")]), #TODO:fix
                             ]
        creator.createTypes(self.standardTypes)

class Go116Types(GoTypes_BASE):
    def __init__(self, creator):
        super(Go116Types, self).__init__(creator)
        self.standardTypes = [
            ("type", [
                ("size",        "uintptr"),
                ("ptrdata",     "uintptr"),
                ("hash",        "__int32"),
                ("flag",        "__int8"),
                ("align",       "__int8"),
                ("fieldAlign",  "__int8"),
                ("kind",        "kind"),
                ("equal",         "*void"),
                ("gcdata",      "*unsigned char"),
                ("string",      "__int32"),
                ("ptrtothis",   "__int32"),
           ])
        ]

        #this types depends on type structure so should be created after
        self.commonTypes += [
            ("uncommonType", [("pkgPath", "__int32"), ("mcount", "__int16"), ("unused1", "__int16"),("moff", "__int32"), ("unused2", "__int16")]),
            ("method__", [("name", "__int32"), ("mtyp", "__int32"),("ifn","__int32"), ("tfn", "__int32")]),
                            ("structField",[
                                    ("Name",   "void *"),
                                    ("typ", "*type"),
                                    ("offset", "uintptr"),
                              ]),
                              ("structType", [
                                    ("type","type"),
                                    ("pkgPath", "void *"),
                                    ("fields", "slice")
                              ]),
                              ("imethod", [
                                  ("name", "__int32"),
                                  ("pkgPath", "__int32"),
                              ]),
                              ("interfaceType",[
                                  ("type", "type"),
                                  ("pkgPath", "void *"),
                                  ("methods", "slice")
                              ]),
                              ("funcType", [
                                  ("type", "type"),
                                  ("incount","__int16"),
                                  ("outcount", "__int16")
                              ]),
                              ("mapType", [
                                  ("type", "type"),
                                  ("key","*type"),
                                  ("elem","*type"),
                                  ("bucket", "*type"),
                                  ("hasher", "void *"),
                                  ("keysize","__int8"),
                                  ("elemsize","__int8"),
                                  ("bucketsize","__int16"),
                                  ("flags","__int32"),
                              ])
                             ]
        
        creator.createTypes(self.standardTypes)
        creator.createTypes(self.commonTypes)

class Go117Types(GoTypes_BASE):
    def __init__(self, creator):
        super(Go117Types, self).__init__(creator)
        self.standardTypes = [
            ("type", [
                ("size",        "uintptr"),
                ("ptrdata",     "uintptr"),
                ("hash",        "__int32"),
                ("flag",        "__int8"),
                ("align",       "__int8"),
                ("fieldAlign",  "__int8"),
                ("kind",        "kind"),
                ("equal",         "*void"),
                ("gcdata",      "*unsigned char"),
                ("string",      "baseptr"),
                ("ptrtothis",   "baseptr"),
           ])
        ]

        #this types depends on type structure so should be created after
        self.commonTypes += [
            ("uncommonType", [("pkgPath", "__int32"), ("mcount", "__int16"), ("unused1", "__int16"),("moff", "__int32"), ("unused2", "__int16")]),
            ("method__", [("name", "__int32"), ("mtyp", "__int32"),("ifn","__int32"), ("tfn", "__int32")]),
                            ("structField",[
                                    ("Name",   "void *"),
                                    ("typ", "*type"),
                                    ("offset", "uintptr"),
                              ]),
                              ("structType", [
                                    ("type","type"),
                                    ("pkgPath", "void *"),
                                    ("fields", "slice")
                              ]),
                              ("imethod", [
                                  ("name", "baseptr"),
                                  ("pkgPath", "baseptr"),
                              ]),
                              ("interfaceType",[
                                  ("type", "type"),
                                  ("pkgPath", "void *"),
                                  ("methods", "slice")
                              ]),
                              ("funcType", [
                                  ("type", "type"),
                                  ("incount","__int16"),
                                  ("outcount", "__int16")
                              ]),
                              ("mapType", [
                                  ("type", "type"),
                                  ("key","*type"),
                                  ("elem","*type"),
                                  ("bucket", "*type"),
                                  ("hasher", "void *"),
                                  ("keysize","__int8"),
                                  ("elemsize","__int8"),
                                  ("bucketsize","__int16"),
                                  ("flags","__int32"),
                              ])
                             ]

        creator.createTypes(self.standardTypes)
        creator.createTypes(self.commonTypes)
        self.creator = creator
    
    def update_robase(self, robase):
        self.creator.configBase(robase)

class Go17Types(GoTypes_BASE):
    def __init__(self, creator):
        super(Go17Types, self).__init__(creator)
        self.standardTypes = [
            ("type", [
                ("size",        "uintptr"),
                ("ptrdata",     "uintptr"),
                ("hash",        "__int32"),
                ("flag",        "__int8"),
                ("align",       "__int8"),
                ("fieldAlign",  "__int8"),
                ("kind",        "kind"),
                ("alg",         "*void"),
                ("gcdata",      "*unsigned char"),
                ("string",      "__int32"),
                ("ptrtothis",   "__int32"),
           ])
        ]

        #this types depends on type structure so should be created after
        self.commonTypes += [
            ("uncommonType", [("pkgPath", "__int32"), ("mcount", "__int16"), ("unused1", "__int16"),("moff", "__int32"), ("unused2", "__int16")]),
            ("method__", [("name", "__int32"), ("mtyp", "__int32"),("ifn","__int32"), ("tfn", "__int32")]),
                            ("structField",[
                                    ("Name",   "void *"),
                                    ("typ", "*type"),
                                    ("offset", "uintptr"),
                              ]),
                              ("structType", [
                                    ("type","type"),
                                    ("pkgPath", "void *"),
                                    ("fields", "slice")
                              ]),
                              ("imethod", [
                                  ("name", "__int32"),
                                  ("pkgPath", "__int32"),
                              ]),
                              ("interfaceType",[
                                  ("type", "type"),
                                  ("pkgPath", "void *"),
                                  ("methods", "slice")
                              ]),
                              ("funcType", [
                                  ("type", "type"),
                                  ("incount","__int16"),
                                  ("outcount", "__int16")
                              ]),
                              ("mapType", [
                                  ("type", "type"),
                                  ("key","*type"),
                                  ("elem","*type"),
                                  ("bucket", "*type"),
                                  ("hmap", "*type"),
                                  ("keysize","__int8"),
                                  ("indirectkey","__int8"),
                                  ("valuesize","__int8"),
                                  ("indirectvalue","__int8"),
                                  ("bucketsize","__int16"),
                                  ("reflexivekey","__int8"),
                                  ("needkeyupdate","__int8"),
                              ])
                             ]

        creator.createTypes(self.standardTypes)
        creator.createTypes(self.commonTypes)


class Go12Types(GoTypes_l7):

    def __init__(self, creator):
        super(Go12Types, self).__init__(creator)
        self.types = [
            ("type", [
                ("size",       "uintptr"),
                ("hash",       "__int32"),
                ("_unused",    "__int8"),
                ("align",      "__int8"),
                ("fieldAlign", "__int8"),
                ("kind",       "kind"),
                ("alg",        "*void"),
                ("gc",         "void *"),
                ("string",     "*string"),
                ("UncommonType","*int"),
                ("ptrtothis",   "*type"),
            ]),
        ]
        creator.createTypes(self.types)
        creator.createTypes(self.commonTypes)


class Go14Types(GoTypes_l7):

    def __init__(self, creator):
        super(Go14Types, self).__init__(creator)
        self.types = [
           ("type", [
                ("size",        "uintptr"),
                ("hash",        "__int32"),
                ("_unused",     "__int8"),
                ("align",       "__int8"),
                ("fieldAlign",  "__int8"),
                ("kind",        "kind"),
                ("alg",         "*void"),
                ("gcdata",      "void *[2]"),
                ("string",      "*string"),
                ("UncommonType","*uncommonType"),
                ("ptrtothis",   "*type"),
                ("zero",        "void *")
           ]),
        ]
        creator.createTypes(self.types)
        creator.createTypes(self.commonTypes)


class Go15Types(GoTypes_l7):

    def __init__(self, creator):
        super(Go15Types, self).__init__(creator)
        self.types = [
           ("type", [
                ("size",        "uintptr"),
                ("ptrdata",     "uintptr"),
                ("hash",        "__int32"),
                ("_unused",     "__int8"),
                ("align",       "__int8"),
                ("fieldAlign",  "__int8"),
                ("kind",        "kind"),
                ("alg",         "*void"),
                ("gcdata",      "*unsigned char"),
                ("string",      "*string"),
                ("UncommonType","*uncommonType"),
                ("ptrtothis",   "*type"),
                ("zero",        "void *")
           ])
        ]
        creator.createTypes(self.types)
        creator.createTypes(self.commonTypes)


class Go16Types(GoTypes_l7):

    def __init__(self, creator):
        super(Go16Types, self).__init__(creator)
        self.types = [
           ("type", [
                ("size",        "uintptr"),
                ("ptrdata",     "uintptr"),
                ("hash",        "__int32"),
                ("_unused",     "__int8"),
                ("align",       "__int8"),
                ("fieldAlign",  "__int8"),
                ("kind",        "kind"),
                ("alg",         "*void"),
                ("gcdata",      "*unsigned char"),
                ("string",      "*string"),
                ("UncommonType","*uncommonType"),
                ("ptrtothis",   "*type"),
           ])
        ]
        creator.createTypes(self.types)
        creator.createTypes(self.commonTypes)


class TypeProcessing(object):

    def __init__(self, pos, endpos, step, settings):
        self.pos = pos
        self.end = endpos
        self.stepper = step
        self.type_addr = []
        self.settings = settings
        self.kind_types = {
            "CHAN": self.makeChanType,
            "ARRAY": self.makeArrType,
            "SLICE": self.makeSliceType,
            "STRUCT": self.makeStructType,
            "PTR"  : self.makePtrType,
            "INTERFACE": self.makeInterface,
            "FUNC":  self.makeFunc,
            "MAP": self.makeMap,
        }


    def __iter__(self):
        return self

    def __next__(self):
        if self.pos >= self.end:
            raise StopIteration
        value = self.stepper.ptr(self.pos)
        self.pos += self.stepper.size
        return self.handle_offset(value)

    def getDword(self, sid, addr, name):
        name_off = idc.get_member_offset(sid, name)
        return idc.get_wide_dword(addr+name_off)

    def getPtr(self, sid, addr, name):
        name_off = idc.get_member_offset(sid, name)
        return self.stepper.ptr(addr+name_off)

    def getPtrToThis(self, sid, offset):
        return self.getPtr(sid, offset, "ptrtothis")

    def getOffset(self, offset):
        return offset

    def make_arr(self, addr, arr_size, struc_size, type):
        res = idc.make_array(addr, arr_size)
        if res == False:
            ida_bytes.del_items(addr, arr_size*struc_size, ida_bytes.DELIT_SIMPLE)
            idc.SetType(addr, type)
            idc.make_array(addr, arr_size)


    def getName(self, offset):
        sid = ida_struct.get_struc_id("type")
        string_addr = offset + idc.get_member_offset(sid, "string")
        ptr = self.stepper.ptr(string_addr)
        idc.SetType(ptr, "string")
        name = self.stepper.ptr(ptr)
        return idc.GetString(name)

    def getKindEnumName(self, addr):
        struc_id = ida_struct.get_struc_id("type")
        offset_kind = idc.get_member_offset(struc_id, "kind")
        kind = idc.get_wide_byte(addr + offset_kind) & 0x1f
        return self.settings.typer.standardEnums[0][1][kind]


    def handle_offset(self, offset):
        #Check if we already parse this
        if offset in self.type_addr:
            return
        print("Processing: %x" % offset)
        self.type_addr.append(offset)

        #Set type and get name
        idc.SetType(offset, "type")
        name = self.getName(offset)
        idc.set_cmt(offset, name, 0)

        #get kind name
        kind_name = self.getKindEnumName(offset)
        print(kind_name)
        if name[0] == "*" and kind_name != "PTR":
            name = name[1:]
        name = Utils.relaxName(name)
        Utils.rename(offset, name)
        self.betterTypePlease(offset)
        sid = ida_struct.get_struc_id("type")
        addr = self.getPtrToThis(sid, offset)
        if addr != 0:
            addr = self.getOffset(addr)
            self.handle_offset(addr)
        return
        if kind_name != "FUNC":
            self.processUncommon(sid, offset)

    def betterTypePlease(self, offset):
        kind_name = self.getKindEnumName(offset)
        if kind_name in self.kind_types:
            self.kind_types[kind_name](offset)

    def makeChanType(self, offset):
        idc.SetType(offset, "chanType")
        sid = ida_struct.get_struc_id("chanType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)

    def makeSliceType(self, offset):
        idc.SetType(offset, "sliceType")
        sid = ida_struct.get_struc_id("sliceType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)

    def makeArrType(self, offset):
        idc.SetType(offset, "arrayType")
        sid = ida_struct.get_struc_id("arrayType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "slice")
        self.handle_offset(addr)

    def makePtrType(self, offset):
        idc.SetType(offset, "ptrType")
        sid = ida_struct.get_struc_id("ptrType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)

    def makeStructType(self, offset):
        idc.SetType(offset, "structType")
        sid = ida_struct.get_struc_id("structType")
        slice_id = ida_struct.get_struc_id("slice")
        offset_elem = idc.get_member_offset(sid, "fields")
        inner_offset = idc.get_member_offset(slice_id, "data")
        addr = self.stepper.ptr(offset_elem + offset + inner_offset)

        inner_offset = idc.get_member_offset(slice_id, "len")
        size = self.stepper.ptr(offset+offset_elem+inner_offset)
        if size == 0:
            return
        idc.SetType(addr, "structField")
        sz = ida_struct.get_struc_size(ida_struct.get_struc_id("structField"))
        self.make_arr(addr, size, sz, "structField")
        sid_type = ida_struct.get_struc_id("type")
        size_new_struct = self.getPtr(sid_type, offset, "size")
        for i in range(size):
            self.processStructField(addr, i*sz)
        name = self.getName(offset)
        while name[0] == "*":
            name = name[1:]
        name = Utils.relaxName(name)
        name = "ut_" + name
        self.createUserTypeStruct(addr, name, size, size_new_struct)

    def processStructField(self, addr, index):
        offset = addr + index
        sid = ida_struct.get_struc_id("structField")
        ptr = self.getPtr(sid, offset, "Name")
        if ptr != 0:
            idc.SetType(ptr, "string")
            fieldName = idc.GetString(self.stepper.ptr(ptr))
            Utils.rename(ptr, fieldName)
        ptr = self.getPtr(sid, offset, "typ")
        self.handle_offset(ptr)    
         

    def getStructFieldOffset(self, sid, addr):
        return self.getPtr(sid, addr, "offset")
        
    def createUserTypeStruct(self, addr, name, size, self_size):
        fields = []
        sid = ida_struct.get_struc_id("structField")
        sz = ida_struct.get_struc_size(sid)
        sid_type = ida_struct.get_struc_id("type")
        fields = []
        curr_offset = 0
        idc.set_cmt(addr, name, 0)
        for i in range(size):
            fieldname = self.nameFromOffset(self.getPtr(sid, addr+i*sz,"Name"))
            type_addr = self.getPtr(sid, addr+i*sz, "typ")
            typename = self.getType(type_addr)
            size = self.getPtr(sid_type, type_addr, "size")
            if fieldname == "" or fieldname is None:
                fieldname = "unused_"+Utils.id_generator()
            offset = self.getStructFieldOffset(sid, addr+i*sz)
            print(f"Get offset: {offset:x}")
            if offset != curr_offset:
                print("Offset missmatch.Got %d expected %d. Adding padding..." % (curr_offset, offset))
                if offset < curr_offset:
                    raise("Too many bytes already")
                while offset != curr_offset:
                    fields.append(("padding", "char"))
                    curr_offset += 1
            curr_offset += size
            if size != 0:
                offset_kind = idc.get_member_offset(sid_type, "kind")
                kind_of_type = self.getKindEnumName(type_addr)
                print(kind_of_type)
                if kind_of_type == "STRUCT_": #Disabled for now
                    name_type = self.getName(type_addr)
                    while name_type[0] == "*":
                        name_type = name_type[1:]
                    name_type = Utils.relaxName(name_type)
                    name_type = "ut_" + name_type
                    #print("setting type %s" % name_type)
                    fields.append((fieldname, name_type))
                elif kind_of_type == "STRING":
                    fields.append((fieldname, "string"))
                elif kind_of_type == "SLICE":
                    fields.append((fieldname, "slice"))
                elif kind_of_type == "INTERFACE":
                    fields.append((fieldname, "__iface"))
                else:
                    fields.append((fieldname, "char [%d]" % size))
        if curr_offset != self_size:
            print("%x: Structure size mismatch: %x" % (addr, curr_offset))
            if self_size < curr_offset:
                    raise("Too many bytes already")
            while self_size != curr_offset:
                fields.append(("padding", "char"))
                curr_offset += 1    
        new_type = [(name, fields)]
        self.settings.structCreator.createTypes(new_type)
        new_type_sid = ida_struct.get_struc_id(name)
        sz = ida_struct.get_struc_size(new_type_sid)
        if sz != self_size:
            print("%x" % addr   )
            raise("Error at creating structure")
    
    def getType(self, addr):
        print("%x" % addr)
        sid = ida_struct.get_struc_id("type")
        name = self.getName(addr)
        if self.getKindEnumName(addr) != "PTR":
            while name[0] == "*":
                name = name[1:]
        return name

    def makeInterface(self, offset):
        idc.SetType(offset, "interfaceType")
        ifaceid = ida_struct.get_struc_id("interfaceType")
        meth_offs = idc.get_member_offset(ifaceid, "methods")
        slice_id = ida_struct.get_struc_id("slice")
        size_off = idc.get_member_offset(slice_id, "len")
        size = self.stepper.ptr(offset + meth_offs + size_off)
        if size != 0:
            addr = self.getPtr(slice_id, offset + meth_offs, "data")
            idc.SetType(addr, "imethod")
            sz = ida_struct.get_struc_size(ida_struct.get_struc_id("imethod"))
            self.make_arr(addr, size, sz, "imethod")
            names = self.processIMethods(addr, size)
            # For now only for go1.7
            if names is None:
                return
            name = self.getName(offset)
            while name[0] == "*":
                name = name[1:]
            name = Utils.relaxName(name)
            name = "user_interface_" + name
            # TODO: this is for go1.7 need additional check for other versions
            fields = [("inter", "void *"), ("type", "void *"), ("link", "void *"), ("bad", "__int32"),
                      ("unused", "__int32")]
            for i in names:
                fields.append((i, "void *"))
            itype = [(name, fields)]
            self.settings.structCreator.createTypes(itype)

    def processIMethods(self, addr, size):
        return None

    def makeFunc(self, offset):
        idc.SetType(offset, "funcType")
        self.parseFuncType(offset)

    def parseFuncType(self, offset):
        return

    def makeMap(self, offset):
        return  # TODO:fix


class TypeProcessing17(TypeProcessing):

    def __init__(self, pos, endpos, step, settings, base_type):
        super(TypeProcessing17, self).__init__(pos, endpos, step, settings)
        self.robase = base_type

    def __next__(self):
        if self.pos >= self.end:
            raise StopIteration
        value = idc.get_wide_dword(self.pos)
        self.pos += 4
        value = self.getOffset(value)
        return self.handle_offset(value)

    def getOffset(self, offset):
        return self.robase + offset


    def get_str(self, pos, len):
        out = ""
        for i in range(len):
            out += chr(idc.get_wide_byte(pos+i))
        return out

    def getName(self, offset):
        sid = ida_struct.get_struc_id("type")
        name_off = self.getDword(sid, offset, "string")
        string_addr = self.getOffset(name_off) + 3
        ln = idc.get_wide_byte(string_addr-1)
        return self.get_str(string_addr, ln)

    def nameFromOffset(self, offset):
        addr = offset
        return self.get_str(addr + 3, idc.get_wide_byte(addr + 2))

    def getPtrToThis(self, sid, offset):
        memb_offs = idc.get_member_offset(sid, "ptrtothis")
        return idc.get_wide_dword(offset + memb_offs)

    def processStructField(self, addr, index):
        offset = addr + index
        sid = ida_struct.get_struc_id("structField")
        ptr = self.getPtr(sid, offset, "Name")
        ln = idc.get_wide_byte(ptr + 2)
        fieldName = self.get_str(ptr + 3, ln)
        Utils.rename(ptr, fieldName)
        ptr = self.getPtr(sid, offset, "typ")
        self.handle_offset(ptr)

    def processIMethods(self, offst, size):
        sz = ida_struct.get_struc_size(ida_struct.get_struc_id("imethod"))
        comm = []
        for i in range(size):
            comm.append(self.processIMethod(offst + i * sz))
        idc.set_cmt(offst, "\n".join(comm), 0)
        return comm

    def processIMethod(self, offst):
        sid = ida_struct.get_struc_id("imethod")
        name = self.getDword(sid, offst, "name")
        name += self.robase
        name = self.get_str(name + 3, idc.get_wide_byte(name + 2))
        return name

    def processMethods(self, offst):
        sid = ida_struct.get_struc_id("method__")
        name = self.getDword(sid, offst, "name")
        name += self.robase
        name = self.get_str(name + 3, idc.get_wide_byte(name + 2))
        type_meth = self.getDword(sid, offst, "mtyp")
        type_meth_addr1 = self.robase + type_meth
        func_body1 = self.getDword(sid, offst, "ifn")
        func_addr1 = self.text_addr + func_body1
        func_body2 = self.getDword(sid, offst, "tfn")
        func_addr2 = self.text_addr + func_body1
        return "%s %x %x %x" % (name, type_meth_addr1, func_addr1, func_addr2)

    def makeMap(self, offset):
        idc.SetType(offset, "mapType")
        sid = ida_struct.get_struc_id("mapType")
        addr = self.getPtr(sid, offset, "key")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "bucket")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "hmap")
        self.handle_offset(addr)

    def parseFuncType(self, offset):
        return
        sid = ida_struct.get_struc_id("funcType")
        in_size = idc.Word(offset + idc.get_member_offset(sid, "incount"))
        out_size = idc.Word(offset + idc.get_member_offset(sid, "outcount"))
        sz = ida_struct.get_struc_size(sid)
        for i in range(in_size + out_size):
            idc.SetType(offset + sz + i * self.stepper.size, "type *")


class TypeProcessing19(TypeProcessing17):
        
    def __init__(self, pos, endpos, step, settings, base_type):
        super(TypeProcessing19, self).__init__(pos, endpos, step, settings, base_type)
        self.robase = base_type

    def getStructFieldOffset(self, sid, addr):
        return (self.getPtr(sid, addr, "offset") >> 1)

class TypeProcessing116(TypeProcessing19):
        
    def __init__(self, pos, endpos, step, settings, base_type):
        super(TypeProcessing116, self).__init__(pos, endpos, step, settings, base_type)
        self.robase = base_type

    def getStructFieldOffset(self, sid, addr):
        return (self.getPtr(sid, addr, "offset") >> 1)
    
    def makeMap(self, offset):
        idc.SetType(offset, "mapType")
        sid = ida_struct.get_struc_id("mapType")
        addr = self.getPtr(sid, offset, "key")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "bucket")
        self.handle_offset(addr)

class TypeProcessing117(TypeProcessing116):        
    def __init__(self, pos, endpos, step, settings, base_type):
        super(TypeProcessing117, self).__init__(pos, endpos, step, settings, base_type)
        self.robase = base_type
        self.basetypes = dict()
        self.basetypes['BOOL'] = 'unsigned __int8'
        self.basetypes['UINT8'] = 'unsigned __int8'
        self.basetypes['INT8'] = 'signed __int8'
        self.basetypes['UINT16'] = 'unsigned __int16'
        self.basetypes['INT16'] = 'signed __int16'
        self.basetypes['UINT32'] = 'unsigned __int32'
        self.basetypes['INT32'] = 'signed __int32'
        self.basetypes['UINT64'] = 'unsigned __int64'
        self.basetypes['INT64'] = 'signed __int64'
        self.basetypes['UINT'] = 'unsigned __int64'
        self.basetypes['INT'] = 'signed __int64'
        self.basetypes['UINTPTR'] = 'unsigned __int64 *'
        self.basetypes['FLOAT32'] = 'float'
        self.basetypes['FLOAT64'] = 'double'

    def get_str_from_struct(self, ea):
        str_sz = idc.get_wide_byte(ea+1)
        str_ea = ea + 2

        sz, ea = self.get_str_sz(ea)
        return self.get_str(ea, sz)

    @staticmethod
    def get_str_sz(ea):
        print('getting str for {:x}'.format(ea))
        ea += 1
        c = idc.get_wide_byte(ea)
        ea += 1
        numbits = 0
        sz = c & 0x7f
        numbits += 7
        while c & 0x80:
            c = idc.get_wide_byte(ea)
            ea += 1
            sz |= (c & 0x7f) << numbits
            numbits += 7

        return sz, ea
        return self.get_str(ea, sz)


    def makeMap(self, offset):
        idc.SetType(offset, "mapType")
        sid = ida_struct.get_struc_id("mapType")
        addr = self.getPtr(sid, offset, "key")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "bucket")
        self.handle_offset(addr)

    def processStructField(self, addr, index):
        offset = addr + index
        sid = ida_struct.get_struc_id("structField")
        ptr = self.getPtr(sid, offset, "Name")
        ln = idc.get_wide_byte(ptr + 1)
        fieldName = self.get_str(ptr + 2, ln)
        Utils.rename(ptr, fieldName)
        ptr = self.getPtr(sid, offset, "typ")
        self.handle_offset(ptr)        

    def nameFromOffset(self, offset):
        return self.get_str_from_struct(offset)

    def getName(self, offset):
        sid = ida_struct.get_struc_id("type")
        name_off = self.getDword(sid, offset, "string")
        string_addr = self.getOffset(name_off)
        return self.get_str_from_struct(string_addr)

    def processIMethod(self, offst):
        sid = ida_struct.get_struc_id("imethod")
        name = self.getDword(sid, offst, "name")
        name += self.robase
        return self.get_str_from_struct(name)
        
    def makeInterface(self, offset):
        print('creating interface {:x}'.format(offset))
        idc.SetType(offset, "interfaceType")
        ifaceid = ida_struct.get_struc_id("interfaceType")
        meth_offs = idc.get_member_offset(ifaceid, "methods")
        slice_id = ida_struct.get_struc_id("slice")
        size_off = idc.get_member_offset(slice_id, "len")
        size = self.stepper.ptr(offset + meth_offs + size_off)

        name = self.getName(offset)
        while name[0] == "*":
            name = name[1:]
        name = Utils.relaxName(name)
        itab_name = "itab_" + name
        iface_name = 'iface_' + name

        names = []
        if size > 0:
            addr = self.getPtr(slice_id, offset + meth_offs, "data")
            idc.SetType(addr, "imethod")
            sz = ida_struct.get_struc_size(ida_struct.get_struc_id("imethod"))
            self.make_arr(addr, size, sz, "imethod")
            names = self.processIMethods(addr, size)
            if names is None:
                return

        # Reference - #https://github.com/teh-cmc/go-internals/blob/master/chapter2_interfaces/README.md#anatomy-of-an-interface
        itab_fields = [("inter", "void *"), ("type", "void *"), ("hash", "__int32"), 
                    ("unused", "__int32")] 
        for i in names:
            itab_fields.append((i, "void *"))

        itype = [(itab_name, itab_fields)]
        self.settings.structCreator.createTypes(itype)
        iface_fields = [('tab', f'{itab_name} *'), ('data', 'void *')]
        itype = [(iface_name, iface_fields)]
        self.settings.structCreator.createTypes(itype)


    def createUserTypeStruct(self, addr, name, size, self_size):
        print('creating struct {}'.format(name))
        fields = []
        sid = ida_struct.get_struc_id("structField")
        sz = ida_struct.get_struc_size(sid)
        sid_type = ida_struct.get_struc_id("type")
        fields = []
        curr_offset = 0
        idc.set_cmt(addr, name, 0)
        for i in range(size):
            print('field in {:x}'.format(addr+i*sz))
            fieldname = self.nameFromOffset(self.getPtr(sid, addr+i*sz,"Name"))
            type_addr = self.getPtr(sid, addr+i*sz, "typ")
            typename = self.getType(type_addr)
            size = self.getPtr(sid_type, type_addr, "size")
            if fieldname == "" or fieldname is None:
                fieldname = "unused_"+Utils.id_generator()
            offset = self.getStructFieldOffset(sid, addr+i*sz)
            print(f"Get offset: {offset:x}")
            if offset != curr_offset:
                print("Offset missmatch.Got %d expected %d. Adding padding..." % (curr_offset, offset))
                if offset < curr_offset:
                    raise("Too many bytes already")
                while offset != curr_offset:
                    fields.append(("padding", "char"))
                    curr_offset += 1
            curr_offset += size
            print('fieldname = {}'.format(fieldname))
            if size != 0:
                fieldtype = None
                offset_kind = idc.get_member_offset(sid_type, "kind")
                kind_of_type = self.getKindEnumName(type_addr)
                print(kind_of_type)
                if kind_of_type == "STRUCT":
                    name_type = self.getName(type_addr) 
                    while name_type[0] == "*":
                        name_type = name_type[1:]
                    name_type = Utils.relaxName(name_type)
                    name_type = "ut_" + name_type

                    if ida_struct.get_struc_id(name_type) != idc.BADADDR:
                        print("setting type %s" % name_type)
                        fieldtype = name_type

                elif kind_of_type == "STRING":
                    fieldtype = "string"

                elif kind_of_type == "SLICE":
                    fieldtype = "slice"

                elif kind_of_type == "INTERFACE":
                    name_type = self.getName(type_addr)
                    while name_type[0] == "*":
                        name_type = name_type[1:]
                    name_type = Utils.relaxName(name_type)
                    name_type = "iface_" + name_type

                    if ida_struct.get_struc_id(name_type) != idc.BADADDR:
                        fieldtype = name_type

                elif kind_of_type == "CHAN":
                    name_type = 'ut_runtime_hchan'
                    ptr_name_type = f'{name_type} *'

                    if ida_struct.get_struc_id(name_type) != idc.BADADDR:
                        fieldtype = ptr_name_type

                elif kind_of_type == "MAP":
                    name_type = 'ut_runtime_hmap'
                    ptr_name_type = f'{name_type} *'
                    if ida_struct.get_struc_id(name_type) != idc.BADADDR:
                        fieldtype = ptr_name_type

                elif kind_of_type == "FUNC":
                    fieldtype = 'void *'

                elif kind_of_type == "PTR":
                    name_type = self.getName(type_addr)
                    while name_type[0] == "*":
                        name_type = name_type[1:]
                    name_type = Utils.relaxName(name_type)
                    name_type = "ut_" + name_type
                    ptr_name_type = f'{name_type} *'

                    if ida_struct.get_struc_id(name_type) != idc.BADADDR:
                        print("setting ptr type %s" % name_type)
                        fieldtype = ptr_name_type

                elif kind_of_type in self.basetypes:
                    fieldtype = self.basetypes[kind_of_type]

                if fieldtype is None:
                    if size == 1:
                        fieldtype = 'char'
                    else:
                        fieldtype = "char [%d]" % size

                fields.append((fieldname, fieldtype))
                
        if curr_offset != self_size:
            print("%x: Structure size mismatch: %x" % (addr, curr_offset))
            if self_size < curr_offset:
                    raise("Too many bytes already")
            while self_size != curr_offset:
                fields.append(("padding", "char"))
                curr_offset += 1    
        new_type = [(name, fields)]
        self.settings.structCreator.createTypes(new_type)
        new_type_sid = ida_struct.get_struc_id(name)
        sz = ida_struct.get_struc_size(new_type_sid)
        if sz != self_size:
            print("%x" % addr   )
            raise Exception("Error at creating structure {}. {:x}!={:x}, fields={}".format(name, sz, self_size, fields))
