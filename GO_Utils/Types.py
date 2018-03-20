import Utils
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

    def next(self):
        if self.pos >= self.end:
            raise StopIteration
        value = self.stepper.ptr(self.pos)
        self.pos += self.stepper.size
        return self.handle_offset(value)

    def getDword(self, sid, addr, name):
        name_off = idc.GetMemberOffset(sid, name)
        return idc.Dword(addr+name_off)

    def getPtr(self, sid, addr, name):
        name_off = idc.GetMemberOffset(sid, name)
        return self.stepper.ptr(addr+name_off)

    def getPtrToThis(self, sid, offset):
        return self.getPtr(sid, offset, "ptrtothis")

    def getOffset(self, offset):
        return offset

    def make_arr(self, addr, arr_size, struc_size, type):
        res = idc.MakeArray(addr, arr_size)
        if res == False:
            idc.MakeUnknown(addr, arr_size*struc_size, idc.DOUNK_SIMPLE)
            idc.SetType(addr, type)
            idc.MakeArray(addr, arr_size)


    def getName(self, offset):
        sid = idc.GetStrucIdByName("type")
        string_addr = offset + idc.GetMemberOffset(sid, "string")
        ptr = self.stepper.ptr(string_addr)
        idc.SetType(ptr, "string")
        name = self.stepper.ptr(ptr)
        return idc.GetString(name)

    def getKindEnumName(self, addr):
        struc_id = idc.GetStrucIdByName("type")
        offset_kind = idc.GetMemberOffset(struc_id, "kind")
        kind = idc.Byte(addr + offset_kind) & 0x1f
        return self.settings.typer.standardEnums[0][1][kind]


    def handle_offset(self, offset):
        #Check if we already parse this
        if offset in self.type_addr:
            return
        print "Processing: %x" % offset
        self.type_addr.append(offset)

        #Set type and get name
        idc.SetType(offset, "type")
        name = self.getName(offset)
        idc.MakeComm(offset, name)

        #get kind name
        kind_name = self.getKindEnumName(offset)
        print kind_name
        if name[0] == "*" and kind_name != "PTR":
            name = name[1:]
        name = Utils.relaxName(name)
        Utils.rename(offset, name)
        self.betterTypePlease(offset)
        sid = idc.GetStrucIdByName("type")
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
        sid = idc.GetStrucIdByName("chanType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)

    def makeSliceType(self, offset):
        idc.SetType(offset, "sliceType")
        sid = idc.GetStrucIdByName("sliceType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)

    def makeArrType(self, offset):
        idc.SetType(offset, "arrayType")
        sid = idc.GetStrucIdByName("arrayType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)
        addr = self.getPtr(sid, offset, "slice")
        self.handle_offset(addr)

    def makePtrType(self, offset):
        idc.SetType(offset, "ptrType")
        sid = idc.GetStrucIdByName("ptrType")
        addr = self.getPtr(sid, offset, "elem")
        self.handle_offset(addr)

    def makeStructType(self, offset):
        idc.SetType(offset, "structType")
        sid = idc.GetStrucIdByName("structType")
        slice_id = idc.GetStrucIdByName("slice")
        offset_elem = idc.GetMemberOffset(sid, "fields")
        inner_offset = idc.GetMemberOffset(slice_id, "data")
        addr = self.stepper.ptr(offset_elem + offset + inner_offset)

        inner_offset = idc.GetMemberOffset(slice_id, "len")
        size = self.stepper.ptr(offset+offset_elem+inner_offset)
        if size == 0:
            return
        idc.SetType(addr, "structField")
        sz = idc.GetStrucSize(idc.GetStrucIdByName("structField"))
        self.make_arr(addr, size, sz, "structField")
        sid_type = idc.GetStrucIdByName("type")
        size_new_struct = self.getPtr(sid_type, offset, "size")
        for i in xrange(size):
            self.processStructField(addr, i*sz)
        name = self.getName(offset)
        name = Utils.relaxName(name)
        name = "ut_" + name
        self.createUserTypeStruct(addr, name, size, size_new_struct)

    def processStructField(self, addr, index):
        offset = addr + index
        sid = idc.GetStrucIdByName("structField")
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
        sid = idc.GetStrucIdByName("structField")
        sz = idc.GetStrucSize(sid)
        sid_type = idc.GetStrucIdByName("type")
        fields = []
        curr_offset = 0
        idc.MakeComm(addr, name)
        for i in xrange(size):
            fieldname = self.nameFromOffset(self.getPtr(sid, addr+i*sz,"Name"))
            type_addr = self.getPtr(sid, addr+i*sz, "typ")
            typename = self.getType(type_addr)
            size = self.getPtr(sid_type, type_addr, "size")
            if fieldname == "" or fieldname is None:
                fieldname = "unused_"+Utils.id_generator()
            offset = self.getStructFieldOffset(sid, addr+i*sz)
            if offset != curr_offset:
                print "Offset missmatch.Got %d expected %d. Adding padding..." % (curr_offset, offset)
                if offset < curr_offset:
                    raise("Too many bytes already")
                while offset != curr_offset:
                    fields.append(("padding", "char"))
                    curr_offset += 1
            curr_offset += size
            if size != 0:
                offset_kind = idc.GetMemberOffset(sid_type, "kind")
                kind_of_type = self.getKindEnumName(type_addr)
                print kind_of_type
                if kind_of_type == "STRUCT_": #Disabled for now
                    name_type = self.getName(type_addr)
                    while name_type[0] == "*":
                        name_type = name_type[1:]
                    name_type = Utils.relaxName(name_type)
                    name_type = "ut_" + name_type
                    #print "setting type %s" % name_type
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
            print "%x: Structure size mismatch: %x" % (addr, curr_offset)
            if self_size < curr_offset:
                    raise("Too many bytes already")
            while self_size != curr_offset:
                fields.append(("padding", "char"))
                curr_offset += 1    
        new_type = [(name, fields)]
        self.settings.structCreator.createTypes(new_type)
        new_type_sid = idc.GetStrucIdByName(name)
        sz = idc.GetStrucSize(new_type_sid)
        if sz != self_size:
            print "%x" % addr   
            raise("Error at creating structure")
    
    def getType(self, addr):
        print "%x" % addr
        sid = idc.GetStrucIdByName("type")
        name = self.getName(addr)
        if self.getKindEnumName(addr) != "PTR":
            while name[0] == "*":
                name = name[1:]
        return name

    def makeInterface(self, offset):
        idc.SetType(offset, "interfaceType")
        ifaceid = idc.GetStrucIdByName("interfaceType")
        meth_offs = idc.GetMemberOffset(ifaceid, "methods")
        slice_id = idc.GetStrucIdByName("slice")
        size_off = idc.GetMemberOffset(slice_id, "len")
        size = self.stepper.ptr(offset + meth_offs + size_off)
        if size != 0:
            addr = self.getPtr(slice_id, offset + meth_offs, "data")
            idc.SetType(addr, "imethod")
            sz = idc.GetStrucSize(idc.GetStrucIdByName("imethod"))
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

    def next(self):
        if self.pos >= self.end:
            raise StopIteration
        value = idc.Dword(self.pos)
        self.pos += 4
        value = self.getOffset(value)
        return self.handle_offset(value)

    def getOffset(self, offset):
        return self.robase + offset


    def get_str(self, pos, len):
        out = ""
        for i in xrange(len):
            out += chr(idc.Byte(pos+i))
        return out

    def getName(self, offset):
        sid = idc.GetStrucIdByName("type")
        name_off = self.getDword(sid, offset, "string")
        string_addr = self.getOffset(name_off) + 3
        ln = idc.Byte(string_addr-1)
        return self.get_str(string_addr, ln)

    def nameFromOffset(self, offset):
        addr = offset
        return self.get_str(addr + 3, idc.Byte(addr + 2))

    def getPtrToThis(self, sid, offset):
        memb_offs = idc.GetMemberOffset(sid, "ptrtothis")
        return idc.Dword(offset + memb_offs)

    def processStructField(self, addr, index):
        offset = addr + index
        sid = idc.GetStrucIdByName("structField")
        ptr = self.getPtr(sid, offset, "Name")
        ln = idc.Byte(ptr + 2)
        fieldName = self.get_str(ptr + 3, ln)
        Utils.rename(ptr, fieldName)
        ptr = self.getPtr(sid, offset, "typ")
        self.handle_offset(ptr)

    def processIMethods(self, offst, size):
        sz = idc.GetStrucSize(idc.GetStrucIdByName("imethod"))
        comm = []
        for i in xrange(size):
            comm.append(self.processIMethod(offst + i * sz))
        idc.MakeComm(offst, "\n".join(comm))
        return comm

    def processIMethod(self, offst):
        sid = idc.GetStrucIdByName("imethod")
        name = self.getDword(sid, offst, "name")
        name += self.robase
        name = self.get_str(name + 3, idc.Byte(name + 2))
        return name

    def processMethods(self, offst):
        sid = idc.GetStrucIdByName("method__")
        name = self.getDword(sid, offst, "name")
        name += self.robase
        name = self.get_str(name + 3, idc.Byte(name + 2))
        type_meth = self.getDword(sid, offst, "mtyp")
        type_meth_addr1 = self.robase + type_meth
        func_body1 = self.getDword(sid, offst, "ifn")
        func_addr1 = self.text_addr + func_body1
        func_body2 = self.getDword(sid, offst, "tfn")
        func_addr2 = self.text_addr + func_body1
        return "%s %x %x %x" % (name, type_meth_addr1, func_addr1, func_addr2)

    def makeMap(self, offset):
        idc.SetType(offset, "mapType")
        sid = idc.GetStrucIdByName("mapType")
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
        sid = idc.GetStrucIdByName("funcType")
        in_size = idc.Word(offset + idc.GetMemberOffset(sid, "incount"))
        out_size = idc.Word(offset + idc.GetMemberOffset(sid, "outcount"))
        sz = idc.GetStrucSize(sid)
        for i in xrange(in_size + out_size):
            idc.SetType(offset + sz + i * self.stepper.size, "type *")


class TypeProcessing19(TypeProcessing17):
        
    def __init__(self, pos, endpos, step, settings, base_type):
        super(TypeProcessing19, self).__init__(pos, endpos, step, settings, base_type)
        self.robase = base_type

    def getStructFieldOffset(self, sid, addr):
        return (self.getPtr(sid, addr, "offset") >> 1)