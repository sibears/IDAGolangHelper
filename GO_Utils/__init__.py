import idaapi
from . import Gopclntab
from . import Utils
from . import Firstmoduledata
from . import Types
import idc
import idautils
import ida_ida
import ida_search

class GoSettings(object):


    def __init__(self):
        self.storage = {}
        self.bt_obj = Utils.get_bitness(ida_ida.inf_get_min_ea())
        self.structCreator = Utils.StructCreator(self.bt_obj)
        self.processor = None
        self.typer = None
        self.is116 = False

    def getVal(self, key):
        if key in self.storage:
            return self.storage[key]
        return None

    def setVal(self, key, val):
        self.storage[key] = val

    def getGopcln(self):
        gopcln_addr = self.getVal("gopcln")
        if gopcln_addr is None:
            gopcln_addr = Gopclntab.findGoPcLn()
            print("Saving gopclntab entry")
            self.setVal("gopcln", gopcln_addr)
        return gopcln_addr

    def findModuleData(self):
        gopcln_addr = self.getGopcln()
        if gopcln_addr is not None:
            fmd = Firstmoduledata.findFirstModuleData(gopcln_addr, self.bt_obj)
            self.setVal("firstModData", fmd)
        return

    def tryFindGoVersion(self):
        fmd = self.getVal("firstModData")
        if fmd is None:
            return "This should be go <= 1.4 : No module data found"
        vers = "go1.5 or go1.6"
        if Firstmoduledata.isGo17(fmd, self.bt_obj) is True:
            vers = "go1.7"
        elif Firstmoduledata.isGo18_10(fmd, self.bt_obj) is True:
            vers = "go1.8 or go1.9 or go1.10"
        elif Firstmoduledata.isGo116(fmd, self.bt_obj) is True:
            vers = "go1.16"
            self.is116 = True
        return "According to moduleData struct is should be %s" % (vers)

    def renameFunctions(self):
        gopcln_tab = self.getGopcln()
        if self.is116:
            Gopclntab.rename16(gopcln_tab, self.bt_obj)
        else:
            Gopclntab.rename(gopcln_tab, self.bt_obj)

    def getVersionByString(self):
        # pos = idautils.Functions().next()
        end_ea = idc.get_segm_end(0)
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 31 36", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.16'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 31 33", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.13'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 31 32", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.12'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 31 31", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.11'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 31 30", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.10'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 39", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.9'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 38", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.8'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 37", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.7'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 36", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.6'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 35", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.5'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 34", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.4'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 33", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.3'
        if ida_search.find_binary(0, end_ea, "67 6f 31 2e 32", 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return 'Go 1.2'

    def createTyper(self, typ):
        if typ == 0:
            self.typer = Types.Go12Types(self.structCreator)
        elif typ == 1:
            self.typer = Types.Go14Types(self.structCreator)
        elif typ == 2:
            self.typer = Types.Go15Types(self.structCreator)
        elif typ == 3:
            self.typer = Types.Go16Types(self.structCreator)
        elif typ == 4 or typ == 5:
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 6: #1.9
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 7: #1.10
            self.typer = Types.Go17Types(self.structCreator)
        elif typ == 8: #1.16
            self.typer = Types.Go116Types(self.structCreator)
        elif typ == 9: #1.17
            self.typer = Types.Go117Types(self.structCreator)

    def typesModuleData(self, typ):
        if typ < 2:
            return
        if self.getVal("firstModData") is None:
            self.findModuleData()
        fmd = self.getVal("firstModData")
        if fmd is None:
            return
        if self.typer is None:
            self.createTyper(typ)
        robase = None
        if typ == 4:
            beg, end, robase = Firstmoduledata.getTypeinfo17(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing17(beg, end, self.bt_obj, self, robase)
        elif typ == 5:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing17(beg, end, self.bt_obj, self, robase)
        elif typ == 6:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing19(beg, end, self.bt_obj, self, robase)
        elif typ == 7:
            beg, end, robase = Firstmoduledata.getTypeinfo18(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing19(beg, end, self.bt_obj, self, robase)
        elif typ == 8:
            beg, end, robase = Firstmoduledata.getTypeinfo116(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing116(beg, end, self.bt_obj, self, robase)
        elif typ == 9:
            beg, end, robase = Firstmoduledata.getTypeinfo117(fmd, self.bt_obj)
            self.typer.update_robase(robase)
            self.processor = Types.TypeProcessing117(beg, end, self.bt_obj, self, robase)            
        else:
            beg, end = Firstmoduledata.getTypeinfo(fmd, self.bt_obj)
            self.processor = Types.TypeProcessing(beg, end, self.bt_obj, self)
        print("%x %x %x" % (beg, end, robase))
        for i in self.processor:
            pass
        return