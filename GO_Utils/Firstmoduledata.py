from . import Utils
import idautils
import struct

def findFirstModuleData(addr, bt):
	# print(f"{addr:x}")
	possible_addr = [x for x in idautils.XrefsTo(addr)]
	for p_a in possible_addr:
		# print(f"Checking addr: {p_a}")
		if Utils.is_hardcoded_slice(p_a.frm, bt):
			return p_a.frm
		elif Utils.is_hardcoded_slice(p_a.frm+bt.size, bt):
			return p_a.frm
	return None

def isGo17(addr, bt):
    addr += bt.size * 27
    addr2 = addr + bt.size * 6 # for go1.7 this addr will be for modulename 
    return Utils.is_hardcoded_slice(addr, bt) and (not Utils.is_hardcoded_slice(addr2, bt))


def isGo18_10(addr, bt):
    addr += bt.size * 27
    addr2 = addr + bt.size * 6 # for go1.8 this addr will be for itablinks 
    return Utils.is_hardcoded_slice(addr, bt) and (Utils.is_hardcoded_slice(addr2, bt))

def isGo116(addr, bt):
    addr += bt.size * 1
    # addr2 = addr + bt.size * 6 # for go1.8 this addr will be for itablinks 
    return Utils.is_hardcoded_slice(addr, bt)

def getTypeinfo17(addr, bt):
    addr2 = addr + bt.size * 25
    robase = bt.ptr(addr2)
    addr += bt.size * 27
    beg = bt.ptr(addr)
    size = bt.ptr(addr+bt.size)
    return beg, beg+size*4, robase


def getTypeinfo18(addr, bt):
    addr2 = addr + bt.size * 25
    robase = bt.ptr(addr2)
    addr += bt.size * 30
    beg = bt.ptr(addr)
    size = bt.ptr(addr+bt.size)
    return beg, beg+size*4, robase

def getTypeinfo116(addr, bt):
    addr2 = addr + bt.size * 35
    robase = bt.ptr(addr2)
    addr += bt.size * 40
    beg = bt.ptr(addr)
    size = bt.ptr(addr+bt.size)
    print(robase)
    return beg, beg+size*4, robase

def getTypeinfo(addr, bt):
    addr += bt.size * 25
    beg = bt.ptr(addr)
    size = bt.ptr(addr+bt.size)

    return beg, beg+size*bt.size

"""
1.16
type moduledata struct {
0	pcHeader     *pcHeader
1	funcnametab  []byte
4	cutab        []uint32
7	filetab      []byte
10	pctab        []byte
13	pclntable    []byte
16	ftab         []functab
19	findfunctab  uintptr
20	minpc, maxpc uintptr

22	text, etext           uintptr
24	noptrdata, enoptrdata uintptr
26	data, edata           uintptr
28	bss, ebss             uintptr
30	noptrbss, enoptrbss   uintptr
32	end, gcdata, gcbss    uintptr
35	types, etypes         uintptr

37	textsectmap []textsect
40	typelinks   []int32 // offsets from types
	itablinks   []*itab

	ptab []ptabEntry

	pluginpath string
	pkghashes  []modulehash

	modulename   string
	modulehashes []modulehash

	hasmain uint8 // 1 if module contains the main function, 0 otherwise

	gcdatamask, gcbssmask bitvector

	typemap map[typeOff]*_type // offset to *_rtype in previous module

	bad bool // module failed to load and should be ignored

	next *moduledata
}
1.10 - same as 1.10
1.9 - same as 1.8
1.8
type moduledata struct {
3	pclntable    []byte
6	ftab         []functab
9	filetab      []uint32

10	findfunctab  uintptr
12	minpc, maxpc uintptr
14	text, etext           uintptr
16	noptrdata, enoptrdata uintptr
18	data, edata           uintptr
20	bss, ebss             uintptr
22	noptrbss, enoptrbss   uintptr
25	end, gcdata, gcbss    uintptr
27	types, etypes         uintptr
30	textsectmap []textsect
	typelinks   []int32 // offsets from types
	itablinks   []*itab
	ptab []ptabEntry
	pluginpath string
	pkghashes  []modulehash
	modulename   string
	modulehashes []modulehash
	gcdatamask, gcbssmask bitvector
	typemap map[typeOff]*_type // offset to *_rtype in previous module
	next *moduledata
}

1.7
type moduledata struct {
3	pclntable    []byte
6	ftab         []functab
9	filetab      []uint32
10	findfunctab  uintptr
12	minpc, maxpc uintptr

14	text, etext           uintptr
16	noptrdata, enoptrdata uintptr
18	data, edata           uintptr
20	bss, ebss             uintptr
22	noptrbss, enoptrbss   uintptr
25	end, gcdata, gcbss    uintptr
27	types, etypes         uintptr

	typelinks []int32 // offsets from types
	itablinks []*itab

	modulename   string
	modulehashes []modulehash

	gcdatamask, gcbssmask bitvector

	typemap map[typeOff]*_type // offset to *_rtype in previous module

	next *moduledata
}
"""

"""1.6
type moduledata struct {
3	pclntable    []byte
6	ftab         []functab
9	filetab      []uint32
10	findfunctab  uintptr
12	minpc, maxpc uintptr

14	text, etext           uintptr
16	noptrdata, enoptrdata uintptr
18	data, edata           uintptr
20	bss, ebss             uintptr
22	noptrbss, enoptrbss   uintptr
25	end, gcdata, gcbss    uintptr

	typelinks []*_type

	modulename   string
	modulehashes []modulehash

	gcdatamask, gcbssmask bitvector

	next *moduledata
}
"""
"""1.5
type moduledata struct {
3	pclntable    []byte
6	ftab         []functab
9	filetab      []uint32
10	findfunctab  uintptr
12	minpc, maxpc uintptr

14	text, etext           uintptr
16	noptrdata, enoptrdata uintptr
18	data, edata           uintptr
20	bss, ebss             uintptr
22	noptrbss, enoptrbss   uintptr
25	end, gcdata, gcbss    uintptr

	typelinks []*_type

	modulename   string
	modulehashes []modulehash

	gcdatamask, gcbssmask bitvector

	next *moduledata
}
"""