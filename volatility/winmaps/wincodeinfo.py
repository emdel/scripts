#
# This script extracts useful information
# about the memory ranges in the process 
# address space. 
# Windows version for /proc/PID/maps
#
# N.B.: It's based on VAD and as @iMHLv2 pointed me out:
# "the VAD shows the initial protection, not the current protection."
#
# emdel - 26/03/2014
#


#
# http://code.google.com/p/volatility/wiki/BasicUsage21#Using_Volatility_as_a_Library 
# Javaid et al - Atomizer: Fast, Scalable and Lightweight Heap Analyzer for Virtual Machines in a Cloud Environment
#
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.plugins.taskmods as taskmods
import volatility.plugins.vadinfo as vadinfo
import sys


TEXT_TAG = ".text"
HEAP_TAG = "[heap]"
STACK_TAG = "[stack]"


def filter_by_name(processes, name):
    for p in processes.calculate():
        if name in str(p.ImageFileName):
            return p


def get_text_section_info(eprocess):
    target_as = eprocess.get_process_address_space()
    imagebase = eprocess.Peb.ImageBaseAddress
    # let's parse it - Volatility has its own 'pefile' :)
    # More info at: volatility/plugins/overlays/windows/pe_vtypes.py
    dos_header = obj.Object('_IMAGE_DOS_HEADER', offset = imagebase, vm = target_as)
    nt_header = dos_header.get_nt_header()
    sections = nt_header.get_sections(False) # unsafe boolean value
    # _IMAGE_SECTION_HEADER realm :)
    found = 0
    for s in sections:
        if str(s.Name) == '.text':
            found = 1
            return imagebase, s.VirtualAddress, s.SizeOfRawData
    if found == 0:
        return None, None, None


def get_dll_info(eprocess): 
    # have a look at: volatility/plugins/taskmods.py
    modules = {}
    for m in eprocess.get_load_modules():
        if m.FullDllName not in modules:
            modules[str(m.FullDllName)] = []
            modules[str(m.FullDllName)].append(m.DllBase)
            modules[str(m.FullDllName)].append(m.SizeOfImage)
    return modules


#
# References: 
# - Marko Thure heap plugin - http://code.google.com/p/volatility/issues/attachmentText?id=149&aid=1490011000&name=heap.py&token=11a90847185e0c716aa76a6bf7638f9d
# - Chris Valasek and Tarjei Mandt - Windows 8 Heap Internals http://illmatics.com/Windows%208%20Heap%20Internals.pdf
# - Leviathan Security Post - http://www.leviathansecurity.com/blog/understanding-the-windows-allocator-a-redux/
#
def get_heap_info(eprocess):
    target_as = eprocess.get_process_address_space()
    heap_cnt = eprocess.Peb.NumberOfHeaps.v()
    heaps = obj.Object("Array", targetType = "Pointer", count = heap_cnt, vm = target_as, offset = eprocess.Peb.ProcessHeaps)
    cnt = 0
    hs = [] 
    for h in heaps:
        cnt += 1
        heap = obj.Object('_HEAP', offset = h, vm = target_as)
        hs.append(heap)
    
    return hs

#
# References:
# - Carl Pulley - https://github.com/carlpulley/volatility/blob/master/exportstack.py
#  
def get_stack_info(eprocess):
    target_as = eprocess.get_process_address_space()
    tebs = []
    for t in eprocess.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
        teb = obj.Object('_TEB', offset = t.Tcb.Teb.v(), vm = target_as)
        tebs.append(teb)
    
    return tebs


def get_vad_protect_flags(eprocess, start, end):
    end -= 1 
    for vad in eprocess.VadRoot.traverse():
        if vad:
            if start >= vad.Start and end <= vad.End:
                return vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v())


def main():
    if len(sys.argv) != 4:
        print "Usage: %s %s %s %s" % (sys.argv[0], "profile", "memdump", "targetprocname")
        sys.exit(1)

    registry.PluginImporter()
    config = conf.ConfObject()

    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)
    config.parse_options()
    
    config.PROFILE = sys.argv[1] 
    config.LOCATION = sys.argv[2]

    processes = taskmods.PSList(config)
    
    target = filter_by_name(processes, sys.argv[3])
     
    # .text info
    imagebase, va, rawsize = get_text_section_info(target)
    
    if imagebase == None:
        print "[-] Error: probably wrong .text section name"
        sys.exit(1)
    
    text_start = imagebase + va
    text_end = imagebase + va + rawsize
    permissions = get_vad_protect_flags(target, text_start, text_end)
    print "0x%x-0x%x %s %s" % (text_start, text_end, permissions, TEXT_TAG)

    # dll info
    modules = get_dll_info(target)

    # printing dll info
    for name, info in modules.items():
        dll_start = info[0]
        dll_end = info[0] + info[1]
        permissions = get_vad_protect_flags(target, dll_start, dll_end)
        print "0x%x-0x%x %s %s" % (dll_start, dll_end, permissions, name)
    
    # heap info
    hs = get_heap_info(target)
    
    # printing heap info
    for h in hs:
        heap_start = h.BaseAddress.v()
        heap_end = h.LastValidEntry.v()
        permissions = get_vad_protect_flags(target, heap_start, heap_end)
        print "0x%x-0x%x %s %s" % (h.BaseAddress, h.LastValidEntry, permissions, HEAP_TAG)

    # stack info
    tebs = get_stack_info(target)
    
    # printing stack info
    for t in tebs:
        stack_start = t.NtTib.StackBase.v()
        stack_end = t.NtTib.StackLimit.v()
        permissions = get_vad_protect_flags(target, stack_start, stack_end)
        print "0x%x-0x%x %s %s" % (stack_start, stack_end, permissions, STACK_TAG)


main()
