# coding=utf-8
# 请以管理员启动
import kar98k
from capstone import *







class Test:
    def __init__(self, procName, modName):
        self.procName = procName
        self.objProcess = kar98k.kar98k(procName)
        self.objProcess.list_mem_info()
        self.objProcess.print_process_meminfo()
        self.objProcess.print_impinfo_by_module(modName)


    def __del__(self):
        print('python 对象<%s> 已释放...' %self.procName)


    def test_get_mem(self):
        value1 = self.objProcess.get_uint8(0x77420000)
        value2= self.objProcess.get_uint16(0x77420000)
        value3 = self.objProcess.get_uint32(0x77420000)
        value4 = self.objProcess.get_uint64(0x77420000)
        value4 = self.objProcess.get_uint64(1)
        value4 = self.objProcess.get_uint64(0)
        tMem1 = self.objProcess.get_tpmem_by_region(0x77420000,0x1000,1)
        tMem2 = self.objProcess.get_tpmem_by_region(0x77420000,0x1000,2)
        tMem4 = self.objProcess.get_tpmem_by_region(0x77420000,0x1000,4)
        tMem8 = self.objProcess.get_tpmem_by_region(0x77420000,0x1000,8)
        tMem8 = self.objProcess.get_tpmem_by_region(1,0,8)
        tMem8 = self.objProcess.get_tpmem_by_region(0,0,8)
        tModMem1 = self.objProcess.get_tpmem_by_module("ntdll.dll",1)
        tModMem2 = self.objProcess.get_tpmem_by_module("ntdll.dll",2)
        tModMem4 = self.objProcess.get_tpmem_by_module("ntdll.dll",4)
        tModMem8 = self.objProcess.get_tpmem_by_module("ntdll.dll",8)
        tModMem8 = self.objProcess.get_tpmem_by_module("ntd.dll",8)

    def test_write_mem(self):
        nAddress = 0x77281000
        self.objProcess.write_uint8(nAddress, 0x11)
        self.objProcess.write_uint16(nAddress, 0x1122)
        self.objProcess.write_uint32(nAddress, 0x11223344)
        self.objProcess.write_uint64(nAddress, 0x1122334455667788)
        binBuffer = b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\xff'
        self.objProcess.write_buffer(nAddress,binBuffer)


    def test_advanced_things(self):
        self.objProcess.inject_dll("C:\\Dll1.dll")
        shellcode = b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3'
        self.objProcess.execute_shell_code(shellcode)
        
    def test_mod_info(self):
        vecMod = self.objProcess.get_mod_info()
        vecModSize = self.objProcess.get_mod_info_size()
        modPath = vecMod[0].modPath
        modName = vecMod[0].modName
        dwSize = vecMod[0].tagModEntry.dwSize
        th32ModuleID = vecMod[0].tagModEntry.th32ModuleID
        th32ProcessI = vecMod[0].tagModEntry.th32ProcessID
        GlblcntUsage = vecMod[0].tagModEntry.GlblcntUsage
        ProccntUsage = vecMod[0].tagModEntry.ProccntUsage
        modBaseSize = vecMod[0].tagModEntry.modBaseSize
        szModule = vecMod[0].tagModEntry.szModule
        hModule = vecMod[0].tagModEntry.hModule
        modBaseAddr = vecMod[0].tagModEntry.modBaseAddr
        tagModEntry = vecMod[0].tagModEntry


    def test_mem_info(self):
        vecMem = self.objProcess.get_mem_info()
        vecMemSize = self.objProcess.get_mem_info_size()
        memBasicInfo = vecMem[0].memBasicInfo
        memInModPath = vecMem[0].memInModPath
        BaseAddress = vecMem[0].memBasicInfo.BaseAddress
        AllocationBase = vecMem[0].memBasicInfo.AllocationBase
        AllocationProtect = vecMem[0].memBasicInfo.AllocationProtect
        RegionSize = vecMem[0].memBasicInfo.RegionSize
        State = vecMem[0].memBasicInfo.State
        Protect = vecMem[0].memBasicInfo.Protect
        Type = vecMem[0].memBasicInfo.Type

    def test_dis(self):
        #CODE = self.objProcess.get_binmem_by_region(0x77901000,0x1000)
        CODE = self.objProcess.get_binmem_by_module("ntdll.dll")
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(CODE, 0x1000):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        pass


def test_x32dbg():
    x32dbg = Test("x32dbg.exe","x32dbg.exe")
    x32dbg.test_dis()
    x32dbg.test_get_mem()
    x32dbg.test_mem_info()
    x32dbg.test_mod_info()
    x32dbg.test_write_mem()
    x32dbg.test_advanced_things()


def test_other():
    other = Test("MFCApplication2 - 副本.exe","ntdll.dll")
    other.test_get_mem()
    other.test_mem_info()
    other.test_mod_info()
    other.test_write_mem()


if __name__ == "__main__":
    test_x32dbg()
    test_other()
    pass