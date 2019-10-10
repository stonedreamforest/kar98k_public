# coding=utf-8
# 请以管理员启动
import kar98k
from capstone import *



PAGE_NOACCESS 	= 0x01    
PAGE_READONLY 	= 0x02    
PAGE_READWRITE	= 0x04    
PAGE_WRITECOPY	= 0x08    
PAGE_EXECUTE  	= 0x10    
PAGE_EXECUTE_READ = 0x20    
PAGE_EXECUTE_READWRITE = 0x40    
PAGE_EXECUTE_WRITECOPY = 0x80    
PAGE_GUARD        = 0x100    
PAGE_NOCACHE      = 0x200    
PAGE_WRITECOMBINE = 0x400    
PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000  
PAGE_REVERT_TO_FILE_MAP     = 0x80000000  
PAGE_TARGETS_NO_UPDATE      = 0x40000000  
PAGE_TARGETS_INVALID        = 0x40000000  
PAGE_ENCLAVE_UNVALIDATED    = 0x20000000  
PAGE_ENCLAVE_DECOMMIT       = 0x10000000  
MEM_COMMIT                     = 0x00001000  
MEM_RESERVE                    = 0x00002000  
MEM_REPLACE_PLACEHOLDER        = 0x00004000  
MEM_RESERVE_PLACEHOLDER        = 0x00040000  
MEM_RESET                      = 0x00080000  
MEM_TOP_DOWN                   = 0x00100000  
MEM_WRITE_WATCH                = 0x00200000  
MEM_PHYSICAL                   = 0x00400000  
MEM_ROTATE                     = 0x00800000  
MEM_DIFFERENT_IMAGE_BASE_OK    = 0x00800000  
MEM_RESET_UNDO                 = 0x01000000  
MEM_LARGE_PAGES                = 0x20000000  
MEM_4MB_PAGES                  = 0x80000000  
MEM_64K_PAGES                  = (MEM_LARGE_PAGES | MEM_PHYSICAL)  
MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001  
MEM_COALESCE_PLACEHOLDERS      = 0x00000001  
MEM_PRESERVE_PLACEHOLDER       = 0x00000002  
MEM_DECOMMIT                   = 0x00004000  
MEM_RELEASE                    = 0x00008000  
MEM_FREE                       = 0x00010000  
MEM_PRIVATE = 0x00020000  
MEM_MAPPED  = 0x00040000  
MEM_IMAGE   = 0x01000000  





class Test:
    def __init__(self, procName, modName):
        self.procName = procName
        self.modName = modName
        self.user32BaseAddr = 0
        self.objProcess = kar98k.kar98k(procName)

    def __del__(self):
        print('python 对象<%s> 已释放...' %self.procName)


    def test_get_mem(self):
        nAddress = self.user32BaseAddr + 0x1000
        value1 = self.objProcess.get_uint8(nAddress)
        value2= self.objProcess.get_uint16(nAddress)
        value3 = self.objProcess.get_uint32(nAddress)
        value4 = self.objProcess.get_uint64(nAddress)
        value4 = self.objProcess.get_uint64(1)
        value4 = self.objProcess.get_uint64(0)
        tMem1 = self.objProcess.get_tpmem_by_region(nAddress,0x1000,1)
        tMem2 = self.objProcess.get_tpmem_by_region(nAddress,0x1000,2)
        tMem4 = self.objProcess.get_tpmem_by_region(nAddress,0x1000,4)
        tMem8 = self.objProcess.get_tpmem_by_region(nAddress,0x1000,8)
        tMem8 = self.objProcess.get_tpmem_by_region(1,0,8)
        tMem8 = self.objProcess.get_tpmem_by_region(0,0,8)
        tModMem1 = self.objProcess.get_tpmem_by_module("ntdll.dll",1)
        tModMem2 = self.objProcess.get_tpmem_by_module("ntdll.dll",2)
        tModMem4 = self.objProcess.get_tpmem_by_module("ntdll.dll",4)
        tModMem8 = self.objProcess.get_tpmem_by_module("ntdll.dll",8)
        tModMem8 = self.objProcess.get_tpmem_by_module("ntd.dll",8)

    def test_write_mem(self):
        nAddress = self.user32BaseAddr + 0x1000
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
    
    # 进程所有模块信息
    def test_mod_info(self):
        vecMod = self.objProcess.get_mod_info()
        vecModInfoSize = self.objProcess.get_mod_info_size()
        print("szModule\t\t th32ProcessID\t\t th32ModuleID\t\t hModule\t\t \
            dwSize\t\t modBaseAddr\t\t modBaseSize\t\t \
            GlblcntUsage\t\t ProccntUsage\t\t szExePath\t\t")
        for i in range(0, vecModInfoSize):
            modPath = vecMod[i].modPath
            modName = vecMod[i].modName
            tagModEntry = vecMod[i].tagModEntry
            szModule = vecMod[i].tagModEntry.szModule
            th32ProcessID = vecMod[i].tagModEntry.th32ProcessID
            th32ModuleID = vecMod[i].tagModEntry.th32ModuleID
            hModule = vecMod[i].tagModEntry.hModule
            dwSize = vecMod[i].tagModEntry.dwSize
            modBaseAddr = vecMod[i].tagModEntry.modBaseAddr
            modBaseSize = vecMod[i].tagModEntry.modBaseSize
            GlblcntUsage = vecMod[i].tagModEntry.GlblcntUsage
            ProccntUsage = vecMod[i].tagModEntry.ProccntUsage
            szExePath = vecMod[i].tagModEntry.szExePath
            if szModule.lower() in "user32.dll":
                self.user32BaseAddr = modBaseAddr
            print("%s\t\t %x\t\t %x\t\t %x\t\t %x\t\t %x\t\t %x\t\t %x\t\t %x\t\t %s" 
            %(szModule, th32ProcessID, th32ModuleID, hModule, dwSize, modBaseAddr, modBaseSize, GlblcntUsage, ProccntUsage, szExePath))

    def format_mem_info(self, meminfo):
        nBaseAddress = meminfo.BaseAddress
        nAllocBase = meminfo.AllocationBase
        nAllocProtect = meminfo.AllocationProtect
        nRegionSize = meminfo.RegionSize
        nState = meminfo.State
        nProtect = meminfo.Protect
        nType = meminfo.Type
        
        # 初始化保护类型
        s_alloc_protect = ""
        if nAllocProtect & PAGE_NOACCESS:
            s_alloc_protect = "NoAccess"
        if nAllocProtect & PAGE_READONLY:
            s_alloc_protect = "Readonly"
        elif nAllocProtect & PAGE_READWRITE:
            s_alloc_protect = "ReadWrite"
        elif nAllocProtect & PAGE_WRITECOPY:
            s_alloc_protect = "WriteCopy"
        elif nAllocProtect & PAGE_EXECUTE:
            s_alloc_protect = "Execute"
        elif nAllocProtect & PAGE_EXECUTE_READ:
            s_alloc_protect = "Execute_Read"
        elif nAllocProtect & PAGE_EXECUTE_READWRITE:
            s_alloc_protect = "Execute_ReadWrite"
        elif nAllocProtect & PAGE_EXECUTE_WRITECOPY:
            s_alloc_protect = "Execute_WriteCopy"
        if nAllocProtect & PAGE_GUARD:
            s_alloc_protect = s_alloc_protect + "+Guard"
        if nAllocProtect & PAGE_NOCACHE:
            s_alloc_protect = s_alloc_protect + "+NoCache"  

        # 内存状态
        s_state = ""
        if nState == MEM_COMMIT:
            s_state = "Commit "
        elif nState == MEM_FREE:
            s_state = "Free   "
        elif nState == MEM_RESERVE:
            s_state = "Reserve"
        else:
            s_state = "Damned " 
        
        # 实际保护类型
        s_protect = ""
        if nProtect & PAGE_NOACCESS:
            s_protect = "NoAccess"
        if nProtect & PAGE_READONLY:
            s_protect = "Readonly"
        elif nProtect & PAGE_READWRITE:
            s_protect = "ReadWrite"
        elif nProtect & PAGE_WRITECOPY:
            s_protect = "WriteCopy"
        elif nProtect & PAGE_EXECUTE:
            s_protect = "Execute"
        elif nProtect & PAGE_EXECUTE_READ:
            s_protect = "Execute_Read"
        elif nProtect & PAGE_EXECUTE_READWRITE:
            s_protect = "Execute_ReadWrite"
        elif nProtect & PAGE_EXECUTE_WRITECOPY:
            s_protect = "Execute_WriteCopy"
        if nProtect & PAGE_GUARD:
            s_protect = s_protect + "+Guard"
        if nProtect & PAGE_NOCACHE:
            s_protect = s_protect + "+NoCache"  
        
        # 内存类型
        s_type = ""
        if nType == MEM_IMAGE:
            s_type = "Image  "
        elif nType == MEM_MAPPED:
            s_type = "Free   "
        elif nType == MEM_PRIVATE:
            s_type = "Private"
        else:
            s_type = "-      "  
        
        strMemInfo = "{}\t {}\t\t {}\t\t {}\t\t {}\t\t {}\t\t {}".format(str(hex(nBaseAddress)), str(hex(nAllocBase)), s_alloc_protect, s_state, s_protect, s_type, str(hex(nRegionSize)))
        return strMemInfo


    def print_mem_info(self, vecMem, vecMemInfoSize):
        print("基地址\t\t 申请地址\t\t 初始化保护类型\t\t 内存状态\t\t 实际保护类型\t\t 内存类型\t\t 内存大小\t\t 所属模块")
        for i in range(0, vecMemInfoSize):
            memBasicInfo = vecMem[i].memBasicInfo
            memInModPath = vecMem[i].memInModPath
            BaseAddress = vecMem[i].memBasicInfo.BaseAddress
            AllocationBase = vecMem[i].memBasicInfo.AllocationBase
            AllocationProtect = vecMem[i].memBasicInfo.AllocationProtect
            RegionSize = vecMem[i].memBasicInfo.RegionSize
            State = vecMem[i].memBasicInfo.State
            Protect = vecMem[i].memBasicInfo.Protect
            Type = vecMem[i].memBasicInfo.Type
            print(self.format_mem_info(vecMem[i].memBasicInfo))

    # 进程所有内存页面信息
    def test_mem_info(self):
        vecMem = self.objProcess.get_mem_info()
        vecMemInfoSize = self.objProcess.get_mem_info_size()
        self.print_mem_info(vecMem, vecMemInfoSize)


    # 进程内所有模块导出函数信息
    def test_expfun_info(self):
        vecExpInfo = self.objProcess.get_expfun_info()
        vecExpInfoSize = self.objProcess.get_expfun_info_size()
        print("函数地址\t\t 函数rva\t\t 函数名字\t\t 函数未粉碎c++签名")
        for i in range(0, vecExpInfoSize):
            funAddress = vecExpInfo[i].funAddress
            funRva = vecExpInfo[i].funRva
            funName = vecExpInfo[i].funName
            funSignature = vecExpInfo[i].funSignature
            if i > 100: # 导出函数可能很多 提前退出
                break
            print("%x %x %s %s" %(funAddress, funRva, funName, funSignature))

    def test_dis(self):
        #CODE = self.objProcess.get_binmem_by_region(0x77901000,0x1000)
        CODE = self.objProcess.get_binmem_by_module("user32.dll")
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(CODE, 0x1000):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        pass



def test_x32dbg():
    x32dbg = Test("Telegram.exe","Telegram.exe")
    x32dbg.test_mem_info()
    x32dbg.test_mod_info()
    x32dbg.test_expfun_info()
    x32dbg.test_get_mem()
    x32dbg.test_write_mem()
    x32dbg.test_dis()
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
