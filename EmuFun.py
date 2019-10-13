#! python3
# coding=utf-8
# 请以管理员启动
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import kar98k



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






# memory address where emulation starts
g_BaseAddress = 0x00520000
g_startAddress = 0x00522CF0
g_EndAddress = -1
g_StackAddress = 0X80000000

g_memPageList = None
g_fs30 = None





REG_EAX = 0x00000000
REG_EBX = 0x00000001
REG_ECX = 0x005DFC7C
REG_EDX = 0x00000000
REG_EBP = 0x005DF3CC
REG_ESP = 0x005DF3BC
REG_ESI = 0x004FFAC0
REG_EDI = 0x00000000
REG_EIP = 0x00832CF0
REG_EFLAGS = 0x00000297






def hook_block(uc, address, size, user_data):
    #print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))
    pass


g_capDis = Cs(CS_ARCH_X86, CS_MODE_32)

def dis_single_ins(Address, Code):
    for i in g_capDis.disasm(Code, Address):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    pass

def get_bin_memory(address):
    for i in g_memPageList:
        memPageInfoDict = g_memPageList[i]
        memBaseAddress = memPageInfoDict['BaseAddress']
        memEndAddress = memPageInfoDict['BaseAddress'] + memPageInfoDict['RegionSize']
        if memBaseAddress <= address and address <= memEndAddress:
            startOffset = address - memBaseAddress
            Code = memPageInfoDict['binMemory'][startOffset : startOffset + 16]
            return Code
    return None


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    try:
        pCode = get_bin_memory(address)
        if pCode != None:
            dis_single_ins(address, pCode)
        #print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
        print("\
        EAX = %x\t EBX = %x\t ECX = %x\t EDX = %x\n\
        EBP = %x\t ESP = %x\t ESI = %x\t EDI = %x\n\
        EIP = %X\t EFLAGS = %x" %(
            uc.reg_read(UC_X86_REG_EAX),
            uc.reg_read(UC_X86_REG_EBX),
            uc.reg_read(UC_X86_REG_ECX),
            uc.reg_read(UC_X86_REG_EDX),
            uc.reg_read(UC_X86_REG_EBP),
            uc.reg_read(UC_X86_REG_ESP),
            uc.reg_read(UC_X86_REG_ESI),
            uc.reg_read(UC_X86_REG_EDI),
            uc.reg_read(UC_X86_REG_EIP),
            uc.reg_read(UC_X86_REG_EFLAGS)))
        pass
    except UcError as e:
        print("ERROR: %s" % e)
        pass
    pass





def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_READ_UNMAPPED:
        print(">>> Missing Read is being READ at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
        return True
    else:
        # return False to indicate we want to stop emulation
        return False




class ExeBasicEnvironment:
    def __init__(self, procName):
        self.objProcess = kar98k.kar98k(procName)
        self.memPageList = ({})
        self.fs30 = self.objProcess.get_fs_value(0x30)
        pass

    def get_mem_page(self):
        vecMem = self.objProcess.get_mem_info()
        vecMemInfoSize = self.objProcess.get_mem_info_size()
        for i in range(0, vecMemInfoSize):
            memBasicInfo = vecMem[i].memBasicInfo
            nState = memBasicInfo.State
            nProtect = memBasicInfo.Protect

            if memBasicInfo.State == MEM_FREE or\
                memBasicInfo.State == MEM_RESERVE or\
                nProtect & PAGE_GUARD or\
                nProtect & PAGE_NOCACHE or\
                nProtect & PAGE_NOACCESS:
                continue

            nRegionSize = memBasicInfo.RegionSize
            nBaseAddress = memBasicInfo.BaseAddress
            # print("%x %x" %(nBaseAddress, nRegionSize))
            memDict = {'RegionSize': nRegionSize, 
            'BaseAddress': nBaseAddress, 
            'binMemory': self.objProcess.get_binmem_by_region(nBaseAddress, nRegionSize)
            }
            self.memPageList[i] = memDict
        pass

    def kar98k_main(self):
        self.get_mem_page()
        pass


def get_exe_env(procName):
    global g_fs30
    global g_memPageList
    Exe = ExeBasicEnvironment(procName)
    Exe.kar98k_main()
    g_fs30 = Exe.fs30
    g_memPageList = Exe.memPageList
    pass



def init_mem_env(Emu):
    for i in g_memPageList:
        memPageInfoDict = g_memPageList[i]
        Emu.mem_map(memPageInfoDict['BaseAddress'], memPageInfoDict['RegionSize'])
        Emu.mem_write(memPageInfoDict['BaseAddress'], memPageInfoDict['binMemory'])
    pass


def init_reg_env(Emu):
    Emu.reg_write(UC_X86_REG_EAX, REG_EAX)
    Emu.reg_write(UC_X86_REG_EBX, REG_EBX)
    Emu.reg_write(UC_X86_REG_ECX, REG_ECX)
    Emu.reg_write(UC_X86_REG_EDX, REG_EDX)
    Emu.reg_write(UC_X86_REG_EBP, REG_EBP)
    Emu.reg_write(UC_X86_REG_ESP, REG_ESP)
    Emu.reg_write(UC_X86_REG_ESI, REG_ESI)
    Emu.reg_write(UC_X86_REG_EDI, REG_EDI)
    #Emu.reg_write(UC_X86_REG_EIP, REG_EIP)
    Emu.reg_write(UC_X86_REG_EFLAGS, REG_EFLAGS)
    pass

def init_fs_30(Emu):
    Emu.mem_map(0, 0x2000)
    Emu.mem_write(0x30, g_fs30)

# 初始化exe环境
def init_exe_env(Emu):
    init_fs_30(Emu)
    init_mem_env(Emu)
    init_reg_env(Emu)
    pass


def unicorn_main(emStartAddress, emEndAddress):
    print("Emulate i386 code")
    try:
        # Initialize emulator in X86-32bit mode
        Emu = Uc(UC_ARCH_X86, UC_MODE_32)

        init_exe_env(Emu)

        Emu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        Emu.hook_add(UC_HOOK_CODE, hook_code)

        # intercept invalid memory events
        Emu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

        # emulate code in infinite time & unlimited instructions
        Emu.emu_start(emStartAddress, emEndAddress)
        
        # now print out some registers
        print("Emulation done. Below is the CPU context")


    except UcError as e:
        print("ERROR: %s" %(e))
        print("\
            EAX = %x\t EBX = %x\t ECX = %x\t EDX = %x\n\
            EBP = %x\t ESP = %x\t ESI = %x\t EDI = %x\n\
            EIP = %X\t EFLAGS = %x" %(
                Emu.reg_read(UC_X86_REG_EAX),
                Emu.reg_read(UC_X86_REG_EBX),
                Emu.reg_read(UC_X86_REG_ECX),
                Emu.reg_read(UC_X86_REG_EDX),
                Emu.reg_read(UC_X86_REG_EBP),
                Emu.reg_read(UC_X86_REG_ESP),
                Emu.reg_read(UC_X86_REG_ESI),
                Emu.reg_read(UC_X86_REG_EDI),
                Emu.reg_read(UC_X86_REG_EIP),
                Emu.reg_read(UC_X86_REG_EFLAGS)))
    pass


if __name__ == "__main__":
    get_exe_env('mfcapplication2.vmp.exe')
    unicorn_main(REG_EIP,0)
    pass
