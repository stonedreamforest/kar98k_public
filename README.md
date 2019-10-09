# kar98k_public




### 工具概述
在分析程序过程中发现部分场景直接调试器附加分析没必要 就想着写款自动化工具尽可能在分析（尤其是前期）过程中解决某些重复操作
然后就选择脚本语言，在js、lua、python等其它不常见脚本（chaiscript、cling）中最后选择了python 原因是支持库多


### 工具特性
1. 支持内存读写（当然可以dump内存 如果你愿意还可以写个自定义PythonCE
2. 支持模块注入
3. 支持执行shellcode
4. 支持32、64
5. python3支持（已测试python3.7.4）

### 函数签名:
```
__init__(...)
    __init__(self: kar98k.kar98k, arg0: str) -> None
    c++签名：kar98k(const std::wstring targetProcessName){...}

execute_shell_code(...)
    execute_shell_code(self: kar98k.kar98k, arg0: bytes) -> None
    c++签名：std::string get_decoding_cpp_name(const std::string & funName){...}

get_binmem_by_module(...)
    get_binmem_by_module(self: kar98k.kar98k, arg0: str) -> bytes
    c++签名：py::bytes get_binmem_by_module(std::wstring MDName){...}

get_binmem_by_region(...)
    get_binmem_by_region(self: kar98k.kar98k, arg0: int, arg1: int) -> bytes
    c++签名：py::bytes get_binmem_by_region(size_t nAddress , size_t nSize){...}

get_decoding_cpp_name(...)
    get_decoding_cpp_name(self: kar98k.kar98k, arg0: str) -> str
    c++签名：std::string get_decoding_cpp_name(const std::string & funName){...}

get_mem_info(...)
    get_mem_info(self: kar98k.kar98k) -> std::vector<kar98k::_MEM_INFO,std::allocator<kar98k::_MEM_INFO> >
    c++签名：std::vector<kar98k::MEMORY_INFO> *get_mem_info(){...}

get_mem_info_size(...)
    get_mem_info_size(self: kar98k.kar98k) -> int
    c++签名：size_t get_mem_info_size(){...}

get_mod_info(...)
    get_mod_info(self: kar98k.kar98k) -> std::vector<kar98k::_MODULE_INFO,std::allocator<kar98k::_MODULE_INFO> >
    c++签名：std::vector<kar98k::MODULE_INFO> *get_mod_info(){...}

get_mod_info_size(...)
    get_mod_info_size(self: kar98k.kar98k) -> int
    c++签名：size_t get_mod_info_size(){...}

get_tpmem_by_module(...)
    get_tpmem_by_module(self: kar98k.kar98k, arg0: str, arg1: int) -> tuple
    c++签名：py::tuple get_tpmem_by_module(std::wstring MDName , int nBitType){...}

get_tpmem_by_region(...)
    get_tpmem_by_region(self: kar98k.kar98k, arg0: int, arg1: int, arg2: int) -> tuple
    c++签名：py::tuple get_tpmem_by_region(size_t nAddress , size_t nSize , int nBitType){...}

get_uint16(...)
    get_uint16(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int16 get_uint16(size_t nAddress){...}

get_uint32(...)
    get_uint32(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int32 get_uint32(size_t nAddress){...}

get_uint64(...)
    get_uint64(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int64 get_uint64(size_t nAddress){...}

get_uint8(...)
    get_uint8(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int8 get_uint8(size_t nAddress){...}

inject_dll(...)
    inject_dll(self: kar98k.kar98k, arg0: str) -> None
    c++签名：void inject_dll(const wchar_t* fullDllPath){...}

list_mem_info(...)
    list_mem_info(self: kar98k.kar98k) -> None
    c++签名：void list_mem_info(){...}

print_impinfo_by_module(...)
    print_impinfo_by_module(self: kar98k.kar98k, arg0: str) -> None
    c++签名：void print_impinfo_by_module(std::wstring MDName){...}

print_process_meminfo(...)
    print_process_meminfo(self: kar98k.kar98k) -> None
    c++签名：void print_process_meminfo(){...}

write_buffer(...)
    write_buffer(self: kar98k.kar98k, arg0: int, arg1: bytes) -> None
    c++签名：void write_buffer(size_t nAddress , py::bytes pyBytes){...}

write_uint16(...)
    write_uint16(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint16(size_t nAddress , unsigned __int16 nValue){...}

write_uint32(...)
    write_uint32(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint32(size_t nAddress , unsigned __int32 nValue){...}

write_uint64(...)
    write_uint64(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint64(size_t nAddress , unsigned __int64 nValue){...}

write_uint8(...)
    write_uint8(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint8(size_t nAddress , unsigned __int8 nValue){...}

```

### 截图
- 打印目标进程模块内导入函数信息：`print_impinfo_by_module` （再结合其它函数对壳和shellcode很有用
![image](https://user-images.githubusercontent.com/16742566/66462446-ac272880-eaad-11e9-8b27-b77463d75974.png)


- 打印目标进程页面信息：`print_process_meminfo`
![image](https://user-images.githubusercontent.com/16742566/66462273-50f53600-eaad-11e9-8ca2-b3d808b98d23.png)

### 示例
[test.py](https://github.com/stonedreamforest/kar98k_public/blob/master/test.py)


### 用法
- 最简单的是将`kar98k.pyd` 和`test.py`放在同一目录 然后执行`python test.py便可`



