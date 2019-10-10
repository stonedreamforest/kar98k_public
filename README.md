# kar98k_public




### 工具概述
在分析程序过程中发现部分场景直接调试器附加分析没必要 就想着写款自动化工具尽可能在分析（尤其是前期）过程中解决某些重复操作
然后就选择脚本语言，在js、lua、python等其它不常见脚本（chaiscript、cling）中最后选择了python 原因是支持库多


### 工具特性
1. 支持内存读写（当然可以dump内存 如果你愿意还可以写个自定义PythonCE
2. 支持模块注入
3. 支持执行shellcode
4. 支持32、64
5. 可同时操作多个进程互不影响 线程安全
6. python2、3支持 （基于python3.7.4、python2.7.16）

### 函数签名及作用:
```
__init__(...)
    __init__(self: kar98k.kar98k, arg0: str) -> None
    c++签名：kar98k(const std::wstring targetProcessName){...}
    作用: 传入目标进程名称，实例化操作目标进程对象

execute_shell_code(...)
    execute_shell_code(self: kar98k.kar98k, arg0: bytes) -> None
    c++签名：std::string get_decoding_cpp_name(const std::string & funName){...}
    作用: 执行shellcode

get_binmem_by_module(...)
    get_binmem_by_module(self: kar98k.kar98k, arg0: str) -> bytes
    c++签名：py::bytes get_binmem_by_module(std::wstring MDName){...}
    作用: 获取目标模块内存（实时

get_binmem_by_region(...)
    get_binmem_by_region(self: kar98k.kar98k, arg0: int, arg1: int) -> bytes
    c++签名：py::bytes get_binmem_by_region(size_t nAddress , size_t nSize){...}
    作用: 获取指定内存区域内存（实时

get_decoding_cpp_name(...)
    get_decoding_cpp_name(self: kar98k.kar98k, arg0: str) -> str
    c++签名：std::string get_decoding_cpp_name(const std::string & funName){...}
    作用: 获取未粉碎c++函数签名

get_mem_info(...)
    get_mem_info(self: kar98k.kar98k) -> std::vector<kar98k::_MEM_INFO,std::allocator<kar98k::_MEM_INFO> >
    c++签名：std::vector<kar98k::MEMORY_INFO> *get_mem_info(){...}
    作用: 获取进程内存页面信息 返回vector 
    MEMORY_INFO 结构：
	typedef struct _MODULE_INFO {
		MODULEENTRY32W tagModEntry; // 参考 https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32?redirectedfrom=MSDN
		std::string modName;
		std::string modPath;
	}MODULE_INFO , *PMODULE_INFO;
    --
get_mem_info_size(...)
    get_mem_info_size(self: kar98k.kar98k) -> int
    c++签名：size_t get_mem_info_size(){...}
    作用: 返回保存内存页面信息vector大小
    
get_mod_info(...)
    get_mod_info(self: kar98k.kar98k) -> std::vector<kar98k::_MODULE_INFO,std::allocator<kar98k::_MODULE_INFO> >
    c++签名：std::vector<kar98k::MODULE_INFO> *get_mod_info(){...}
    作用: 获取进程模块信息 返回vector
    MODULE_INFO 结构：
	typedef struct _MEM_INFO {
		MEMORY_BASIC_INFORMATION memBasicInfo; //参考 https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information?redirectedfrom=MSDN
		std::string memInModPath;
	}MEMORY_INFO , *PMEM_INFO;
    
get_mod_info_size(...)
    get_mod_info_size(self: kar98k.kar98k) -> int
    c++签名：size_t get_mod_info_size(){...}
    作用: 返回保存模块信息vector大小
    
get_tpmem_by_module(...)
    get_tpmem_by_module(self: kar98k.kar98k, arg0: str, arg1: int) -> tuple
    c++签名：py::tuple get_tpmem_by_module(std::wstring MDName , int nBitType){...}
    作用: 以元组形式返回指定模块内存值 （nBitType：1、2、4、8分别对应：8位、16位、32位、64位整形值）
    
get_tpmem_by_region(...)
    get_tpmem_by_region(self: kar98k.kar98k, arg0: int, arg1: int, arg2: int) -> tuple
    c++签名：py::tuple get_tpmem_by_region(size_t nAddress , size_t nSize , int nBitType){...}
    作用: 以元组形式返回指定内存区域内存值 （nBitType：1、2、4、8分别对应：8位、16位、32位、64位整形值）
    
get_uint16(...)
    get_uint16(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int16 get_uint16(size_t nAddress){...}
    作用: 读取指定地址中的16位整形值
    
get_uint32(...)
    get_uint32(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int32 get_uint32(size_t nAddress){...}
    作用: 读取指定地址中的32位整形值
    
get_uint64(...)
    get_uint64(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int64 get_uint64(size_t nAddress){...}
    作用: 读取指定地址中的64位整形值
    
get_uint8(...)
    get_uint8(self: kar98k.kar98k, arg0: int) -> int
    c++签名：unsigned __int8 get_uint8(size_t nAddress){...}
    作用: 读取指定地址中的8位整形值
    
inject_dll(...)
    inject_dll(self: kar98k.kar98k, arg0: str) -> None
    c++签名：void inject_dll(const wchar_t* fullDllPath){...}
    作用: 注入模块

write_buffer(...)
    write_buffer(self: kar98k.kar98k, arg0: int, arg1: bytes) -> None
    c++签名：void write_buffer(size_t nAddress , py::bytes pyBytes){...}
    作用: 在指定地址写入一整块数据
    
write_uint16(...)
    write_uint16(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint16(size_t nAddress , unsigned __int16 nValue){...}
    作用: 在指定地址写入16位整形值
    
write_uint32(...)
    write_uint32(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint32(size_t nAddress , unsigned __int32 nValue){...}
    作用: 在指定地址写入32位整形值
    
write_uint64(...)
    write_uint64(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint64(size_t nAddress , unsigned __int64 nValue){...}
    作用: 在指定地址写入64位整形值
    
write_uint8(...)
    write_uint8(self: kar98k.kar98k, arg0: int, arg1: int) -> None
    c++签名：void write_uint8(size_t nAddress , unsigned __int8 nValue){...}
    作用: 在指定地址写入8位整形值
    
get_expfun_info(...)
    get_expfun_info(self: kar98k.kar98k) -> std::vector<kar98k::_FUN_INFO,std::allocator<kar98k::_FUN_INFO> >
	c++签名：std::vector<FUN_INFO>* get_expfun_info(){...}
	作用：获取进程所有模块导出表信息
	
get_expfun_info_size(...)
    get_expfun_info_size(self: kar98k.kar98k) -> int
	c++签名：size_t get_expfun_info_size(){...}
	作用：获取保存导出表信息vector大小

refresh_expfun_info(...)
    refresh_expfun_info(self: kar98k.kar98k) -> None
	c++签名：void refresh_expfun_info(){...}
	作用：刷新导出表信息
	
refresh_mem_info(...)
    refresh_mem_info(self: kar98k.kar98k) -> None
	c++签名：void refresh_mem_info(){...}
	作用：刷新进程内存信息
	
refresh_mod_info(...)
    refresh_mod_info(self: kar98k.kar98k) -> None
	c++签名：void refresh_mod_info(){...}
	作用：刷新进程模块信息
	
```

### 部分函数作用截图

- 打印目标进程页面信息：`print_process_meminfo`
![image](https://user-images.githubusercontent.com/16742566/66467246-b8fc4a00-eab6-11e9-8149-3d31ea2d7896.png)


- 打印目标进程模块内导入函数信息：`print_impinfo_by_module` （再结合其它函数对壳和shellcode分析很有用
![image](https://user-images.githubusercontent.com/16742566/66467209-a5e97a00-eab6-11e9-8edc-de3f540a37ed.png)







### 测试示例
[test.py](https://github.com/stonedreamforest/kar98k_public/blob/master/test.py)


### 下载

https://github.com/stonedreamforest/kar98k_public/releases

### 用法
- 最简单的是将`kar98k.pyd` 和`test.py`放在同一目录 然后执行`python test.py`便可
![image](https://user-images.githubusercontent.com/16742566/66468475-c9adbf80-eab8-11e9-8080-04e7b2d7c95d.png)



### 更改日志
[CHANGELOG.MD](https://github.com/stonedreamforest/kar98k_public/blob/master/CHANGELOG.MD)


