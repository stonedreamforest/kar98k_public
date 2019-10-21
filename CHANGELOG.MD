
#### 2019-10-09
公开发行 基于python3 下载：[python-374](https://www.python.org/downloads/release/python-374/)

#### 2019-10-10
1. 部分代码重构，库仅提供核心基础功能
删除api：
```
print_impinfo_by_module
print_process_meminfo
list_mem_info`
```
添加api:
```
refresh_mem_info：刷新进程内存信息
refresh_mod_info：刷新进程模块信息
refresh_expfun_info：刷新导出表信息
get_expfun_info：获取进程所有模块导出表信息
get_expfun_info_size：获取保存导出表信息vector大小
```


2. 添加python2支持 下载：[python-2716](https://www.python.org/downloads/release/python-2716/)

3. 更新示例脚本`test.py`以便兼容新api，更详细的api使用展示

#### 2019-10-13
1. 添加`EumFun.py`: 用来模拟函数执行
2. 添加api:
```
get_fs_value: 获取目标进程fs[offset]值
get_gs_value:：获取目标进程gs[offset]寄存器值
```


#### 2019-10-21
bug修复...
