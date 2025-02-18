0x01 环境准备
=========

Mimikatz源码：<https://github.com/gentilkiwi/mimikatz>  
笔者调试环境：vs2022社区版  
在将项目导入重新生成解决方案的时候可能会出现以下两个小问题：  
1、`类型强制转换”: 从“PVOID”到“DWORD”的指针截断报错`  
解决：在报错处修改将指针类型强行转换成DWORD  
2、`PRINTER_NOTIFY_CATEGORY_ALL”: 宏重定义`  
解决：将重复定义变量在报错处修改成重复定义变量的值即可  
3、因官方项目默认没给出debug方案，所以需要手动添加debug配置  
解决：

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0c28e9e0a55740a23a7ad8c6fbf7c185f6592920.png)

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bae3eb9a6624dc92e93be1f162bcbd808f6910ed.png)

若遇其他问题可百度解决，具体没太记录  
另外，若想做远程debug，可以在项目属性中这样配置

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8d03662283613b26d4b82ad90ecca8ae43da5e49.png)

参考：<https://blog.csdn.net/thebulesky/article/details/120852560>

0x02 程序如何执行命令
=============

同项目名c文件中的`wmain()`是整个mimikatz的入口函数

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ba154c759e65fdacdf75491d1a68de0802eb32ef.png)

```cpp
for(i = MIMIKATZ_AUTO_COMMAND_START ; (i < argc) && (status != STATUS_PROCESS_IS_TERMINATING) && (status != STATUS_THREAD_IS_TERMINATING) ; i++) 
{ 
    kprintf(L"\n" MIMIKATZ L"(" MIMIKATZ_AUTO_COMMAND_STRING L") # %s\n", argv[i]); 
    status = mimikatz_dispatchCommand(argv[i]); 
}
```

从上面的循环中可以看到执行文件获取到命令行参数后，会将命令传入`mimikatz_dispatchCommand()`函数，利用这个函数可以根据当前命令在不同场景下执行接下来的操作

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3d6a490defe7d297acdbf802d91cee63530e7a1e.png)

例如：当我们想要做万能钥匙攻击的时候，键入`!+`将利用`mimidrv.sys`去执行当前命令的操作

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eb88acd1aae744a8a47ad7eb7e203f3203fd612c.png)

否则通过`mimikatz_doLocal()`函数默认进入常用命令的场景

在获取到命令进行命令分发之后，将获取到`module`和`command`两个参数，之后就进入命令执行的阶段

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b5d70e8a6c84ab0fb8b6104b9a38372f121e0b3c.png)

先来看看`mimikatz_modules`数组中已定义的模块都有哪些，该数组里面存放的是每一个模块的结构体的指针。将`module`的值和每个模块结构体中所定义的`shortName`继续比较

```cpp
const KUHL_M * mimikatz_modules[] = { 
&kuhl_m_standard, 
&kuhl_m_crypto, 
&kuhl_m_sekurlsa, 
&kuhl_m_kerberos, 
&kuhl_m_ngc, 
&kuhl_m_privilege, 
&kuhl_m_process, 
&kuhl_m_service, 
&kuhl_m_lsadump, 
&kuhl_m_ts, 
&kuhl_m_event, 
&kuhl_m_misc, 
&kuhl_m_token, 
&kuhl_m_vault, 
&kuhl_m_minesweeper, 
#if defined(NET_MODULE) 
&kuhl_m_net, 
#endif 
&kuhl_m_dpapi,
&kuhl_m_busylight,
&kuhl_m_sysenv, 
&kuhl_m_sid, 
&kuhl_m_iis, 
&kuhl_m_rpc, 
&kuhl_m_sr98, 
&kuhl_m_rdm, 
&kuhl_m_acr, 
};
```

然后也是以一样的方式，将`command`与模块结构体中的每个`command`做比较，去执行指定模块中的指定命令函数。例如我们做`privilege::debug`操作的时候，执行的函数是`kuhl_m_privilege.c`文件下调用的`kuhl_m_privilege_simple()`函数

```cpp
NTSTATUS kuhl_m_privilege_debug(int argc, wchar_t * argv[]) 
{ 
return kuhl_m_privilege_simple(SE_DEBUG); 
}
```

而该函数将调用到系统的API

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-10d790ed00945e7227ab257541142a9b5460498f.png)

0x03 MSV模块
==========

MSV介绍
-----

`msv`功能模块的原理个人理解就是在`lsasrv.dll`这个模块中找到`LogonSessionListLock()`函数同时使用了`LogonSessionList`和`LogonSessionListCount`两个变量作为参数，这个`LogonSessionList`中应该就保存当前活动的 Windows 登录会话列表。那么只要根据这个`LogonSessionListLock()`这个函数位置，加上偏移位置，就可以获取两个全局变量的位置。以windows1803为例，通俗理解：`LogonSessionListLock`函数的起始地址是`80065926`

`LogonSessionListCount`变量的起始地址是`80065922`，`LogonSessionList`变量的起始地址`8006593D`，那经过计算`LogonSessionListCount`相对`LogonSessionListLock`的偏移是`-4`，`LogonSessionList`相对`LogonSessionListLock`的偏移是`23`，这个也正好对于`mimikatz`中的定义

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-68e14e88a55c4f9689858133c5b90f0f6ae38c44.png)

至于如何找这两个全局变量可以学习：[](https://www.praetorian.com/blog/inside-mimikatz-part2/)<https://www.praetorian.com/blog/inside-mimikatz-part2/>

那首先通过找到`LSASS.exe`进程，然后列举进程中全部的`dll`模块，计算出`lsasrv.dll`模块的基址，然后根据`LogonSessionListLock`函数在`lsasrv.dll`模块中的偏移找到这个函数的位置（而这个函数在不同windows版本下的`lsasrv.dll`模块中的位置也不同），然后再根据两个全局变量的相对位置，找到两个全局变量在内存中的位置

MSV功能分析
-------

### 远程Debug Tips

因为`mimikatz`本身就需要高权限运行，所以远程调试中的`msvsmon.exe`要以管理员运行，且选择无身份验证最合适

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7f7dbacbaf2886b40d0c8e64761b4d6fc7cef015.png)

### 正题

回到正题，当我们知道上面的命令分发、执行等操作就是为了通过命令去做指向性功能的操作时。那就直接单独看想看的功能模块就好  
在`mimikatz`中`msv`模块的作用是枚举`LM`和`NTLM`凭证，`KUHL_M_C`结构体中的描述是`Lists LM & NTLM credentials`，根据之前分析的命令分发过程，`sekurlsa::msv`最终通过函数指针调用函数`kuhl_m_sekurlsa_msv()`

根据模块名直接找到函数所在文件`kuhl_m_seckurlsa_msv1_0.c`，先看到c文件处定义的`kuhl_m_sekurlsa_msv_package`，将功能名、回调函数、需要找的进程模块等赋值到新的结构体中

```cpp
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = {L"msv", kuhl_m_sekurlsa_enum_logon_callback_msv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
```

此处可以看到`ModuleName`的值设置为`lsasrv.dll`，这个也是抓取`NTML`的重点模块

```cpp
typedef struct _KUHL_M_SEKURLSA_PACKAGE {
    const wchar_t * Name;
    PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;
    BOOL isValid;
    const wchar_t * ModuleName;
    KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;
```

随后找到`msv`模块功能入口点，打下断点开始分析

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b6bf069d956fbf4542beeed73d73561da61ae897.png)

跟进到`kuhl_m_sekurlsa_getLogonData()`函数里，可以看到将新赋值的结构体`OptionalData`和`kuhl_m_sekurlsa_enum_callback_logondata()`函数传入到`kuhl_m_sekurlsa_enum()`函数中

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ef186d1a1dd686fb8c4886c5254ee8ccefcdfa73.png)

跟进到`kuhl_m_sekurlsa_enum()`函数中，可以看到一个关键函数`kuhl_m_sekurlsa_acquireLSA()`

跟进该函数又可以看到调用了`kull_m_process_getProcessIdForName()`函数通过`lsass.exe`进程名去获取其PID。其之后的调用路线就是`kull_m_process_getProcessInformation()` -&gt;`kull_m_process_NtQuerySystemInformation()` -&gt;`NtQuerySystemInformation()`，最后调用的是不公开的系统API（[](https://blog.csdn.net/qq_37232329/article/details/111401002)[https://blog.csdn.net/qq\_37232329/article/details/111401002](https://blog.csdn.net/qq_37232329/article/details/111401002))，就不深究先

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-55abc27fb8f3085d18a94b1a5f2b01d01b9cdd24.png)

当获取了`lsass.exe`进程ID后，回到`kuhl_m_sekurlsa_acquireLSA()`中，之后根据PID利用`OpenProcess(processRights, FALSE, pid)`函数，获取进程句柄

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-322a9b5c3d30481cb53e9503278b871fa85a81af.png)

打开句柄之后，首先调用`kull_m_memory_open()`给`&cLsass.hLsassMem`分配一块内存`KUHL_M_SEKURLSA_CONTEXT cLsass = {NULL, {0, 0, 0}};`

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bb3d30ef53a046be9f025c29b413dcf235e40ee6.png)

然后对`cLsass.osContext.MajorVersion`等三个属性赋值，这个赋值保存的是`windows当前版本`的相关信息。我用的机器是1803的，所以`MIMIKATZ_NT_BUILD_NUMBER=17134,MIMIKATZ_NT_MINOR_VERSION=0,MIMIKATZ_NT_MAJOR_VERSION=10`，不同机器这些值会存在差异

现在来到了获取`lssas.exe`进程中各模块、地址等信息的操作

![16.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d88c9f51775f832a89b5a77539a83aa19a3db6d5.png)

先跟进到`kull_m_process_getVeryBasicModuleInformations()`函数中，当中先调用`kull_m_process_peb()`函数获取`LSASS.exe`进程的`PEB进程环境块`(<https://bbs.pediy.com/thread-266678.htm>)，实际也是调用`NtQueryInformationProcess()`函数

![17.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-361742a67cfadf06f1de8705f7d90c5fb9194c0a.png)

![18.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f68a5c3b10cf004d5064b779c033d99eff73484d.png)

在`PEB`的结构中有一个`PEB.Ldr.InMemoryOrderModuleList`的列表，这个列表记录了进程加载的模块地址和大小，接下来通过遍历列表来查找需要的`LSASRV.dll`模块

![19.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3fa0630e5718bdf07834c34d2e2d692bb85ddd1c.png)

当查找到`lsasrv.dll`模块时，进入`callback回调函数->kuhl_m_sekurlsa_findlibs()`，将`pModuleInformation`结构体中获取到的`lsasrv.dll`模块地址、偏移量等信息存入`kuhl_m_sekurlsa_msv_package`结构体当中

![20.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f7e1535a7977605fcda28716575a17b155ab9ec7.png)

![21.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6f53052c4d17167131f7c231c03ecdffe0e45d89.png)

在成功查找到`lsasrv.dll`模块的相关信息便返回后，进入`kuhl_m_sekurlsa_utils_search`函数当中，这个函数继而调用`kuhl_m_sekurlsa_utils_search\_generic`，通过搜索的是`lsasrv.dll`模块的特征码，结合偏移量找到所有的登录会话信息即`LogonSessionList`和`LogonSessionListCount`这两个全局变量的地址，但是还需要调用`kull_m_memory_copy`获取其值

![22.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f3359eb07e2883bed12cb78256379734af68c683.png)

之后会进入到`lsassLocalHelper->AcquireKeys(&cLsass, &lsassPackages[0]->Module.Informations)`即调用`kuhl_m_sekurlsa_nt6_acquireKeys()`函数去获取加密用户密码的密钥。用`kull_m_patch_getGenericFromBuild()`函数通过识别不同系统版本返回相应系统的`PTRN_WALL_LsaInitializeProtectedMemory_KEY`作为特征码进行搜索

![23.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-384d24bd27744c7aacf123322c3fe0306f9e5c57.png)

![24.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c5fea3499dbeb3760d9549bd5cdc215aa978b0dd.png)

再通过偏移量获取初始化向量和密钥本身

![25.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b43deb958a587040e6f149bc39a9d3408fb83b32.png)

以上就是要分析的`kuhl_m_sekurlsa_acquireLSA()`函数功能，回到`kuhl_m_sekurlsa_enum()`函数里，就是枚举用户信息的时刻~先是通过识别不同系统找到相应的结构体以及偏移量

![26.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5ec72bb5a5bcfe529213cd3553280ca13ee8be57.png)

再通过`LogonSessionList`会话活动信息根据以上偏移量得到会话用户的`UserName、LogonDomain、LogonServer`等信息

![27.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0bfe8f19c0109cffe5fd359ea3f46570dfd66df0.png)

跟进`callback`回调函数即`kuhl_m_sekurlsa_enum_callback_logondata()`函数

```cpp
retCallback = callback(&sessionData, pOptionalData);
```

在该函数里先是调用`kuhl_m_sekurlsa_printinfos_logonData()`函数将会话中获取到的用户信息打印出来

![28.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a46b445473fe644381ff3cf7abfe71db0f5c38be.png)

![29.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-71e14263ae3c0dcbc0f722d3086f5ad11a2c41d1.png)

接着将会话信息传入`kuhl_m_sekurlsa_enum_logon_callback_msv()`函数

![30.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2eb531adcdced96abfc42749fc36fb72eec51f0e.png)

```cpp
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
    kuhl_m_sekurlsa_msv_enum_cred(pData->cLsass, pData->pCredentials, kuhl_m_sekurlsa_msv_enum_cred_callback_std, pData);
}
```

我们直接跟进到`credCallback`回调函数即`kuhl_m_sekurlsa_msv_enum_cred_callback_std()`函数中的`kuhl_m_sekurlsa_genericCredsOutput()`函数

![31.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b671f30361663e47c87b813b88a26cb2f7c8b73b.png)

以下将结合会话凭证和的NTLM等信息的特征码偏移量来在内存中获取会话列表中用户的ntlm hash值，再利用hex转string的方式打印出来

![32.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-064d1515dcef3c9d50892bfc93bc0bb891850151.png)

将通过以下凭证和地址偏移量找到NTLM等信息，例：

![33.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a08ed4c4169f470d992462888a2e427b8c5bb336.png)

![34.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eb21b22e61d605853e510a248e1fce76aeffd6b5.png)

而NTLM这类信息则调用到`kull_m_string_wprintf_hex()`函数根据凭证加地址偏移量，一位一位读出打印

![35.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a0f32bef331422ab03ba61f32e7b85a7e3edb31b.png)

之后的操作就是获取SHA1等值、遍历获取会话列表中获取以上信息的操作（不是目的，不关注咯）最后以释放内存结束

0x04 小结
=======

个人认为，`mimikatz`在利用`msv`获取`NTLM`的原理是通过特征码定位`lsass.exe`进程的`lsasvr.dll`中的`LogonSessionList`全局变量和`LogonSessionListCount`全局变量的地址，然后解析`LogonSessionList`结构体，通过结构体内的偏移量读取到凭证等用户信息（这不同系统的特征码及偏移量的收集是真牛b）

Tips：这种读取lsass.exe进程及其中模块获取内存内容的方式可能也会造成大多数杀软或EDR的告警拦截，那么主机弱口检测就不好以这种方式实现