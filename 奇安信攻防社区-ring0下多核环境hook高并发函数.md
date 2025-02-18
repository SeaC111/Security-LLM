0x00 前言
=======

> r0层多核下hook高并发函数存在的问题是：在使用如memcpy的时候，无法一次性拷贝5个字节的硬编码。即有可能拷贝到一半，别的线程去执行了代码导致蓝屏。

解决的办法有：

1. 短跳中转
2. 中断门
3. 找一条一次性修改8字节的指令

这里将使用第三种方法实现。

0x01 SwapContext
================

这是线程切换核心函数，Windows几乎无时无刻在执行这个函数，所以属于是高并发函数。

本文将在多核环境下通过hook SwapContext作为实现。

需要获取的是SwapContext的地址：采用的方法是暴力搜索特征码，由于需要在`ntoskrnl.exe`文件中搜索特征码，所以需要获取`ntoskrnl.exe`的基址和大小。

整个过程为：

1. 0环下fs:\[0\]指向KPCR，fs:\[0x34\]即指向`KdVersionBlock`
2. `KdVersionBlock`地址对应的结构体为`_DBGKD_GET_VERSION64`，`_DBGKD_GET_VERSION64`+18h的指向`PsLoadedModuleList`的地址
3. 取出`PsLoadedModuleList`中的内容，即`KLDR_DATA_TABLE_ENTRY`结构
4. 在`KLDR_DATA_TABLE_ENTRY`结构中找到+18h位置上的DllBase（基址）和+20h位置上的SizeOfImage（大小）。

可以用如下图示表示：  
![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5e038876dad766598dcbe6b0d0f667714ed724ad.jpg)

> 注意：一个核意味着就有一个kpcr，而只有cpu编号为1对应的kpcr才有`KdVersionBlock`的值，其余核对应KPCR的`KdVersionBlock`值均为null，所以我们这里要使用`KeSetSystemAffinityThread`对执行该线程的cpu进行绑定，确保当前线程运行在一号cpu上。

综上所述，这一段代码如下

```assembly
PVOID DllBase = NULL;
SIZE_T viewSize = 0;
KeSetSystemAffinityThread(1);
__asm{
          push eax;
          push ebx;
          mov eax, fs: [0x34];
          add eax, 18h;   
          mov eax, [eax];   
          mov eax, [eax]; 
          mov ebx, [eax + 18h];
          mov DllBase, ebx;
          mov ebx, [eax + 20h];
          mov viewSize, ebx;
          pop ebx;
          pop eax;
     }
KeRevertToUserAffinityThread();//恢复线程运行的处理器
```

获取到基址和大小后，然后就是提取硬编码，这里就选取最前面的16个字节硬编码，一组四个四节，分四组。  
![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a5e976bfd00b994ac113f9f350c55a4a46494320.png)

```c
ULONG opCodeArray[TRAITCODELEN] = { 0xc626c90a ,0x9c022d46 ,0x05408b8d  ,0xdde80000 };
```

使用循环在`ntoskrnl.exe`模块中遍历这段特征码。

OpCode1-4对应着四段特征码。返回的值就为`SwapContext`的地址。

```c
ULONG endDllAddr = (ULONG)DllBase + viewSize;
for (ULONG i = (ULONG)DllBase; i < endDllAddr; i++)
{
    try
    {
        if (*(PULONG)i == OpCode1 && *(PULONG)(i + 4) == OpCode2
            && *(PULONG)(i + 8) == OpCode3 && *(PULONG)(i + 0xC) == OpCode4)
        {
            // 返回函数地址偏移
            return i;
        }
    }
    except(1)
    {
        continue;
    }
}
```

0x02 获取os版本和分页模式
================

操作系统版本判断用**RtlGetVersion**获取前正在运行的操作系统的版本信息。

分页模式通过对cr4，PAE位的判断，如果为1，则为29912分页，如果为0，则为101012分页。

```c
ULONG GetWindowsVersion()
{
    RTL_OSVERSIONINFOW lpVersionInformation = { sizeof(RTL_OSVERSIONINFOW) };
    if (NT_SUCCESS(RtlGetVersion(&lpVersionInformation)))
    {
        ULONG dwMajorVersion = lpVersionInformation.dwMajorVersion;
        ULONG dwMinorVersion = lpVersionInformation.dwMinorVersion;
        if (dwMajorVersion == 5 && dwMinorVersion == 1)
        {
            return WINXP;
        }
        else if (dwMajorVersion == 6 && dwMinorVersion == 1)
        {
            return WIN7;
        }
        else if (dwMajorVersion == 6 && dwMinorVersion == 2)
        {
            return WIN8;
        }
        else if (dwMajorVersion == 10 && dwMinorVersion == 0)
        {
            return WIN10;
        }
    }
    return 0;
}
// 获取操作系统分页模式
ULONG GetWindowsPageMode()
{
    ULONG PageMode = 0x1; // 默认为 2-9-9-12 分页
    __asm
    {
        _emit 0x0F;     // mov  eax, cr4;
        _emit 0x20;
        _emit 0xE0;
        test eax, 0x20;
        jnz  End;
        // 为 10-10-12 分页
        mov  dword ptr[PageMode], 0x0;
    End:
        ;
    }
    return PageMode;
}
```

0x03 除去保护
=========

我们自己的代码空间可以随便读写，但是操作系统的代码想改，是需要去除掉保护。

这里最简单的方式就是改变cr0的wp位，将该位清0，注意这里首先要提升irql，即中断执行等级。

```c
KIRQL irQl;
// 修改Cr0寄存器, 去除写保护（内存保护机制）
KIRQL RemoveP()
{
    DbgPrint("RemoveP\n");
    // (PASSIVE_LEVEL)提升 IRQL 等级为DISPATCH_LEVEL，并返回旧的 IRQL
    irQl = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0(); //mov eax,cr0;
    cr0 &= ~0x10000; //将第16位（WP位）清0
    _disable(); //相当于 cli 指令,屏蔽软中断
    __writecr0(cr0); //mov cr0, eax
    DbgPrint("退出RemoveP\n");
    return irQl;
}
```

然后是恢复保护属性的代码

```c
KIRQL ResumeP()
{
    DbgPrint("ResumeP\n");
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000; //WP复原为1
    _disable();
    __writecr0(cr0);mov cr0, eax
    // 恢复IRQL等级
    KeLowerIrql(irQl);
    DbgPrint("ResumeP退出\n");
    return irQl;
}
```

0x04 CMPXCHG8B
==============

该指令可一次性替换八个字节硬编码 。

cmpxchg8b mem64 指令的工作如下：

1. 比较 mem64 和 EDX:EAX。
2. 如果相等，那么把 ECX:EBX 存储到 mem64。
3. 如果不相等，那么把 mem64 存储到 EDX:EAX。

```c
ULONG DataLow = 0x0, DataHigh = 0x0;
VOID _declspec(naked) _fastcall FastSwapMemory(ULONG* TargetAddr, ULONG* SoulAddr)
{
    __asm
    {
        pushad;
        pushfd;

        mov esi, ecx; //ecx = TargetAddr
        mov edi, edx; //edx = SoulAddr(_fastcall调用约定)
        mov edx, 0x0;
        mov eax, 0x0;
        // 读取ShellCode
        lock CMPXCHG8B qword ptr[edi];
        mov DataLow, eax;
        mov DataHigh, edx;
        // 读取目标内存
        lock CMPXCHG8B qword ptr[esi]; //edx:eax = [TargetAddr]
        mov ebx, dword ptr[DataLow];
        mov ecx, dword ptr[DataHigh];
        // HOOK目标内存
        lock CMPXCHG8B qword ptr[esi]; //相等，把[SoulAddr]存储到 [TargetAddr]。

        popfd;
        popad;
        retn;
    }
}
```

0x05 HOOKFunction
=================

通过逆向SwapContext可以知道,esi存储的实际上是下一线程，edi存储的是当前线程

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-964d0959aff64fe3545024476dc0ce8483546896.png)

这里就可以简单打印一下当前线程和下一线程信息。

```assembly
void _declspec(naked) HookSwapContextFunction()
{
    _asm
    {
        mov dword ptr[CurrentThread], edi;
        mov dword ptr[NextThread], esi;
    }
    _asm
    {
        pushad;
        pushfd;
    }

    DbgPrint("当前线程为：%x\t\t下一个线程为：%x\n",CurrentThread,NextThread);

    _asm 
    {
        popfd;
        popad;
        mov eax, dword ptr[SwapContext];
        jmp eax;
    }
}
```

0x06实现效果
========

加载驱动后成功hook了SwapContext并打印出线程信息。

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2ed023d04df8409621e2775e907ca869ecbff669.png)