0x00前言
======

Windows所提供给R3环的API，实质就是对操作系统接口的封装，其实现部分都是在R0实现的。很多恶意程序会利用钩子来钩取这些API，从而达到截取内容，修改数据的意图。现在我们使用ollydbg对ReadProcessMemory进行跟踪分析，查看其在R3的实现。

0x01测试
======

od
--

我们首先在od里面跟一下在ring3层`ReadProcessMemory`的调用过程

首先在 exe 中 调用 `kernel32.ReadProcessMemory`函数，我们可以看到这一部分主要是`call dword ptr ds:[<&KERNEL32.ReadProcessMemory>]; kernel32.ReadProcessMemory`这一行代码比较关键，调用了`kernel32.ReadProcessMemory`，继续往里面跟

```c++
　　01314E3E  8BF4            mov esi,esp
　　01314E40  6A 00           push 0x0
　　01314E42  6A 04           push 0x4
　　01314E44  8D45 DC         lea eax,dword ptr ss:[ebp-0x24]
　　01314E47  50              push eax
　　01314E48  8B4D C4         mov ecx,dword ptr ss:[ebp-0x3C]
　　01314E4B  8D548D E8       lea edx,dword ptr ss:[ebp+ecx*4-0x18]
　　01314E4F  52              push edx
　　01314E50  6A FF           push -0x1
　　01314E52  FF15 64B0310    call dword ptr ds:[<&KERNEL32.ReadProcessMemory>]; kernel32.ReadProcessMemory
　　01314E58  3BF4            cmp esi,esp
```

在 `ReadProcessMemory`函数 中调用 `jmp.&API-MS-Win-Core-Memory-L1-1-0.ReadProcessMemory>` 函数，在`kenel32.dll`中，`mov edi,edi` 是用于热补丁技术所保留的，这段代码仔细看其实除了`jmp`什么也没干，继续跟`jmp`

```c++
7622C1CE  8BFF             mov edi,edi
7622C1D0  55               push ebp
7622C1D1  8BEC             mov ebp,esp
7622C1D3  5D               pop ebp                              
7622C1D4  E9 F45EFCFF      jmp <jmp.&API-MS-Win-Core-Memory-L1-1-0.ReadProcessMemory>
```

在 `API-MS-Win-Core-Memory-L1-1-0.ReadProcessMemo` 中调用 `KernelBase.ReadProcessMemory` 函数，这里的调用链就是从`kernel32.dll`到了`kernelBase.dll`

```c++
761F20CD  FF25 0C191F7      
    jmp dword ptr ds:[<&API-MS-Win-Core-Memory-L1-1-0.ReadProcessMemory>; KernelBase.ReadProcessMemory
```

在`KernelBase.ReadProcessMemory`中 调用 `<&ntdll.NtReadVirtualMemory>` 函数，将`ReadProcessMemory`中传入的参数再次入栈，调用`ntdll.ZwReadVirtualMemory`函数，再往里面走

```c++
　　75DA9A0A  8BFF        mov edi,edi
　　75DA9A0C  55          push ebp
　　75DA9A0D  8BEC        mov ebp,esp
　　75DA9A0F  8D45 14     lea eax,dword ptr ss:[ebp+0x14]
　　75DA9A12  50          push eax
　　75DA9A13  FF75 14     push dword ptr ss:[ebp+0x14]
　　75DA9A16  FF75 10     push dword ptr ss:[ebp+0x10]
　　75DA9A19  FF75 0C     push dword ptr ss:[ebp+0xC]
　　75DA9A1C  FF75 08     push dword ptr ss:[ebp+0x8]
　　75DA9A1F  FF15 C411DA7
      call dword ptr ds:[<&ntdll.NtReadVirtualMemory>] ; ntdll.ZwReadVirtualMemory
```

在 `<&ntdll.NtReadVirtualMemory>` 中调用 `ntdll.KiFastSystemCall` 函数，这里往eax里存放了一个编号，对应在内核中`ReadProcessMemory`的实现，在 `0x7FFE0300`处存放了一个函数指针，该函数指针决定了以什么方式进入0环(中断/快速调用)

```c++
　　77A162F8  B8 15010000     mov eax,0x115 // 对应操作系统内核中某一函数的编号
　　77A162FD  BA 0003FE7F     mov edx,0x7FFE0300 // 该地方是一个函数，该函数决定了什么方式进零环
　　77A16302  FF12            call dword ptr ds:[edx] ; ntdll.KiFastSystemCall
```

在 `ntdll.KiFastSystemCall` 中 调用 `sysenter`

```c++
　　77A170B0  8BD4     mov edx,esp
　　77A170B2  0F34     sysenter
　　77A170B4  C3       retn
```

ida
---

其实在ida里面整个调用链会更加清晰，首先定位到`ReadProcessMemory`可以发现，在调用`NtReadVirtualMemory`之前会往参数里面压入5个值

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b63284eb8bc8af38cedc6c7e3d18bd0c304daa76.png)

再到`Imports`模块继续跟`NtProtectVirtualMemory`可以发现是调用了`ntdll.dll`

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ac3ac02c4c93a8beb8d5bd18aa244725c7c15d88.png)

那么我们再到`ntdll.dll`里面定位，因为这里我直接拿的win10的`ntdll.dll`，在win10里面`NtProtectVirtualMemory`和`ZwProtectVirtualMemory`是同一个函数，可以看到这个地方首先也是将内核函数的编号给了eax，然后将函数指针存入edx，该函数指针决定了是以中断方式还是快速调用方式进入0环，然后再调用`Wow64SystemServiceCall()`

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6bce5d1fe9e0cfef149484eec53f7cccbbb2234b.png)

0x02
====

虽然这里因为系统的原因最后调用的函数不同，但是实现的方法都是相同的。因为是在xp里面进行实验，这里就用od里面的调用进行分析实现

我们希望可以在自己的代码中直接使用 `sysenter`，但经过编写发现其并没有提供这种指令。因此在`sysenter`无法直接使用的情况下，只能去调用`ntdll.KiFastSystemCall`函数

`ntdll.KiFastSystemCall`函数需要借助`ntdll.NtReadVirtualMemory`传递过来的参数，然后执行call指令。我们并不希望执行call指令执行，因为执行call指令意味着又上了一层。我们希望自己的代码中直接传递参数，并且直接调用调用`ntdll.KiFastSystemCall`函数。因此我们需要模拟call指令，call指令的本质就是将返回地址入栈，并跳转。所以我们不需要跳转，只需要将返回地址入栈(四个字节 使用 `sub esp,4` 模拟)

我们内嵌汇编代码后，需要手动平衡栈，我们只需要分析esp改变了多少(push、pop以及直接对esp的计算)。经过分析共减少了24字节，所以代码最后应该有 `add esp,0x18` 来平衡栈

0x03实现
======

代码如下

```c++
// MyReadMemory.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

void  MyReadMemory(HANDLE hProcess, PVOID pAddr, PVOID pBuffer, DWORD dwSize, DWORD  *dwSizeRet)
{

    _asm
    {
        lea eax, [ebp + 0x14]
        push eax                //dwSizeRet
        push [ebp + 0x14]       //dwSize
        push [ebp + 0x10]       //pBuffer
        push [ebp + 0xC]        //pAddr
        push [ebp + 0x8]        //hProcess
        sub esp,4               //平衡 call NtReadProcessMemory 堆栈
        mov eax, 0x115
        mov edx, 0X7FFE0300  
        call dword ptr [edx]
        add esp, 0x18
    }
}
int main()
{
    HANDLE hProcess = 0;
    int t = 123;
    DWORD pBuffer;

    MyReadMemory((HANDLE)-1, (PVOID)&t, &pBuffer, sizeof(int), 0);
    printf("MyReadMemory : %x\n", pBuffer);

    ReadProcessMemory((HANDLE)-1, &t, &pBuffer, sizeof(int), 0);
    printf("ReadProcessMemory : %x\n", pBuffer);

    getchar();
    return 0;
}
```

实现效果如下，可以看到我们自己实现的函数跟调用`ReadProcessMemory`输出的结果是相同的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-40eb36f619cd9bf040a9c08f65faf65f5e6ebbdc.png)

0x04拓展
======

再看下`WriteProcessMemory`，还是调用了`ntdll.dll`的`NtProtectVirtualMemory`

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a9896fd7b502647de951e2ed6e7156ae77baab9b.png)

跟到`NtProtectVirtualMemory`后发现跟`ReadProcessMemory`的结构相同

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d804274f5e7fb0bdbad148301e2fd227e6a727ba.png)

那么也可以进行`WriteProcessMemory`的重写

```c++
// MyWriteProcessMemory.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

void MyWriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpBuffer,DWORD nSize,LPDWORD lpNumberOfBytesWritten)
{
    _asm
    {
        lea eax,[ebp + 0x18]
        push eax                //lpNumberOfBytesWritten
        push [ebp + 0x14]       //nSize
        push [ebp + 0x10]       //lpBuffer
        push [ebp + 0xC]        //lpBaseAddress
        push [ebp + 0x8]        //hProcess
        sub esp,4               //平衡 call NtWriteProcessMemory 堆栈
        mov eax, 0x115          
        mov edx,0x7FFE0300
        call dword ptr [edx]
        add esp,0x18
    }
}

int main(int argc, char* argv[])
{
    char szBuffer[10] = "Drunkmars";
    char InBuffer[10] = {0};
    SIZE_T size = 0;

    WriteProcessMemory((HANDLE)-1,InBuffer,szBuffer,sizeof(szBuffer)9,&size);
    printf("WriteProcessMemory : %s\n",InBuffer);

    MyWriteProcessMemory((HANDLE)-1,InBuffer,szBuffer,sizeof(szBuffer),&size);
    printf("MyWriteProcessMemory : %s\n",InBuffer);
    return 0;
}
```

也跟`WriteProcessMemory`所打印出的效果相同

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-24144442696a9c7f0b364691526ae340467d2e4b.png)

0x05进阶
======

在前面我们是直接通过间接call `0x7FFE0300`这个地址，来实现进入ring0的效果，我们继续探究

\_KUSER\_SHARED\_DATA
---------------------

在 User 层和 Kernel 层分别定义了一个 `_KUSER_SHARED_DATA`结构区域，用于 User 层和 Kernel 层共享某些数据，它们使用固定的地址值映射，`_KUSER_SHARED_DATA` 结构区域在 User 和 Kernel 层地址分别为：

> User 层地址为：0x7ffe0000
> 
> Kernnel 层地址为：0xffdf0000

虽然指向的是同一个物理页，但在ring3层是只读的，在ring0层是可写的

在0x30偏移处`SystemCall`存放的地址就是真正进入ring0的实现方法

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7e28c0f524fd5cc6afa26dbc0982f0654b750f8e.png)

我们跟进去看看，这里有两个函数，一个是`KiFastSystemCall`即快速调用，一个是`KiIntSystemCall`。因为在系统版本的原因，一些操作系统并不支持快速调用进ring0的指令，这时候就会使用到`KiIntSystemCall`，即中断门的形式进入ring0

```c++
kd> u 0x7c92e4f0
ntdll!KiFastSystemCall:
7c92e4f0 8bd4      mov   edx,esp
7c92e4f2 0f34      sysenter
ntdll!KiFastSystemCallRet:
7c92e4f4 c3       ret
7c92e4f5 8da42400000000 lea   esp,[esp]
7c92e4fc 8d642400    lea   esp,[esp]
ntdll!KiIntSystemCall:
7c92e500 8d542408    lea   edx,[esp+8]
7c92e504 cd2e      int   2Eh
7c92e506 c3       ret
```

那么我们该如何判断当前系统是否支持快速调用呢？

当通过eax=1来执行cpuid指令时，处理器的特征信息被放在ecx和edx寄存器中，其中edx包含了一个SEP位（11位），该位指明了当前处理器是否支持`sysenter/sysexit`指令，进入od使用`cpuid`指令，这里为了方便查看寄存器的变化把eax置1，ecx和edx置0

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-34953e9ae3c1c17ce8bc183c21d783aed1c8b3a5.png)

执行命令后，这里的edx为`BFEBFBFF`，拆完edx后，SEP位为1，证明支持`sysenter/sysexit`，即调用`ntdll.dll!KiFastSystemCall()`这个函数进入ring0

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b14a588c4de8583cb108dbb4e468cb4ccd2c3930.png)

也可以在ida里面查看这两个函数

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e21891ba75bbde72bfa1b4009509a13fe5073778.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-adffa2cb734bda55da84f634b937aa0e5484a6f0.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9297cf93b7edc68f1af6395c5a3ba6123c20a939.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5c1bb38d22879e09a3b2a8dc81845aad441bb2eb.png)

进0环需要更改CS、SS、ESP、EIP四个寄存器

> CS的权限由3变为0 意味着需要新的CS
> 
> SS与CS的权限永远一致 需要新的SS
> 
> 权限发生切换的时候，堆栈也一定会切换，需要新的ESP
> 
> 进0环后代码的位置，需要EIP

首先看一下中断门，通过`0x2E`的中断号最终进入了`KiSystemService`这个内核模块

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-80525d1155a11eb5ff8f7fd0b3b1c1f888f4bf0c.png)

如果通过sysenter，即快速调用进入内核。中断门进0环，需要的CS、EIP在IDT表中，需要查内存(SS与ESP由TSS提供)

而CPU如果支持sysenter指令时，操作系统会提前将CS/SS/ESP/EIP的值存储在MSR寄存器中，sysenter指令执行时，CPU会将MSR寄存器中的值直接写入相关寄存器，没有读内存的过程，所以叫快速调用，本质是一样的

我们在三环执行的api无非是一个接口，真正执行的功能在内核实现，我们便可以直接重写三环api，直接sysenter进内核，这样可以规避所有三环hook。

API通过中断门进0环：

固定中断号为0x2E，CS/EIP由门描述符提供 ESP/SS由TSS提供，进入0环后执行的内核函数：NT!KiSystemService

API通过sysenter指令进0环：

CS/ESP/EIP由MSR寄存器提供(SS是算出来的)，进入0环后执行的内核函数：NT!KiFastCallEntry

0x06代码实现
========

因为这里`_asm`不支持 `sysenter`指令，可以用 `_emit` 代替，在模拟调用`CALL [0x7FFE0300]`这条指令的时候需要填入调用函数的真实地址，否则会报错`0xC0000005`

```c++
// sysenter.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>

BOOL __stdcall MyReadProcessMemory_IntGate(HANDLE hProcess, PVOID pAddr, PVOID pBuffer, DWORD dwSize, DWORD  *dwSizeRet)
{
    LONG NtStatus;
    __asm
    {
        // 直接模拟 KiIntSystemCall
        lea edx,hProcess; // 要求 edx 存储最后入栈的参数
        mov eax, 0xBA;
        int 0x2E;
        mov NtStatus, eax;      
    }

    if (dwSizeRet != NULL)
    {
        *dwSizeRet = dwSize;
    }

    if (NtStatus < 0)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL __stdcall MyReadProcessMemory_sysenter(HANDLE hProcess, PVOID pAddr, PVOID pBuffer, DWORD dwSize, DWORD  *dwSizeRet)
{
    LONG NtStatus;
    __asm
    {
        // 模拟 ReadProcessMemory
        lea eax,[ebp + 0x18]
        push eax                //dwSizeRet
        push [ebp + 0x14]       //dwSize
        push [ebp + 0x10]       //pBuffer
        push [ebp + 0xC]        //pAddr
        push [ebp + 0x8]        //hProcess
        sub esp, 4; // 模拟 ReadProcessMemory 里的 CALL NtReadVirtualMemory
        // 模拟 NtReadVirtualMemory
        mov eax, 0xBA;
        push 0x004010EC; // 模拟 NtReadVirtualMemory 函数里的 CALL [0x7FFE0300]
        // 模拟 KiFastSystemCall
        mov edx, esp;
        _emit 0x0F; // sysenter 
        _emit 0x34;

NtReadVirtualMemoryReturn:      
        add esp, 0xBA; // 模拟 NtReadVirtualMemory 返回到 ReadProcessMemory 时的 RETN 0x14
        mov NtStatus, eax;
    }
    if (dwSizeRet != NULL)
    {
        *dwSizeRet = dwSize;        
    }
    // 错误检查
    if (NtStatus < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BOOL __stdcall MyWriteProcessMemory_IntGate(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpBuffer,DWORD nSize,LPDWORD lpNumberOfBytesWritten)
{
    LONG NtStatus;
    _asm
    {
        lea edx,hProcess;
        mov eax, 0x115;
        int 0x2E;
        mov NtStatus, eax;
    }

    if (lpNumberOfBytesWritten != NULL)
    {
        *lpNumberOfBytesWritten = nSize;        
    }

    if (NtStatus < 0)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL __stdcall MyWriteProcessMemory_sysenter(HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpBuffer,DWORD nSize,LPDWORD lpNumberOfBytesWritten)
{
    LONG NtStatus;
    _asm
    {
        lea eax,[ebp + 0x18]
        push eax                //lpNumberOfBytesWritten
        push [ebp + 0x14]       //nSize
        push [ebp + 0x10]       //lpBuffer
        push [ebp + 0xC]        //lpBaseAddress
        push [ebp + 0x8]        //hProcess
        sub esp,4               //平衡 call NtWriteProcessMemory 堆栈
        mov eax, 0x115          
        push 0x004011F9; // 模拟 NtWriteVirtualMemory 函数里的 CALL [0x7FFE0300]
        // 模拟 KiFastSystemCall
        mov edx, esp;
        _emit 0x0F; // sysenter 
        _emit 0x34;
NtWriteVirtualMemoryReturn:     
        add esp, 0x18; // 模拟 NtWriteVirtualMemory 返回到 WriteProcessMemory 时的 RETN 0x14
        mov NtStatus, eax;
    }

    if (lpNumberOfBytesWritten != NULL)
    {
        *lpNumberOfBytesWritten = nSize;        
    }

    if (NtStatus < 0)
    {
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char* argv[])
{
    char szBuffer[10] = "Drunkmars";
    char InBuffer[10] = {0};
    SIZE_T size = 0;

    HANDLE hProcess = 0;
    int t = 123;
    DWORD pBuffer, dwRead;

    ReadProcessMemory((HANDLE)-1, &t, &pBuffer, sizeof(int), &dwRead);
    printf("ReadProcessMemory : %x\n", pBuffer);

    MyReadProcessMemory_IntGate((HANDLE)-1, &t, &pBuffer, sizeof(int), &dwRead);
    printf("MyReadProcessMemory_IntGate : %x\n", pBuffer);

    MyReadProcessMemory_sysenter((HANDLE)-1, &t, &pBuffer, sizeof(int), &dwRead);
    printf("MyReadProcessMemory_sysenter : %x\n", pBuffer);

    WriteProcessMemory((HANDLE)-1,InBuffer,szBuffer,sizeof(szBuffer),&size);
    printf("WriteProcessMemory : %s\n",InBuffer);

    MyWriteProcessMemory_IntGate((HANDLE)-1,InBuffer,szBuffer,sizeof(szBuffer),&size);
    printf("MyWriteProcessMemory_IntGate : %s\n",InBuffer);

    MyWriteProcessMemory_sysenter((HANDLE)-1,InBuffer,szBuffer,sizeof(szBuffer),&size);
    printf("MyWriteProcessMemory_sysenter : %s\n",InBuffer);

    getchar();
    return 0;
}
```

实现效果如下

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8c4d6570dc93303928dd6f6369ccaef642b4f7cc.png)