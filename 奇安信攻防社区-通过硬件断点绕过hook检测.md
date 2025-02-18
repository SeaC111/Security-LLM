0x00 前言
=======

我们知道常见的注入方式有IAT hook、SSDT hook、Inline hook等，但其实大体上可以分为两类，一类是基于修改函数地址的hook，一类则是基于修改函数代码的hook。而基于修改函数地址的hook最大的局限性就是只能hook已导出的函数，对于一些未导出函数是无能为力的，所以在真实的hook中，Inline hook反而是更受到青睐的一方。

0x01 hook测试
===========

这里我用win32写了一个`MessageBox`的程序，当点击开始按钮就会弹窗，通过一个`Hook_E9`函数用来限制对`MessageBoxA`的hook，如果检测到了hook，则调用`ExitProcess`直接退出程序

![image-20220406165822281.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b7a920e0e69aa9d4aa3b238fb2bffed008c53f6e.png)

如下所示，这里我们的目的就是通过`Inline hook`来修改文本框中的内容

![image-20220406165833227.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fef745693a8ad648a3f10f0ec3640c5133561631.png)

这里使用常规方式修改5个字节的硬编码，通过E9跳转到我们自己的函数进行修改，这里将代码打包成dll

![image-20220406170042141.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-63a777bf0d7515cac91e25f816253e9144e2b322.png)

通过远程线程注入，这里显示是注入成功了，但是会被我们的检测函数拦截，这里可以看到拦截的是`E9`这个硬编码

![image-20220406165929083.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-696976d3b968759fdf506c4bdb734c0ee4dbe291.png)

然后我们这里对我们的程序的E9指令进行替换，修改为先用`call`短跳到没有被监控的区域，然后再跳到我们自己的函数

然而这里还是被拦截，这里显示的是被CRC检测拦截了

![image-20220406170152970.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3b22ebce96ea2501863ace1681a573c6ebe3f7a2.png)

我们知道`Inline hook`无论是通过E8还是E9跳转，肯定是要修改内存的，那么如果程序有CRC检测，那么我们这种使用汇编跳到自己的处理函数的方法是怎么都行不通的。这里就不能使用常规的方法去规避hook，而是通过CPU的dr0-dr7寄存器去触发异常，通过异常处理函数来修改文本框的值，这里我们首先需要了解的是硬件断点

0x02 硬件断点
=========

简单说一下软件断点和内存断点，软件断点就是我们通常在OD里面通过F2下的断点，它的原理是将我们想要断点的一个硬编码修改为cc，内存断点就是通过`VirtualProtect`函数来修改PTE的属性来触发异常达到断点的效果，这两种断点都需要修改内存里面的数据。

与软件断点与内存断点不同，**硬件断点**不依赖被调试程序，而是依赖于CPU中的**调试寄存器**。调试寄存器有**7个**，分别为**Dr0~Dr7**。用户最多能够设置4个硬件断点，这是由于只有Dr0~Dr3用于存储线性地址。其中，Dr4和Dr5是保留的。

在OD里面也能够看到只能设置4个硬件断点

![image-20220402185424231.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f2b7477fb76f9bc2c81ab7b469ff1a118cb60b1e.png)

设置硬件断点
------

Dr0~Dr3用于设置硬件断点，由于只有4个断点寄存器，所以最多只能设置4个硬件调试断点。在这7个寄存器里面，Dr7是最重要的寄存器

L0/G0 ~ L3/G3：控制Dr0~Dr3是否有效，局部还是全局；每次异常后，Lx都被清零，Gx不清零。

若Dr0有效，L0=1则为局部，G0=1则为全局，以此类推

![image-20220402213248841.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fbe04b3593d50ca733b957a381b8b73dd654087f.png)

断点长度(LENx)：00(1字节)、01(2字节)、11(4字节)

通过DR7的LEN控制

![image-20220402213410805.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-126a2b63e2ae5eba1466bdcfe09fb5cc92185674.png)

断点类型(R/Wx)：00(执行断点)、01(写入断点)、11(访问断点)

![image-20220402213439641.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-344c79da9ed9994030928da34acf1b437ff529b0.png)

流程
--

被调试进程

> 1.CPU执行时检测当前线性地址与调试寄存器（Dr0~Dr3）中的线性地址相等。 2.查IDT表找到对应的中断处理函数（`nt!_KiTrap01`） 3.CommonDispatchException 4.KiDispatchException 5.DbgkForwardException收集并发送调试事件

`DbgkForwardException`最终会调用`DbgkpSendApiMessage(x, x)`，第一个参数是消息类型，第二个参数则是选择是否挂起其它线程

调试器进程

> 1.循环判断 2.取出调试事件 3.列出信息：寄存器、内存 4.用户处理

0x03 思路
=======

我们首先明确一下思路，我们知道硬件断点是基于线程的，因为每个线程的`CONTEXT`结构是不同的，这里首先就需要找到我们要修改dr寄存器的线程，也就是我们要hook的检测线程，找到线程之后我们通过`OpenThread`去获得线程的句柄，然后通过`SetUnhandledExceptionFilter`去注册一个异常处理函数，注册完成之后就可以更改dr寄存器的值来触发`访问/写入/执行`断点，然后再通过`SetThreadContext`放到`CONTEXT`结构里面即可

0x04 规避检测
=========

那么这里先找到`OpenThread`和`MessageBoxA`在内存中的地址

```c++
    g_fnOpenThread = (FNOPENTHREAD)::GetProcAddress(LoadLibrary("kernel32.dll"), "OpenThread");  
    g_dwHookAddr = (DWORD)GetProcAddress(GetModuleHandle("user32.dll"),"MessageBoxA");
```

然后拍摄快照遍历线程

```c++
HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
```

定位到我们要hook的线程

```c++
if (Thread32First(hTool32, &thread_entry32))  
        {  
            do  
            {  
                if (thread_entry32.th32OwnerProcessID == GetCurrentProcessId())  
                {  
                    dwCount++;   
                    if (dwCount == 1) 
```

这里定位到线程之后我们把`THREADENTRY32`里面的进程ID和线程ID打印出来

```c++
char szBuffer[0x100];  
ZeroMemory(szBuffer,0x100);  
sprintf(szBuffer, "PID:%x - TID:%x\n", thread_entry32.th32OwnerProcessID, thread_entry32.th32ThreadID);  
OutputDebugString(szBuffer);
```

然后通过内存中定位的`OpenThread`得到线程的句柄

```c++
hHookThread = g_fnOpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_entry32.th32ThreadID);
```

拿到线程句柄之后我们通过`SetUnhandledExceptionFilter`注册一个异常处理函数`MyExceptionFilter`

```c++
SetUnhandledExceptionFilter(MyExceptionFilter);
```

这里需要了解SEH异常，在SEH异常中有三个返回值

```c++
1.EXCEPTION_EXECUTE_HANDLER(1) 执行except代码  
​  
2.EXCEPTION_CONTINUE_SEARCH(0) 寻找下一个   
​  
3.EXCEPTION_CONTINUE_EXECUTION(-1) 重新执行
```

通过`ExceptionRecord`里面的`ExceptionCode`判断错误码是否为`EXCEPTION_SINGLE_STEP`即单步异常以及`ExceptionAddress`判断是否到我们设置hook的地址，然后通过`ChangeContext`修改`CONTEXT`，再修改EIP

```c++
LONG WINAPI MyExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)  
{  
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)  
    {  
        if((DWORD)pExceptionInfo->ExceptionRecord->ExceptionAddress == g_dwHookAddr)  
        {  
            PCONTEXT pContext = pExceptionInfo->ContextRecord;  
            ChangeContext(pContext);  
            pContext->Eip = (DWORD)&OriginalFunc;  
            return EXCEPTION_CONTINUE_EXECUTION;  
        }  
    }  
​  
    return EXCEPTION_CONTINUE_SEARCH;  
}
```

这里`ChangeContext`要实现的功能就是修改文本框中的内容，esp指向的是`MessageBox`，那么esp+8即为`MessageBox`的第二个参数

```c++
void ChangeContext(PCONTEXT pContext)  
{  
    char szBuffer[0x100];  
    DWORD dwOldProtect = 0;  
    DWORD dwLength = 0;  
    LPSTR lpOldText = NULL;  
​  
    char szNewText[] = "SEH Hook successfully";  

    lpOldText = (LPSTR)(*(DWORD*)(pContext->Esp + 0x8));  
    dwLength = strlen(lpOldText);  
​  
    VirtualProtect(lpOldText, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect);  
    memcpy(lpOldText, szNewText, dwLength);  
    VirtualProtect(lpOldText, dwLength, dwOldProtect, 0);  
}
```

然后就是Eip修改到hook+2的位置，我们知道一般API起始的位置都是`mov edi,edi`，不能从这个起始位置执行，否则会死循环

```c++
g_dwHookAddrOffset = g_dwHookAddr + 2;  
​  
void __declspec(naked) OriginalFunc(void)  
{  
    __asm  
    {  
        mov edi,edi  
        jmp [g_dwHookAddrOffset]  
    }  
}
```

然后将hook的地址放到dr0寄存器里面，设置dr7的L0位为1即局部有效，断点长度设置为1即18、19位设置为0即可，断点类型设置为访问断点对应的值为0(20、21位设置为0)，这样dr7寄存器的1-31位都为0，32位为1，所以将dr7寄存器的值设置为1。然后通过`SetThreadContext`存入`CONTEXT`结构

```c++
            threadContext.Dr0 = g_dwHookAddr;  
            threadContext.Dr7 = 1;  
​  
            SetThreadContext(hHookThread, &threadContext);  
            CloseHandle(hHookThread);
```

0x05 实现效果
=========

首先还是使用常规的Inline hook配合E8、E9跳转，被CRC检测拦截

![image-20220406192150175.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ae86a3d1cbfd9a56b31ecf653a20bbee861484ad.png)

然后这里把dll打包一下

![image-20220406192750242.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-19a354773e42d7f3246b9144544555da34b1c6cb.png)

使用`Hook_SEH.dll`注入成功，没有被拦截

![image-20220406192244269.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-acc5eedd896ee4fe774918478f41d584e7b78668.png)

这里为了可以使用`sprintf`配合`OutputDebugString`来看一下`CONTEXT`结构里面寄存器的值

![image-20220406192420541.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-03e0301cc4310f67316c22f22ede21b294a84d01.png)

如下所示，hook成功

![image-20220406192336400.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f63be5482e6a78f01ef374d9bd5f28db023fa48f.png)