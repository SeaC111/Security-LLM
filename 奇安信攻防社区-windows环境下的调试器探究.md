0x00 前言
=======

在windows里面触发异常主要通过三种方式：软件断点、内存断点、硬件断点来实现，本文对这三种方式进行原理分析，通过自己构造代码来实现调试器的效果。

0x01 软件断点
=========

当在调试器下一个断点，其实就是把这行汇编语句的硬编码改为CC，即`int 3`

![image-20220401163633170.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-12933c94537daef7b94c0886ac15521b78c69e49.png)

被调试进程

> 1.CPU检测到INT 3指令  
> 2.查IDT表找到对应的函数  
> 3.CommonDispatchException  
> 4.KiDispatchException  
> 5.DbgkForwardException收集并发送调试事件

首先找到IDT表的3号中断

![image-20220401173115746.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b27b53b1503ef5dc06f6f4bc58fc1f20ec0aeebe.png)

调用`CommonDispatchException`

![image-20220401173221221.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7b25e82442e402277acc48bbee212c571ed598b9.png)

通过`KiDispatchException`分发异常

![image-20220401173322672.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c6eef62303cf78477b2444a48127d47dae5cb3b6.png)

首先用`KeContextFromframes`备份，若为用户调用则跳转

![image-20220401181028062.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ac731fa7fec981a4143630041a0e381a007e61b8.png)

进入函数如果没有内核调试器则跳转，也就是说如果有内核调试器的存在，3环调试器是接收不到异常的

![image-20220401181427103.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fbc49c88c611cb83063869800666b6670abf69fe.png)

然后调用调试事件

![image-20220401181849466.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-32469e0e7c0ec6383a9ebcdbee6756b9a17ce345.png)

`DbgkForwardException`主要是通过`DbgkpSendApiMessage`来发送调试事件，第二个参数决定线程是否挂起，首先通过cmp判断，如果为0则直接跳转，如果不为0则调用`DbgkpSuspendProcess`将被调试进程挂起

也就是说如果要想调试进程，就必须要调用`DbgkpSuspendProcess`将调试进程挂起

![image-20220401182810735.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-28bbb5404ab27158bc816b46befb0ebb7041b74a.png)

首先用调试模式创建进程，然后使用调试循环

![image-20220401210427370.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3e610dbb66c9af914552b8ae1cd9bf7f4cfdaa91.png)

如果是异常事件则调用`ExceptionHandler`

![image-20220401210528898.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9304f5e2bd163c73a3a70928a97a5e537833316d.png)

`ExceptionHandler`主要是通过判断`ExcptionRecord`结构里面的`ExceptionCode`来判断异常的类型，然后调用相应的函数，这里首先看软件断点，即`int 3`，调用`Int3ExceptionProc`

![image-20220401210654430.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-233e87c2f124274f4dac314926d10aecc4413d50.png)

![image-20220401212239579.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-354fd093045f88ca86cb3b1bcdc4f00e93595842.png)

![image-20220401212317494.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d5af2839b425b63e36473a136709589910f297c7.png)

下断点会把之前的指令修改为`CC`，如果不是系统断点，就把下断点的位置修改的指令写回去，然后获取`int3`断点的地址

![image-20220401212500170.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3491a468c8ef2447ca752db361b57d7510b3d04c.png)

然后获取上下文，所有调试寄存器都存储在`ContextFlags`里面

![image-20220401212831739.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-61ded823e4d864e924096e1c7f1abfad23be8b45.png)

当我们下软件断点的时候，EIP并不会停留在断点的地方，而是会停留在断点+1的地方(这里不同的异常EIP停留的位置不同)，所以这里需要进行EIP-1的操作

![image-20220401213324112.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9afaaae3ecb04d36cd5d37aed52a51e1c504dbbe.png)

然后调用处理的函数

![image-20220401213713782.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5ec0d8b0bfe60d4388cc34cabf4f8bdc47bf0b13.png)

![image-20220401213725277.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-29df02c1e1bfcbe2c45597c82a78e11c68425d13.png)

当被调试进程收集并发送调试事件之后就会处于阻塞状态，根据异常处理的结果决定下一步的执行

![image-20220401213954580.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-69ad3f54261b1bd000be8cbcea0937b7823cb133.png)

实现代码如下

```c++
// Debug4.cpp : Defines the entry point for the console application.  
//  
​  
#include "stdafx.h"  
#include <stdio.h>  
#include <windows.h>  
#include <tlhelp32.h>  
​  
#define DEBUGGEE "C:\\\\ipmsg.exe"  
​  
//被调试进程ID,进程句柄，OEP  
DWORD dwDebuggeePID \= 0;  
​  
//被调试线程句柄  
HANDLE hDebuggeeThread \= NULL;  
HANDLE hDebuggeeProcess \= NULL;  
​  
//系统断点  
BOOL bIsSystemInt3 \= TRUE;  
​  
//被INT 3覆盖的数据  
CHAR OriginalCode \= 0;  
​  
//线程上下文  
CONTEXT Context;  
​  
typedef HANDLE (\_\_stdcall \*FnOpenThread) (DWORD, BOOL, DWORD);  
​  
VOID InitDebuggeeInfo(DWORD dwPID, HANDLE hProcess)  
{  
    dwDebuggeePID \= dwPID;  
    hDebuggeeProcess \= hProcess;  
}  
​  
DWORD GetProcessId(LPTSTR lpProcessName)  
{  
    HANDLE hProcessSnap \= NULL;  
    PROCESSENTRY32 pe32 \= {0};  

    hProcessSnap \= CreateToolhelp32Snapshot(TH32CS\_SNAPPROCESS, 0);  
    if(hProcessSnap \== (HANDLE)\-1)  
    {  
        return 0;  
    }  

    pe32.dwSize \= sizeof(PROCESSENTRY32);  

    if(Process32First(hProcessSnap, &pe32))  
    {  
        do   
        {  
            if(!strcmp(lpProcessName, pe32.szExeFile))  
                return (int)pe32.th32ProcessID;  
        } while (Process32Next(hProcessSnap, &pe32));  
    }  
    else  
    {  
        CloseHandle(hProcessSnap);  
    }  

    return 0;  
}  
​  
BOOL WaitForUserCommand()  
{  
    BOOL bRet \= FALSE;  
    CHAR command;  
​  
    printf("COMMAND > ");  
​  
    command \= getchar();  
​  
    switch(command)  
    {  
        // into  
    case 't':  
        bRet \= TRUE;  
        break;  
        // pass  
    case 'p':  
        bRet \= TRUE;  
        break;  
        // go  
    case 'g':  
        bRet \= TRUE;  
        break;  
    }  
​  
    getchar();  
    return bRet;  
}  
​  
BOOL Int3ExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
​  
    //1. 将INT 3修复为原来的数据(如果是系统断点，不用修复)  

    if(bIsSystemInt3)  
    {  
        bIsSystemInt3 \= FALSE;  
        return TRUE;  
    }  
​  
    else  
    {  
        WriteProcessMemory(hDebuggeeProcess, pExceptionInfo\->ExceptionRecord.ExceptionAddress, &OriginalCode, 1, NULL);  
    }  
​  
    //2. 显示断点位置  
    printf("Int 3断点 : 0x%p \\r\\n", pExceptionInfo\->ExceptionRecord.ExceptionAddress);  
​  
    //3. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  

    //4. 修正EIP  
    //printf("Eip : %x\\n",Context.Eip);  
    Context.Eip\--;  
    SetThreadContext(hDebuggeeThread, &Context);  
​  
    //5. 显示反汇编代码、寄存器等  

    //6. 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  

    return bRet;  
}  
​  
BOOL AccessExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= TRUE;  
​  
    return bRet;  
}  
​  
BOOL SingleStepExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= TRUE;  

    return bRet;  
}  
​  
BOOL ExceptionHandler(DEBUG\_EVENT \*pDebugEvent)  
{   
    BOOL bRet \= TRUE;  
    EXCEPTION\_DEBUG\_INFO \*pExceptionInfo \= NULL;  
    pExceptionInfo \= &pDebugEvent\->u.Exception;  
​  
    //得到线程句柄，后面要用  
    FnOpenThread MyOpenThread \= (FnOpenThread)GetProcAddress(LoadLibrary("kernel32.dll"), "OpenThread");  
    hDebuggeeThread \= MyOpenThread(THREAD\_ALL\_ACCESS, FALSE, pDebugEvent\->dwThreadId);  
​  
    switch(pExceptionInfo\->ExceptionRecord.ExceptionCode)  
    {  
    //INT 3异常  
        case EXCEPTION\_BREAKPOINT:  
            bRet \= Int3ExceptionProc(pExceptionInfo);  
            break;  
​  
    //访问异常  
        case EXCEPTION\_ACCESS\_VIOLATION:  
            bRet \= AccessExceptionProc(pExceptionInfo);  
            break;  
​  
    //单步执行  
        case EXCEPTION\_SINGLE\_STEP:  
            bRet \= SingleStepExceptionProc(pExceptionInfo);  
            break;  
    }  
​  
    return bRet;  
}  
​  
void SetInt3BreakPoint(LPVOID addr)  
{  
    ReadProcessMemory(hDebuggeeProcess, addr, &OriginalCode, 1, NULL);  

    BYTE int3\[1\] \= { 0xcc };  
​  
    WriteProcessMemory(hDebuggeeProcess, addr, int3, 1, NULL);  
}  
​  
BOOL ExceptionTest()  
{  
    BOOL nIsContinue \= TRUE;  
    DEBUG\_EVENT debugEvent \= {0};  
    BOOL bRet \= TRUE;  
    DWORD dwContinue \= DBG\_CONTINUE;  
​  
    //1.创建调试进程  
    STARTUPINFO startupInfo \= {0};  
    PROCESS\_INFORMATION pInfo \= {0};  
    GetStartupInfo(&startupInfo);  
​  
    bRet \= CreateProcess(DEBUGGEE, NULL, NULL, NULL, TRUE, DEBUG\_PROCESS || DEBUG\_ONLY\_THIS\_PROCESS, NULL, NULL, &startupInfo, &pInfo);  

    if(!bRet)  
    {  
        printf("CreateProcess error: %d \\n", GetLastError());  
        return 0;  
    }  
​  
    hDebuggeeProcess \= pInfo.hProcess;  
​  
    //2.调试循环  
    while(nIsContinue)  
    {  
        bRet \= WaitForDebugEvent(&debugEvent, INFINITE);  

        if(!bRet)  
        {  
            printf("WaitForDebugEvent error: %d \\n", GetLastError());  
            return 0;  
        }  
​  
        switch(debugEvent.dwDebugEventCode)  
        {  
        //1.异常  
        case EXCEPTION\_DEBUG\_EVENT:  
            bRet \= ExceptionHandler(&debugEvent);  
            if(!bRet)  
                dwContinue \= DBG\_EXCEPTION\_NOT\_HANDLED;  
            break;  
        //2.  
        case CREATE\_THREAD\_DEBUG\_EVENT:  
            break;  
        //3.创建进程  
        case CREATE\_PROCESS\_DEBUG\_EVENT:  
            SetInt3BreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);  
            break;  
        //4.  
        case EXIT\_THREAD\_DEBUG\_EVENT:  
            break;  
        //5.  
        case EXIT\_PROCESS\_DEBUG\_EVENT:  
            break;  
        //6.  
        case LOAD\_DLL\_DEBUG\_EVENT:  
            break;  
        //7.  
        case UNLOAD\_DLL\_DEBUG\_EVENT:  
            break;  
        //8.  
        case OUTPUT\_DEBUG\_STRING\_EVENT:  
            break;  
        }  

        bRet \= ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG\_CONTINUE);  
    }  
​  
    return 0;  
}  
​  
int main(int argc, char\* argv\[\])  
{  
    ExceptionTest();  
​  
    return 0;  
}
```

实现效果

![image-20220401214231280.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-68217bf3803d871c7c74cf0e0e0eeeec078a3ba8.png)

0x02 内存断点
=========

描述：当需要在某块内存被访问时产生中断，可以使用内存断点。

内存断点能够分为两种类型：

> 内存访问：内存被读写时产生中断。  
> 内存写入：内存被写入时产生中断。

原理：VirtualProtectEx

```c++
BOOL VirtualProtectEx(  
    HANDLE hProcess,        // handle to process  
    LPVOID lpAddress,       // region of committed pages  
    SIZE\_T dwSize,          // size of region  
    DWORD flNewProtect,     // desired access protection  
    PDWORD lpflOldProtect   // old protection  
);
```

内存访问：将指定内存的属性修改为`PAGE_NOACCESS`（修改后，PTE的P位等于0）

内存写入：将指定内存的属性修改为`PAGE_EXECUTE_READ`（修改后，PTE的P位等于1，R/W位等于0）

流程
--

被调试进程：

> 1）CPU访问错误的内存地址，触发页异常  
> 2）查IDT表找到对应的中断处理函数（`nt!_KiTrap0E`）  
> 3）`CommonDispatchException`  
> 4）`KiDispatchException`  
> 5）`DbgkForwardException`收集并发送调试事件

最终调用`DbgkpSendApiMessage(x, x)` 第一个参数：消息类型，共有7种类型 第二个参数：是否挂起其它线程

调试器进程：

> 1）循环判断  
> 2）取出调试事件  
> 3）列出消息（寄存器/内存）  
> 4）用户处理

在创建进程的地方使用内存断点

![image-20220402154008317.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-14445432dc2196bc87a8750bff11da64b8a23fab.png)

通过修改PTE的P=0来设置页不可访问

![image-20220402154028491.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f28141b455b0514e03a8d83155b165783a91a19f.png)

我们首先看一下`EXCEPTION_DEBUG_INFO`结构

![image-20220402154800949.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a8e0b8fa28c23a36a4571ad69bf8a5c5dd3f7a1f.png)

然后再看`ExceptionRecord`

![image-20220402154814655.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-37c880038121c6f6f6bc1517a4af7a721a8cef0d.png)

定位到`_EXCEPTION_RECORD`

![image-20220402154853465.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ddf602177ecf2413e1353b497f838fdec06ce076.png)

到msdn里面看一下`EXCEPTION_RECORD`，这里主要关注`ExceptionInformation`

![image-20220402164207943.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-595b752f76db7f63fd0886b1f65def6de504191c.png)

如果这个值为0有线程试图读这块内存，如果这个值为1则有线程试图写这块内存

![image-20220402164349679.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d6fd790934fa2224115c5e67d4e015baa55c4b0c.png)

这里显示出异常的信息，打印异常类型和异常地址

![image-20220402164529085.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8200392a425a92f26315536f8d2c9068e76c1824.png)

内存断点的EIP就是原EIP，不需要进行减的操作

![image-20220402165412874.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-19a99b5209296136cfd5b749c0843a75ed1671ef.png)

![image-20220402165450796.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-518985d9aeeb9b42cf9f0c4202585579f47f83c4.png)

实现代码如下

```c++
// Debug4.cpp : Defines the entry point for the console application.  
//  
​  
#include "stdafx.h"  
#include <stdio.h>  
#include <windows.h>  
#include <tlhelp32.h>  
​  
#define DEBUGGEE "C:\\\\ipmsg.exe"  
​  
//被调试进程ID,进程句柄，OEP  
DWORD dwDebuggeePID \= 0;  
​  
//被调试线程句柄  
HANDLE hDebuggeeThread \= NULL;  
HANDLE hDebuggeeProcess \= NULL;  
​  
//系统断点  
BOOL bIsSystemInt3 \= TRUE;  
​  
//被INT 3覆盖的数据  
CHAR OriginalCode \= 0;  
​  
//原始内存属性  
DWORD dwOriginalProtect;  
​  
//线程上下文  
CONTEXT Context;  
​  
typedef HANDLE (\_\_stdcall \*FnOpenThread) (DWORD, BOOL, DWORD);  
​  
VOID InitDebuggeeInfo(DWORD dwPID, HANDLE hProcess)  
{  
    dwDebuggeePID \= dwPID;  
    hDebuggeeProcess \= hProcess;  
}  
​  
DWORD GetProcessId(LPTSTR lpProcessName)  
{  
    HANDLE hProcessSnap \= NULL;  
    PROCESSENTRY32 pe32 \= {0};  

    hProcessSnap \= CreateToolhelp32Snapshot(TH32CS\_SNAPPROCESS, 0);  
    if(hProcessSnap \== (HANDLE)\-1)  
    {  
        return 0;  
    }  

    pe32.dwSize \= sizeof(PROCESSENTRY32);  

    if(Process32First(hProcessSnap, &pe32))  
    {  
        do   
        {  
            if(!strcmp(lpProcessName, pe32.szExeFile))  
                return (int)pe32.th32ProcessID;  
        } while (Process32Next(hProcessSnap, &pe32));  
    }  
    else  
    {  
        CloseHandle(hProcessSnap);  
    }  

    return 0;  
}  
​  
BOOL WaitForUserCommand()  
{  
    BOOL bRet \= FALSE;  
    CHAR command;  
​  
    printf("COMMAND>");  
​  
    command \= getchar();  
​  
    switch(command)  
    {  
    case 't':  
        bRet \= TRUE;  
        break;  
    case 'p':  
        bRet \= TRUE;  
        break;  
    case 'g':  
        bRet \= TRUE;  
        break;  
    }  
​  
    getchar();  
    return bRet;  
}  
​  
BOOL Int3ExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
​  
    //1. 将INT 3修复为原来的数据（如果是系统断点，不用修复）  
    if(bIsSystemInt3)  
    {  
        bIsSystemInt3 \= FALSE;  
        return TRUE;  
    }  
    else  
    {  
        WriteProcessMemory(hDebuggeeProcess, pExceptionInfo\->ExceptionRecord.ExceptionAddress, &OriginalCode, 1, NULL);  
    }  
​  
    //2. 显示断点位置  
    printf("Int 3断点 : 0x%p \\r\\n", pExceptionInfo\->ExceptionRecord.ExceptionAddress);  
​  
    //3. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  

    //4. 修正EIP  
    Context.Eip\--;  
    SetThreadContext(hDebuggeeThread, &Context);  
​  
    //5. 显示反汇编代码、寄存器等  

    //6. 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  

    return bRet;  
}  
​  
BOOL AccessExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
    DWORD dwAccessFlag; //访问类型 0为读 1为写  
    DWORD dwAccessAddr; //访问地址  
    DWORD dwProtect;    //内存属性  
​  
    //1. 获取异常信息，修改内存属性  
    dwAccessFlag \= pExceptionInfo\->ExceptionRecord.ExceptionInformation\[0\];  
    dwAccessAddr \= pExceptionInfo\->ExceptionRecord.ExceptionInformation\[1\];  
    printf("内存断点 : dwAccessFlag - %x dwAccessAddr - %x \\n", dwAccessFlag, dwAccessAddr);  
    VirtualProtectEx(hDebuggeeProcess, (VOID\*)dwAccessAddr, 1, dwOriginalProtect, &dwProtect);  

    //2. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  
    //3. 修正EIP(内存访问异常，不需要修正EIP)  
    printf("Eip: 0x%p \\n", Context.Eip);  
    //4. 显示汇编/寄存器等信息  
    //5. 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  
​  
    return bRet;  
}  
​  
BOOL SingleStepExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= TRUE;  

    return bRet;  
}  
​  
BOOL ExceptionHandler(DEBUG\_EVENT \*pDebugEvent)  
{   
    BOOL bRet \= TRUE;  
    EXCEPTION\_DEBUG\_INFO \*pExceptionInfo \= NULL;  
​  
    pExceptionInfo \= &pDebugEvent\->u.Exception;  
​  
    //得到线程句柄，后面要用  
    FnOpenThread MyOpenThread \= (FnOpenThread)GetProcAddress(LoadLibrary("kernel32.dll"), "OpenThread");  
    hDebuggeeThread \= MyOpenThread(THREAD\_ALL\_ACCESS, FALSE, pDebugEvent\->dwThreadId);  
​  
    switch(pExceptionInfo\->ExceptionRecord.ExceptionCode)  
    {  
    //INT 3异常  
    case EXCEPTION\_BREAKPOINT:  
        {  
            bRet \= Int3ExceptionProc(pExceptionInfo);  
            break;  
        }  
    //访问异常  
    case EXCEPTION\_ACCESS\_VIOLATION:  
        bRet \= AccessExceptionProc(pExceptionInfo);  
        break;  
    //单步执行  
    case EXCEPTION\_SINGLE\_STEP:  
        bRet \= SingleStepExceptionProc(pExceptionInfo);  
        break;  
    }  
​  
    return bRet;  
}  
​  
VOID SetInt3BreakPoint(LPVOID addr)  
{  
    CHAR int3 \= 0xCC;  

    //1. 备份  
    ReadProcessMemory(hDebuggeeProcess, addr, &OriginalCode, 1, NULL);  
    //2. 修改  
    WriteProcessMemory(hDebuggeeProcess, addr, &int3, 1, NULL);  
}  
​  
VOID SetMemBreakPoint(PCHAR pAddress)  
{  
    //1. 访问断点  
    VirtualProtectEx(hDebuggeeProcess, pAddress, 1, PAGE\_NOACCESS, &dwOriginalProtect); //PTE P=0  
    //2. 写入断点  
    //VirtualProtectEx(hDebuggeeProcess, pAddress, 1, PAGE\_EXECUTE\_READ, &dwOriginalProtect);   //PTE R/W=0  
}  
​  
int main(int argc, char\* argv\[\])  
{  
    BOOL nIsContinue \= TRUE;  
    DEBUG\_EVENT debugEvent \= {0};  
    BOOL bRet \= TRUE;  
    DWORD dwContinue \= DBG\_CONTINUE;  
​  
    //1.创建调试进程  
    STARTUPINFO startupInfo \= {0};  
    PROCESS\_INFORMATION pInfo \= {0};  
    GetStartupInfo(&startupInfo);  
​  
    bRet \= CreateProcess(DEBUGGEE, NULL, NULL, NULL, TRUE, DEBUG\_PROCESS || DEBUG\_ONLY\_THIS\_PROCESS, NULL, NULL, &startupInfo, &pInfo);  
    if(!bRet)  
    {  
        printf("CreateProcess error: %d \\n", GetLastError());  
        return 0;  
    }  
​  
    hDebuggeeProcess \= pInfo.hProcess;  
​  
    //2.调试循环  
    while(nIsContinue)  
    {  
        bRet \= WaitForDebugEvent(&debugEvent, INFINITE);  
        if(!bRet)  
        {  
            printf("WaitForDebugEvent error: %d \\n", GetLastError());  
            return 0;  
        }  
​  
        switch(debugEvent.dwDebugEventCode)  
        {  
        //1.异常  
        case EXCEPTION\_DEBUG\_EVENT:  
            bRet \= ExceptionHandler(&debugEvent);  
            if(!bRet)  
                dwContinue \= DBG\_EXCEPTION\_NOT\_HANDLED;  
            break;  
        //2.  
        case CREATE\_THREAD\_DEBUG\_EVENT:  
            break;  
        //3.创建进程  
        case CREATE\_PROCESS\_DEBUG\_EVENT:  
            //int3 断点  
            //SetInt3BreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);  
            //内存断点  
            SetMemBreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);  
            break;  
        //4.  
        case EXIT\_THREAD\_DEBUG\_EVENT:  
            break;  
        //5.  
        case EXIT\_PROCESS\_DEBUG\_EVENT:  
            break;  
        //6.  
        case LOAD\_DLL\_DEBUG\_EVENT:  
            break;  
        //7.  
        case UNLOAD\_DLL\_DEBUG\_EVENT:  
            break;  
        //8.  
        case OUTPUT\_DEBUG\_STRING\_EVENT:  
            break;  
        }  

        bRet \= ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG\_CONTINUE);  
    }  

    return 0;  
}
```

实现效果如下

![image-20220402165639018.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-27b4ac09b798e6a514c4a92cdcdd245cdd619fbe.png)

0x03 硬件断点
=========

1. 与软件断点与内存断点不同，**硬件断点**不依赖被调试程序，而是依赖于CPU中的**调试寄存器**。
2. 调试寄存器有**7个**，分别为**Dr0~Dr7**。
3. 用户最多能够设置4个硬件断点，这是由于只有Dr0~Dr3用于存储线性地址。
4. 其中，Dr4和Dr5是保留的。

![image-20220402185424231.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9aea81a78b137f769283a57c7ced664f44e5c856.png)

那么假如在Dr0寄存器中写入线性地址，是否所有线程都会受影响？

实际上是不会的，每个线程都拥有一份独立的寄存器，切换线程时，寄存器的值也会被切换。

设置硬件断点
------

Dr0~Dr3用于设置硬件断点，由于只有4个断点寄存器，所以最多只能设置4个硬件调试断点，在7个寄存器中，Dr7是最重要的寄存器

L0/G0 ~ L3/G3：控制Dr0~Dr3是否有效，局部还是全局；每次异常后，Lx都被清零，Gx不清零。

若Dr0有效，L0=1则为局部，G0=1则为全局，以此类推

![image-20220402213248841.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-713b5336f5614ed3ac406bcba6f0084f295469f6.png)  
断点长度(LENx)：00(1字节)、01(2字节)、11(4字节)

通过DR7的LEN控制

![image-20220402213410805.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-20c64ad205b4d14882d06702d004c50c91a9d33f.png)

断点类型(R/Wx)：00(执行断点)、01(写入断点)、11(访问断点)

![image-20220402213439641.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8d4225f6597a886d1213e054667a8aa391052167.png)

流程
--

被调试进程：

> 1）CPU执行时检测当前线性地址与调试寄存器（Dr0~Dr3）中的线性地址相等。 &gt;2）查IDT表找到对应的中断处理函数（`nt!_KiTrap01`）  
> 3）CommonDispatchException  
> 4）KiDispatchException  
> 5）DbgkForwardException收集并发送调试事件

最终调用`DbgkpSendApiMessage(x, x)` 第一个参数：消息类型 第二个参数：是否挂起其它线程

调试器进程：

> 1）循环判断  
> 2）取出调试事件  
> 3）列出信息：寄存器、内存  
> 4）用户处理

处理硬件断点
------

> 1）硬件调试断点产生的异常是 `STATUS_SINGLE_STEP`（单步异常）  
> 2）检测Dr6寄存器的B0~B3：哪个寄存器触发的异常

这里硬件断点有两种情况，一种情况是dr0-dr3寄存器引发的异常，另外一种情况就是`TF=1`引发的异常

![image-20220402215101783.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-60852a97df6fe39225f7731c6212cc7a75d454e7.png)

这里如果是DR0寄存器引发的异常，那么`B0=1`，以此类推 如果是`TF=1`引发的异常，那么DR6的低4位为全0

首先看一下异常处理函数

```c++
BOOL SingleStepExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
​  
    //1. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  
    //2. 判断是否是硬件断点导致的异常  
    if(Context.Dr6 & 0xF)   //B0~B3不为空 硬件断点  
    {  
        //2.1 显示断点信息  
        printf("硬件断点：%x 0x%p \\n", Context.Dr7&0x00030000, Context.Dr0);  
        //2.2 将断点去除  
        Context.Dr0 \= 0;  
        Context.Dr7 &= 0xfffffffe;  
    }  
    else    //单步异常  
    {  
        //2.1 显示断点信息  
        printf("单步：0x%p \\n", Context.Eip);  
        //2.2 将断点去除  
        Context.Dr7 &= 0xfffffeff;  
    }  
​  
    SetThreadContext(hDebuggeeThread, &Context);  
​  
    // 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  

    return bRet;  
}
```

之前我们是在创建进程的时候进行断点，但是因为硬件断点需要在线程创建完成之后，设置在被调试程序的上下文中

![image-20220402214947584.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5d34b88b996add81edea9aa6d01c266cf61c0e9b.png)

因此当被调试程序触发调试器设置的INT 3断点时，此时设置硬件断点较为合理

![image-20220402215101783.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-92c3931ef45e3fab3f8d0ec39284976fb92a4c83.png)

再就是硬件断点的代码，这里把Dr0寄存器置1，然后把16、17为置0为执行断点，异常长度为1字节(18、19位置0)，地址的话就是`int3`断点的地址+1

```php
VOID SetHardBreakPoint(PVOID pAddress)  
{  
    //1. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  
    //2. 设置断点位置  
    Context.Dr0 \= (DWORD)pAddress;  
    Context.Dr7 |= 1;  
    //3. 设置断点长度和类型  
    Context.Dr7 &= 0xfff0ffff;  //执行断点（16、17位 置0） 1字节（18、19位 置0）  
    //5. 设置线程上下文  
    SetThreadContext(hDebuggeeThread, &Context);  
}
```

完整代码如下

```c++
// Debug4.cpp : Defines the entry point for the console application.  
//  
​  
#include "stdafx.h"  
#include <stdio.h>  
#include <windows.h>  
#include <tlhelp32.h>  
​  
#define DEBUGGEE "C:\\\\ipmsg.exe"  
​  
//被调试进程ID,进程句柄，OEP  
DWORD dwDebuggeePID \= 0;  
​  
//被调试线程句柄  
HANDLE hDebuggeeThread \= NULL;  
HANDLE hDebuggeeProcess \= NULL;  
​  
//系统断点  
BOOL bIsSystemInt3 \= TRUE;  
​  
//被INT 3覆盖的数据  
CHAR OriginalCode \= 0;  
​  
//原始内存属性  
DWORD dwOriginalProtect;  
​  
//线程上下文  
CONTEXT Context;  
​  
typedef HANDLE (\_\_stdcall \*FnOpenThread) (DWORD, BOOL, DWORD);  
​  
VOID InitDebuggeeInfo(DWORD dwPID, HANDLE hProcess)  
{  
    dwDebuggeePID \= dwPID;  
    hDebuggeeProcess \= hProcess;  
}  
​  
DWORD GetProcessId(LPTSTR lpProcessName)  
{  
    HANDLE hProcessSnap \= NULL;  
    PROCESSENTRY32 pe32 \= {0};  

    hProcessSnap \= CreateToolhelp32Snapshot(TH32CS\_SNAPPROCESS, 0);  
    if(hProcessSnap \== (HANDLE)\-1)  
    {  
        return 0;  
    }  

    pe32.dwSize \= sizeof(PROCESSENTRY32);  

    if(Process32First(hProcessSnap, &pe32))  
    {  
        do   
        {  
            if(!strcmp(lpProcessName, pe32.szExeFile))  
                return (int)pe32.th32ProcessID;  
        } while (Process32Next(hProcessSnap, &pe32));  
    }  
    else  
    {  
        CloseHandle(hProcessSnap);  
    }  

    return 0;  
}  
​  
BOOL WaitForUserCommand()  
{  
    BOOL bRet \= FALSE;  
    CHAR command;  
​  
    printf("COMMAND>");  
​  
    command \= getchar();  
​  
    switch(command)  
    {  
    case 't':  
        bRet \= TRUE;  
        break;  
    case 'p':  
        bRet \= TRUE;  
        break;  
    case 'g':  
        bRet \= TRUE;  
        break;  
    }  
​  
    getchar();  
    return bRet;  
}  
​  
VOID SetHardBreakPoint(PVOID pAddress)  
{  
    //1. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  
    //2. 设置断点位置  
    Context.Dr0 \= (DWORD)pAddress;  
    Context.Dr7 |= 1;  
    //3. 设置断点长度和类型  
    Context.Dr7 &= 0xfff0ffff;  //执行断点（16、17位 置0） 1字节（18、19位 置0）  
    //5. 设置线程上下文  
    SetThreadContext(hDebuggeeThread, &Context);  
}  
​  
BOOL Int3ExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
​  
    //1. 将INT 3修复为原来的数据（如果是系统断点，不用修复）  
    if(bIsSystemInt3)  
    {  
        bIsSystemInt3 \= FALSE;  
        return TRUE;  
    }  
    else  
    {  
        WriteProcessMemory(hDebuggeeProcess, pExceptionInfo\->ExceptionRecord.ExceptionAddress, &OriginalCode, 1, NULL);  
    }  
​  
    //2. 显示断点位置  
    printf("Int 3断点：0x%p \\r\\n", pExceptionInfo\->ExceptionRecord.ExceptionAddress);  
​  
    //3. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  

    //4. 修正EIP  
    Context.Eip\--;  
    SetThreadContext(hDebuggeeThread, &Context);  
​  
    //5. 显示反汇编代码、寄存器等  
​  
    /\*  
    硬件断点需要设置在被调试进程的的线程上下文中。  
    因此当被调试程序触发调试器设置的INT 3断点时，此时设置硬件断点较为合理。  
    \*/  
    SetHardBreakPoint((PVOID)((DWORD)pExceptionInfo\->ExceptionRecord.ExceptionAddress+1));  

    //6. 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  

    return bRet;  
}  
​  
BOOL AccessExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
    DWORD dwAccessFlag; //访问类型 0为读 1为写  
    DWORD dwAccessAddr; //访问地址  
    DWORD dwProtect;    //内存属性  
​  
    //1. 获取异常信息，修改内存属性  
    dwAccessFlag \= pExceptionInfo\->ExceptionRecord.ExceptionInformation\[0\];  
    dwAccessAddr \= pExceptionInfo\->ExceptionRecord.ExceptionInformation\[1\];  
    printf("内存断点 : dwAccessFlag - %x dwAccessAddr - %x \\n", dwAccessFlag, dwAccessAddr);  
    VirtualProtectEx(hDebuggeeProcess, (VOID\*)dwAccessAddr, 1, dwOriginalProtect, &dwProtect);  

    //2. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  
    //3. 修正EIP(内存访问异常，不需要修正EIP)  
    printf("Eip: 0x%p \\n", Context.Eip);  
    //4. 显示汇编/寄存器等信息  
    //5. 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  
​  
    return bRet;  
}  
​  
BOOL SingleStepExceptionProc(EXCEPTION\_DEBUG\_INFO \*pExceptionInfo)  
{  
    BOOL bRet \= FALSE;  
​  
    //1. 获取线程上下文  
    Context.ContextFlags \= CONTEXT\_FULL | CONTEXT\_DEBUG\_REGISTERS;  
    GetThreadContext(hDebuggeeThread, &Context);  
    //2. 判断是否是硬件断点导致的异常  
    if(Context.Dr6 & 0xF)   //B0~B3不为空 硬件断点  
    {  
        //2.1 显示断点信息  
        printf("硬件断点：%x 0x%p \\n", Context.Dr7&0x00030000, Context.Dr0);  
        //2.2 将断点去除  
        Context.Dr0 \= 0;  
        Context.Dr7 &= 0xfffffffe;  
    }  
    else    //单步异常  
    {  
        //2.1 显示断点信息  
        printf("单步：0x%p \\n", Context.Eip);  
        //2.2 将断点去除  
        Context.Dr7 &= 0xfffffeff;  
    }  
​  
    SetThreadContext(hDebuggeeThread, &Context);  
​  
    //6. 等待用户命令  
    while(bRet \== FALSE)  
    {  
        bRet \= WaitForUserCommand();  
    }  

    return bRet;  
}  
​  
BOOL ExceptionHandler(DEBUG\_EVENT \*pDebugEvent)  
{   
    BOOL bRet \= TRUE;  
    EXCEPTION\_DEBUG\_INFO \*pExceptionInfo \= NULL;  
    pExceptionInfo \= &pDebugEvent\->u.Exception;  
    //得到线程句柄，后面要用  
    FnOpenThread MyOpenThread \= (FnOpenThread)GetProcAddress(LoadLibrary("kernel32.dll"), "OpenThread");  
    hDebuggeeThread \= MyOpenThread(THREAD\_ALL\_ACCESS, FALSE, pDebugEvent\->dwThreadId);  
​  
    switch(pExceptionInfo\->ExceptionRecord.ExceptionCode)  
    {  
    //INT 3异常  
    case EXCEPTION\_BREAKPOINT:  
        bRet \= Int3ExceptionProc(pExceptionInfo);  
        break;  
    //访问异常  
    case EXCEPTION\_ACCESS\_VIOLATION:  
        bRet \= AccessExceptionProc(pExceptionInfo);  
        break;  
    //单步执行  
    case EXCEPTION\_SINGLE\_STEP:  
        bRet \= SingleStepExceptionProc(pExceptionInfo);  
        break;  
    }  
​  
    return bRet;  
}  
​  
VOID SetInt3BreakPoint(LPVOID addr)  
{  
    CHAR int3 \= 0xCC;  

    //1. 备份  
    ReadProcessMemory(hDebuggeeProcess, addr, &OriginalCode, 1, NULL);  
    //2. 修改  
    WriteProcessMemory(hDebuggeeProcess, addr, &int3, 1, NULL);  
}  
​  
VOID SetMemBreakPoint(PCHAR pAddress)  
{  
    //1. 访问断点  
    VirtualProtectEx(hDebuggeeProcess, pAddress, 1, PAGE\_NOACCESS, &dwOriginalProtect); //PTE P=0  
    //2. 写入断点  
    //VirtualProtectEx(hDebuggeeProcess, pAddress, 1, PAGE\_EXECUTE\_READ, &dwOriginalProtect);   //PTE R/W=0  
}  
​  
int main(int argc, char\* argv\[\])  
{  
    BOOL nIsContinue \= TRUE;  
    DEBUG\_EVENT debugEvent \= {0};  
    BOOL bRet \= TRUE;  
    DWORD dwContinue \= DBG\_CONTINUE;  
​  
    //1.创建调试进程  
    STARTUPINFO startupInfo \= {0};  
    PROCESS\_INFORMATION pInfo \= {0};  
    GetStartupInfo(&startupInfo);  
​  
    bRet \= CreateProcess(DEBUGGEE, NULL, NULL, NULL, TRUE, DEBUG\_PROCESS || DEBUG\_ONLY\_THIS\_PROCESS, NULL, NULL, &startupInfo, &pInfo);  
    if(!bRet)  
    {  
        printf("CreateProcess error: %d \\n", GetLastError());  
        return 0;  
    }  
​  
    hDebuggeeProcess \= pInfo.hProcess;  
​  
    //2.调试循环  
    while(nIsContinue)  
    {  
        bRet \= WaitForDebugEvent(&debugEvent, INFINITE);  
        if(!bRet)  
        {  
            printf("WaitForDebugEvent error: %d \\n", GetLastError());  
            return 0;  
        }  
​  
        switch(debugEvent.dwDebugEventCode)  
        {  
        //1.异常  
        case EXCEPTION\_DEBUG\_EVENT:  
            bRet \= ExceptionHandler(&debugEvent);  
            if(!bRet)  
                dwContinue \= DBG\_EXCEPTION\_NOT\_HANDLED;  
            break;  
        //2.  
        case CREATE\_THREAD\_DEBUG\_EVENT:  
            break;  
        //3.创建进程  
        case CREATE\_PROCESS\_DEBUG\_EVENT:  
            //int3 断点  
            SetInt3BreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);  
            //内存断点  
            //SetMemBreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);  
            break;  
        //4.  
        case EXIT\_THREAD\_DEBUG\_EVENT:  
            break;  
        //5.  
        case EXIT\_PROCESS\_DEBUG\_EVENT:  
            break;  
        //6.  
        case LOAD\_DLL\_DEBUG\_EVENT:  
            break;  
        //7.  
        case UNLOAD\_DLL\_DEBUG\_EVENT:  
            break;  
        //8.  
        case OUTPUT\_DEBUG\_STRING\_EVENT:  
            break;  
        }  

        bRet \= ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG\_CONTINUE);  
    }  

    return 0;  
}
```

实现效果如下

![image-20220402215902212.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c19657383b9d657d60cee261fa7066803e5824bf.png)