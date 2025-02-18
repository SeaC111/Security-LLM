0x00 前言
=======

断链这种技术非常古老，同时应用于非常多的场景，在内核层如果我们需要隐藏一个进程的内核结构体，也会使用这种技术。本文基于PEB断链在用户层和内核层分别进行实现，在用户层达到的效果主要是dll模块的隐藏，在内核层达到的效果主要是进程的隐藏。

0x01 3环PEB断链
============

每个线程都有一个TEB结构来存储线程的一些属性结构，TEB的地址用`fs:[0]`来获取，在0x30这个地址有一个指针指向`PEB`结构

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-36fd1e97e914388ddbbb8aff457b9ee928583e5c.png)

然后定位到PEB，PEB就是进程用来记录自己信息的一个结构，在PEB的`0x00c`偏移有一个 `Ldr _PEB_LDR_DATA`结构跟进去

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-122119c9a5a220715639d2a7df7e0762ceb72526.png)

在`_PEB_LDR_DATA`里有三个双向链表

> `InLoadOrderModuleList`：模块加载的顺序
> 
> `InMemoryOrderModuleList`：模块在内存的顺序
> 
> `InInitializationOrderModuleList`：模块初始化的顺序

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-82ca0cea2700726abe6c13025ba0f2cd3d762322.png)

以`InLoadOrderModuleList`为例，双向链表的含义起始就是最后的指针会指向自己

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f3f8c6e3b2fc2658045c366a9f30532a635e6959.png)

那么了解了基本原理之后我们就可以通过断链来实现模块的隐藏，我们知道如果要枚举模块一般都是使用`CreateToolhelp32Snapshot`拍摄快照，然后找到模块列表之后进行遍历，其实api也是通过找`_PEB_LDR_DATA`这个结构来获取程序有哪些模块，那么我们如果想隐藏某个dll，就可以通过修改这几个双向链表的方法来进行隐藏

`_DRIVER_OBJECT` 结构体中 0x014的偏移有一个成员，`DriverSection` 可以实现对内核模块的遍历。DriverSection 是一个指针，实际上是对应着一个结构体：`_LDR_DATA_TABLE_ENTRY`

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a81e0efc6ec7363f147ab67845f718599d21ebfb.png)

在`_LDR_DATA_TABLE_ENTRY`的0x018偏移处有一个`DllBase`，这里存放的就是dll的地址

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d24eda999218afc5a6c762aa6e2f8097d9e589de.png)

所以这里我们如果要想隐藏某个指定的dll，就可以通过`DllBase`的方式，通过`GetModuleHandleA`获取dll的句柄，来进行比对

0x02 实现
=======

那么我们首先定义`_PEB_LDR_DATA`和`_LDR_DATA_TABLE_ENTRY`结构

```c++
// LDR链表头
typedef struct _PEB_LDR_DATA
{
    DWORD Length;
    bool Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList; // 指向了 InLoadOrderModuleList 链表的第一项
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA,*PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    void*               BaseAddress;
    void*               EntryPoint;  
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    HANDLE              SectionHandle;
    ULONG               CheckSum;
    ULONG               TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

然后通过汇编定位到LDR

```c++
    __asm
    {
        mov eax,fs:[0x30] // PEB 
        mov ecx,[eax + 0x0c] // LDR
        mov ldr,ecx  
    }
```

因为这里三个双向链表的结构都是一样的，这里就以`InLoadOrderModuleList`来进行断链示范，这里要实现断链，最简单的做法就是让Head的Flink和Blink指向它自己

首先通过获取到的ldr结构指向`InLoadOrderModuleList`

```c++
Head = &(ldr->InLoadOrderModuleList);
```

然后通过`CONTAINING_RECORD`这个宏返回结构体基址

```c++
Cur = Head->Flink;
ldte = CONTAINING_RECORD( Cur, LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList); 
```

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-779788bb1189cbe40967c1be5f91bcb0ddc5261b.png)

```c++
void CONTAINING_RECORD(
   address,
   type,
   field
);
```

进行断链操作

```php
        ldte->InInitializationOrderModuleList.Blink->Flink = ldte->InInitializationOrderModuleList.Flink;  
        ldte->InInitializationOrderModuleList.Flink->Blink = ldte->InInitializationOrderModuleList.Blink;   
```

然后将指针指向下一个结构

```c++
Cur = Cur->Flink;
```

因为需要遍历链表进行断链指向自身的操作，这里就需要写一个循环进行断链，完整代码如下

```c++
// killPEB.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    DWORD Length;
    bool Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA,*PPEB_LDR_DATA;

// LDR表项，存储了模块信息
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    void*               BaseAddress;
    void*               EntryPoint;  
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    HANDLE              SectionHandle;
    ULONG               CheckSum;
    ULONG               TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

void HideModule(HMODULE hModule)
{   
    PPEB_LDR_DATA ldr;  
    PLDR_DATA_TABLE_ENTRY ldte;
    __asm
    {
        mov eax,fs:[0x30]  
        mov ecx,[eax + 0x0c] 
        mov ldr,ecx  
    }

    PLIST_ENTRY Head, Cur; 

    Head = &(ldr->InLoadOrderModuleList);
    Cur = Head->Flink;

    do
    {

        ldte = CONTAINING_RECORD( Cur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (ldte->BaseAddress == hModule)
        {       

            ldte->InLoadOrderModuleList.Blink->Flink = ldte->InLoadOrderModuleList.Flink;  
            ldte->InLoadOrderModuleList.Flink->Blink = ldte->InLoadOrderModuleList.Blink;        
        }
        Cur = Cur->Flink;
    } while(Head != Cur);

    Head = &(ldr->InMemoryOrderModuleList);
    Cur = Head->Flink;

    do  
    {  

        ldte = CONTAINING_RECORD( Cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);  
        if (ldte->BaseAddress == hModule)
        {

            ldte->InMemoryOrderModuleList.Blink->Flink = ldte->InMemoryOrderModuleList.Flink;  
            ldte->InMemoryOrderModuleList.Flink->Blink = ldte->InMemoryOrderModuleList.Blink;        
        }
        Cur = Cur->Flink;

    } while(Head != Cur);

    Head = &(ldr->InInitializationOrderModuleList);
    Cur = Head->Flink;

    do  
    {  

        ldte = CONTAINING_RECORD( Cur, LDR_DATA_TABLE_ENTRY, InInitializationOrderModuleList);  
        if (ldte->BaseAddress == hModule)
        {

            ldte->InInitializationOrderModuleList.Blink->Flink = ldte->InInitializationOrderModuleList.Flink;  
            ldte->InInitializationOrderModuleList.Flink->Blink = ldte->InInitializationOrderModuleList.Blink;                   
        }
        Cur = Cur->Flink;
    } while(Head != Cur);
}

int main(int argc, CHAR* argv[])
{
    printf("点任意按键开始断链");
    getchar();
    HideModule(GetModuleHandleA("kernel32.dll"));
    printf("断链成功\n");
    getchar();
    return 0;
}
```

这里在没有开始断链的时候可以看到是由3个模块的

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2834d117d48f7a0b499b686ca01677ad6be35668.png)

锻炼之后可以发现`kerner32.dll`已经被隐藏

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-74e32c02b0b9f1112628330867336fff4634d381.png)

如果要实现所有模块的隐藏，直接将模块判断的代码删除即可

```c++
void HideModule_All()
{   
    PPEB_LDR_DATA ldr;  
    PLDR_DATA_TABLE_ENTRY ldte;
    // 获取LDR
    __asm
    {
        mov eax,fs:[0x30] 
        mov ecx,[eax + 0x0c] 
        mov ldr,ecx  
    }

    PLIST_ENTRY Head; 

    Head = &(ldr->InLoadOrderModuleList);
    Head->Flink = Head->Blink = Head;
    Head = &(ldr->InMemoryOrderModuleList);
    Head->Flink = Head->Blink = Head;
    Head = &(ldr->InInitializationOrderModuleList);
    Head->Flink = Head->Blink = Head;   
}
```

实现效果如下

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f1b88f95b2c48e41b09d269301c0cfa82ea0aa08.png)

锻炼之后，模块已经全部看不到了

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5d5a971b8252526f02ec20d5cf56af4d4e0227f9.png)

0x03 0环PEB断链
============

在操作系统层面上，进程本质上就是一个结构体，当操作系统想要创建一个进程时，就分配一块内存，填入一个结构体，并为结构体中的每一项填充一些具体值。而这个结构体，就是`EPROCESS`

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2a0d404d59c3e577d8fc3bb767ac18e8ad9c2d7c.png)

在`+0x088`偏移处有一个指针`ActiveProcessLinks`，指向的是 `_LIST_ENTRY`。它是双向链表，所有的活动进程都连接在一起，构成了一个链表

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-54ee98e34231eae218afaea1d5682cb8c397e75b.png)

那么链表总有一个头，全局变量`PsActiveProcessHead`（八个字节）指向全局链表头。这个链表跟进程隐藏有关，只要我们把想要隐藏进程对应的`EPROCESS`的链断掉，就可以达到在0环进程隐藏的目的。

我们看一下`PsActiveProcessHead`

```c++
kd> dd PsActiveProcessHead
```

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0d760db67244f66b9c56e00ce74d98c2aae3ce5b.png)

前四个字节指向的是下一个`EPROCESS`结构，但指向的并不是EPROCESS的首地址，而是每一个进程的 `_EPROCESS + 0x88`的位置

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9b956ea8ac57ff6549828171ad23559dd40b9410.png)

所以当我们要查询下一个进程结构时，需要 -0x88。比如当前`PsActiveProcessHead`指向的下一个地址为`0x863b58b8`

```c++
kd> dt _EPROCESS 863b58b8-0x88
```

在0x174偏移的地方存储着进程名，我们可以看到第一个`EPROCESS`结构对应的是`System`进程，这里0x88偏移存放的就是下一个`EPROCESS`结构的地址，但是这里注意，因为这个结构的地址是指向下一个链表的地址，所以如果要得到`EPROCESS`的首结构就需要`-0x88`

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-db0dd8cac335fe4a76230678515d426ef8b0915d.png)

我们通过偏移得到下一个`EPROCESS`结构，可以发现为`smss.exe`进程

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-deb83b571c0a3e296601a13b1ed94fcb2ea2a924.png)

0x04 实现
=======

那么到这里我们的思路就清晰了，通过`EPROCESS`找到我们要隐藏的进程的`ActiveProcessLinks`，将双向链表的值修改，就可以将我们想要隐藏的这个进程的`ActiveProcessLinks`从双向链表中抹去的效果，这里的话如果在windbg里面直接使用`ed`修改的话是比较方便的，但是如果要使用代码来进行修改的话就需要首先定位到`EPROCESS`

在`ETHREAD`的`0x220`偏移得到`ThreadsProcess`，指向的是`_EPROCESS`这个结构体

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9f19106cd5813e7b6775445b36875dcf86e51a8b.png)

那么就可以用汇编实现找到`EPROCESS`结构

```c++
    __asm
    {
        mov eax, fs: [0x124] ;
        mov eax, [eax + 0x220];
        mov pEprocess, eax;
    }
```

首先定义一个指针指向`EPROCESS`结构，并初始化指向`ActiveProcessLinks`的指针

```c++
pCurProcess = pEprocess;

curNode = (PLIST_ENTRY)((ULONG)pCurProcess + 0x88);
```

然后判断通过`EPROCESS`的0x174处的`ImageFileName`来判断进程名是不是我们想要隐藏的进程

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8d653b33198872e9826efa06a90e91a2ca8eec7a.png)

```c++
        ImageFileName = (PCHAR)pCurProcess + 0x174;
        if (strcmp(ImageFileName, "notepad.exe") == 0)
```

如果是我们想要隐藏的进程就执行断链操作

```c++
            curNode = (PLIST_ENTRY)((ULONG)pCurProcess + 0x88);
            nextNode = curNode->Flink;
            preNode = curNode->Blink;

            preNode->Flink = curNode->Flink;

            nextNode->Blink = curNode->Blink;
```

如果不是我们想要的进程就继续往下取`ActiveProcessLinks`的值

```c++
pCurProcess = (PEPROCESS)(*(PULONG)((ULONG)pCurProcess + 0x88) - 0x88);
```

完整代码如下

```c++
#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path);
VOID DriverUnload(PDRIVER_OBJECT driver);

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
    PEPROCESS pEprocess, pCurProcess;
    PCHAR ImageFileName;

    __asm
    {
        mov eax, fs: [0x124] ;
        mov eax, [eax + 0x220];
        mov pEprocess, eax;
    }
    pCurProcess = pEprocess;

    do
    {
        ImageFileName = (PCHAR)pCurProcess + 0x174;
        if (strcmp(ImageFileName, "notepad.exe") == 0)
        {
            PLIST_ENTRY preNode, curNode, nextNode;

            curNode = (PLIST_ENTRY)((ULONG)pCurProcess + 0x88);
            nextNode = curNode->Flink;
            preNode = curNode->Blink;

            preNode->Flink = curNode->Flink;

            nextNode->Blink = curNode->Blink;

            DbgPrint("断链成功!\n");
        }
        pCurProcess = (PEPROCESS)(*(PULONG)((ULONG)pCurProcess + 0x88) - 0x88);
    } while (pEprocess != pCurProcess);

    driver->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    DbgPrint("驱动卸载成功\n");
}
```

实现效果如下

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7a40ee556e29dc5311d8632869a8c393105c9a77.png)

安装驱动之后在任务管理器跟cmd里面都已经看不到`notepad.exe`这个进程

![](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-78f570f0285b9fd025f16e1c46b2ad3ae9b2619c.png)