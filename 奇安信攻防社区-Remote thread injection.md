由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。（本文仅用于交流学习）

基础知识
----

我们先来看看几个Windows的API函数

### CreateProcessA

创建一个进程及其主线程，我们使用这个函数主要就是为了自己创建一个进程，这样可以很方便的获得其标识进程或线程的值（当然也可以通过遍历的方式去获取目标标识进程或线程的值）

MSDN官方文档如下  
<https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-CreateProcessAa>

![212.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-ee0d53809327a6d8a62c143162289030803370a6.png)  
其参数如下

```php
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

函数的具体用法这里不再给出，具体参考MSDN的官方文档即可。

### virtualAllocEx

既然我们是远程线程注入，因此在目标程序中肯定需要一块空间，那么我们就需要使用函数去目标进程中申请一块地址空间  
MSDN参考如下

<https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex>

![208.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-874837d15d080bbf4741225793eec3322f8c77cd.png)  
其参数如下

```php
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

### WriteProcessMemory

我们有了空间，然后我们还需要把其移动进去，因此我们还需要一个函数WriteProcessMemory（将数据写入指定进程中的内存区域，即我们使用virtualAllocEx获得的内存区域）

MSDN参考如下  
<https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory>

![209.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-86a674f6e48f5cec9ff2d74fa21e20b4cf953aa5.png)  
参数如下

```php
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```

主要就是这几个函数，其实现都不难

CreateRemoteThread经典注入
----------------------

我们看看MSDN中对于这个函数的解释

<https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread>

![206.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d6347050f801b316f0bc45aab4efaa5a7bf8a9e3.png)  
参数如下

```php
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```

CreateRemoteThread函数共提供有七个参数，这些看官方文档就一目了然了。  
我们来看看CreateRemoteThread函数的LPTHREAD\_START\_ROUTINE lpStartAddress这个参数，我们看看官方的解释是什么，  
该参数表示的是远程进程中线程的起始地址，有基础的读者应该很快的明白了，我们需要在远程进程中申请一块虚拟地址

![207.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b3996605ed80e2e3aad1d7fce02bf819d0e4c022.png)  
根据前面的基础知识，我们应该就很清楚了

### 代码实现

- CreateProcessA创建一个进程（目的为了获得其标识进程或线程的值）
- 通过VirtualAllocEx函数在打开的进程中申请一块内存，返回值为基地址
- WriteProcessMemory函数将数据写入上面申请的内存中
- 利用CreateRemoteThread函数创建在上面打开的进程的虚拟地址空间中运行的线程  
    这里我们执行一个弹窗来测试

![1.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b1884904bc94bb22d3ccc9695906992d8d5b5278.png)

NtCreateThreadEx注入
------------------

NtCreateThreadEx是更底层的API，很显然属于未公开的api，NtCreateThreadEx在32位下和64位下函数原型不一致。  
我们任然可以很清楚的看到所需的参数，与CreateRemoteThread函数很类似，对照MSDN的官方手册填写即可

```php
#ifdef _AMD64_
    typedef DWORD(WINAPI* functypeNtCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        ULONG CreateThreadFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximunStackSize,
        LPVOID pUnkown);

functypeNtCreateThreadEx NtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

#else
typedef DWORD(WINAPI *functypeNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateThreadFlags,
    DWORD  ZeroBits,
    DWORD  StackSize,
    DWORD  MaximumStackSize,
    LPVOID pUnkown);

functypeNtCreateThreadEx NtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

#endif // DEBU
```

### 代码实现

- CreateProcessA创建一个进程（目的为了获得其标识进程或线程的值）
- 通过VirtualAllocEx函数在打开的进程中申请一块内存，返回值为基地址
- WriteProcessMemory函数将数据写入上面申请的内存中
- 利用NtCreateThreadEx函数创建在上面打开的进程的虚拟地址空间中运行的线程

![2.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-226664e3235da0329d07425d99761b95ab469214.png)

RtlCreateUserThread注入
---------------------

RtlCreateUserThread其实是对NtCreateThreadEx的包装，话不多说了直接看函数的参数  
很清晰了，实现也很简单这里就不多说了

```php
typedef DWORD(WINAPI* pRtlCreateUserThread)(    //函数申明
    IN HANDLE                     ProcessHandle,
    IN PSECURITY_DESCRIPTOR     SecurityDescriptor,
    IN BOOL                     CreateSuspended,
    IN ULONG                    StackZeroBits,
    IN OUT PULONG                StackReserved,
    IN OUT PULONG                StackCommit,
    IN LPVOID                    StartAddress,
    IN LPVOID                    StartParameter,
    OUT HANDLE                     ThreadHandle,
    OUT LPVOID                    ClientID
    );

pRtlCreateUserThread RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
```

### 代码实现

- CreateProcessA创建一个进程（目的为了获得其标识进程或线程的值）
- 通过VirtualAllocEx函数在打开的进程中申请一块内存，返回值为基地址
- WriteProcessMemory函数将数据写入上面申请的内存中
- 利用RtlCreateUserThread函数创建在上面打开的进程的虚拟地址空间中运行的线程

![3.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d85e9ca51f007b19580039dcd2478e2a72a694aa.png)

Injection 突破Session 0
---------------------

假如我们想要注入到lsass进程，我们是否也可以注入成功呢？ 这里还需要了解到一个知识点，就是关于SeDebugPrivilege，SeDebugPrivilege是调试权限的程序，开启了这个特权之后可以可以读写system启动的进程的内存，很显然我们想要dump或者OpenProcess下lsass.exe进程，那么肯定需要SeDebugPrivilege权限 这里就直接给出了，权限提升我另外一篇介绍过，这里用修改访问令牌进行权限提升获得SeDebugPrivilege权限

```php
void GetPrivilege() {
    HANDLE TokenHandle = NULL;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &TokenHandle);
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = true ? SE_PRIVILEGE_ENABLED : 0;

    AdjustTokenPrivileges(TokenHandle, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(TokenHandle);

}
```

我们用CreateRemoteThread函数进行测试，函数注入失败

![4.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-95bcb8cd565a3ca37a3f897d4b72bf39ff299cdb.png)

在使用传统的进程注入技术的过程中，可以向普通用户用户进程注入shellcode或dll，那么如果我们想更进一步注入到系统进程内，通常会失败，这是由于session 0隔离的缘故  
Session 0会话：在Windows XP、Windows Server 2003，以及更老版本的Windows操作系统中，第一个登录到控制台的用户来启动服务和应用程序（所有的服务和应用程序都是运行在与第一个登录到控制台的用户得Session中），由于服务是以高权限运行的，所以会造成一些安全风险。  
Session 0隔离：从Windows Vista开始应用程序和服务是隔离开来的，即服务在一个叫做Session 0 的特殊Session中承载，应用程序运行在Session 0之后（Session 1、Session 2等），因此是不能互相传递窗体消息，共享UI元素或者共享kernel对象。

### ZwCreateThreadEx函数

ZwCreateThreadEx函数比CreateRemoteThread函数更接近内核，CreateRemoteThread最终也是调用ZwCreateThreadEx函数来创建线程的。 ZwCreateThreadEx的第7个参数 CreateSuspended（CreateThreadFlags）的值始终为1,它会导致线程创建完成后一直挂起无法恢复运行,于是我们选择直接调用ZwCreateThreadEx,将第7个参数直接置为0,这样可达到注入目的

函数原型

```php
#ifdef _WIN64
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG CreateThreadFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID pUnkown
    );
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD dwStackSize,
    DWORD dw1,
    DWORD dw2,
    LPVOID pUnkown
    );
#endif

typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwCreateThreadEx");
```

### 代码实现

接下来实现就很简单了，这里采用Dll进行注入（因为系统程序中不能显示程序窗体），就是经典注入换了个函数

![5.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-66d0cb264317c2acfdb93f1df4a6a705178deec4.png)

线程劫持注入
------

顾名思义，我们去劫持指定进程的线程来进行注入代码，整体也很简单，我们先来看看几个Windows的API函数

### SuspendThread

挂起指定的线程，非常简单的一个函数，只有一个参数

<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread>

![213.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0589a6a1a38c0f53af13e5f7933dc2406e58c007.png)  
参数如下

```php
DWORD SuspendThread(
  [in] HANDLE hThread
);
```

可以看出不是很难，大致流程如上，对照MSDN的官方文档即可写出

### GetThreadContext

检索指定线程的上下文

<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext>

![214.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-61f7a55d640d1934a3597da16c062621cd3cbc58.png)

```php
BOOL GetThreadContext(
  [in]      HANDLE    hThread,
  [in, out] LPCONTEXT lpContext
);
```

### SetThreadContext

设置指定线程的上下文，主要就是设置eip\\rip指向payload的地址

<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext>

![215.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e60cb1dd2e3948046c952e2674ad888539560566.png)

```php
BOOL SetThreadContext(
  [in] HANDLE        hThread,
  [in] const CONTEXT *lpContext
);
```

### ResumeThread

恢复由SuspendThread函数挂起的线程

<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread>

![216.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1ca565320640a67203cd3d98c447a414a86df837.png)

```php
DWORD ResumeThread(
  [in] HANDLE hThread
);
```

### 代码实现

- CreateProcessA创建一个进程（目的为了获得其标识进程或线程的值）
- 通过VirtualAllocEx函数在打开的进程中申请一块内存，返回值为基地址
- WriteProcessMemory函数将数据写入上面申请的内存中
- 利用SuspendThread函数挂起指定的线程
- GetThreadContext函数检索指定线程的上下文
- 通过SetThreadContext函数设置eip\\rip指向payload的地址
- 最后通过ResumeThread函数恢复挂起的线程

![6.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4963672165d667dc7b3419818738690fec6f3981.png)

APC注入
-----

APC（异步过程调用）。每个线程都维护着一个APC链，可以让一个线程在本应该执行的步骤前执行别的代码。 因此我们只需要向目标进程中的线程APC队列中添加APC过程，等线程恢复即可实现APC注入（当然我们可以向进程的所有线程都进行注入，虽然提高了准确率，但是风险性也提高了）  
MSDN的参考链接  
<https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls>

### QueueUserAPC

每个线程都有自己的 APC 队列。应用程序通过调用 QueueUserAPC 函数将 APC排队到线程。调用线程在对QueueUserAPC的调用中指定APC函数的地址。 当用户模式APC排队时，除非它处于可报警状态，否则它排队的线程不会被引导调用APC函数。当线程调用SleepEx、SignalObjectAndWait、MsgWaitForMultipleObjectsEx、WaitFormultipleObjectsOx或WaitForSingleObjectEx函数时，它将进入可报警状态。（即需要让线程进入可告警状态其才会触发）

#### QueueUserAPC

我们需要使用QueueUserApc这个函数将其添加到指定线程的 APC 队列中，我们看看MSDN上对于这个函数的详细解释 <https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc>

![210.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c697176ce6b5c5ab88c1581593aeca891881a52a.png)  
函数的参数

```php
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,
  [in] HANDLE    hThread,
  [in] ULONG_PTR dwData
);
```

#### SleepEx

我们这里使用SleepEx函数让线程进入可告警状态

<https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex>

![218.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-6d6bac88b81b8eacffbd065cb626f4b8ef98f090.png)

```php
DWORD SleepEx(
  [in] DWORD dwMilliseconds,
  [in] BOOL  bAlertable
);
```

该函数也很简单

#### 代码实现

- CreateProcessA创建一个进程（目的为了获得其标识进程或线程的值）
- 通过VirtualAllocEx函数在打开的进程中申请一块内存，返回值为基地址
- WriteProcessMemory函数将数据写入上面申请的内存中
- QueueUserApc这个函数将其添加到指定线程的 APC 队列中
- SleepEx函数使线程进入可告警状态

![232.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e50708e20a980d6f8a3e601ce2eaff1cdbd2eba0.png)

![233.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c19d0d8589f459f7e5c89256ca2fceb4e9f0625e.png)

### Early bird

其实大致和上面差不多，只不过这种手法是将打开进程先挂起，然后在进行申请空间，写入然后将APC插入线程，最后恢复挂起的线程。 Early Bird是一种简单而强大的技术，Early Bird本质上是一种APC注入与线程劫持的变体，由于线程初始化时会调用ntdll未导出函数NtTestAlert，NtTestAlert是一个检查当前线程的 APC 队列的函数，如果有任何排队作业，它会清空队列。当线程启动时，NtTestAlert会在执行任何操作之前被调用。因此，如果在线程的开始状态下对APC进行操作，就可以完美的执行。

![219.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-dbbc536401977f4112fdcd0a88d3ef7ce0262dd6.png)

#### 代码实现

- CreateProcessA创建一个进程，并将其主线程挂起（目的为了获得其标识进程或线程的值）
- 通过VirtualAllocEx函数在打开的进程中申请一块内存，返回值为基地址
- WriteProcessMemory函数将数据写入上面申请的内存中
- QueueUserApc这个函数将其添加到指定线程的 APC 队列中
- ResumeThread恢复挂起的线程

![211.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0ab9812d91b31589577917f1e94a6348bd56c5b9.png)

映射注入
----

映射注入是一种内存注入技术，可以避免使用一些经典注入技术使用的API,如VirtualAllocEx,WriteProcessMemory等被杀毒软件严密监控的API，同时创建Mapping对象本质上属于申请一块物理内存，而申请的物理内存又能比较方便的通过系统函数直接映射到进程的虚拟内存里，这也就避免使用经典写入函数，增加了隐蔽性。

![220.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-65733504756cfd4823b38363a8129808d7be9814.png)  
我们先来看看几个基础的函数

### CreateProcessA

创建一个进程  
<https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-CreateProcessAa>

![212.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-44b318a2920387bed5fcc2278bd65c11fe41ad37.png)  
参数如下

```php
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

### CreateFileMappingA

其返回值是新创建的文件映射对象的句柄  
<https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-createfilemappinga>

![221.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-2d0b738fe26909faa7e48b1037f2db9bca164702.png)

```php
HANDLE CreateFileMappingA(
  [in]           HANDLE                hFile,
  [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  [in]           DWORD                 flProtect,
  [in]           DWORD                 dwMaximumSizeHigh,
  [in]           DWORD                 dwMaximumSizeLow,
  [in, optional] LPCSTR                lpName
);
```

### MapViewOfFile

将文件映射的视图映射到调用进程的地址空间，返回值为映射视图的起始地址。  
<https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile>

![222.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d7a818bbcab2c1180bb208d6acd034ac5b67a1fd.png)

```php
LPVOID MapViewOfFile(
  [in] HANDLE hFileMappingObject,
  [in] DWORD  dwDesiredAccess,
  [in] DWORD  dwFileOffsetHigh,
  [in] DWORD  dwFileOffsetLow,
  [in] SIZE_T dwNumberOfBytesToMap
);
```

其中hFileMappingObject即是CreateFileMappingA函数的返回值

### memcpy

将buf复制到被映射的虚拟地址

### MapViewOfFile2

将文件视图或页面文件备份部分映射到指定进程的地址空间。  
<https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2>

![223.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e4e84168b551f72c332667bcf5670b3e7961d8a6.png)

```php
PVOID MapViewOfFile2(
  [in]           HANDLE  FileMappingHandle,
  [in]           HANDLE  ProcessHandle,
  [in]           ULONG64 Offset,
  [in, optional] PVOID   BaseAddress,
  [in]           SIZE_T  ViewSize,
  [in]           ULONG   AllocationType,
  [in]           ULONG   PageProtection
);
```

函数都不难，参照官方文档即可

### 代码实现

- CreateFileMappingA在注入进程创建文件映射对象
- MapViewOfFile函数将CreateFileMappingA创建的文件映射对象映射到调用进程的地址空间。
- memcpy往被映射的虚拟地址写入shellcode
- CreateProcessA创建一个进程，并将其主线程挂起（目的为了获得其标识进程或线程的值，）
- MapViewOfFile2将文件视图或页面文件备份部分映射到指定进程的地址空间（CreateProcessA创建的进程）。
- QueueUserApc往这个队列中插入一个回调
- ResumeThread恢复主线程的运行

![224.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-061822180ca126493fa576ba13e961228171b6bf.png)

NtCreateSection&amp;NtMapViewOfSection
--------------------------------------

此技术与映射注入大致流程差不多，但是这个技术更为接近底层，映射注入使用的api本质上是ntdll导出函数的封装，这个注入技术则是直接调用ntdll的导出函数。（NtCreateSection、NtMapViewOfSection）  
这种技术与映射注入具有同样的优点，我们可以不使用VirtualAllocEx,WriteProcessMemory经典函数。  
我们来看看这两个函数

### NtCreateSection

创建Section对象，即具有关联文件的虚拟内存块

![226.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-708236cd381c3469cfaa61cad6537c30a3b11a59.png)

### NtMapViewOfSection

就是将NtCreateSection函数创建的Section对象，映射到内存中

![227.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-73563c86165a499bac0055ee7ee138f3c56bf113.png)

### 代码实现

- NtCreateSection函数创建Section对象，即具有关联文件的虚拟内存块（RWX）
- NtMapViewOfSection将Section对象映射到本地进程内存（RW）
- 然后NtMapViewOfSection将Section对象又映射到目标进程内存（RX）
- memcpy将shellcode复制到本地视图，这将反映在目标进程的映射视图中
- 利用RtlCreateUserThread函数创建在上面打开的进程的虚拟地址空间中运行的线程，其指向目标进程映射内存的虚拟地址

![225.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-03398c8d644cc384c5d3659a14b2b9b9d7cb3fa0.png)