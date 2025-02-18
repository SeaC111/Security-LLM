由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。（本文仅用于交流学习）

这个方法大概是2020年的时候国外友人提出的了，虽然不是新方法但是思路还是很有意思，值得去学习。  
作者的大概思路就是利用NtDuplicateObject间接的去获取句柄，我们先来看看NtDuplicateObject函数是什么意思。

NtDuplicateObject
-----------------

<https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject>

![9.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-090959fd60ae6f4b70808da25809552e9134b82a.png)

```php
NTSYSAPI NTSTATUS ZwDuplicateObject(
  [in]            HANDLE      SourceProcessHandle,
  [in]            HANDLE      SourceHandle,
  [in, optional]  HANDLE      TargetProcessHandle,
  [out, optional] PHANDLE     TargetHandle,
  [in]            ACCESS_MASK DesiredAccess,
  [in]            ULONG       HandleAttributes,
  [in]            ULONG       Options
);
```

我们着重看前三个参数

![10.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a498bf28fa1668798cb8dc0ec5c9b531a83674d1.png)  
其和DuplicateHandle参数是差不多的，我们先创建两个个实例m.exe、t.exe，我们将m.exe的线程句柄复制到t.exe中，并在t.exe中将其线程终止。  
m.exe

```php
#include <iostream>
#include <windows.h>
#include <process.h>
#include <TlHelp32.h>
#include "ntdll.h"
#pragma comment(lib, "ntdll.lib")

using namespace std;

unsigned __stdcall thread(void* lpPragma)
{
    while (1)
    {
        Sleep(500);
        cout << "terminal me" << endl;
    }

    return 0;
}

HANDLE GetProcessHandle()
{
    DWORD pid;
    PROCESSENTRY32 ed;
    ed.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &ed) == TRUE)
    {
        while (Process32Next(snapshot, &ed) == TRUE)
        {
            if (string(ed.szExeFile) == "t.exe") {
                pid = ed.th32ProcessID;

                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            }
        }
    }
}

int main(void)
{
    HANDLE hThread;
    hThread = (HANDLE)_beginthreadex(NULL, 0, thread, NULL, 0, NULL);
    cout << "Thread Handle: " << hThread << endl;

    HANDLE hTarget;

    if (NtDuplicateObject(GetCurrentProcess(), hThread, GetProcessHandle(), &hTarget, 
                            PROCESS_ALL_ACCESS, 0, DUPLICATE_SAME_ACCESS) == STATUS_SUCCESS) {
        cout << "句柄复制成功, 其句柄值为：" << hTarget << endl;
    }
    cin.get();
    return 0;
}
```

t.exe

```php
#include <iostream>
#include <windows.h>
#include <stdlib.h>
#include <process.h>
using namespace std;

int main(void)
{
    HANDLE hRecv;

    cout << "请输入复制过来的句柄:" << endl;
    cin >> hRecv;

    TerminateThread(hRecv, 0);

    system("pause");
    return 0;
}
```

![11.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-77790a328b07faaca010f5ca2f1dec59a03fccea.png)  
了解了NtDuplicateObject函数，那么我们如何获得进程打开的句柄呢？我们再来看看NtQuerySystemInformation函数

NtQuerySystemInformation
------------------------

<https://learn.microsoft.com/zh-cn/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation>

![1.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-777036ca5ff6e11dc48c8dfe43485990238196c7.png)

```php
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
```

我们着重看一下第一个参数SystemInformationClass（官方文档给出的参数很多，我们着重看一下要使用的就行）  
我们使用SystemHandleInformation参数，遍历系统句柄信息，我们来看看SYSTEM\_HANDLE\_INFORMATION结构体

![12.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-447f299c13622704ef725778c141fddf831b15b2.png)  
将所以的句柄放在Handles\[1\]中，其总数由NumberOfHandles参数表示，我们再来看看SYSTEM\_HANDLE\_INFORMATION结构体

![3.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a744591eeaa8f6d075540ba4fe80ee5f3e4d66ac.png)  
其中UniqueProcessId、HandleValue是什么意思很明了了

OpenProcess
-----------

这个函数再熟悉不过了，我们主要看看第一个参数  
<https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights>  
因为我们只是要复制句柄，因此我们不必使用PROCESS\_ALL\_ACCESS，我们可以使用如下

![14.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-94fc38094b1169256d844f9b9bf0591612688edc.png)

大致思路
----

- 我们先获得SeDebug权限
- 通过NtQuerySystemInformation函数获取所有进程打开的句柄
- 通过OpenProcess打开进程的句柄
- 通过NtDuplicateObject函数获得句柄的副本信息
- NtQueryObject获得句柄的信息，来筛选是否是进程
- 最后通过QueryFullProcessImageName函数来获得进程的路径，以判断是不是我们要获得的指定进程
- 最后利用MiniDumpWriteDump进行转储  
    怎么获得SeDebug权限这里就不叙述了  
    NtQuerySystemInformation获得所以进程打开的句柄  
    ![4.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f95d1ef54214d756ecfc22675f2a3822632f0133.png)  
    NtDuplicateObject  
    ![6.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-35a8c3f2ed1a2872e215beff25fd565c0476eedd.png)  
    NtQueryObject  
    ![5.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-328fa36122211e72c8166fc8473dbf07d6b40dac.png)  
    QueryFullProcessImageNameW

![8.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-31a9ff8f87935689c08a11373c49d429b0f26b30.png)

![14.PNG](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-bd1e8aff2e8617835b9ef65c26ee7154cf1d40dc.png)

参考
--

<https://skelsec.medium.com/duping-av-with-handles-537ef985eb03>