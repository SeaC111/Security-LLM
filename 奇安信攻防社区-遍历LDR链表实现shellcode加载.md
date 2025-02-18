0x00 前言
=======

shellcode是不依赖环境，放到任何地方都可以执行的机器码。shellcode的应用场景很多，本文不研究shellcode的具体应用，而只是研究编写一个shellcode需要掌握哪些知识。

0x01 ShellCode编写原则
==================

1、不能有全局变量\*\*
-------------

因为我们编写shellcode时，使用的全局变量是自己的进程里面的全局变量，注入到别的进程里，这个地址就没用了。

2、不能使用常量字符串\*\*
---------------

和第一点原因一样，字符串常量值也是全局变量，注入到别的进程里，根本没有这个字符串。

要使用字符串，需要使用字符数组。

```c
char s[] = {'1','2',0};
```

3、不能直接调用系统函数\*\*
----------------

调用系统函数的方式是间接调用(FF15)，需要从IAT表里获取API地址，每个进程的IAT表位置不同，且对方的进程可能没有导入你需要调用的函数的DLL，那么你是不能调用这个系统函数的。

所以我们需要用到 LoadLibrary 和 GetProcAddress 这两个函数，来动态获取系统API的函数指针。

但是 LoadLibrary，GetProcAddress 本身就是系统函数，它们本身就依赖IAT表，咋办呢？

解决方案是这样的：通过FS:\[0x30\] 找到PEB，然后通过PEB里的LDR链表 \[PEB+0x0C\]找到 kernel32.dll 的地址，然后我们遍历它的 IAT表，找到 LoadLibrary 和 GetProcAddress 函数。

4、不能嵌套调用其他函数\*\*
----------------

和前两点道理是一样的，本进程里的函数地址，拿到别的进程的虚拟地址空间是无效的。

0x02 TEB/PEB
============

每个线程都有一个TEB结构来存储线程的一些属性结构，TEB的地址用`fs:[0]`来获取

![image-20220214100731251.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f5cdf55bb73d096d3758027e248a5dd347e70122.png)

在0x30这个地址有一个指针指向`PEB`结构，PEB就是进程用来记录自己信息的一个结构

![image-20220214100850094.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6fc504b3d4f2de13011025108ea75aa2de410fc7.png)

完整结构如下

![image-20220214101109806.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-110258def4e4013d70091149f87ba15fa43a6511.png)

在PEB的`0x00c`偏移有一个 `Ldr _PEB_LDR_DATA`结构跟进去

![image-20220214101230643.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-be6e7b182cea016c5011b7ba552a36623a9075c4.png)

可以得到3个结构如下所示

> `InLoadOrderModuleList`：模块加载的顺序
> 
> `InMemoryOrderModuleList`：模块在内存的顺序
> 
> `InInitializationOrderModuleList`：模块初始化的顺序

​

![image-20220217185640234.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2d774392f8766a25b623e81e2ab0fe80b08062a5.png)

0x03 思路
=======

我们一般使用api会直接使用`LoadLibrary`和`GetProcessAddress`，但是这里肯定会依赖IAT表，所以这里我们就需要自己实现api所完成的功能

`TEB` -&gt; `PEB` -&gt; `PEB + 0x0C` -&gt; `Ldr _PEB_LDR_DATA` -&gt; `InLoadOrderModuleList` -&gt; `kernel32.dll` -&gt; `导出表定位GetProcessAddress` -&gt; `通过找到的GetProcessAddress实现LoadLibrary`

0x04 实现过程
=========

首先我们自己定义几个结构体，因为我们不依赖系统自己实现

```c++
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

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    UINT32 Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    UINT32 CheckSum;
    UINT32 TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef HMODULE (WINAPI * PLOADLIBRARY)(LPCSTR);
typedef DWORD (WINAPI * PGETPROCADDRESS)(HMODULE, LPCSTR);
typedef DWORD (WINAPI * PMESSAGEBOX)(HWND, LPCSTR,LPCSTR,UINT);
```

然后定义shellcode，这里因为kernel32.dll是unicode字符串所以用两字节存储

```c++
    char szKernel32[] = {'k',0,'e',0,'r',0,'n',0,'e',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0,0,0}; // Unicode
    char szUser32[] = {'u','s','e','r','3','2','.','d','l','l',0};
    char szGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char szLoadLibrary[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char szMessageBox[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    char szHelloShellCode[] = {'H','e','l','l','o','S','h','e','l','l','C','o','d','e',0};
```

找到`InLoadOrderModuleList`存入寄存器

```c++
    __asm
    {
        mov eax,fs:[0x30] // PEB
        mov eax,[eax+0x0C] // PEB->LDR
        add eax,0x0C    // LDR->InLoadOrderModuleList
        mov pBeg,eax
        mov eax,[eax]
        mov pPLD,eax
    }
```

找到kernel32.dll，通过遍历的方式来寻找，通过LDR指向`DllBase`获取基址

![image-20220217112719053.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d92e0a0ed03df0bf4b235f1da11fd785d9ae0cf0.png)

```c++
    // Find Kerner32.dll
    while (pPLD != pBeg)
    {
        pLast = (WORD*)pPLD->BaseDllName.Buffer;
        pFirst = (WORD*)szKernel32;

        while (*pFirst && *pLast == *pFirst)
            pFirst++,pLast++;

        if (*pFirst == *pLast)
        {
            dwKernelBase = (DWORD)pPLD->DllBase;
            break;
        }
        pPLD = (LDR_DATA_TABLE_ENTRY*)pPLD->InLoadOrderLinks.Flink;
    }
```

然后通过指针定位到导出表

```c++
        // 通过指针定位到导出表
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwKernelBase;
        PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
        PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
        PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(/images/shellcode/image_FILE_HEADER));
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)dwKernelBase + pOptionHeader->DataDirectory[0].VirtualAddress);

        // 导出函数地址表RVA
        DWORD *pAddOfFun_Raw = (DWORD*)((DWORD)dwKernelBase + pExportDirectory->AddressOfFunctions);
        // 导出函数名称表RVA
        WORD *pAddOfOrd_Raw = (WORD*)((DWORD)dwKernelBase + pExportDirectory->AddressOfNameOrdinals);
        // 导出函数序号表RVA
        DWORD *pAddOfNames_Raw = (DWORD*)((DWORD)dwKernelBase + pExportDirectory->AddressOfNames);
```

还是通过遍历找到`GetProcessAddress`，用指针指向这个地址

```c++
        DWORD dwCnt = 0;
        char* pFinded = NULL, *pSrc = szGetProcAddress;

        for (; dwCnt < pExportDirectory->NumberOfNames;dwCnt++)
        {
            pFinded = (char*)((DWORD)dwKernelBase + pAddOfNames_Raw[dwCnt]);

            while (*pFinded && *pFinded == *pSrc)
                pFinded++, pSrc++;

            if (*pFinded == *pSrc)
            {
                pGetProcAddress = (PGETPROCADDRESS)(pAddOfFun_Raw[pAddOfOrd_Raw[dwCnt]] + (DWORD)dwKernelBase);
                break;
            }
            pSrc = szGetProcAddress;
        }
```

然后就可以使用`pGetProcessAddress`实现`LoadLibrary`和`MessageBox`

```c++
    // 通过pGetProcAddress进行调用
    pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)dwKernelBase, szLoadLibrary);
    pMessageBox = (PMESSAGEBOX)pGetProcAddress(pLoadLibrary(szUser32),szMessageBox);

    pMessageBox(NULL,szHelloShellCode,0,MB_OK);
```

完整代码如下

```c++
// shellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

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

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    UINT32 Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    UINT32 CheckSum;
    UINT32 TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef HMODULE (WINAPI * PLOADLIBRARY)(LPCSTR);
typedef DWORD (WINAPI * PGETPROCADDRESS)(HMODULE, LPCSTR);
typedef DWORD (WINAPI * PMESSAGEBOX)(HWND, LPCSTR,LPCSTR,UINT);

DWORD WINAPI ShellCode();

int main(int argc, char* argv[])
{
    ShellCode();

    getchar();
    return 0;
}

DWORD WINAPI ShellCode()
{
    PGETPROCADDRESS pGetProcAddress = NULL;
    PLOADLIBRARY pLoadLibrary = NULL;
    PMESSAGEBOX  pMessageBox = NULL;
    PLDR_DATA_TABLE_ENTRY pPLD;
    PLDR_DATA_TABLE_ENTRY pBeg;
    WORD *pFirst = NULL;
    WORD *pLast = NULL;
    DWORD ret = 0, i = 0;
    DWORD dwKernelBase = 0;

    char szKernel32[] = {'k',0,'e',0,'r',0,'n',0,'e',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0,0,0}; // Unicode
    char szUser32[] = {'u','s','e','r','3','2','.','d','l','l',0};
    char szGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char szLoadLibrary[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char szMessageBox[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    char szHelloShellCode[] = {'H','e','l','l','o','S','h','e','l','l','C','o','d','e',0};

    __asm
    {
        mov eax,fs:[0x30] // PEB
        mov eax,[eax+0x0C] // PEB->LDR
        add eax,0x0C    // LDR->InLoadOrderModuleList
        mov pBeg,eax
        mov eax,[eax]
        mov pPLD,eax
    }

    // Find Kerner32.dll
    while (pPLD != pBeg)
    {
        pLast = (WORD*)pPLD->BaseDllName.Buffer;
        pFirst = (WORD*)szKernel32;

        while (*pFirst && *pLast == *pFirst)
            pFirst++,pLast++;

        if (*pFirst == *pLast)
        {
            dwKernelBase = (DWORD)pPLD->DllBase;
            break;
        }
        pPLD = (LDR_DATA_TABLE_ENTRY*)pPLD->InLoadOrderLinks.Flink;
    }

    // Kernel32.dll -> GetProcAddress
    if (dwKernelBase != 0)
    {
        // 通过指针定位到导出表
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwKernelBase;
        PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
        PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
        PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(/images/shellcode/image_FILE_HEADER));
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)dwKernelBase + pOptionHeader->DataDirectory[0].VirtualAddress);

        // 导出函数地址表RVA
        DWORD *pAddOfFun_Raw = (DWORD*)((DWORD)dwKernelBase + pExportDirectory->AddressOfFunctions);
        // 导出函数名称表RVA
        WORD *pAddOfOrd_Raw = (WORD*)((DWORD)dwKernelBase + pExportDirectory->AddressOfNameOrdinals);
        // 导出函数序号表RVA
        DWORD *pAddOfNames_Raw = (DWORD*)((DWORD)dwKernelBase + pExportDirectory->AddressOfNames);

        DWORD dwCnt = 0;
        char* pFinded = NULL, *pSrc = szGetProcAddress;

        for (; dwCnt < pExportDirectory->NumberOfNames;dwCnt++)
        {
            pFinded = (char*)((DWORD)dwKernelBase + pAddOfNames_Raw[dwCnt]);

            while (*pFinded && *pFinded == *pSrc)
                pFinded++, pSrc++;

            if (*pFinded == *pSrc)
            {
                pGetProcAddress = (PGETPROCADDRESS)(pAddOfFun_Raw[pAddOfOrd_Raw[dwCnt]] + (DWORD)dwKernelBase);
                break;
            }
            pSrc = szGetProcAddress;
        }

    }

    // 通过pGetProcAddress进行调用
    pLoadLibrary = (PLOADLIBRARY)pGetProcAddress((HMODULE)dwKernelBase, szLoadLibrary);
    pMessageBox = (PMESSAGEBOX)pGetProcAddress(pLoadLibrary(szUser32),szMessageBox);

    pMessageBox(NULL,szHelloShellCode,0,MB_OK);

    return 0;
}
```

成功弹窗

![image-20220217113020990.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e6fcd935e30acff4d4c8a8f8dec2ec57dc855251.png)

这里我们进反汇编看一下，是有检测堆栈平衡的代码的

![image-20220217113109918.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6e11d71cf30727283af82a65120ced3704ab1769.png)

在物理机里面查看也是有的

![image-20220217113326459.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-163b67690d63c2b07f12d3f4faefe8efe2ace000.png)

这里关闭一下堆栈平衡的检测，默认情况如下

![image-20220217113408424.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-66eaeced2632107944424c56da291e7ac96ca878.png)

修改为禁用安全检查

![image-20220217113434792.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-510b8caf37496821edcabfcbf29dcf50c5e059e6.png)

即可生成没有检查堆栈平衡的代码

![image-20220217113457999.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ffbabfc2f536a7fdf798d620f73d995efe4b5953.png)