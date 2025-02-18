代码节空白区添加代码(手动添加)
================

0x0前言
-----

双击exe程序，首先跳转执行我们添加的代码(一个弹窗代码做演示)，然后继续跳转到程序入口

0x1思路
-----

修改原先的程序入口(OEP:它是可选PE头中的参数)，指向我们的代码(call 0x12345678)，代码完成之后，跳转回去(jmp OEP)

注意：**我们的代码应该是二进制(程序编译后硬编码)**

0x2手动分析
-------

MessageBox它是一个宏，有MessageBoxA和MessageBoxW

我们要找的是MessageBoxA函数的地址

```php
bp MessageBoxA
```

这条命令的意思是在这个`MessageBoxA`函数这里 设置一个断点

![image-20220126124554383](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cd0f733012ba164331a14ea54956e7f9ebbb59e5.png)

可以看B 看到我们设置的断点

![image-20220126124700566](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0311d565660b1febe0293fed359508466a60a07c.png)

双击点进去，就是MessageBoxA函数 开始的地址

![image-20220126124734528](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-60d6db6b7cda8cb6d9f329b114b6765a768984dd.png)

要记录下来

```php
MessageBox函数地址:0x77263670
```

![image-20220126124835278](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e71d35d362422788a4e5f2af04dedd1938ddf885.png)

继续学习一下`call`和`jmp`的硬编码

```php
00401072 E8 29 00 00 00       call        printf (004010a0)
```

![image-20220126130516283](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ce439758f74d2d54ca27717c08610b2293031e21.png)

F11 进入地址

```php
0040100A E9 41 00 00 00       jmp         main (00401050)
```

![image-20220126130436583](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-52492a0525dc7cd905ade799cb8641f85513c0bd.png)

所以

```php
call:E8

jmp:E9
```

注意：E8后面跳转的值，跟真正跳转的值是需要计算的

这里有一个公式

```php
真正要跳转的地址 = E8这条指令的下一行地址 + X

X = 真正要跳转的地址 - E8这条指令的下一行地址
```

尝试 计算一下

```php
00401068 E8 98 FF FF FF       call        @ILT+0(Function) (00401005)
0040106D 68 1C 20 42 00       push        offset string "Hello World!\n" (0042201c)
```

```php
X = 00401005 - 0040106D = FFFFFF98
```

所以对应的硬编码就是

```php
98 FF FF FF
```

![image-20220126142337335](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b3337961b8dbecf935d6c6be88a6ee869d5ce6f3.png)

![image-20220126142651877](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-43bf489a42753ec526898c499360a34a534f946e.png)

![image-20220126142855591](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a62c832fb842474c164189782b1530b1ccf14e5a.png)

指令长度是：`E8 + 4 = 5`

```php
真正要跳转的地址 = E8这条指令的地址 + 5 + X

X = 真正要跳转的地址 - E8这条指令的地址 - 5
```

注意：E8这条指令的地址是拉伸之后的地址(ImageBuffer)

jmp和call是一样的

观察一下`MessageBox`

```php
0040106F 6A 00                push        0
00401071 6A 00                push        0
00401073 6A 00                push        0
00401075 6A 00                push        0
00401077 FF 15 AC A2 42 00    call        dword ptr [__imp__MessageBoxA@16 (0042a2ac)]
```

我们要把这四个`push 0`的硬编码 拿过来

![image-20220126144740149](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5b0fb198f56e79ba75583cfb5fa55c6d580780c9.png)

![image-20220126144658145](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-de9f901ca6d026a8e310fd7e33cf7cf93e49f087.png)

所以最后 总结 我们为MessageBox函数添加的硬编码是

```php
6A 00 6A 00 6A 00 6A 00 E8 00 00 00 00 E9 00 00 00 00
```

总共18个字节

我们现在是要把它加到代码的空白区，数据区当然也可以

但是我们加到代码的空白区，它不用改当前exe程序的节就可以跑起来，因为它里面本来就存储代码的

就是加到这里

![image-20220126145940161](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2248e9887f34b9c23e4f56b0d44cf1622c5371a3.png)

这里我们要考虑一个问题，它这因为内存对齐，从而剩下的空间 够不够我们用

要保证有18字节，以上

可以使用`PETool`进行分析这个exe的节

```php
VirtualSize：            0x00000180     0001A000     [V(VS),内存中大小(对齐前的长度).]

SizeOfRawData：          0x00000188     0000C600     [R(RS),文件中大小(对齐后的长度).]
```

所以，第一个节，就是够用的

![image-20220126151205310](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-43cf0649d4755a1389eca2e9641d233d98dd165c.png)

![image-20220126151129522](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-16ebca32a6707aed7a4350ee33635672aa0843ef.png)

从文件中的偏移开始找，然后跳过内存中的大小(代码区)，放到它的后面

```php
VirtualSize：            0x00000180     0001A000     [V(VS),内存中大小(对齐前的长度).]

SizeOfRawData：          0x00000188     0000C600     [R(RS),文件中大小(对齐后的长度).]

PointerToRawData：       0x0000018c     00000400     [R(RO),文件中偏移.]
```

代码节，从这里开始

![image-20220126152006411](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8ac18a25465851d396351fb38990c9a888fe9dc3.png)

```php
对齐后的地址 = 文件中偏移 + 文件中大小 

           = 400 + C600

           = CA00
```

![image-20220126152147003](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c550488bf0c7890532acf749874109be32817f8a.png)

注意：这个算是文件注入，我们平时所说的是代码注入

![image-20220126170439523](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-619b81dd0d4864f85de43b09a39fb7486a09b347.png)

```php
0x000001a0     [.rdata]     [名称,长度:8位(16字节)的ASCII码.]
VirtualSize：            0x000001a8     00002000     [V(VS),内存中大小(对齐前的长度).]
VirtualAddress：         0x000001ac     0001B000     [V(VO),内存中偏移(该块的RVA).]
SizeOfRawData：          0x000001b0     00000600     [R(RS),文件中大小(对齐后的长度).]
PointerToRawData：       0x000001b4     0000CA00     [R(RO),文件中偏移.]
```

从文件中的偏移开始找，然后跳过内存中的大小(代码区)，放到它的后面

```php
对齐后的地址 = 文件中偏移 + 文件中大小 

           = CA00 + 600

           = D000
```

代码节，从文件偏移这里开始

```php
CA00
```

![image-20220126170855415](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7fdb08ae2d0f3f9500ae31eab593834008d3b01d.png)

到这里结束

```php
0000D000
```

![image-20220126170954893](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cd89f1bf31acf9b5c8ca043cdca811ef33a091d8.png)

所以这些都是代码区的空闲区域

我们的代码是要插到这里

![image-20220126171113584](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4831d170b25b1d235b47445d311ac3f2e47227ac.png)

![image-20220126171446042](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-84a1c0a252ac3d8f086162eb797f243b2529641f.png)

E8：是MessageBox函数要跳转的地址

```php
0x77263670
```

E8这条指令的下一行地址：

```php
0000CE8D
```

![image-20220126171841190](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-60480e026df3645bf155ab1d8601e1600c163d5b.png)

找它的ImageBase

```php
ImageBase:00400000
```

![image-20220126172138333](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5cbc7485e6a90f655e790e955070ee0878e328bb.png)

最终E8这条指令的下一行地址：

```php
0040CE8D
```

根据公式 等量代换

```php
真正要跳转的地址 = E8这条指令的下一行地址 + X

X = 真正要跳转的地址 - E8这条指令的下一行地址

X = 77263670 - 0040CE8D
```

```php
76E567E3
```

![image-20220126173311122](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ca49c607443402a4020acd1ea125cea44d4f274d.png)

我们可以开始填了，根据小段存储

```php
E3 67 E5 76
```

E9：要跳到OEP，它真正入口的地方

继续在可选PE头的中，找EntryPoint

```php
0002A001
```

![image-20220126173614152](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f1cb673d945b3979f287be6f1618022475670910.png)

它真正的地址，需要加上ImageBase

```php
42A001
```

E9的下一条指令地址

```php
40CE92
```

![image-20220126173843943](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-125630cfaf385fcb7222f7604a2b65e6ba94029e.png)

两者相减(注意双字)

```php
X = 真正的地址 - E9的下一条指令地址
  = 42A001 - 40CE92
```

```php
0001D16F
```

![image-20220126174108715](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8659d6786638087c4f795fc72bf67511b1fde367.png)

我们可以开始填了，根据小段存储

```php
6F D1 01 00
```

最后，我们需要去改OEP，保证参数压到栈中

0002A001-&gt;0000CE80

```php
01 A0 02 00 -> 80 CE 00 00
```

任意代码空白区添加代码
===========

0x0前言
-----

用代码去，实现在任意代码空白区添加代码

0x1FileBuffer-&gt;ImageBuffer过程细节
---------------------------------

1、根据sizeofImage(可选PE头中的参数)分配ImageBuffer空间

2、根据sizeofHeaders去copy头

注：

```php
1、sizeofHeaders包括：Dos头、标准PE头、可选PE头、节表(而且是文件对齐后的大小)

2、从FileBuffer到ImageBuffer拉伸过程中，头是没有任何变化的
```

3、开始拷贝节

从哪里拷贝，根据节表中的

```php
PointerToRawData:[R(RO),文件中偏移.]
```

拷贝到哪里，根据节表中的

```php
VirtualAddress:[V(VO),内存中偏移(该块的RVA).]
```

拷贝多少，根据节表中的

```php
SizeOfRawData:[R(RS),文件中大小(对齐后的长度).]
```

0x2ImageBuffer-&gt;NewBuffer过程细节
--------------------------------

1、申请多大的空间

找到最后一个节，(文件中起始的位置+在文件中对齐后的大小) = NewBuffer申请的空间

2、根据sizeofHeaders去copy头

注：

```php
1、sizeofHeaders包括:Dos头、标准PE头、可选PE头、节表(而且是文件对齐后的大小)

2、从FileBuffer到ImageBuffer拉伸过程中，头是没有任何变化的
```

3、开始拷贝节

从哪里拷贝，根据节表中的

```php
VirtualAddress:[V(VO),内存中偏移(该块的RVA).]
```

拷贝到哪里，根据节表中的

```php
PointerToRawData:[R(RO),文件中偏移.]
```

拷贝多少，根据节表中的

```php
SizeOfRawData:[R(RS),文件中大小(对齐后的长度).]
```

0x3核心代码
-------

```php
// test.h: 头文件

#if !defined(AFX_test_H__DDA6AB97_A94D_41F9_B3B9_8426B6CB7934__INCLUDED_)
#define AFX_test_H__DDA6AB97_A94D_41F9_B3B9_8426B6CB7934__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <windows.h>
#include <stdio.h>

#define FilePath_In         "C:\\notepad.exe"
#define FilePath_Out        "C:\\notepadnewpes.exe"

#define MESSAGEBOXADDR      0x77D5050B
#define SHELLCODELENGTH     0x12 //16进制的，转换为十进制就是18

extern BYTE ShellCode[];

DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);

BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);

//DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

VOID AddCodeInCodeSec();

#endif // !defined(AFX_test_H__DDA6AB97_A94D_41F9_B3B9_8426B6CB7934__INCLUDED_)
```

```php
// test.cpp: implementation of the test class.

#include "stdafx.h"
#include "test.h"
#include <string.h>
#include <windows.h>
#include <stdlib.h>

//定义一个全局变量
BYTE ShellCode[] =
{
    0x6A,00,0x6A,00,0x6A,00,0x6A,00, //MessageBox push 0的硬编码
    0xE8,00,00,00,00,               // call汇编指令E8和后面待填充的硬编码
    0xE9,00,00,00,00               // jmp汇编指令E9和后面待填充的硬编码
};

//ExeFile->FileBuffer  返回值为计算所得文件大小

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
    //下面有个IN和OUT，大致意思就是参数的类型传入进来之后不进行宏扩展；
    //啥也不干，即使理解成干，也是扩展成空白，这个是C++语法中允许的；
    //LPSTR  ---->  typedef CHAR *LPSTR, *PSTR; 意思就是char* 指针；在WINNT.H头文件里面
    FILE* pFile = NULL;
    //定义一个FILE结构体指针，在标准的Stdio.h文件头里面
    //可参考：https://blog.csdn.net/qq_15821725/article/details/78929344
    DWORD fileSize = 0;
    // typedef unsigned long       DWORD;  DWORD是无符号4个字节的整型
    LPVOID pTempFileBuffer = NULL;
    //LPVOID ---->  typedef void far *LPVOID;在WINDEF.H头文件里面；别名的void指针类型

    //打开文件
    pFile = fopen(lpszFile,"rb"); //lpszFile是当作参数传递进来
    if (!pFile)
    {
        printf("打开文件失败!\r\n");
        return 0;
    }

    //读取文件内容后，获取文件的大小
    fseek(pFile,0,SEEK_END);
    fileSize = ftell(pFile);
    fseek(pFile,0,SEEK_SET);

    //动态申请内存空间
    pTempFileBuffer = malloc(fileSize);

    if (!pTempFileBuffer)
    {
        printf("内存分配失败!\r\n");
        fclose(pFile);
        return 0;
    }

    //根据申请到的内存空间，读取数据

    size_t n = fread(pTempFileBuffer,fileSize,1,pFile);
    if (!n)
    {
        printf("读取数据失败!\r\n");
        free(pTempFileBuffer);   // 释放内存空间
        fclose(pFile);           // 关闭文件流
        return 0;
    }

    //数据读取成功，关闭文件
    *pFileBuffer = pTempFileBuffer;  // 将读取成功的数据所在的内存空间的首地址放入指针类型pFileBuffer
    pTempFileBuffer = NULL;  // 初始化清空临时申请的内存空间
    fclose(pFile);           // 关闭文件
    return fileSize;         // 返回获取文件的大小
}

//CopyFileBuffer --> ImageBuffer

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempImageBuffer = NULL;

    /*
    上面都是PE里面的相关结构体类型，使用其类型进行自定义变量，并初始化值为NULL
    PIMAGE_DOS_HEADER ---> 指向结构体，别名为这两个 IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER
    PIMAGE_NT_HEADERS ---> 指向结构体，typedef PIMAGE_NT_HEADERS32    PIMAGE_NT_HEADERS;
    PIMAGE_FILE_HEADER ---> 指向结构体，别名为这两个 IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    PIMAGE_OPTIONAL_HEADER32 ---> 指向结构体，别名为这两个 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
    PIMAGE_SECTION_HEADER ---> 指向结构体，别名为这两个 IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
    */

    if (pFileBuffer == NULL)
    {
        printf("FileBuffer 获取失败!\r\n");
        return 0;
    }

    //判断是否是有效的MZ标志
    if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("无效的MZ标识\r\n");
        return 0;
    }

    /*
    IMAGE_DOS_SIGNATURE 这个在头文件WINNT.H里面，对应是个无参数宏；
    #define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
    在宏扩展的时候就会替换为0x5A4D ，然后根据架构的不同进行排序存储，分大端和小端模式；
    使用上面方式进行比对是否是有效的MZ头是非常有效；
    而且IMAGE_DOS_SIGNATURE存储的值是两个字节，刚好就是PWORD ---> typedef WORD near *PWORD;
    所以在进行比较的时候需要强制类型转换为相同的类型进行比较
    */

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    //这里的定义，就相当于已经确定了，其头肯定是MZ了，然后强制转换类型为PIMAGE_DOS_HEADER，就是Dos头

    //判断是否是有效的PE标志
    if (*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("无效的PE标记\r\n");
        return 0;
    }
    /*
    IMAGE_NT_SIGNATURE  ---> #define IMAGE_NT_SIGNATURE   0x00004550  // PE00
    上述同样是个宏扩展，在头文件WINNT.H里面；
    在进行比对的时候因为在Dos头里面有个值是 e_lfanew 对应的时候DWORD类型，所以在进行指针相加的时候
    需要先进行强制类型转换，然后相加，即移动指针位置；然后最终需要比对的结果是0x4550站两个字节
    所以又要强制转换类型为PWORD；
    */
    //定位NT头
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    //上面偏移完成之后pFileBuffer的指针偏移到了NT头---> pNTHeader
    //****************************************************************************************
    //定位PE文件头
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
    //根据PE头的结构体内容，PE文件头位置在NT头首地址偏移4个字节即可得到pPEHeader
    //****************************************************************************************
    //定位可选PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    /*
    要得到可选PE的首地址位置，就根据上面得到的PE文件头位置里面的IMAGE_SIZEOF_FILE_HEADER来定位；
    IMAGE_SIZEOF_FILE_HEADER也是个宏扩展，里面字节描述了PE文件头的大小是20个字节；
    #define IMAGE_SIZEOF_FILE_HEADER  20，所以只要在PE文件头的首地址偏移20个字节即可移动到可选PE头；
    指针相加的时候，此处的类型依然是DWORD
    */
    //****************************************************************************************
    //第一个节表指针
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    /*
    这里要移动到第一个节表指针的首地址，就需要根据上面标准PE文件头中的SizeOfOptionalHeader获取具体可选PE
    头的大小，然后根据这个大小进行偏移即可；
    */
    //****************************************************************************************

    /*
    到了节表的首地址位置之后，因为需要将FileBuffer复制到ImageBuffer，这个过程中，节表之前的Dos头，NT头
    PE文件头，可选PE头，她们的大小都是不变的，所以定位出来之后，到后面的操作中直接复制即可，而节表不一样
    她在FileBuffer状态和ImageBuffer状态是不相同的，她们节表之间复制转换到ImageBuffer是需要拉长节表，所以
    在操作的时候是需要确定FileBuffer到ImageBuffer之后ImageBuffer的大小是多少，而这个大小，已经在可选PE头
    里面的某一个值中已经给出来了 ---> SizeOfImage ;
    注意：FileBuffer和ImageBuffer都是在内存中的展示，只不过FileBuffer是使用winhex等类似的形式打开查看其
    二进制的形式，而ImageBuffer则是双击打开应用程序，将其加载至内存中显示的二进制的形式；
    */
    //****************************************************************************************

    //根据SizeOfImage申请新的内存空间
    pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);

    if (!pTempImageBuffer)
    {
        printf("再次在堆中申请一块内存空间失败\r\n");
        return 0;
    }

    //因为下面要开始对内存空间进行复制操作，所以需要初始化操作，将其置为0，避免垃圾数据，或者其他异常
    //初始化新的缓冲区
    memset(pTempImageBuffer,0,pOptionHeader->SizeOfImage);
    /*
    参考：http://c.biancheng.net/cpp/html/157.html

    在头文件string.h里面

    void* memset( void* ptr,int value,size_t num );
    memset()函数用来将指定内存的前n个字节设置为特定的值;

    参数说明：
    ptr     为要操作的内存的指针;
    value   为要设置的值;既可以向value传递int类型的值,也可以传递char类型的值,int和char可以根据ASCII码相互转换;
    num     为ptr的前num个字节,size_t就是unsigned int。
    函数说明：memset()会将ptr所指的内存区域的前num个字节的值都设置为value,然后返回指向ptr的指针;
    */
    //****************************************************************************************

    //根据SizeOfHeaders大小的确定，先复制Dos头
    memcpy(pTempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
    /*
    参考：http://c.biancheng.net/cpp/html/155.html

    在头文件string.h里面

    void* memcpy (void* dest,const void* src,size_t num);
    memcpy()函数功能用来复制内存的；她会复制src所指向内容的首地址，作为起始位置，然后偏移num个字节到dest所指的内存地址
    的位置；此函数有个特征就是，她并不关心被复制的数据类型，只是逐字节地进行复制，这给函数的使用带来了很大的灵活性，
    可以面向任何数据类型进行复制；

    需要注意的是：
    dest 指针要分配足够的空间，也就是要大于等于num字节的空间，如果没有分配足够的空间会出现错误；
    dest和src所指的内存空间不能重叠（如果发生了重叠，使用 memmove() 会更加安全）。

    所以上面的代码的含义如下：
    (1)pDosHeader ---> 是指向pFileBuffer的首地址，也就是内存复制的时候从这里开始；
    (2)pTempImageBuffer  ---> 这里是表示上面要复制的目的，要把内容复制到这块内存来；
    (3)pOptionHeader->SizeOfHeaders  ---> 这里表示复制多大的内容到pTempImageBuffer里面去；
    (4)从上面看来我们就知道复制到目标pOptionHeader->SizeOfHeaders所在的内存空间一定要比pTempImageBuffer大；
    */
    //****************************************************************************************

    //上面把已经确定的头都复制好了，那么下面就可以开始复制节的里面的内容，因为节不仅仅是一个，所以需要用到for循环进行操作
    //根据节表循环copy节的内容
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    //定义一个临时节表的指针
    for (int i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
    {
        memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
            (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
    }
    /*
    上面的大概操作就是根据标准PE文件头里面的值 NumberOfSections确定有几个节，然后不断的计算并增加指针偏移位置，不停的复制

    PointerToRawData   ---> 节在文件中的偏移地址；
    VirtualAddress     ---> 节在内存中的偏移地址;
    SizeOfRawData      ---> 节在文件中对齐后的尺寸;

    (void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress)   ---> Dest（目的地）
    上面我们已经知道了函数memcpy是怎么复制操作的，所以这里我们依依解释下：
    首先我们知道，上面展示的是目的地，而且我们的目的是要从FileBuffer节内容复制到ImageBuffer节的内容，
    那么要使用到的是文件被双击打开之后在内存中的偏移地址，这个地址就是VirtualAddress；这里举个例子:
    正常打开notepad.exe,然后使用winhex加载这个notepad.exe的内存数据，同时使用PE解析工具得到两个值的信息如下：
    可选PE头 ---> ImageBase   ---> 0x01000000
    第一个节表显示的VirtualAddress  ---> 00001000
    上面两个值相加就得到了文件被打开在内存中第一个节的真实数据的起始位置 ---> 0x01001000
    查看winhex对应的地址，确认是对的；

    (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData)      ---> Src（源复制的起始内存地址）
    同样是上面的例子：
    PointerToRawData是节在文件中的偏移地址，而我们知道，在文件中和在内存中是不一样的，因为在内存中有ImageBase的说法，
    但在文件中没有，所以她的起始位置就是文件存储在硬盘的时候使用winhex打开的开头位置，为这里同样使用winhex以二进制的形式
    打开notepad.exe（非双击打开），发现文件的起始位置是0x00000000，同时使用PE解析工具确认出了PointerToRawData的值
    PointerToRawData  ---> 0x00000400 ; 起始位置为0x00000000 ,她们相加就得到第一个节表的起始位置为0x00000400
    查看winhex对应的地址，确认是对的；
    所以这里总结下来的Src，就是内存复制的时候，从这个偏移地址开始拿数据开始复制；

    pTempSectionHeader->SizeOfRawData
    这里就是告诉我们上面复制要复制多大的内容到 (void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress)
    SizeOfRawData ---> 节在文件中对齐后的尺寸;
    例子还是以上面的为例：
    通过PE解析工具确认SizeOfRawData的大小为：0x00007800

    总结：
    memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
    (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData),
    pTempSectionHeader->SizeOfRawData);

    上面代码就是在文件中的形式找到要复制的位置0x00000400的起始位置开始复制，要复制0x00007800个字节大小，也就是从
    0x00000400这个地址开始向后偏移7800个字节，将这些数据复制到文件双击被打开时候的内存地址0x01001000为起点向后覆盖复制
    完成即可，为这里测试算了下；0x00000400+0x00007800=0x00007C00 ; 0x00007C00这个地址刚好是第二个节的PointerToRawData
    这样就可以很好的理解for循环对第二个节的复制；
    */

    //****************************************************************************************
    //返回数据
    *pImageBuffer = pTempImageBuffer;
    //将复制好后节的首地址保存到指针pImageBuffer中
    pTempImageBuffer = NULL;
    //初始化清空临时使用的pTempImageBuffer

    return pOptionHeader->SizeOfImage;
}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer)
{
    //下面大部分操作都是跟上面一样的，这里就不再赘述了
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempNewBuffer = NULL;
    DWORD sizeOfFile = 0;
    DWORD numberOfSection = 0;

    if (pImageBuffer == NULL)
    {
        printf("缓冲区指针无效\r\n");
    }
    //判断是否是有效的MZ标志
    if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("不是有效的MZ头\r\n");
        return 0;
    }
    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    //判断是否是有效的PE标志
    if (*((PDWORD)((DWORD)pImageBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("不是有效的PE标志\r\n");
        return 0;
    }
    //NT头地址
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
    //标准PE文件头
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    //可选PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    //第一个节表地址
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    //计算文件需要的空间--最后一个节的文件偏移+节对齐后的长度
    /*
    numberOfSection = pPEHeader->NumberOfSections;
    pSectionHeader = pSectionHeader[numberOfSection-1];
    sizeOfFile = (pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize + pOptionHeader->FileAlignment);
    printf("sizeOfFile %X \r\n",sizeOfFile);

    for (DWORD i=0;i<=numberOfSection;i++)
    {
        sizeOfFile += sizeOfFile[i];
    }
    */

    sizeOfFile = pOptionHeader->SizeOfHeaders;
    //使用winhex打开notepad.exe 是0x00000400，这是第一个节之前的所有大小
    for(DWORD i = 0;i<pPEHeader->NumberOfSections;i++)
    {
        sizeOfFile += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]另一种加法
    }

    /*
    上面的for循环大概意思就是基于几个节的数量依次循环叠加sizeOfFile的值；因为SizeOfRawData是文件中对齐后的大小；
    所以循环计算如下：
    sizeOfFile = 0x00000400 + 0x00007800 = 0x00007C00
    sizeOfFile = 0x00007C00 + 0x00000800 = 0x00008400
    sizeOfFile = 0x00008400 + 0x00008000 = 0x00010400

    */

    //根据SizeOfImage申请新的空间
    pTempNewBuffer = malloc(sizeOfFile);

    if (!pTempNewBuffer)
    {
        printf("申请内存空间失败\r\n");
        return 0;
    }
    //初始化新的缓冲区
    memset(pTempNewBuffer,0,sizeOfFile);
    //根据SizeOfHeaders 先copy头
    memcpy(pTempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
    //根据节表循环复制节
    //PIMAGE_SECTION_HEADER pTempSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader);
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    for (int j=0;j<pPEHeader->NumberOfSections;j++,pTempSectionHeader++)
    {
        /*memcpy((LPVOID)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),
        (LPVOID)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress),
        pTempSectionHeader->SizeOfRawData);*/
        //PointerToRawData节区在文件中的偏移,VirtualAddress节区在内存中的偏移地址,SizeOfRawData节在文件中对齐后的尺寸
        memcpy((PDWORD)((DWORD)pTempNewBuffer+pTempSectionHeader->PointerToRawData),
        (PDWORD)((DWORD)pImageBuffer+pTempSectionHeader->VirtualAddress),
        pTempSectionHeader->SizeOfRawData);
        //printf("%X  --> PoniterToRadata\r\n",pTempSectionHeader->PointerToRawData);
        //printf("%X  --> VirtualAddress\r\n",pTempSectionHeader->VirtualAddress);
        //printf("%X  --> VirtualSize\r\n",pTempSectionHeader->Misc.VirtualSize);
    }

    //返回数据
    *pNewBuffer = pTempNewBuffer;
    pTempNewBuffer = NULL;
    return sizeOfFile;
  }

BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile)
{
    FILE* fp = NULL;
    fp = fopen(lpszFile, "wb+");
    if (!fp)  //  这里我刚开始写漏了一个等于号，变成复制NULL了，导致错误
//  if(fp == NULL)  可以这么写，没问题
    {
        return FALSE;
    }
    fwrite(pMemBuffer,size,1,fp);
    fclose(fp);
    fp = NULL;
    return TRUE;
}
/*
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva)
{
    DWORD dwFOAValue = 0;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    //判断指针是否有效
    if (!pFileBuffer)
    {
        printf("FileBuffer 指针无效\r\n");
        return dwFOAValue;
    }
    //判断是否是有效的MZ标志
    if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("不是有效的MZ标志\r\n");
        return dwFOAValue;
    }
    //为需要用到的指针赋值
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);

    //判断dwRva所处的节

    //计算与节开始位置的差

    //该节文件中的偏移+差 == 该值在文件中的偏移
    return 0;
}
*/

//开始添加ShellCode代码

VOID AddCodeInCodeSec()
{
    LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;
    LPVOID pNewBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PBYTE codeBegin = NULL;
    BOOL isOK = FALSE;
    DWORD size = 0;

    //File-->FileBuffer
    ReadPEFile(FilePath_In,&pFileBuffer);
    if (!pFileBuffer)
    {
        printf("文件-->缓冲区失败\r\n");
        return ;
    }

    //FileBuffer-->ImageBuffer
    CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
    if (!pImageBuffer)
    {
        printf("FileBuffer-->ImageBuffer失败\r\n");
        free(pFileBuffer);
        return ;
    }

    //判断代码段空闲区域是否能够足够存储ShellCode代码
    pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)(((DWORD)pImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER + IMAGE_SIZEOF_NT_OPTIONAL32_HEADER);
    if (((pSectionHeader->SizeOfRawData) - (pSectionHeader->Misc.VirtualSize)) < SHELLCODELENGTH)
    {
        printf("代码区域空闲空间不够\r\n");
        free(pFileBuffer);
        free(pImageBuffer);
    }

    //将代码复制到空闲区域
    //地址是这么算的:ImageBuffer+VirtualAddress([V(VO),内存中偏移(该块的RVA).])+Misc.VirtualSize
    codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
    printf("pSectionHeader->VirtualAddress: %#010X\r\n", pSectionHeader->VirtualAddress);
    printf("pSectionHeader->Misc.VirtualSize: %#010X\r\n", pSectionHeader->Misc.VirtualSize);
    printf("codeBegin: %#010X\r\n", codeBegin);

    //内存复制
    memcpy(codeBegin,ShellCode,SHELLCODELENGTH);

    //现在还是0xE8,00,00,00,00
    //E9,00,00,00,00，所以要进行修正
    //注意ImageBase

    //修正E8-->call后面的代码区域
    DWORD callAddr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)));

    /*
    codeBegin是从0x6A开始的
    E8下一条指令的地址:codeBegin + 0xD
    ImageBuffer开始的位置:(DWORD)pImageBuffer
    得到在ImageBuffer中的偏移:((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)
    E8在内存中真正运行时候的地址:(pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer))
    */
    printf("callAddr ---> %#010X \r\n",callAddr);
    *(PDWORD)(codeBegin + 0x09) = callAddr;
    printf("*(PWORD)(codeBegin + 0x09) ---> %#010X \r\n",*(PDWORD)(codeBegin + 0x09));
    /*
     公式:真正要跳转的地址 = E8这条指令的下一行地址 + X
                     X = 真正要跳转的地址 - E8这条指令的下一行地址
    注意这里E8这条指令的下一行地址它是运行时的地址:靠考虑ImageBase

    */

    //修正E9-->jmp后面的代码区域
    DWORD jmpAddr = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + SHELLCODELENGTH) - (DWORD)pImageBuffer)));
    printf("jmpAddr ---> %#010X \r\n",jmpAddr);
    *(PDWORD)(codeBegin + 0x0E) = jmpAddr;
    printf("*(PWORD)(codeBegin + 0x0E) ---> %#010X \r\n",*(PDWORD)(codeBegin + 0x0E));

    /*
    和E8一样的用法
    */

    //修正OEP
    printf("pOptionHeader->AddressOfEntryPoint ---> %#010X \r\n",pOptionHeader->AddressOfEntryPoint);
    printf("(DWORD)codeBegin ---> %#010X \r\n",((DWORD)codeBegin - (DWORD)pImageBuffer));
    pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;
    printf("pOptionHeader->AddressOfEntryPoint ---> %#010X \r\n",pOptionHeader->AddressOfEntryPoint);

    //修正OEP好理解，就是定位到OEP地址，然后直接通过codeBegin地址减去pImageBuffer的首地址即可；

    //ImageBuffer-->NewBuffer
    size = CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
    if (size == 0 || !pNewBuffer)
    {
        printf("ImageBuffer-->NewBuffer失败\r\n");
        free(pFileBuffer);
        free(pImageBuffer);
        return ;
    }

    //NewBuffer-->文件
    isOK = MemeryTOFile(pNewBuffer,size,FilePath_Out);
    if (isOK)
    {
        printf("修改代码添加SHELLCODE 存盘成功\r\n");
        return ;
    }

    //释放内存
    free(pFileBuffer);
    free(pImageBuffer);
    free(pNewBuffer);
}
```

```php
// test2.cpp:程序执行代码

#include "stdafx.h"
#include "test.h"

int main(int argc, char* argv[])
{
    AddCodeInCodeSec();
    return 0;
}
```

![image-20220205163357582](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c3d3eb95efcfa8e50f9e42bc82a1e540eb15d080.png)