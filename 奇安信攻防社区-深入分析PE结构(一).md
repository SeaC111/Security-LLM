0x0前言
=====

PE学习是基本功，绕不过去的。

PE的全称是Portable Executable，直译就是可移植的可执行文档

一个exe文件，是由一堆PE文件组成的

0x1准备阶段
=======

define
------

C程序-&gt;替换(预编译时)-&gt;编译-&gt;链接-&gt;硬编码(0x21)

宏定义 就是做替换(在预编译时)

```php
#define TRUE 1
#define FALSE 0
```

注：

1、它不是常量，它只是在预处理时，做了替换

2、只作字符序列的替换工作，不作任何语法的检查

3、如果宏定义不当，错误要到预处理之后的编译阶段才能发现

带参数宏定义

格式：

```php
#define 标识符(参数表)字符序列
```

举个例子：

```php
#define MAX(A, B) ((A)>(B)?(A):(B))
```

两者是等价的

Function是一个函数，要给它开辟一个新的堆栈空间

MAX是宏定义，本身是直接替换的，不会开辟新的堆栈

从内存使用的角度来看，宏定义是有优势的

```php
#include "stdafx.h"
#include <stdlib.h>
#include <windows.h>

#define MAX(A, B) ((A)>(B)?(A):(B))

int Function(int x, int y)
{
    return x>y?x:y;
}

int main(int argc, char* argv[])
{
    int x = Function(3, 2);

    int y = MAX(3, 2);

    printf("%d %d\n", x, y);

    return 0;
}
```

![image-20220124221127822](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-84d59322bc1056bde0853dc0f674797560ff89be.png)

注：

```php
#define MAX(A, B) ((A)>(B)?(A):(B))
```

```php
1、宏名标识符与左圆括号之间不允许有空白符，应紧接在一起.                   

2、宏与函数的区别：函数分配额外的堆栈空间，而宏只是替换.                   

3、为了避免出错，宏定义中给形参加上括号.                       

4、末尾不需要分号.                      

5、define可以替代多行的代码，记得后面加 \
```

头文件
---

头文件包含

```php
<>:当前目录
"":配置的环境变量目录下，系统目录去找

自己的头文件使用:""
使用系统头文件:<>
```

![image-20220124221918885](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5f10d4008575812adf9c412913a15bada585570d.png)

![image-20220124221937422](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9202d82cba9804fd4f6fe85211ef3374581ac233.png)

![image-20220124221957469](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d152fe3189e2528d48f7c01c4255c05652dfce11.png)

头文件中写上声明，cpp文件中写入代码，谁调用谁引用`.h`文件

头文件重复包含问题

![image-20220125103442167](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-dfda60a47862284d741fe671fe6259e4c1a5cc5c.png)

如果此时有个文件同时包含了`x.h`和`y.h`会出问题

```php
#include "stdafx.h"
#include "X.h"
#include "Y.h"
int main(int argc, char* argv[])
{

    return 0;
}
```

解决方案：

```php
#if !defined(ZZZ)
#define ZZZ

struct Student
{
    int level;
};

#endif
```

这句话的意思可以这样去理解，如果ZZZ已经存在了，就不在声明.  
ZZZ相当于一个编号，越复杂越好，保证它的唯一性.

![image-20220125104400339](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-73f7005de62ef0f8a53de2bde748452a30a37d4e.png)

0x2内存分配与释放
==========

前言
--

根据需要，去动态申请内存

```php
int* ptr;//声明指针

//在堆中申请内存,分配128个int
ptr = (int *)malloc(sizeof(int)*128);
```

选中`malloc`，F1之后，可以看msdn

需要包含

```php
<stdlib.h>、<malloc.h>
```

```php
void* malloc(size_t size);
```

`void*`：无类型的指针

`size_t` 代码中可以直接F12跳过来

```php
typedef unsigned int size_t;
```

全局变量，放到全局区，使用完之后，就不用管了

函数中的变量，是放到堆区的，使用完之后，是要释放的，否则会造成内存泄露

堆：现用现分

核心代码
----

```c
//无论申请的空间大小 一定要进行校验 判断是否申请成功
if(ptr == NULL)
{
    return 0;
}

//初始化分配的内存空间                    
memset(ptr,0,sizeof(int)*128);

//使用
*(ptr) = 1; 

//使用完毕 释放申请的堆空间     
free(ptr);

//将指针设置为NULL(堆区)
ptr = NULL;
```

注意：

```php
1、使用sizeof(类型)*n 来定义申请内存的大小                 

2、malloc返回类型为void*类型 需要强制转换                 

3、无论申请的内存有多小 一定要判断是否申请成功                    

4、申请完空间后要记得初始化.                 

5、使用完一定要是否申请的空间.                    

6、将指针的值设置为NULL.
```

每个进程都有自己独立的4GB虚拟内存

2G用户使用，2G操作系统使用

继续再看一下`memset`：将缓冲区设置为指定字符。

```C
void *memset(
   void *dest,
   int c,
   size_t count
);
```

参数分析

```php
dest
指向目标的指针

c
要设置的字符

count
字符数
```

0x3文件读写
=======

前言
--

```php
1、fopen函数        打开文件函数(打开一个文件并返回文件指针)

2、fseek函数        查找文件头或者尾函数(移动文件的读写指针到指定的位置)->设置文件的指针

3、ftell函数        定位指针函数(获取文件读写指针的当前位置)->判断文件大小

4、fclose函数       关闭文件函数(关闭文件流)

5、fread函数        读取文件内容函数(从文件流中读取数据)
```

看一下`fseek`，这个函数

参考：<https://docs.microsoft.com/zh-cn/cpp/c-runtime-library/reference/fseek-fseeki64?view=msvc-170>

必须包含的文件头：`<stdio.h>`

```php
int fseek(
   FILE *stream,
   long offset,
   int origin
);
```

分析参数：

```php
stream
指向 FILE 结构的指针

offset
origin 中的字节数

origin
初始位置
```

自变量 origin 必须是下列常量之一，在`stdio.h`中定义

```php
自变量 origin 必须是下列常量之一，在中定义 STDIO.H

SEEK_SET    文件开头，可以写0
SEEK_CUR    文件指针的当前位置，可以写1
SEEK_END    文件结尾，可以写2
```

返回值：如果成功，返回 0，否则，返回一个非零值。

再看一下`fread`，这个函数

参考：<https://docs.microsoft.com/zh-cn/cpp/c-runtime-library/reference/fread?view=msvc-170>

```php
size_t fread(
   void *buffer,
   size_t size,
   size_t count,
   FILE *stream
);
```

具体分析一下参数：

```php
buffer
数据的存储位置

size
项目大小(以字节为单位)

count
要读取的项的最大数量

stream
指向 FILE 结构的指针
```

fread 要包好的文件头：`<stdio.h>`

文件-&gt;内存
---------

### 前言

将记事本`.exe`读取到内存中，并返回读取后在内存中的地址

(把exe读取出来，放到内存中)

### 整体流程

大概思路：

```php
1、打开文件

2、得到文件的大小 --> 读取文件到内存，然后跳转到文件末尾，查看跳转的长度

3、根据大小申请内存

4、把文件中内容读取到内存里

5、返回内存编号
```

### 核心代码

```php
#include "stdafx.h"
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>

#define F_PATH "C:\\notepad.exe"

int Pe_Getfile_Sizes()
{
    FILE* fp=fopen(F_PATH,"r");
    if (fp == NULL)
    {
        return 0;
    }
    fseek(fp,0L,SEEK_END);
    int size = ftell(fp);
    fseek(fp,0,SEEK_SET);
    fclose(fp);

    printf("%d\n",size);
    return size;
}

int FileSizes = Pe_Getfile_Sizes();

int Pe_ReadMemtory_addrs()
{
    //定义一个文件的指针，并初始化其为NULL
    FILE* fstream = NULL;

    //初始化exe文件长度
    int FstreamSizes = 0;

    //准备打开文件notepad.exe ，读写，且是读二进制文件
    fstream = fopen(F_PATH,"ab+");

    //获取打开文件的exe大小
    FstreamSizes = FileSizes;

    //申请动态内存指向FileBuffer
    int* FileBuffer = (int*)malloc(FstreamSizes);

    //判断申请的内存是否成功，不成功就返回0，成功就开始读exe内容写入申请的内存中
    if (FileBuffer == NULL)
    {
        return 0;
    }
    else
    {
        fread(FileBuffer,FstreamSizes,1,fstream);
    }
    memset(FileBuffer,0,FstreamSizes);

    //返回内存编号
    int addr = (int)FileBuffer;
    printf("%x\n",addr);

    //释放申请的内存空间
    free(FileBuffer);
    FileBuffer = NULL;
    fclose(fstream);

    return 0;
}

int main(int argc, char* argv[])
{
    Pe_ReadMemtory_addrs();
    return 0;
}
```

![image-20220125164746147](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-70a81e448ae84fe656b2ce05bf97b26398719934.png)

内存-&gt;硬盘
---------

### 前言

将记事本`.exe`读取到内存中，然后将内存中的的数据，重新存储到一个文件中(.exe格式)，然后双击打开，看是否能够使用.

(把内存中的数据，读取到硬盘上，变成exe，还能运行)

### 核心代码

```php
#include "stdafx.h"
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>

#define F_PATH "C:\\notepad.exe"
#define W_PATH "C:\\newnotepad.exe"

int Pe_Getfile_Size()
{
    FILE* fp=fopen(F_PATH,"r");
    if (!fp)
    {
        return -1;
    }
    fseek(fp,0L,SEEK_END);
    int size = ftell(fp);
    fseek(fp,0,SEEK_SET);
    fclose(fp);

    return size;
}

int FileSizes = Pe_Getfile_Size();

int Pe_ReadMemtory_addrs1()
{
    //定义两个文件的指针，并初始化为NULL
    FILE* fstream1 = NULL;
    FILE* fstream2 = NULL;

    //初始化exe文件长度
    int FstreamSizes = 0;

    //准备打开文件notepad.exe ，读写，且是读二进制文件
    fstream1 = fopen(F_PATH,"ab+");

    //写入一个新的不存在的exe文件
    fstream2 = fopen(W_PATH,"ab+");

    //获取打开文件的exe大小
    FstreamSizes = FileSizes;
    //    printf("%d \n",FstreamSizes);

    //申请动态内存指向FileBuffer
    int* FileBuffer = (int*)malloc(FstreamSizes);

    //判断申请的内存是否成功，不成功就返回0
    //成功的话就开始读exe文件内容，写入到另一个exe文件中

    if (FileBuffer == NULL)
    {
        return 0;
    }
    else
    {
        fread(FileBuffer,FstreamSizes+1,1,fstream1);
        fwrite(FileBuffer,FstreamSizes,1,fstream2);
    }
    memset(FileBuffer,0,Pe_Getfile_Size());
    //释放堆中申请的内存，并关闭打开的文件流

    free(FileBuffer);
    FileBuffer = NULL;
    fclose(fstream1);
    fclose(fstream2);

    return 0;
}

int main(int argc, char* argv[])
{
    Pe_ReadMemtory_addrs1();
    return 0;
}
```

是可以使用的

![image-20220125165152730](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9709bbced89eb7e6752a55ca798dd038717bbc5e.png)

0x4PE头解析
========

前言
--

使用WinHex打开

```php
C:\Windows\System32\notepad.exe
```

![image-20220112095530792](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cec965297107eb785120f1073f0a4191da16252f.png)

我们现在看到的样子 就是它在硬盘上的样子

![image-20220112095708124](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0af637e9cdcb705017812c5c5a2baf61d73dc2f2.png)

再看一下它在内存中运行时的样子

本机打开一个notepad.exe

![image-20220112100111559](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-57a4b5737a27a03d6651f5c5062983532da5dfab.png)

![image-20220112112805846](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-199ac19486dfa43f14d85a4f4d87d4df3554e0b7.png)

![image-20220112113700353](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c2a26c3282b48a55cd03e85d535ecf815296dcb6.png)

![image-20220112113750092](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b721560ed3e250728174b59f7853941bd3c118e9.png)

进行分析

1、开始的位置不一样

2、填充00的大小不一样。硬盘上填充00小，内存中填充00比较大，大部分数据是一样的

OD是逆向分析别人的程序，OD看到的是在内存中的样子

`.exe`、`.dll`、`.sys`都是以4D 5A开头的

它是一个标记，是MZ，属于可执行文件

可执行文件，简单来说，记事本(`.txt`)它是由`notepad.exe`打开的

PE结构是分节的，一段一段的

1、节省硬盘空间

硬盘间隔小，内存间隔大，这是老的编译器

任何一个exe程序都会有一个自己独立的4G内存空间，虚拟内存

2G是平时写应用程序用的，2G是给操作系统用的

这里注意：还有一些exe程序 当我们用winhex打开时

它在硬盘上和内存中是一样的

这个时候我们要有两个概念 就是硬盘对齐(200h字节)和内存对齐(1000h字节)，它是为了增加读写速度

2、节省内存空间，操作系统考虑到了多开

只需要开 不同的节 即可

![image-20220112115548235](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bba247b433ec65df3d914d6375e6bc10f72c108c.png)

PE磁盘文件与内存映像图

![image-20220112120208042](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-448b0fc02ae8a5acd8df4ee093cfa4e9cf0a52c0.png)

一个PE文件从硬盘到内存执行中，是有一个拉伸的过程

块表：所有的数据都存储在块表(节表)，对当前整个exe程序做概要性描述

PE文件头、DOS头：整个exe的特征

实操ipmsg.exe

使用winhex打开`ipmsg.exe`

![image-20220112123022983](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cd9e68ac1464f271c894bccb239a256a7c3cb459.png)

WORD:无符号两字节

DWORD:无符号四字节

DOS头(大小是确定的)-&gt;40
-------------------

DOS头是16位系统中使用的

带`*`数据是要记住的

作用：

1、解析前两个字节，判断文件类型

2、通过DOS头找PE文件真正开始的地方

```php
0x00 WORD e_magic; //5A4D * MZ标记用于判断是否为可执行文件
0x02 WORD e_cblp; //0090
0x04 WORD e_cp; //0003
0x06 WORD e_crlc; //0000
0x08 WORD e_cparhdr; //0004
0x0a WORD e_minalloc; //0000
0x0c WORD e_maxalloc; //FFFF
0x0e WORD e_ss; //0000
0x10 WORD e_sp; //00B8
0x12 WORD e_csum; //0000
0x14 WORD e_ip; //0000
0x16 WORD e_cs; //0000
0x18 WORD e_lfarlc; //0040
0x1a WORD e_ovno; //0000
0x1c WORD e_res[4]; //0000000000000000
0x24 WORD e_oemid; //0000
0x26 WORD e_oeminfo; //0000
0x28 WORD e_res2[10]; //20
0x3c DWORD e_lfanew; //00000080 * PE头相对于文件的偏移，用于定位PE文件
```

使用`PETool`小工具 进行查看

拖入我们的`ipmsg.exe`

![image-20220112124021322](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3a1f9c0d1e1db40bfa9b0556dcdb6d2062206386.png)

可以看到 确实是一致的

![image-20220112124056611](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c6d0ff9a5bdb6829235b997baf0ff7d1a2aa3b48.png)

32位程序和64位程序 结构是不一样的

80：从文件开始的地方算，过80个字节，就是PE文件真正开始的地方

![image-20220112125230743](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7494ca02acc10ea891e30046225f32c8f28bf581.png)

中间这一部分大小是不确定的

留了一块空间，可以放一些随意的数据

![image-20220112125355815](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-907b8c5c215e3a14e862c0121eceee2ccd57fbd0.png)

NT头
---

NT头包含：PE标记、标准PE头、可选PE头

### PE标记

```php
0x00 DWORD Signature; //00004550
```

### 标准PE头(大小是确定的)-&gt;20

```php
0x00 WORD Machine;  //014C * 程序运行的CPU型号，0x0任何处理器
0x02 WORD NumberOfSections; //0008 * 文件中存在的节的总数，除了头，还有几节数据，如果要新增节或者合并节就要修改这个值.
0x04 DWORD TimeDateStamp; //3E22F0DF * 时间戳:文件的创建时间（和操作系统的创建时间无关），编译器填写的
0x08 DWORD PointerToSymbolTable; //00000000
0x0c DWORD NumberOfSymbols; //00000000
0x10 WORD SizeOfOptionalHeader; //00E0 * 可选PE头的大小，32位PE文件默认E0h=16*14，64位PE文件默认为F0h，大小可以自定义
0x12 WORD Characteristics; //010E * 每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1
```

**TimeDateStamp**

`.map`文件是对`.exe`文件中函数的描述，对`.exe`文件的说明

当`.map`文件和`.exe`文件 不同步时

就是检查 时间戳是否 一致

**Characteristics**

![image-20220112135457065](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-185d59ed8ff1022a5ef1006515430a6a7ac6cba0.png)

![image-20220112153714023](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-eb64615a58ba343dd6ddb242b4b86e920114f33d.png)

打勾的 即为1

把所有值 对应起来 0 1 0 E

```php
0000 0001 0000 1110
```

![image-20220112153733828](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-40399817ccd977a718b1eca2a132b251da285f48.png)

### 可选PE头(大小是不确定的)

程序入口 + 内存镜像基址 才是真正的地址

```php
0x00 WORD Magic; * 说明文件类型：10B->32位下的PE文件 20B->64位下的PE文件
0x02 BYTE MajorLinkerVersion;
0x03 BYTE MinorLinkerVersion;
0x04 DWORD SizeOfCode; * 所有代码节的和，必须是FileAlignment的整数倍 编译器填的 没用
0x08 DWORD SizeOfInitializedData; * 已初始化数据大小的和，必须是 FileAlignment的整数倍 编译器填的 没用
0x0c DWORD SizeOfUninitializedData; * 未初始化数据大小的和，必须是 FileAlignment的整数倍 编译器填的 没用 
0x10 DWORD AddressOfEntryPoint; * 程序入口
0x14 DWORD BaseOfCode; * 代码开始的基址，编译器填的 没用
0x18 DWORD BaseOfData; * 数据开始的基址，编译器填的 没用
0x1c DWORD ImageBase; * 内存镜像基址
0x20 DWORD SectionAlignment; * 内存对齐
0x24 DWORD FileAlignment; * 文件对齐
0x28 WORD MajorOperatingSystemVersion;
0x2a WORD MinorOperatingSystemVersion;
0x2c WORD MajorImageVersion;
0x2e WORD MinorImageVersion;
0x30 WORD MajorSubsystemVersion;
0x32 WORD MinorSubsystemVersion;
0x34 DWORD Win32VersionValue;
0x38 DWORD SizeOfImage; * 内存中整个PE文件的映射的尺寸，可以比实际的值大，但必须是FileAlignment的整数倍，是拉伸之后的大小
0x3c DWORD SizeOfHeaders; * 所有头+节表，技照文件对齐后的大小，否则加载会出错
0x40 DWORD CheckSum; * 校验和，一些系统文件有要求，用来判断文件是否被修改
0x44 WORD Subsystem;
0x46 WORD DllCharacteristics;
0x48 DWORD SizeOfStackReserve; * 初始化时保留的堆栈大小

0x4c DWORD SizeOfStackCommit; * 初始化时实际提交的大小
0x50 DWORD SizeOfHeapReserve; * 初始化时保留的堆大小
0x54 DWORD SizeOfHeapCommit; * 初始化时实践提交的大小
0x58 DWORD LoaderFlags;
0x5c DWORD NumberOfRvaAndSizes; * 目录项数目
0x60 _IMAGE_DATA_DIRECTORY DataDirectory[16]; 16个结构体，每个结构体是8个字节
```

![image-20220112135755194](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7a83f45434ade368de16a9fb0ceb2fe84d5701ed.png)

进行了拉伸，完成之后完全遵守操作系统，就可以执行了

程序入口 + 内存镜像基址 才是真正的入口点地址

![image-20220112162514212](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f4d923e02f0d6a119705b08ccc2b56f7003c07a9.png)

输出整个PE头
-------

### 核心代码

编写程序读取一个exe文件，输出所有的PE头信息

```php
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int* OpenFile()
{
    FILE* PointToFile = NULL;
    int FileSize = 0;
    int* StrBuffer = NULL;
    int Num = 0;

    //打开文件
    if ((PointToFile = fopen("C:\\notepad.exe","rb")) == NULL) {
        printf("打开文件失败!\n");
        exit(1);
    }

    //获取文件大小
    fseek(PointToFile,0,2);
    FileSize = ftell(PointToFile);

    //重定位指针
    fseek(PointToFile,0,0);

    //buffer指向申请的堆
    StrBuffer = (int*)(malloc(FileSize));
    if (!StrBuffer)
    {
        printf("堆空间分配失败!\n");
        free(StrBuffer);
        return 0;
    }

    //读取文件内容
    Num = fread(StrBuffer,FileSize,1,PointToFile);
    if (!Num)
    {
        printf("读取文件内容失败!\n");
        free(StrBuffer);
        return 0;
    }

    //关闭文件
    fclose(PointToFile);

    //将缓冲区内的文件内容的地址返回到调用函数的地方
    return StrBuffer;
}

int* FileSizes = OpenFile();

int PrintfNtHeaders()
{
    //文件指针
    unsigned int* PointBuffer = (unsigned int*)FileSizes;
    unsigned short* pBuffer = (unsigned short*)PointBuffer;
    unsigned char* pcBuffer = (unsigned char*)PointBuffer;

    //判断MZ和PE的标志
    unsigned short Cmp1 = 0x5A4D;
    unsigned int Cmp2 = 0x00004550;

    //判断文件是否读取成功
    if(!PointBuffer)
    {
        printf("文件读取失败！\n");
        free(PointBuffer);
        return 0;
    }

    //判断是否为MZ标志
    if (*pBuffer != Cmp1)
    {
        printf("不是有效MZ标志！\n");
        printf("%X\n",*pBuffer);
        free(PointBuffer);
        return 0;
    }
    printf("*********打印DOS头*********\n");
    printf("e_magic:\t\t\t%X\n",*(pBuffer));
    printf("e_ifanew:\t\t\t%08X\n\n\n",*(PointBuffer+15));

    //判断是否为PE标志
    if (*(PointBuffer+56) != Cmp2)
    {
        printf("不是有效的PE标志！\n");
        printf("%X\n",*(PointBuffer+56));
        free(PointBuffer);
        return 0;
    }

    printf("*********打印标准PE文件头*********\n");

    printf("PE标志:\t\t\t\t%X\n",*(PointBuffer+56));

    printf("Machine:\t\t\t%04X\n",*(pBuffer+114));
    printf("NumberOfSection:\t\t%04X\n",*(pBuffer+115));
    printf("TimeDateStamp:\t\t\t%08X\n",*(PointBuffer+58));
    printf("PointerToSymbolTable:\t\t%08X\n",*(PointBuffer+59));
    printf("NumberOfSymbols:\t\t%08X\n",*(PointBuffer+60));
    printf("SizeOfOptionalHeader:\t\t%04X\n",*(pBuffer+122));
    printf("Chrarcteristics:\t\t%04X\n\n\n",*(pBuffer+123));

    printf("*********打印标准可选PE头*********\n");

    printf("Magic:\t\t\t\t%04X\n", *(pBuffer+124));
    printf("MajorLinkerVersion:\t\t%02X\n", *(pcBuffer+250));
    printf("MinorLinkerVersion:\t\t%02X\n", *(pcBuffer+251));
    printf("SizeOfCode:\t\t\t%08X\n", *(PointBuffer+63));
    printf("SizeOfInitializedData:\t\t%08X\n", *(PointBuffer+64));
    printf("SizeOfUninitializedData:\t%08X\n", *(PointBuffer+65));
    printf("AddressOfEntryPoint:\t\t%08X\n", *(PointBuffer+66));
    printf("BaseOfCode:\t\t\t%08X\n", *(PointBuffer+67));
    printf("BaseOfData:\t\t\t%08X\n", *(PointBuffer+68));
    printf("ImageBase:\t\t\t%08X\n", *(PointBuffer+69));
    printf("SectionAlignment:\t\t%08X\n", *(PointBuffer+70));
    printf("FileAlignment:\t\t\t%08X\n", *(PointBuffer+71));
    printf("MajorOperatingSystemVersion:\t%04X\n", *(pBuffer+144));
    printf("MinorOperatingSystemVersion:\t%04X\n", *(pBuffer+145));
    printf("MajorImageVersion:\t\t%04X\n", *(pBuffer+146));
    printf("MinorImageVersion:\t\t%04X\n", *(pBuffer+147));
    printf("MajorSubsystemVersion:\t\t%04X\n", *(pBuffer+148));
    printf("MinorSubsystemVersion:\t\t%04X\n", *(pBuffer+149));
    printf("Win32VersionValue:\t\t%08X\n", *(PointBuffer+75));
    printf("SizeOfImage:\t\t\t%08X\n", *(PointBuffer+76));
    printf("SizeOfHeaders:\t\t\t%08X\n", *(PointBuffer+77));
    printf("CheckSum:\t\t\t%08X\n", *(PointBuffer+78));
    printf("Subsystem:\t\t\t%04X\n", *(pBuffer+158));
    printf("DllCharacteristics:\t\t%04X\n", *(pBuffer+159));
    printf("SizeOfStackReserve:\t\t%08X\n", *(PointBuffer+80));
    printf("SizeOfStackCommit:\t\t%08X\n", *(PointBuffer+81));
    printf("SizeOfHeapReserve:\t\t%08X\n", *(PointBuffer+82));
    printf("SizeOfHeapCommit:\t\t%08X\n", *(PointBuffer+83));
    printf("LoaderFlags:\t\t\t%08X\n", *(PointBuffer+84));
    printf("NumberOfRvaAndSizes:\t\t%08X\n", *(PointBuffer+85));

    free(PointBuffer);
    return 0;
}

int main()
{
    PrintfNtHeaders();
    OpenFile();
    return 0;
}
```

联合体
---

### 联合体类型

```php
union TestUnion
{
    char x;
    int y;
}
```

### 特点

```php
联合体的成员是共享内存空间的

联合体的内存空间大小是联合体成员中对内存空间大小要求最大的空间大小

空间分配上，联合体最多只有一个成员有效
```

分析
--

一：

```php
union TestUnion
{
    char x;
    int y;
};
```

二：

```php
union
{
    char x;
    int y;
}TestUnion;
```

以上两者是有不同的意义的

一：TestUnion是联合体类型

二：联合体是匿名的，TestUnion是变量

0x5节表
=====

前言
--

节表：相当于这本书的目录

位置
--

找节表的位置：在标准PE头中`SizeOfOptionalHeader`找到可选PE头的大小

然后DOC头+标准PE头+可选PE头 就找到了节表的位置

在标准PE头中，`NumberOfSections`记录了节的数量

注意这里-&gt;**SizeOfHeaders：是包含节表之后，还要按照文件对齐之后的大小**

![image-20220112182912942](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-adad5eee7287f03bbfaf86d6de4214cd54760ef3.png)

![image-20220112185041095](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f693bd7f838bf5ad290d453f203068fbb0d9174e.png)

根据这张图 分析节表 属性

![image-20220112195828367](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0e2cc99b66e48ea917eb381c6c2f5896293d3066.png)

属性
--

### 1、Name

8字节，一般情况下是以`\0`结尾的 ASCII吗字符串来标识的名称，内容可以自定义

注意：该名称并不遵守必须以`\0`结尾的规律，如果不是以`\0`结尾，系统会截取8个字节的长度进行处理

考虑到`\0`

![image-20220112185340364](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-63b6785a3254cc5ceec0b0019de334cdf47cbf41.png)

### 2、Misc

Misc：4字节，它是节在补齐规定大小之前的真实尺寸，该值可以不准确，因为这个值是可以干掉的

A到B，后面的内存是为了内存对齐

![image-20220112193615229](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f45f851ebd75742bf97ca814ef84115d94d7dd2c.png)

### 3、VirtualAddress

VirtualAddress：4字节，它是节区在内存中的相对偏移地址。这个值就是离ImageBase多远，加上ImageBase才是在内存中的真正地址

它只在内存中有意义

![image-20220112194402440](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-16058e7ce8c4d916dfeca4d05127c8dbfecc306e.png)

### 4、SizeOfRawData

SizeOfRawDVirtualAddressata：4字节，节在文件中对齐后的尺寸

就是这个绿色框

![image-20220112194547342](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-82571584c89cf8979b5c2e4f6ffd174ae5fbbe53.png)

### 5、PointerToRawData

PointerToRawData：4字节，节区在文件中的偏移,他一定是文件对齐的整数倍，因为文件是有整数大小

它是在文件中，注意和`VirtualAddress`区分

![image-20220112195859408](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b303a7ec69b6cecc9939e95df903000874723270.png)

### 6、PointerToRelocations

4字节，在obj文件中使用 对exe无意义

### 7、PointerToLinenumbers

4字节，行号表的位置 调试的时候使用

### 8、NumberOfRelocations

2字节，在obj文件中使用 对exe无意义

### 9、NumberOfLinenumbers

2字节，行号表中行号的数量 调试的时候使用

![image-20220112195007503](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c925f829e7da00436bb28390960c6d1e52b1d6a2.png)

### 10、Characteristics

4字节，当前节的属性，可读可写可执行

4字节的16进制：00000000~FFFFFFFF

![image-20220112205152741](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b52b41218c4033a47e921ce992331ca3a9d21bfc.png)

看标志(属性块)特征值对照

0020-&gt;二进制表示：0000000000100000-&gt;就是第6位

![image-20220112205600594](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-49f8e95841029c7d0137f0ce0d03dc2edee63351.png)

包含已初始化的数据，可写，可执行，还有共享块

总结
--

![image-20220112195054506](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-182954030afc38f70363a9ec86e9648eb93a0044.png)

输出节表中的信息
--------

### 前言

到文件中找到所有的节，观察节的开始位置与大小是否与在工具中节表中的描述一致

### 核心代码

```php
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define F_PATH "C:\\notepad.exe"

int* OpenFile()
{
    FILE* PointToFile = NULL;
    int FileSize = 0;
    int* StrBuffer = NULL;
    int Num = 0;

    //打开文件
    if ((PointToFile = fopen(F_PATH,"rb")) == NULL) {
        printf("打开文件失败!\n");
        exit(1);
    }

    //获取文件大小
    fseek(PointToFile,0,2);
    FileSize = ftell(PointToFile);

    //重定位指针
    fseek(PointToFile,0,0);

    //buffer指向申请的堆
    StrBuffer = (int*)(malloc(FileSize));
    if (!StrBuffer)
    {
        printf("堆空间分配失败!\n");
        free(StrBuffer);
        return 0;
    }

    //读取文件内容
    Num = fread(StrBuffer,FileSize,1,PointToFile);
    if (!Num)
    {
        printf("读取文件内容失败!\n");
        free(StrBuffer);
        return 0;
    }

    //关闭文件
    fclose(PointToFile);

    //将缓冲区内的文件内容的地址返回到调用函数的地方
    return StrBuffer;
}

int* FileSizes = OpenFile();

int PrintfNtHeaders()
{
    //文件指针
    unsigned int* PointBuffer = (unsigned int*)FileSizes;
    unsigned short* pBuffer = (unsigned short*)PointBuffer;
    unsigned char* pcBuffer = (unsigned char*)PointBuffer;

    //判断MZ和PE的标志
    unsigned short Cmp1 = 0x5A4D;
    unsigned int Cmp2 = 0x00004550;

    //判断文件是否读取成功
    if(!PointBuffer)
    {
        printf("文件读取失败！\n");
        free(PointBuffer);
        return 0;
    }

    //判断是否为MZ标志
    if (*pBuffer != Cmp1)
    {
        printf("不是有效MZ标志！\n");
        printf("%X\n",*pBuffer);
        free(PointBuffer);
        return 0;
    }
    printf("*********打印DOS头*********\n");
    printf("e_magic:\t\t\t%X\n",*(pBuffer));
    printf("e_ifanew:\t\t\t%08X\n\n\n",*(PointBuffer+15));

    //判断是否为PE标志
    if (*(PointBuffer+56) != Cmp2)
    {
        printf("不是有效的PE标志！\n");
        printf("%X\n",*(PointBuffer+56));
        free(PointBuffer);
        return 0;
    }

    printf("*********打印标准PE文件头*********\n");

    printf("PE标志:\t\t\t\t%X\n",*(PointBuffer+56));

    printf("Machine:\t\t\t%04X\n",*(pBuffer+114));
    printf("NumberOfSection:\t\t%04X\n",*(pBuffer+115));
    printf("TimeDateStamp:\t\t\t%08X\n",*(PointBuffer+58));
    printf("PointerToSymbolTable:\t\t%08X\n",*(PointBuffer+59));
    printf("NumberOfSymbols:\t\t%08X\n",*(PointBuffer+60));
    printf("SizeOfOptionalHeader:\t\t%04X\n",*(pBuffer+122));
    printf("Chrarcteristics:\t\t%04X\n\n\n",*(pBuffer+123));

    printf("*********打印标准可选PE头*********\n");

    printf("Magic:\t\t\t\t%04X\n", *(pBuffer+124));
    printf("MajorLinkerVersion:\t\t%02X\n", *(pcBuffer+250));
    printf("MinorLinkerVersion:\t\t%02X\n", *(pcBuffer+251));
    printf("SizeOfCode:\t\t\t%08X\n", *(PointBuffer+63));
    printf("SizeOfInitializedData:\t\t%08X\n", *(PointBuffer+64));
    printf("SizeOfUninitializedData:\t%08X\n", *(PointBuffer+65));
    printf("AddressOfEntryPoint:\t\t%08X\n", *(PointBuffer+66));
    printf("BaseOfCode:\t\t\t%08X\n", *(PointBuffer+67));
    printf("BaseOfData:\t\t\t%08X\n", *(PointBuffer+68));
    printf("ImageBase:\t\t\t%08X\n", *(PointBuffer+69));
    printf("SectionAlignment:\t\t%08X\n", *(PointBuffer+70));
    printf("FileAlignment:\t\t\t%08X\n", *(PointBuffer+71));
    printf("MajorOperatingSystemVersion:\t%04X\n", *(pBuffer+144));
    printf("MinorOperatingSystemVersion:\t%04X\n", *(pBuffer+145));
    printf("MajorImageVersion:\t\t%04X\n", *(pBuffer+146));
    printf("MinorImageVersion:\t\t%04X\n", *(pBuffer+147));
    printf("MajorSubsystemVersion:\t\t%04X\n", *(pBuffer+148));
    printf("MinorSubsystemVersion:\t\t%04X\n", *(pBuffer+149));
    printf("Win32VersionValue:\t\t%08X\n", *(PointBuffer+75));
    printf("SizeOfImage:\t\t\t%08X\n", *(PointBuffer+76));
    printf("SizeOfHeaders:\t\t\t%08X\n", *(PointBuffer+77));
    printf("CheckSum:\t\t\t%08X\n", *(PointBuffer+78));
    printf("Subsystem:\t\t\t%04X\n", *(pBuffer+158));
    printf("DllCharacteristics:\t\t%04X\n", *(pBuffer+159));
    printf("SizeOfStackReserve:\t\t%08X\n", *(PointBuffer+80));
    printf("SizeOfStackCommit:\t\t%08X\n", *(PointBuffer+81));
    printf("SizeOfHeapReserve:\t\t%08X\n", *(PointBuffer+82));
    printf("SizeOfHeapCommit:\t\t%08X\n", *(PointBuffer+83));
    printf("LoaderFlags:\t\t\t%08X\n", *(PointBuffer+84));
    printf("NumberOfRvaAndSizes:\t\t%08X\n\n\n", *(PointBuffer+85));

    printf("*********打印PE节表成员信息*********\n");

    printf("*********打印PE节表[.text]成员信息*********\n");

    printf("Name:\t\t\t\t0x%08X%08X\n", (*(PointBuffer+119)),(*(PointBuffer+118)));
    printf("Misc:\t\t\t\t0x%08X\n", *(PointBuffer+120));
    printf("VirtualAddress:\t\t\t0x%08X\n", *(PointBuffer+121));
    printf("SizeOfRawData:\t\t\t0x%08X\n", *(PointBuffer+122));
    printf("PointerToRawData:\t\t0x%08X\n", *(PointBuffer+123));
    printf("PointerToRelocation:\t\t0x%08X\n", *(PointBuffer+124));
    printf("PointerToLinenumbers:\t\t0x%08X\n", *(PointBuffer+125));
    printf("NumberOfRelocations:\t\t0x%04X\n", *(pBuffer+251));
    printf("NumberOfLinenumbers:\t\t0x%04X\n", *(pBuffer+252));
    printf("Characteristics:\t\t0x%08X\n\n\n", *(PointBuffer+127));

    printf("*********打印PE节表[.data]成员信息*********\n");

    printf("Name:\t\t\t\t0x%08X%08X\n", (*(PointBuffer+129)),(*(PointBuffer+128)));
    printf("Misc:\t\t\t\t0x%08X\n", *(PointBuffer+130));
    printf("VirtualAddress:\t\t\t0x%08X\n", *(PointBuffer+131));
    printf("SizeOfRawData:\t\t\t0x%08X\n", *(PointBuffer+132));
    printf("PointerToRawData:\t\t0x%08X\n", *(PointBuffer+133));
    printf("PointerToRelocation:\t\t0x%08X\n", *(PointBuffer+134));
    printf("PointerToLinenumbers:\t\t0x%08X\n", *(PointBuffer+135));
    printf("NumberOfRelocations:\t\t0x%04X\n", *(pBuffer+271));
    printf("NumberOfLinenumbers:\t\t0x%04X\n", *(pBuffer+272));
    printf("Characteristics:\t\t0x%08X\n\n\n", *(PointBuffer+137));

    printf("*********打印PE节表[.rsrc]成员信息*********\n");

    printf("Name:\t\t\t\t0x%08X%08X\n", (*(PointBuffer+139)),(*(PointBuffer+138)));
    printf("Misc:\t\t\t\t0x%08X\n", *(PointBuffer+140));
    printf("VirtualAddress:\t\t\t0x%08X\n", *(PointBuffer+141));
    printf("SizeOfRawData:\t\t\t0x%08X\n", *(PointBuffer+142));
    printf("PointerToRawData:\t\t0x%08X\n", *(PointBuffer+143));
    printf("PointerToRelocation:\t\t0x%08X\n", *(PointBuffer+144));
    printf("PointerToLinenumbers:\t\t0x%08X\n", *(PointBuffer+145));
    printf("NumberOfRelocations:\t\t0x%04X\n", *(pBuffer+291));
    printf("NumberOfLinenumbers:\t\t0x%04X\n", *(pBuffer+292));
    printf("Characteristics:\t\t0x%08X\n\n\n", *(PointBuffer+147));

    free(PointBuffer);
    return 0;
}

int main()
{
    PrintfNtHeaders();
     OpenFile();
     return 0;
}
```

![image-20220205155531754](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a8165397b044bb06c611f5cf7888deb4b9302272.png)

### 对比

使用工具PETool即可

![image-20220205155722805](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-26c7cd1b8d519800b3aff62fc387ae3e122199b8.png)

0x6PE加载过程
=========

FileBuffer(文件缓存)---&gt;(拉伸之后)ImageBuffer(内存映像)

ImageBuffer 是跑不起来的，操作系统还需要一些操作

ImageBuffer只能说 和运行状态很像

### 首先

首先根据可选PE头中的`SizeOfImage`去分配`ImageBuffer`内存大小，并且将`ImageBuffer`内存初始化为0

然后进行分块拷贝

### 第二步

把所有头，文件对齐后文件的大小，就是SizeOfHeaders，当成一块数据 拷贝过来

### 第三步

根据节表参数：

通过在文件中的`PointerToRawData`找到`节开始`的位置

然后根据`VirtualAddress`找到`ImageBuffer`的位置，然后根据`SizeOfRawData或者Misc`去拷贝每一个 节的大小

简单来说：

`PointerToRawData`决定从FileBuffer哪里开始拷贝

`VirtualAddress`决定拷贝到ImageBuffer什么位置

`SizeOfRawData或者Misc`决定拷贝的每一个`节`的大小

这里注意：Misc是可能比`SizeOfRawData`大的，因为Misc中可能存在未初始化的数据，它存的是在内存里的size

但是没有关系，其实拷贝`Misc`、`SizeOfRawData`都可以

下面就是循环 copy每一个节

注意：当这个exe运行时，ImageBuffer中首地址才是ImageBase

但是ImageBuffer只能说和运行状态很像，首地址是我们申请的地址

```php
节:PointerToRawData 400      
  :VirtualAddress 1000      

节:PointerToRawData 600      
  :VirtualAddress 2000      

节:PointerToRawData 800      
  :VirtualAddress 3000
```

![image-20220126110029275](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-611db0809dc0beaaf1b3be129c0ea1e09cb3ee74.png)

### 输出PE加载过程

![image-20220205160133084](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e13aeaa7159dffdea5d55a481409e2fb63c05708.png)

#### 前言

封装成一个个函数，功能独立且单一

同时要编写一个函数，能够将RVA的值转换成FOA

RVA：相对偏移地址，就是它在`ImageBuffer`中离开始我们申请的内存，有多少字节，就是1234

FOA：F是文件的意思，O：是偏移的意思：A：Adress，就是我们在`ImageBuffer`中的地址对应在`FileBuffer`中的地址是多少字节，就是234+400 = 634

#### 相关的函数说明

#### `ReadPEFile`：

作用：

```php
将文件读取到缓冲区
```

参数说明：

```php
lpszFile 文件路径                               

pFileBuffer 缓冲区指针
```

返回值说明：

```php
读取失败返回0，否则返回实际读取的大小
```

示例

```php
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);
```

使用IN和OUT，这个是C++语法中允许的  
允许`#define NAME` 这样不带替换表达式的定义，目的就是为了告诉用户参数是传入还是传出

`LPSTR  ---->  typedef CHAR *LPSTR, *PSTR;` 是一个`char*`指针；在WINNT.H头文件里面  
`LPVOID ---->  typedef void far *LPVOID;` 是一个`void*`指针，在WINDEF.H头文件里面

它是别名一个`void far *`类型的指针，其中far是以前针对16位系统的，而现在基本都是32位以上系统  
所以这个far已经没有意义了，可以忽略，总结下来 LPVOID就是个`void*`指针类型

`DWORD ---> typedef unsigned long DWORD;` 是32位系统里面是无符号4字节整数

#### `CopyFileBufferToImageBuffer`：

作用：

将文件从`FileBuffer`复制到`ImageBuffer`

参数说明：

```php
pFileBuffer  FileBuffer指针                               

pImageBuffer ImageBuffer指针
```

返回值说明：

```php
读取失败返回0，否则返回ImageBuffer的大小
```

示例

```php
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);
```

#### `CopyImageBufferToNewBuffer`：

作用：

将`ImageBuffer`中的数据复制到新的缓冲区

参数说明：

```php
pImageBuffer ImageBuffer指针                              

pNewBuffer NewBuffer指针  
```

返回值说明：

```php
读取失败返回0，否则返回NewBuffer的大小    
```

```php
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);
```

#### `MemeryTOFile`：

作用：

将内存中的数据复制到文件

参数说明：

```php
pMemBuffer 内存中数据的指针                             

size 要复制的大小                             

lpszFile 要存储的文件路径   
```

返回值说明：

```php
读取失败返回0，否则返回复制的大小   
```

示例：

```php
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
```

#### `RvaToFileOffset`：

将内存偏移转换为文件偏移

参数说明：

```php
pFileBuffer FileBuffer指针                                

dwRva RVA的值 
```

返回值说明：

```php
返回转换后的FOA的值，如果失败返回0
```

示例：

```php
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);
```

#### 核心代码

```php
//test.h 这个头文件的内容

#include "StdAfx.h"
#include <windows.h>
#include <malloc.h>

//#include <windows.h>
//#include <stdio.h>

#if !defined(AFX_test_H__0810D756_B958_41E2_9AE8_2B4A9C4917F0__INCLUDED_)
#define AFX_test_H__0810D756_B958_41E2_9AE8_2B4A9C4917F0__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define FilePath_In         "C:\\notepad.exe"

#define FilePath_Out        "C:\\notepadnewpes.exe"

#define MessageBoxAddr      0x77E5425F
#define ShellCodeLength     0x12

//全局变量声明
extern BYTE ShellCode[];

//函数声明
//ReadPEFile:将文件读取到缓冲区
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);

//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);

//MemeryTOFile:将内存中的数据复制到文件
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
//**************************************************************************

//RvaToFileOffset:将内存偏移转换为文件偏移
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

//执行函数的名称
void Fun();

#endif // !defined(AFX_test_H__0810D756_B958_41E2_9AE8_2B4A9C4917F0__INCLUDED_)
```

```php

//test.cpp 对应文件头test.h的核心代码部分

// test.cpp: implementation of the test class.

#include "stdafx.h"
#include "test.h"
#include <string.h>
#include <windows.h>
#include <stdlib.h>

//定义一个全局变量
BYTE ShellCode[] =
{
    0x6A,00,0x6A,00,0x6A,00,0x6A,00,
    0xE8,00,00,00,00,
    0xE9,00,00,00,00
};

//ExeFile->FileBuffer  返回值为计算所得文件大小

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{

    FILE* pFile = NULL;
    //定义一个FILE结构体指针，在标准的stdio.h文件头里面

    DWORD fileSize = 0;
    LPVOID pTempFileBuffer = NULL;

    //打开文件
    pFile = fopen(lpszFile,"rb"); //lpszFile是当作参数传递进来
    if (!pFile)
    {
        printf("打开文件失败!\r\n");
        return 0;
    }
    /*
    关于在指针类型中进行判断的操作，下面代码出现的情况和此一样，这里解释下：
    1.因为指针判断都要跟NULL比较，相当于0，假值，其余都是真值
    2.if(!pFile)和if(pFile == NULL), ----> 为空，就执行语句；这里是两个等于号不是一个等于号
    3.if(pFile)就是if(pFile != NULL), 不为空，就执行语句；
    */

    //读取文件内容后，获取文件的大小
    fseek(pFile,0,SEEK_END);
    fileSize = ftell(pFile);
    fseek(pFile,0,SEEK_SET);

    //动态申请内存空间，得到的是内存分配的指针
    pTempFileBuffer = malloc(fileSize);

    if (!pTempFileBuffer)
    {
        printf("内存分配失败!\r\n");
        fclose(pFile);
        return 0;
    }

    //根据申请到的内存空间，将文件读取到缓冲区

    size_t n = fread(pTempFileBuffer,fileSize,1,pFile);
    if (!n)
    {
        printf("读取数据失败!\r\n");
        free(pTempFileBuffer);   // 释放内存空间
        fclose(pFile);            // 关闭文件流
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
    //PWORD:无符号两字节的指针
    //*((PWORD)pFileBuffer->取头两字节的内容
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
    需要先进行强制类型转换，然后相加，即PE标记，移动指针位置；然后最终需要比对的结果是0x4550站两个字节
    所以又要强制转换类型为PWORD；
    */

    //定位NT头
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    //上面偏移完成之后pFileBuffer的指针偏移到了NT头---> pNTHeader
    //****************************************************************************************
    //定位标准PE头
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
    //指针类型
    pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);

    if (!pTempImageBuffer)
    {
        printf("再次在堆中申请一块内存空间失败\r\n");
        return 0;
    }

    //因为下面要开始对内存空间进行复制操作，所以需要初始化操作，将其置为0，避免垃圾数据，或者其他异常
    //初始化新的缓冲区
    memset(pTempImageBuffer,0,pOptionHeader->SizeOfImage);

    //****************************************************************************************

    //根据SizeOfHeaders大小的确定，先复制Dos头
    memcpy(pTempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);

    /*
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
    pSectionHeader = pSectionHeader+(numberOfSection-1);
    sizeOfFile = (pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize + pOptionHeader->FileAlignment);
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
        /*memcpy((void*)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),
        (void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress),
        pTempSectionHeader->SizeOfRawData);*/
        //PointerToRawData节区在文件中的偏移,VirtualAddress节区在内存中的偏移地址,SizeOfRawData节在文件中对齐后的尺寸
        memcpy((PDWORD)((DWORD)pTempNewBuffer+pTempSectionHeader->PointerToRawData),
        (PDWORD)((DWORD)pImageBuffer+pTempSectionHeader->VirtualAddress),
        pTempSectionHeader->SizeOfRawData);
        printf("%X  --> PoniterToRadata\r\n",pTempSectionHeader->PointerToRawData);
        printf("%X  --> VirtualAddress\r\n",pTempSectionHeader->VirtualAddress);
        printf("%X  --> VirtualSize\r\n",pTempSectionHeader->Misc.VirtualSize);
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
//    if(fp == NULL)  可以这么写，没问题
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

void Fun()
{
    DWORD    Size            =    0;        //用来接收数据大小
    BOOL    isok            =    FALSE;        //用来接收写入磁盘是否成功
    LPVOID    pFileBuffer        =    NULL;    //用来接收缓冲区的首地址
    LPVOID    pImageBuffer    =    NULL;
    LPVOID    pNewBuffer        =    NULL;

    //File---> FileBuffer
    Size = ReadPEFile(FilePath_In,&pFileBuffer);    //调用函数读取文件数据
    if(!pFileBuffer || !Size)
    {
        printf("File-> FileBuffer失败");
        return;
    }
    else
    {
        printf("Size %x\r\n",Size);
        printf("pFilBuffer %d\r\n",pFileBuffer);
        printf("pFi
```