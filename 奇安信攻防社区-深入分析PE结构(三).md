0x0新增节
======

前言
--

手动新增一个节表和节，保证修改后的程序能正确执行.

PE结构
----

![image-20220204152216145](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f5b65572794e1df5f88a8292655c01094f620a81.png)

整体过程
----

SizeOfHeaders：DOS + DOS stub(垃圾数据) + NT头(PE标记 + 标准PE头 + 可选PE头) + 已存在节表 --&gt;&gt;对齐之后的大小

SizeOfHeaders是不能随便变的，代价太大了

1、新增一个节

2、在新增一个节表(40个字节)

判断条件：

我们要保证在我们新增的这个节表后边，还有40个0的空间，所以我们要计算的是节表剩下的空间够不够80个字节，还有没有两个节表

导出我们的计算公式：

SizeOfHeader - (DOS + DOS stub(垃圾数据) + PE标记 + 标准PE头 + 可选PE头 + 已存在节表) &gt;= 2个节表的大小(80个字节)

3、需要修改的数据

```php
1) 添加一个新的节(可以copy一份)

2) 在新增节后面 填充一个节大小的000

3) 修改标准PE头中节的数量(NumberOfSections参数)

4) 修改内存中整个PE文件的映射的尺寸(可选PE头中sizeOfImage参数)

5) 再原有数据的最后，新增一个节的数据(内存对齐的整数倍)

6）修正新增节表的属性
```

手动分析-1
------

先把我们要操作的exe复制一份出来，一会可以用作参考

### 判断空间

节表从这里开始

![image-20220131174500396](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ecee0c5fd837c73659e53bfbf871365bbc34d041.png)

判断有几个节

```php
0008
```

有8个节，所以有8个节表

![image-20220131174653422](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f389d6977a3ddb6d508e1753844341c3f044df07.png)

一个节表40个字节

第一个节表

![image-20220131180040301](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6c419a830b6a95e174b373013a2edcd12ffa4742.png)

第二个节表

![image-20220131180114356](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e6867659f1181814181490711356e8fe95e50e77.png)

这下面都是空白区，足够80个字节(2个节表)了

![image-20220131180218835](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-70f6f106b09fa6e002e8db32524c62be3910d1f6.png)

### 添加新节表

把第一个`.text`节表 粘贴过来 放到最后面

![image-20220131180513970](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-73fe06d13ee2455f556040cb5eec665734248a38.png)

### 修改NumberOfSections参数

修改标准PE头中节的数量(NumberOfSections参数)

![image-20220131180747473](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cb49123e1aa800d477e8f876a3e1befdf3700661.png)

修改内存中整个PE文件的映射的尺寸(可选PE头中sizeOfImage参数)

注：在可选PE头中的后56个字节

![image-20220131180858866](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fe3196bb59526b9239b8cbb51c7be64983c090c2.png)

标准PE头

![image-20220131181100362](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-22630d53cc2d001e67072fe55414cc621dc8ad6c.png)

### 修改sizeOfImage参数

我们找到sizeOfImage了

```php
0002E000
```

![image-20220131181440911](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fd7bec5ef9130c1bbca8c63b92f652a2ffcaee33.png)

进行修改，给1000个字节

```php
0002F000
```

![image-20220131183635101](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-15342f24a518f42a625d564231968bfccb2dd3b0.png)

### 填充新节

开始插入，进行添加节

16进制1000个字节对应十进制4096

![image-20220203200747703](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-eb14a511198121fece03c44f00d2b411621f71ed.png)

![image-20220203200818355](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-acbee36ce5af7c7bfa3421996a768573bf7e9d85.png)

这里注意：别碰原来的数据

![image-20220203201046757](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-68892e9fb6b7db829ab699e86fcd53042d47a37e.png)

### 修改新增的节表

**注意是小端存储！**

![image-20220203201537193](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-af5ed8063579fabf4e325e00f11d9a867d0a90dd.png)

拿出之前复制的exe，进行参考

![image-20220203201857395](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e265c99daf50c766b5072ec4c0e1d9b103512faa.png)

第一个参数是：Name，8个字节

![image-20220203202000763](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-82a29526d34eabdd0f94b70d79d45101d79b06d8.png)

第二个参数是：VirtualSize，它是内存中大小(对齐前的长度).

这里有个小技巧，我们可以把它和文件中大小(对齐后的长度)写成一样的大小

我们要加的值是1000

```php
00 10 00 00
```

![image-20220203203124094](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4bb40893a4ad880aa9d44b319c52a255027849e8.png)

第三个参数是：VirtualAddress，它是内存中偏移(该块的RVA)

我们要看最后一个节表

![image-20220203204758797](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-50460b57cce14b90c54504058f652d561fb29845.png)

这里要看他两谁大

```php
内存中大小(对齐前的长度)
文件中大小(对齐后的长度)
```

要用`内存中偏移(该块的RVA)+上面两者大的那个`

```php
0002D000 + 1000 = 0002E000
```

然后 按照1000进行对齐，在根据小端存储

最后的结果就是

```php
00 E0 02 00
```

第四个参数是：SizeOfRawData，它是文件中大小(对齐后的长度)

我们要加的值是1000

```php
00 10 00 00
```

第五个参数是：PointerToRawData，它是文件中偏移.

继续看最后一个节表

![image-20220203210121424](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2cefae02491741b2f5e1a4afbf66ccd16516912d.png)

要用`文件中偏移+文件中大小(对齐后的长度)`

```php
00013A00 + 00000000 = 00013A00
```

然后使用小端存储

```php
00 3A 01 00
```

![image-20220203212603538](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-671fd7072d88634fee5da23e2374b168fa7a2150.png)

最后是节表的属性

因为这个节，是我从`.texe`复制过来的，所以我就不用改了

保存 尝试执行

重新看一下

9个节 没有问题

![image-20220203211002867](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e2d018ac528b01b9f051116d648bc8442ba0d5ae.png)

![image-20220203212943505](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-941b4e29ba1ce337766d2df292b02c7809be97ed.png)

手动分析-2
------

考虑另一种极端情况

打开notepad.exe

我们可以看到节表后又跟了一堆数据，他们是有用的数据，我们不能去动

![image-20220204151701261](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-68850ca8965d259ac06361813a6e976c5916ab25.png)

这块数据不能干掉，也不能动，但是我们没地方进行新增节

同时节表是连续存储的，不可以断掉的

重新看PE结构

![image-20220204152259001](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1a78c3a601b613de4e1dbc411ceb951d52e2589c.png)

我们的思路就是

把PE结构中间的垃圾数据给干掉，然后把下面的PE标记往上提

只需要修改一个参数：DOS头中的`e_lfanew1`参数

![image-20220204153239390](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-86312b0c679534ca48b681fe7641caf5e5c66e81.png)

进行覆盖数据

![image-20220204153857044](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-be7929151f6cb7155bbdd93c0914beaa5cb0dbe3.png)

覆盖成功

![image-20220204154008276](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-523a641ceebffc1b2476f8566bb47b32d1014fa6.png)

原先这块数据就没有用了 全部补0即可

![image-20220204154037750](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a1a6bc703cf58e5bad2136859526ae8395ede656.png)

![image-20220204154136028](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fb4d070b4e2a1205c7b0011abb0a8946358229e7.png)

最后修改DOS头中的`e_lfanew1`参数 把它指向40即可

![image-20220204154326479](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2ab6f202abca9ed8bc58a5ddd1a957090c56b7af.png)

双击 依然可以正常运行

![image-20220204154433908](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e4d74687abf29bbd64380abebb5a97ad8ff75624.png)

核心代码
----

```php
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{

    FILE* pFile = NULL;
    DWORD fileSize = 0; 
    LPVOID pTempFileBuffer = NULL;

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

//通过复制FileBuffer并增加1000H到新的ImageBuffer里面
DWORD CopyFileBufferToNewImageBuffer(IN LPVOID pFileBuffer,IN size_t fileSize,OUT LPVOID* pNewImageBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeder = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
    LPVOID pTempNewImageBuffer = 0;
    DWORD sizeOfFile = 0;
    DWORD numberOfSection = 0;
    DWORD okAddSections = 0;

    //判断读取pFileBuffer读取是否成功
    if (!pFileBuffer)
    {
        printf("缓冲区指针无效\r\n");
        return 0;
    }

    //判断是否为MZ标志

    if ((*(PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)// IMAGE_DOS_SIGNATURE --> MZ
    {
        printf("不是一个有效的MZ标志\r\n");
        return 0;
    }

    //判断是否为PE标志
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (*((PWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) // IMAGE_NT_SIGNATURE --> PE
    {
        printf("不是有效的PE标志\r\n");
        return 0;
    }

//申请开辟内存空间

    sizeOfFile = fileSize+0x1000;
    pTempNewImageBuffer = malloc(sizeOfFile);

    //判断内存空间开辟是否成功
    if (!pTempNewImageBuffer)
    {
        printf("pTempNewImageBuffer开辟内存空间失败\r\n");
        return 0;
    }

    //初始化内存内容
    memset(pTempNewImageBuffer,0,sizeOfFile);

    //初始化完成之后，先把为修改的内存空间全部拷贝到新的内存空间
    memcpy(pTempNewImageBuffer,pFileBuffer,fileSize);

    //定位Dos头地址
    pDosHeader = (PIMAGE_DOS_HEADER)(pTempNewImageBuffer);

    //定位NT头的地址
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pTempNewImageBuffer+pDosHeader->e_lfanew);

    //定位标志PE头地址
    pPEHeder = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+0x04);//PE SIGNATURE 站4个字节

    //定位可选PE头地址
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pPEHeder)+IMAGE_SIZEOF_FILE_HEADER);//IMAGE_SIZEOF_FILE_HEADER -> 20个字节

    //定位第一个节表地址
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeder->SizeOfOptionalHeader);

    //定位最后一个节表的地址
    pLastSectionHeader = &pSectionHeader[pPEHeder->NumberOfSections-1];

    //判断是否有足够的空间添加一个节表
    //判断条件:
    /*
        SizeOfHeader - (DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表) >= 2个节表的大小
        SizeOfHeader在可选PE头里面
    */

    okAddSections = (DWORD)(pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + 0x04 + \
        sizeof(PIMAGE_FILE_HEADER) + pPEHeder->SizeOfOptionalHeader + sizeof(PIMAGE_SECTION_HEADER) \
        * pPEHeder->NumberOfSections));

    if (okAddSections < 2*sizeof(PIMAGE_SECTION_HEADER))
    {
        printf("这个exe文件头不剩余空间不够\r\n");
        free(pTempNewImageBuffer);
        return 0;
    }

//修改

    //初始化新节表信息
    PWORD pNumberOfSection = &pPEHeder->NumberOfSections;
    PDWORD pSizeOfImage = &pOptionHeader->SizeOfImage;

    numberOfSection = pPEHeder->NumberOfSections;
    PVOID pSecName = &pSectionHeader[numberOfSection].Name;
    PDWORD pSecMisc = &pSectionHeader[numberOfSection].Misc.VirtualSize;
    PDWORD pSecVirtualAddress = &pSectionHeader[numberOfSection].VirtualAddress;
    PDWORD pSecSizeOfRawData = &pSectionHeader[numberOfSection].SizeOfRawData;
    PDWORD pSecPointToRawData = &pSectionHeader[numberOfSection].PointerToRawData;
    PDWORD pSecCharacteristics = &pSectionHeader[numberOfSection].Characteristics;

    //修改PE文件头里面的节数量信息

    printf("*pNumberOfSection:%#X \r\n",pPEHeder->NumberOfSections);
    *pNumberOfSection = pPEHeder->NumberOfSections + 1;
    printf("*pNumberOfSection:%#X \r\n",pPEHeder->NumberOfSections);

    //修改PE可选头里面SizeOfImage信息
    printf("*pSizeOfImage:%#X \r\n",pOptionHeader->SizeOfImage);
    *pSizeOfImage = pOptionHeader->SizeOfImage + 0x1000;
    printf("*pSizeOfImage:%#X \r\n",pOptionHeader->SizeOfImage);

    //向节表中添加数据

    memcpy(pSecName,".newSec",8);
    *pSecMisc = 0x1000;

    //使用上面的公式
    //判断出要添加的值
    DWORD add_size = pLastSectionHeader->Misc.VirtualSize > pLastSectionHeader->SizeOfRawData?\
        pLastSectionHeader->Misc.VirtualSize:pLastSectionHeader->SizeOfRawData;
    //上面是个三目运算符

    printf("pLastSectionHeader: %#X \r\n",pLastSectionHeader);
    printf("add_size: %#X \r\n",add_size);
    printf("numberOfSection: %#X \r\n",pPEHeder->NumberOfSections);
    printf("pLastSectionHeader->Misc.VirtualSize: %#X \r\n",pLastSectionHeader->Misc.VirtualSize);
    printf("pLastSectionHeader->SizeOfRawData: %#X \r\n",pLastSectionHeader->SizeOfRawData);
    printf("add_size: %#X \r\n",add_size);

    *pSecVirtualAddress = pLastSectionHeader->VirtualAddress + add_size;

    //SectionAlignment对齐

    if (*pSecVirtualAddress % pOptionHeader->SectionAlignment)
    {
        *pSecVirtualAddress = *pSecVirtualAddress / pOptionHeader->SectionAlignment * \
            pOptionHeader->SectionAlignment + pOptionHeader->SectionAlignment;
    }

    *pSecSizeOfRawData = 0x1000;
    *pSecPointToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

    //FileAlignment对齐

    if (*pSecPointToRawData % pOptionHeader->FileAlignment)
    {
        *pSecPointToRawData = *pSecPointToRawData / pOptionHeader->FileAlignment * \
            pOptionHeader->FileAlignment + pOptionHeader->FileAlignment;
    }

    *pSecCharacteristics = 0xFFFFFFFF;

    *pNewImageBuffer = pTempNewImageBuffer;
    pTempNewImageBuffer = NULL;

    return sizeOfFile;
}

BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile)
{
    FILE* fp = NULL;
    fp = fopen(lpszFile, "wb+");
    if (!fp)  //  这里我刚开始写漏了一个等于号，变成复制NULL了，导致错误
//  if(fp == NULL)  可以这么写，没问题
    {
        fclose(fp);
        return FALSE;
    }
    fwrite(pMemBuffer,size,1,fp);
    fclose(fp);
    fp = NULL;
    return TRUE;
}
```

```php
VOID NewSectionsInCodeSec()
{
    LPVOID pFileBuffer = NULL;
    LPVOID pNewImageBuffer = NULL;
    BOOL isOK = FALSE;
    DWORD size1 = 0;
    DWORD size2 = 0;

    //File-->FileBuffer
    size1 = ReadPEFile(FilePath_In,&pFileBuffer);
    if (size1 == 0 || !pFileBuffer)
    {
        printf("文件-->缓冲区失败\r\n");
        return ;
    }
    printf("fileSize - Final: %#X \r\n",size1);

    //FileBuffer-->NewImageBuffer
    size2 = CopyFileBufferToNewImageBuffer(pFileBuffer,size1,&pNewImageBuffer);
    if (size2 == 0 || !pFileBuffer)
    {
        printf("FileBuffer-->NewImageBuffer失败\r\n");
        free(pFileBuffer);
        return ;
    }
    printf("sizeOfFile - Final: %#X \r\n",size2);
    //NewImageBuffer-->文件
    isOK = MemeryTOFile(pNewImageBuffer,size2,FilePath_Out);
    if (isOK)
    {
        printf("新增节表和节存盘成功\r\n");
       return ;
    }

    //释放内存
    free(pFileBuffer);
    free(pNewImageBuffer);
}
```

```php
// test2.cpp:程序执行代码
#include "stdafx.h"
#include "test.h"

int main(int argc, char* argv[])
{
    NewSectionsInCodeSec();
    printf("Hello World! Cntf\r\n");
    return 0;
}
```

手动分析-3
------

继续考虑一种更极端的情况

DOS头到PE标记中的垃圾数据是由编译器生成的，那么如果我们提升了PE标记，空间任然不够我们去新增一个节表

这个时候，我们就要去扩大最后一个节

0x2扩大节
======

前言
--

之前我们都是在空白区域，去新增我们的节

但是，当空白区域无法满足我们的要求，我们就要去扩大节

整体流程
----

```php
1、拉伸到内存

2、分配一块新的空间:SizeOfImage + Ex(要扩大的节)  

3、将最后一个节的SizeOfRawData(文件中对齐后的大小)和VirtualSize(内存中对齐前的大小)改成一样大，改成N

N是SizeOfRawData(文件中对齐后的大小)和VirtualSize(内存中对齐前的大小)两者之间，大的那个值

N = 大的那个值 + Ex

SizeOfRawData = VirtualSize = N 

4、修改SizeOfImage大小                       

   SizeOfImage = SizeOfImage + Ex
```

![image-20220204160435499](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bca3740d27216f52ff185565610c66892f14f454.png)

核心代码
----

```php
// test.h: 头文件

#if !defined(AFX_test_H__C24C6881_E003_41F7_BE14_24DDA1702CCD__INCLUDED_)
#define AFX_test_H__C24C6881_E003_41F7_BE14_24DDA1702CCD__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string.h>
#include <windows.h>
#include <stdlib.h>

#define FilePath_In         "C:\\notepad.exe"
#define FilePath_Out        "C:\\notepadnewpes.exe"

#define MESSAGEBOXADDR      0x77D5050B
#define SHELLCODELENGTH     0x12 //16进制的，转换为十进制就是18

extern BYTE ShellCode[];

//读文件 --->FileBuffer
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

//写到ImageBuffer,FileBuffer ---> ImageBuffer
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);

//写到NewImageBuffer, FileBuffer ---> NewImageBuffer
DWORD CopyFileBufferToNewImageBuffer(IN LPVOID pFileBuffer,IN size_t fileSize,OUT LPVOID* pNewImageBuffer);

//写到NewImageBuffer, 这里是从ImageBuffer写入 ---> NewImageBuffer
DWORD FileBufferToModifyImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pNewImageBuffer);

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);

//写到pNewBuffer里面，从pNewImageBuffer写入 ---> pNewBuffer
//DWORD ModifyImageBufferToNewBuffer(IN LPVOID pNewImageBuffer,OUT LPVOID* pNewBuffer);

//对齐大小
DWORD AlignLength(DWORD Actuall_size,DWORD Align_size);

//将MemBuffer写入到硬盘，这里就是将各种修改好的内存文件，存入到本地硬盘中；
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);

//DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

//调用函数，添加ShellCode代码
VOID AddCodeInCodeSec();  //这个调用函数用到下面的4个函数
//ReadPEFile CopyFileBufferToImageBuffer CopyImageBufferToNewBuffer MemeryTOFile

//调用函数，新增节表和节操作；
VOID NewSectionsInCodeSec();  //这个调用函数用到下面的3个函数
//ReadPEFile CopyFileBufferToNewImageBuffer MemeryTOFile

//调用函数，扩大最后一个节
VOID ExtendLastSectionsInCodeSec(); //这个调用函数用到下面的4个函数
//ReadPEFile CopyFileBufferToImageBuffer CopyImageBufferToNewImageBuffer MemeryTOFile

#endif // !defined(AFX_test_H__C24C6881_E003_41F7_BE14_24DDA1702CCD__INCLUDED_)
```

```php
// test.cpp

#include "stdafx.h"
#include "test.h"

//定义一个全局变量
BYTE ShellCode[] =
{
    0x6A,00,0x6A,00,0x6A,00,0x6A,00, //MessageBox push 0的硬编码
    0xE8,00,00,00,00,  // call汇编指令E8和后面待填充的硬编码
    0xE9,00,00,00,00   // jmp汇编指令E9和后面待填充的硬编码
};

//ExeFile->FileBuffer  返回值为计算所得文件大小
//读取一个exe文件，然后输出为FileBuffer
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
//将读取的FileBuffer拉伸加载到ImageBuffer，用作测试验证文件拉伸；
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID pTempImageBuffer = NULL;

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

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

    //判断是否是有效的PE标志
    if (*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("无效的PE标记\r\n");
        return 0;
    }

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

    //根据SizeOfHeaders大小的确定，先复制Dos头
    memcpy(pTempImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);

    //上面把已经确定的头都复制好了，那么下面就可以开始复制节的里面的内容，因为节不仅仅是一个，所以需要用到for循环进行操作
    //根据节表循环copy节的内容
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    //定义一个临时节表的指针
    for (int i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
    {
        memcpy((void*)((DWORD)pTempImageBuffer + pTempSectionHeader->VirtualAddress),
            (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
    }

    //返回数据
    *pImageBuffer = pTempImageBuffer;
    //将复制好后节的首地址保存到指针pImageBuffer中
    pTempImageBuffer = NULL;
    //初始化清空临时使用的pTempImageBuffer

    return pOptionHeader->SizeOfImage;
}

//FileBuffer ---> NewImageBuffer（新增节操作）?
//通过复制FileBuffer并增加1000H到新的NewImageBuffer,用作新增节；
DWORD CopyFileBufferToNewImageBuffer(IN LPVOID pFileBuffer,IN size_t fileSize,OUT LPVOID* pNewImageBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeder = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
    LPVOID pTempNewImageBuffer = 0;
    DWORD sizeOfFile = 0;
    DWORD numberOfSection = 0;
    DWORD okAddSections = 0;

    //判断读取pFileBuffer读取是否成功
    if (!pFileBuffer)
    {
        printf("缓冲区指针无效\r\n");
        return 0;
    }

    //判断是否为MZ标志

    if ((*(PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)// IMAGE_DOS_SIGNATURE --> MZ
    {
        printf("不是一个有效的MZ标志\r\n");
        return 0;
    }

    //判断是否为PE标志
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (*((PWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) // IMAGE_NT_SIGNATURE --> PE
    {
        printf("不是有效的PE标志\r\n");
        return 0;
    }

//申请开辟内存空间

    sizeOfFile = fileSize+0x1000;
    pTempNewImageBuffer = malloc(sizeOfFile);

    //判断内存空间开辟是否成功
    if (!pTempNewImageBuffer)
    {
        printf("pTempNewImageBuffer开辟内存空间失败\r\n");
        return 0;
    }

    //初始化内存内容
    memset(pTempNewImageBuffer,0,sizeOfFile);

    //初始化完成之后，先把为修改的内存空间全部拷贝到新的内存空间
    memcpy(pTempNewImageBuffer,pFileBuffer,fileSize);

    //定位Dos头地址
    pDosHeader = (PIMAGE_DOS_HEADER)(pTempNewImageBuffer);

    //定位NT头的地址
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pTempNewImageBuffer+pDosHeader->e_lfanew);

    //定位标志PE头地址
    pPEHeder = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+0x04);//PE SIGNATURE 站4个字节

    //定位可选PE头地址
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pPEHeder)+IMAGE_SIZEOF_FILE_HEADER);//IMAGE_SIZEOF_FILE_HEADER -> 20个字节

    //定位第一个节表地址
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeder->SizeOfOptionalHeader);

    //定位最后一个节表的地址
    pLastSectionHeader = &pSectionHeader[pPEHeder->NumberOfSections-1];

    //判断是否有足够的空间添加一个节表
    //判断条件：
    /*
        SizeOfHeader - (DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表) >= 2个节表的大小
        SizeOfHeader在可选PE头里面
    */

    okAddSections = (DWORD)(pOptionHeader->SizeOfHeaders - (pDosHeader->e_lfanew + 0x04 + \
        sizeof(PIMAGE_FILE_HEADER) + pPEHeder->SizeOfOptionalHeader + sizeof(PIMAGE_SECTION_HEADER) \
        * pPEHeder->NumberOfSections));

    if (okAddSections < 2*sizeof(PIMAGE_SECTION_HEADER))
    {
        printf("这个exe文件头不剩余空间不够\r\n");
        free(pTempNewImageBuffer);
        return 0;
    }

//修改

    //初始化新节表信息
    PWORD pNumberOfSection = &pPEHeder->NumberOfSections;
    PDWORD pSizeOfImage = &pOptionHeader->SizeOfImage;

    numberOfSection = pPEHeder->NumberOfSections;
    PVOID pSecName = &pSectionHeader[numberOfSection].Name;
    PDWORD pSecMisc = &pSectionHeader[numberOfSection].Misc.VirtualSize;
    PDWORD pSecVirtualAddress = &pSectionHeader[numberOfSection].VirtualAddress;
    PDWORD pSecSizeOfRawData = &pSectionHeader[numberOfSection].SizeOfRawData;
    PDWORD pSecPointToRawData = &pSectionHeader[numberOfSection].PointerToRawData;
    PDWORD pSecCharacteristics = &pSectionHeader[numberOfSection].Characteristics;

    //修改PE文件头里面的节数量信息

    printf("*pNumberOfSection:%#X \r\n",pPEHeder->NumberOfSections);
    *pNumberOfSection = pPEHeder->NumberOfSections + 1;
    printf("*pNumberOfSection:%#X \r\n",pPEHeder->NumberOfSections);

    //修改PE可选头里面SizeOfImage信息
    printf("*pSizeOfImage:%#X \r\n",pOptionHeader->SizeOfImage);
    *pSizeOfImage = pOptionHeader->SizeOfImage + 0x1000;
    printf("*pSizeOfImage:%#X \r\n",pOptionHeader->SizeOfImage);

    //向节表中添加数据

    memcpy(pSecName,".newSec",8);
    *pSecMisc = 0x1000;

    //判断出要添加的值
    DWORD add_size = pLastSectionHeader->Misc.VirtualSize > pLastSectionHeader->SizeOfRawData?\
        pLastSectionHeader->Misc.VirtualSize:pLastSectionHeader->SizeOfRawData;
    //上面是个三目运算符

    printf("pLastSectionHeader: %#X \r\n",pLastSectionHeader);
    printf("add_size: %#X \r\n",add_size);
    printf("numberOfSection: %#X \r\n",pPEHeder->NumberOfSections);
    printf("pLastSectionHeader->Misc.VirtualSize: %#X \r\n",pLastSectionHeader->Misc.VirtualSize);
    printf("pLastSectionHeader->SizeOfRawData: %#X \r\n",pLastSectionHeader->SizeOfRawData);
    printf("add_size: %#X \r\n",add_size);

    *pSecVirtualAddress = pLastSectionHeader->VirtualAddress + add_size;

    //SectionAlignment对齐

    if (*pSecVirtualAddress % pOptionHeader->SectionAlignment)
    {
        *pSecVirtualAddress = *pSecVirtualAddress / pOptionHeader->SectionAlignment * \
            pOptionHeader->SectionAlignment + pOptionHeader->SectionAlignment;
    }

    *pSecSizeOfRawData = 0x1000;
    *pSecPointToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

    //FileAlignment对齐

    if (*pSecPointToRawData % pOptionHeader->FileAlignment)
    {
        *pSecPointToRawData = *pSecPointToRawData / pOptionHeader->FileAlignment * \
            pOptionHeader->FileAlignment + pOptionHeader->FileAlignment;
    }

    *pSecCharacteristics = 0xFFFFFFFF;

    *pNewImageBuffer = pTempNewImageBuffer;
    pTempNewImageBuffer = NULL;

    return sizeOfFile;
}

//求对齐后的大小
//Actuall_size  ---> 实际大小
//Align_size  ---> 对齐大小
DWORD AlignLength(DWORD Actuall_size,DWORD Align_size)
{
    if (Actuall_size % Align_size == 0)
    {
        return Actuall_size;
    }
    else
    {
        DWORD n = Actuall_size / Align_size;
        return Align_size*(n+1);
    }
}

//ImageBuffer ---> NewImageBuffer
//将拉伸后加载到内存的ImageBuffer存入到NewImageBuffer，修改数据完成之后，准备存盘操作
DWORD FileBufferToModifyImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pNewImageBuffer)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
    LPVOID pTempNewImageBuffer = NULL;
    DWORD ImageBuffer_Size = 0;
    DWORD numberOfSection = 0;

    //判断读取pImageBuffer是否成功
    if (!pFileBuffer)
    {
        printf("缓冲区指针无效\r\n");
    }

    //判断是否是有效的MZ头
    if ((*(PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
    {
        printf("不是有效的MZ头\r\n");
        return 0;
    }

    //判断是否是有效的PE头
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (*((PWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("不是有效的PE头\r\n");
        return 0;
    }

    //定位NT头
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);

    //定位标准的PE文件头
    pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader+0x04);

    //定位可选PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);

    //定位第一个节表地址
    numberOfSection = pPEHeader->NumberOfSections;
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);

    //定位最后一个节表地址
    pLastSectionHeader = &pSectionHeader[numberOfSection-1];
    printf("numberOfSection --> %#X \r\n",numberOfSection);
    printf("*pSectionHeader --> %#X \r\n",pSectionHeader->Misc.VirtualSize);
    printf("*pLastSectionHeader --> %#X \r\n",&pLastSectionHeader);

    //开始操作需要修改的部分

    //最后一个节中内存中对齐前的大小；
    PDWORD pVirtualSize = &pLastSectionHeader->Misc.VirtualSize;
    //最后一个节在文件中对齐后的大小；
    PDWORD pSizeOfRawData = &pLastSectionHeader->SizeOfRawData;
    //文件中SizeOfImage的大小；
    PDWORD pSizeOfImage = &pOptionHeader->SizeOfImage;

    //扩展修改之前的数据
printf("&pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",pVirtualSize);
printf("*pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",*pVirtualSize);
//
printf("&pLastSectionHeader->SizeOfRawData --> %#X \r\n",pSizeOfRawData);
printf("*pLastSectionHeader->SizeOfRawData --> %#X \r\n",*pSizeOfRawData);
//
printf("&pOptionHeader->SizeOfImage --> %#X \r\n",pSizeOfImage);
printf("*pOptionHeader->SizeOfImage --> %#X \r\n",*pSizeOfImage);

    //扩展修改pVirtualSize
    *pVirtualSize = AlignLength(*pVirtualSize,pOptionHeader->SectionAlignment)+0x1000;
    printf("&pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",pVirtualSize);
    printf("*pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",*pVirtualSize);
    printf("&pLastSectionHeader->SizeOfRawData --> %#X \r\n",pSizeOfRawData);
    printf("*pLastSectionHeader->SizeOfRawData --> %#X \r\n",*pSizeOfRawData);

    //扩展修改pSizeOfRawData
    *pSizeOfRawData = AlignLength(*pSizeOfRawData,pOptionHeader->SectionAlignment)+0x1000;
    printf("&pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",pVirtualSize);
    printf("*pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",*pVirtualSize);
    printf("&pLastSectionHeader->SizeOfRawData --> %#X \r\n",pSizeOfRawData);
    printf("*pLastSectionHeader->SizeOfRawData --> %#X \r\n",*pSizeOfRawData);
    printf("&pOptionHeader->SizeOfImage --> %#X \r\n",pSizeOfImage);
    printf("*pOptionHeader->SizeOfImage --> %#X \r\n",*pSizeOfImage);

    //修改SizeOfImage
    *pSizeOfImage += 0x1000;
    printf("&pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",pVirtualSize);
    printf("*pLastSectionHeader->Misc.VirtualSize --> %#X \r\n",*pVirtualSize);
    printf("&pLastSectionHeader->SizeOfRawData --> %#X \r\n",pSizeOfRawData);
    printf("*pLastSectionHeader->SizeOfRawData --> %#X \r\n",*pSizeOfRawData);
    printf("&pOptionHeader->SizeOfImage --> %#X \r\n",pSizeOfImage);
    printf("*pOptionHeader->SizeOfImage --> %#X \r\n",*pSizeOfImage);

    //得到修改之后的大小准备申请内存空间

    ImageBuffer_Size = pOptionHeader->SizeOfImage;
    pTempNewImageBuffer = malloc(ImageBuffer_Size);

    if (!pTempNewImageBuffer)
    {
        printf("分配内存空间失败\r\n");
        return 0;
    }

    //初始化内存空间
    memset(pTempNewImageBuffer,0,ImageBuffer_Size);

    //复制SizeOfHeaders
    memcpy(pTempNewImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);

    //创建临时节的结构体指针，遍历数据
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;

    for (DWORD i = 0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
    {
        memcpy((PVOID)((DWORD)pTempNewImageBuffer+pTempSectionHeader->VirtualAddress),\
            (void*)((DWORD)pFileBuffer+pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
    }

    *pNewImageBuffer = pTempNewImageBuffer;
    pTempNewImageBuffer = NULL;
    return *pSizeOfImage;
}

//ImageBuffer ---> NewBuffer
//将拉伸后加载到内存的ImageBuffer存入到NewBuffer里面，然后准备存盘；
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

//将上面得到的MemBuffer存盘到本地；
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile)
{
    FILE* fp = NULL;
    fp = fopen(lpszFile, "wb+");
    if (!fp)  //  这里我刚开始写漏了一个等于号，变成复制NULL了，导致错误
//  if(fp == NULL)  可以这么写，没问题
    {
        fclose(fp);
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

//在原有的exe文件中开始操作添加ShellCode代码；

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
    codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
    printf("pSectionHeader->VirtualAddress: %#010X\r\n", pSectionHeader->VirtualAddress);
    printf("pSectionHeader->Misc.VirtualSize: %#010X\r\n", pSectionHeader->Misc.VirtualSize);
    printf("codeBegin: %#010X\r\n", codeBegin);

    memcpy(codeBegin,ShellCode,SHELLCODELENGTH);

    //修正E8-->call后面的代码区域
    DWORD callAddr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)));
    printf("callAddr ---> %#010X \r\n",callAddr);
    *(PDWORD)(codeBegin + 0x09) = callAddr;
    printf("*(PWORD)(codeBegin + 0x09) ---> %#010X \r\n",*(PDWORD)(codeBegin + 0x09));

    //修正E9-->jmp后面的代码区域
    DWORD jmpAddr = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + SHELLCODELENGTH) - (DWORD)pImageBuffer)));
    printf("jmpAddr ---> %#010X \r\n",jmpAddr);
    *(PDWORD)(codeBegin + 0x0E) = jmpAddr;
    printf("*(PWORD)(codeBegin + 0x0E) ---> %#010X \r\n",*(PDWORD)(codeBegin + 0x0E));

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

//调用函数新增节表和节操作，成功之后并存盘到本地；
VOID NewSectionsInCodeSec()
{
    LPVOID pFileBuffer = NULL;
    LPVOID pNewImageBuffer = NULL;
    BOOL isOK = FALSE;
    DWORD size1 = 0;
    DWORD size2 = 0;

    //File-->FileBuffer
    size1 = ReadPEFile(FilePath_In,&pFileBuffer);
    if (size1 == 0 || !pFileBuffer)
    {
        printf("文件-->缓冲区失败\r\n");
        return ;
    }
    printf("fileSize - Final: %#X \r\n",size1);

    //FileBuffer-->NewImageBuffer
    size2 = CopyFileBufferToNewImageBuffer(pFileBuffer,size1,&pNewImageBuffer);
    if (size2 == 0 || !pFileBuffer)
    {
        printf("FileBuffer-->NewImageBuffer失败\r\n");
        free(pFileBuffer);
        return ;
    }
    printf("sizeOfFile - Final: %#X \r\n",size2);
    //NewImageBuffer-->文件
    isOK = MemeryTOFile(pNewImageBuffer,size2,FilePath_Out);
    if (isOK)
    {
        printf("新增节表和节存盘成功\r\n");
       return ;
    }

    //释放内存
    free(pFileBuffer);
    free(pNewImageBuffer);
}

VOID ExtendLastSectionsInCodeSec()
{
    //ReadPEFile CopyFileBufferToImageBuffer CopyImageBufferToNewImageBuffer

    LPVOID pFileBuffer = NULL;
    LPVOID pImageBuffer = NULL;
    LPVOID pNewImageBuffer = NULL;
    BOOL isOK = FALSE;
    DWORD FileBufferSize = 0;
    DWORD ImageBufferSize = 0;
    DWORD size = 0;

    //File-->FileBuffer
    FileBufferSize = ReadPEFile(FilePath_In,&pFileBuffer);
    if (FileBufferSize == 0 || !pFileBuffer)
    {
        printf("文件-->缓冲区失败\r\n");
        return ;
    }
    printf("FileBufferSize - Final: %#X \r\n",FileBufferSize);

    //FileBuffer-->ImageBuffer
    ImageBufferSize = FileBufferToModifyImageBuffer(pFileBuffer,&pImageBuffer);
    if (ImageBufferSize == 0 || !pFileBuffer)
    {
        printf("FileBuffer-->ImageBuffer失败\r\n");
        free(pFileBuffer);
        return ;
    }
    printf("ImageBufferSize - Final: %#X \r\n",ImageBufferSize);

    size = CopyImageBufferToNewBuffer(pImageBuffer,&pNewImageBuffer);
    if (size == 0 || !pImageBuffer)
    {
        printf("pImageBuffer-->pNewImageBuffer失败\r\n");
        free(pFileBuffer);
        return ;
    }
    //pNewImageBuffer-->文件
    isOK = MemeryTOFile(pNewImageBuffer,size,FilePath_Out);
    if (isOK)
    {
        printf("扩大一个节成功，并存盘\r\n");
        return ;
    }

    //释放内存
    free(pFileBuffer);
    free(pImageBuffer);
    free(pNewImageBuffer);
}
```

```php
// test2.cpp:程序入口
//

#include "stdafx.h"
#include "test.h"

int main(int argc, char* argv[])
{
    //Fun();
    //AddCodeInCodeSec();
    //NewSectionsInCodeSec();
    ExtendLastSectionsInCodeSec();
    printf("Hello World! Cntf\r\n");
    return 0;
}
```