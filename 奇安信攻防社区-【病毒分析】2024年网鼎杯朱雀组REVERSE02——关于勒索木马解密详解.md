**1.背景**
========

1.1 网鼎杯比赛介绍
-----------

为深入贯彻落实习近平总书记关于网络强国的重要思想，全面践行总体国家安全观，充分调动社会力量积极性，挖掘和选拔网络安全实战化人才，进一步筑牢网络安全防线，在前三届“网鼎杯”网络安全大赛基础上，第四届“网鼎杯”网络安全大赛以“网数融合，鼎筑未来”为主题，打造最大规模、最新技术、最高水平的“网络安全奥运会”。

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-c7a5617696341200c90aa1bd815a9658466d1720.png)

网站链接：<https://www.wangdingcup.com/>\#/

1.2 朱雀组介绍
---------

（能源、电力、化工、国防及其他行业单位）

1.3 题目介绍 RE02
-------------

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-b519a9cb8416d14f975253b4dede2d995e36e3d0.jpeg)

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-fb98181e74310334e8d91b79f6845f1f823adbcc.png)

2.恶意文件基础信息
==========

2.1 加密器基本信息
-----------

|  |  |
|---|---|
| 文件名: | ReMe.exe |
| 编译器: | Microsoft Visual C/C++(16.00.30319)\[LTCG/C++\] |
| 大小: | 499.00KB |
| 操作系统: | Windows(XP)\[I386, 32位, Console\] |
| 架构: | 386 |
| 模式: | 32 位 |
| 类型: | EXEC |
| 字节序: | LE |
| MD5: | 4fd22bc6938254c2ba65fcc38f23d603 |
| SHA1: | b388453c3a4aa0d3142ecebf4eb9637e6b9d559c |
| SHA256: | c2964f90a0d4ef70e0092aed526c482d9ab157ee3f59a40955f3e1087fbeee07 |

3.加密后文件分析
=========

3.2 加密的测试文件
-----------

### 3.2.1文件名

flag.txt

### 3.2.2具体内容

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-f1d8e7b2a369231a3dbcd3c7f6d3e308adc83038.png)

### 3.2.3加密文件名特征

加密文件名 = 原始文件名+.cry ，例如：flag.txt.cry

### 3.2.4加密算法

文件加密使用了AES-ECB加密算法。

#### 3.2.4.1AES密钥生成

key内置于文件中

### 3.2.5程序执行流程

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-8dd2e1747da870515a65c30ac6252da3c061bfcf.png)

4逆向分析
=====

4.1加密器逆向分析
----------

拖入die，发现是一个vmp保护的程序

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-daa1b9006772cf8dac3eda66d4c9532a3e5faa88.png)

### 4.1.1 简单脱壳

拖入ida中，发现了一个跟堆栈保护相关的函数，通过他我们可以跟踪到入口点

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-50efb2b5eecc7523c27c99b4bc874bfa7948b640.png)

通过交叉引用最后能找到，猜测此处为入口点

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-d1143c0cdde45e8bd314a6324158c13b6ba0e6fe.png)

此处为跳转的入口点的地方

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-33aa8fefa0e5ee8b3df4e6426fb8ce800853f8b5.png)

拖入xdbg，并在此处下硬件断点

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-d09c9f116985c67d6c58d91def70c2ff08a275f9.png)

断住之后使用sycall插件修复iat并转储文件

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-57677333970b23728ed9c379f21b1b5a9d1e18ef.png)

将其拖入ida中，最后出现了三个函数

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-b1fccba1946ca96d267abafa5f19dc82fd709fc4.png)

### 4.1.2 进程注入初次加密

第一个函数如下，首先自解密出字符串

```C
  memset(Buffer, 0, sizeof(Buffer));
  for ( i = 0; i < strlen(LibFileName); ++i )
    LibFileName[i] ^= 1u;
  LibraryA = LoadLibraryA(LibFileName);
  for ( j = 0; j < strlen(aBsdUdghmd); ++j )
    aBsdUdghmd[j] ^= 1u;
  Buffer[0] = (int)GetProcAddress(LibraryA, aBsdUdghmd);
  for ( k = 0; k < strlen(aSdEghmd); ++k )
    aSdEghmd[k] ^= 1u;
  Buffer[1] = (int)GetProcAddress(LibraryA, aSdEghmd);
  for ( m = 0; m < strlen(aVshudghmd); ++m )
    aVshudghmd[m] ^= 1u;
  Buffer[2] = (int)GetProcAddress(LibraryA, aVshudghmd);
  for ( n = 0; n < strlen(aBmnrdiOemd); ++n )
    aBmnrdiOemd[n] ^= 1u;
  Buffer[3] = (int)GetProcAddress(LibraryA, aBmnrdiOemd);
  for ( ii = 0; ii < strlen(aEdmdudghmd); ++ii )
    aEdmdudghmd[ii] ^= 1u;
  Buffer[4] = (int)GetProcAddress(LibraryA, aEdmdudghmd);
  for ( jj = 0; jj < strlen(String2); ++jj )
    String2[jj] ^= 1u;
  lstrcpyA((LPSTR)&Buffer[5], String2);
  memset(pszPath, 0, sizeof(pszPath));
```

得到如下字符串

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-cd24c2cdfa263f576db743d852679cb48182adea.png)

检测当前进程是否运行在wow模式，并尝试获取系统文件夹路径

```C
  Wow64Process = 0;
  CurrentProcess = GetCurrentProcess();
  IsWow64Process(CurrentProcess, &Wow64Process);
  SHGetFolderPathA(0, 4 * Wow64Process + 37, 0, 0, pszPath);
```

得到如下字符串

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-c2a55af3c2bd153170c020bb3c572fcbd84d5195.png)

自解密后拼接生成字符串C:\\\\Windows\\\\SysWOW64\\\\svchost.exe

```C
 for ( kk = 0; kk < strlen(aRwbinruDyd); ++kk )
    aRwbinruDyd[kk] ^= 1u;
  lstrcatA(pszPath, aRwbinruDyd);
```

创建进程svchost.exe并进行注入

```C
 if ( CreateProcessA(0, pszPath, 0, 0, 0, 4u, 0, 0, v11, v13) )
  {
    v14 = (char *)VirtualAllocEx(v13->hProcess, 0, 0x2000u, 0x3000u, 0x40u);
    if ( v14
      && (!WriteProcessMemory(v13->hProcess, v14, Buffer, 0x34u, &NumberOfBytesWritten)
       || !WriteProcessMemory(
             v13->hProcess,
             v14 + 52,
             sub_6E14E0,
             (char *)sub_6E15F0 - (char *)sub_6E14E0,
             &NumberOfBytesWritten)) )
    {
      GetLastError();
      return VirtualFree(v14, 0x2000u, 0x4000u);
    }
  }
  else
  {
    v14 = (char *)NumberOfBytesWritten;
  }
  RemoteThread = CreateRemoteThread(v13->hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(v14 + 52), v14, 0, 0);
  return WaitForSingleObject(RemoteThread, 0xFFFFFFFF);
}
```

对v13-&gt;hProcess 指向的进程进行附加，并跳转到WriteProcessMemory注入内存的位置

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-f50eb2666efb35e4cf269cc6dd91f9bddb5874e8.png)

得到一个字符串

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-9a52a9a2b835449502e438db33dc43d3160fb322.png)

对文件进行读取，同时对文件内容进行异或0x9

```C
int __stdcall sub_B30034(int a1)
{
  int (__stdcall *CreateFileA)(int, int, int, _DWORD, int, int, _DWORD); // eax
  int v2; // ebx
  int v3; // edi
  unsigned int v5; // ecx
  int v6; // edi
  int v7; // eax
  int v8; // [esp-4h] [ebp-3Ch]
  char v9[36]; // [esp+Ch] [ebp-2Ch] BYREF
  int v10; // [esp+30h] [ebp-8h]
  int v11; // [esp+34h] [ebp-4h] BYREF

  memset(v9, 0, sizeof(v9));
  CreateFileA = *(int (__stdcall **)(int, int, int, _DWORD, int, int, _DWORD))a1;
  v2 = a1 + 20;
  v11 = 0;
  v3 = CreateFileA(a1 + 20, -1073741824, 1, 0, 3, 128, 0);
  v10 = v3;
  if ( v3 != -1 )
  {
    if ( !(*(int (__stdcall **)(int, char *, int, int *, _DWORD))(a1 + 4))(v3, v9, 32, &v11, 0) )
    {
      v8 = v3;
LABEL_4:
      (*(void (__stdcall **)(int))(a1 + 12))(v8);
      return 0;
    }
    v5 = 0;
    if ( &v9[strlen(v9) + 1] != &v9[1] )
    {
      do
        v9[v5++] ^= 9u;
      while ( v5 < strlen(v9) );
      v3 = v10;
    }
    (*(void (__stdcall **)(int))(a1 + 12))(v3);
    (*(void (__stdcall **)(int))(a1 + 16))(v2);
    v6 = (*(int (__stdcall **)(int, int, int, _DWORD, int, int, _DWORD))a1)(v2, -1073741824, 1, 0, 2, 128, 0);
    v7 = (*(int (__stdcall **)(int, char *, unsigned int, int *, _DWORD))(a1 + 8))(v6, v9, strlen(v9), &v11, 0);
    v8 = v6;
    if ( !v7 )
      goto LABEL_4;
    (*(void (__stdcall **)(int))(a1 + 12))(v6);
  }
  return 0;
}
```

### 4.1.3 释放pe文件

由于转储没修复好，因此无法读取到资源

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-3aebb50c97a1c102152e02f3ac347e05f22e943e.png)

因此将Reme.exe拖入xdbg中分析，对sizeofresource下硬件执行断点

读取资源

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-282d3bf00af1d378b9bbe359cae2569f7565a3eb.png)

该资源大小为b800

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-14c995eb1cbdeae11ce8f1892895e573887b8491.png)

对提取出的资源进行异或解密

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-730f56e853905891088ed6cbab7da274eab87992.png)

解密出一个pe文件

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-564f144876e6e9a83281de5d1f054e08f6bc9582.png)

创建进程，其中ebx所在的地址的第三个值即使进程的pid

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-97622f611bcf38c3c855713547c8b5bfd2c40581.png)

分配内存

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-efa51068bf69cfda3bce112a8f170473104a02aa.png)

循环写入内存，修复释放的pe文件

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-bf3fba78afd62ebc9adeee35ef41b7d153d98516.png)

使用xdbg附加到创建的进程，并转储刚刚注入的文件

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-20e1cda451c0474964246cebc25a6acb0da4969f.png)

拖入die

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-f57e19eecce88498b5163e40581c053df598e46b.png)

### 4.1.4 二次加密

拖入ida中，发现了一个有趣的东西

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-4a7785d95dccd5cfe6073ceec0182300b2b9a651.png)

主函数为，其中输入的参数是'D:\\test'

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-dee757961155e04db46b967f2d9e8ebf6b9cdf5c.png)

判断文件类型是否为文件夹，如果是文件夹，就递归进入该函数

```C
    if ( (FindFileData.dwFileAttributes & 0x10) != 0 )
      {
        if ( FindFileData.cFileName[0] != 46 )
        {
          wsprintfA(FileName, "%s\\%s", lpString2, FindFileData.cFileName);
          sub_F21000(FileName);
        }
```

如果是文件，就判断后缀是否等于以下几个

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-0adeb8f520c146a3cfd0b5fe815222b273b368a8.png)

如果判断成功，就进入下一个函数，读取文件，并进行加密

```C
HANDLE __thiscall sub_F21230(LPCSTR lpFileName)
{
  _BYTE *v2; // eax
  char v4; // cl
  HANDLE result; // eax
  void *v6; // esi
  void *v7; // edi
  DWORD NumberOfBytesRead; // [esp+8h] [ebp-210h] BYREF
  _BYTE Buffer[260]; // [esp+Ch] [ebp-20Ch] BYREF
  CHAR FileName[260]; // [esp+110h] [ebp-108h] BYREF

  memset(Buffer, 0, sizeof(Buffer));
  memset(FileName, 0, sizeof(FileName));
  NumberOfBytesRead = 0;
  strcpy(FileName, lpFileName);
  v2 = &Buffer[259];
  while ( *++v2 )
    ;
  v4 = byte_F2ACEC;
  *(_DWORD *)v2 = dword_F2ACE8;
  v2[4] = v4;
  result = CreateFileA(lpFileName, 0xC0000000, 1u, 0, 3u, 0x80u, 0);
  v6 = result;
  if ( result != (HANDLE)-1 )
  {
    result = CreateFileA(FileName, 0xC0000000, 1u, 0, 2u, 0x80u, 0);
    v7 = result;
    if ( result != (HANDLE)-1 )
    {
      ReadFile(v6, Buffer, 0x104u, &NumberOfBytesRead, 0);
      sub_F21360(Buffer);
      WriteFile(v7, Buffer, 0x20u, &NumberOfBytesRead, 0);
      CloseHandle(v7);
      return (HANDLE)CloseHandle(v6);
    }
  }
  return result;
}
```

加密函数为，进入其中子函数观察

```C
int __thiscall sub_F21360(char *this)
{
  _BYTE v3[508]; // [esp+4h] [ebp-210h] BYREF
  _DWORD v4[4]; // [esp+200h] [ebp-14h] BYREF

  v4[0] = 370507323;
  v4[1] = -1496142280;
  v4[2] = -2011826245;
  v4[3] = 1011863321;
  memset(v3, 0, sizeof(v3));
  sub_F21450(v3, 0, 16, v4, 0);
  sub_F21930(v3, this);
  return sub_F21930(v3, this + 16);
}
```

明显是aes加密

![](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-5a4a67ad4e3ff6171a9db12b007137bb96763cab.png)

其中密钥为

```C
  v4[0] = 0x16157E3B;
  v4[1] = 0xA6D2AE38;
  v4[2] = 0x8815F7BB;
  v4[3] = 0x3C4FCF19;
```

### 4.1.5 flag获取

使用python解密

```Python
from Crypto.Cipher import AES
keys=bytes([0x3b,0x7e,0x15,0x16,0x38,0xae,0xd2,0xa6,0xbb,0xf7,0x15,0x88,0x19,0xcf,0x4f,0x3c])
data = open('./flag.txt.cry','rb').read()
aes = AES.new(keys, AES.MODE_ECB)
honduras = aes.decrypt(data)
decrypted_data=[]
for i in honduras:
  decrypted_data.append(i^9)
print(bytes(decrypted_data))

```

得到结果

```C
b'wdflag{70O9TSGICPQSLGDC}\t\t\t\t\t\t\t\t'
```

5.总结
====

该文章对名为 `ReMe.exe` 的勒索加密程序进行了深入分析，包括其基础信息、加密算法（AES-ECB）和执行流程。通过逆向工程，揭示了该程序的自解密、进程注入及加密机制，并最终利用 Python 成功解密出题目要求的 `flag` 值。