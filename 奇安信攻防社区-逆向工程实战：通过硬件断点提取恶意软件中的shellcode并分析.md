前言
==

在进行恶意软件分析的过程中，经常会遇到恶意软件在内存地址空间中加载Shellcode的行为。如何通过硬件断点来提取恶意软件中的shellcode并进行分析？

当标准的加载器解压文件时，通常会结合使用 `VirtualAlloc`、`VirtualProtect` 和 `CreateThread` 这些函数。这些函数允许恶意软件分配新的内存区域，用于存储和执行解压后的有效负载。

在大多数恶意软件中 - 我们可以在`VirtualAlloc`和`VirtualProtect`函数调用上设置断点，并使用硬件断点监视结果。当访问新分配的缓冲区时，这将发出警报，从那里通常很容易获得解码的有效载荷。

前置知识
====

硬件断点
----

**硬件断点（Hardware Breakpoint）** 是一种由处理器提供的调试功能，用于在特定条件下暂停程序执行。与软件断点不同，硬件断点不依赖于在代码中插入特殊指令（如INT 3指令），而是利用处理器的内置机制来监控内存地址或数据访问。

处理器会提供几组特殊的寄存器，被称为**调试寄存器（Debug Registers）**，如x86架构中的`DR0`到`DR7`。这些寄存器课可以设置特定的内存地址或条件，同时，调试过程中可以设置的硬件断点的有限的。

硬件断点在实战过程中经常被用来检测内存地址的读写操作，是否被访问。

函数介绍
----

**VirtualAlloc**:

- Windows API函数，用于在进程的虚拟地址空间中分配内存。恶意软件使用它来创建新的内存区域，通常是为了解压后的代码或数据预留空间。
- 这个函数允许指定内存的大小和属性（如可读、可写、可执行），这对加载和执行恶意代码非常重要。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b5bf14b541c4f3111a979b3121ccb24c773a97c2.png)

**VirtualProtect**:

- 这个函数用于更改内存区域的保护属性。恶意软件在使用 `VirtualAlloc` 分配内存后，可能需要使用 `VirtualProtect` 来调整内存的权限。
- 解压缩后的代码可能首先以可写入的方式存储，然后在需要执行时将该内存区域的权限修改为可执行。这种动态更改内存权限的行为是很多恶意软件常用的手段，目的是绕过某些安全防护机制。

实战分析
====

IOC
---

| HASH | Value |
|---|---|
| SHA256 | 08ec3f13e8637a08dd763af6ccb46ff8516bc46efaacb1e5f052ada634a90c0e95cfc3dd3c9ac6713202be2fbc0ffd2d |
| MD5 | 95cfc3dd3c9ac6713202be2fbc0ffd2d |
| SHA1 | 66dc4ca8d51d03c729d70b888bc57fec44738f0d |

样本分析
----

```php
（虚拟环境运行and打快照）
```

DIE查看：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-afbcbbff24277493e5e12a0db2eae01524516eb8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-7057e41c1ac53da2abbbfc7cee6256a7aa6950bc.png)

64位的DLL文件，同时查看导出表，DllRegisterServer应该是载入shellcode的地方。

x64dbg分析
--------

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-ec1a2b7f6a2560618f67e1bd849708eaf205981c.png)

断在了Entrypoint上，这里直接运行就可以发现。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-e38a240e0b6b8128582bba9309840d5a6d97c354.png)

这是一个DLL文件，如果直接运行越过EntryPoint将什么也不会发生，真正的实现应该在导出函数上。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-cfeeda8153cd18a88c2556542e3880d6618dff8d.png)

因此我们应该让它在导出函数中运行，跳转到导出函数DllRegisterServer后，在这里设置新的RIP位置。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-1d26987c0351a04b7210706f66aa4e9161dddc51.png)

之后根据上面的思路先下个断点，`bp kernelbase.VirtualAlloc`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-3dfe25b4ce246fd5142fd4ec65b50d5346b4c392.png)

下完断点后F9运行，断下来后再Ctrl+F9，这将运行到函数结束：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c61bbb523e8897812a2478447a91563cc8f1b9c6.png)

如果成功VirtualAlloc将会返回一个指向RAX寄存器中空缓存区的地址，右键它选择在内存窗口中显示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-05a26fe0b1bf83f28d46485831acbe1a5f6e3ca0.png)

硬件断点设置
------

右键点击空缓冲区的第一个字节：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-72efb7c7bc42c5ce887d527817bcd73c070e49a9.png)

之后F9运行，程序会中断并开始填充空缓冲区：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-09db2453463de98c7e37405a6dc15a724ef4d264.png)

接着Ctrl+F9运行到函数返回。填充完整个内存空间。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-8fe3879babd013c0d5ec89547cd2afb4a967c70b.png)

这样就得到了DLL中隐藏的shellcode了。

shellcode分析
===========

shellcode可以提取出来，也可以直接在dbg上调试

cyberchef
---------

选中所有的十六进制，复制：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-b7c917f24fb16a6b20e6586a0ebe5bb555fa7caf.png)

打开CyberChef（一个加解密十分好用的网站）

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-f835da21f6da685c14def50401613052ac7d67af.png)

speakeasy
---------

一个二进制模拟器：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-35e11bed5791c0fddee399476319d4fc75f6723c.png)

github链接：<https://github.com/mandiant/speakeasy>

将shellcode复制到txt，重命名为shellcode.bin即可。

x64dbg
------

选中第一处字节，跳转到反汇编窗口：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9150fb7200ffd65edf6e3de18bcfe28766585e00.png)

在shellcode中执行，将FC设置为新的RIP，然后进入第一个call：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-81fd3741fc9a679edfcdf10005587a939d90d753.png)

对所有的call rbp都打上断点，F9运行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-944d6d034a323620d42ff5d860f3eb2c8fa29c56.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-6a9651a38ee0230a8fb7ccb8df3c6ee3995926fa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-9f8b57bbba768949d9e214099b96458ea781b597.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-c7a9397ebe9e7622aa7f56d42119f2e596c87990.png)

几次之后，你就可以得到一个C2域了。

### API哈希

可以搜索call rbp的上一条语句的hash：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-d286e943e4582bad6eedc3bd6be1135ed6f3db96.png)

可以快速知道哪一些哈希对应的API函数是什么。

同时可以选中F7进入call rbp中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/08/attach-0117988848439a28de44db8b6e16a4d77bdf01bb.png)

例如这里，遍历TEB/PEB表并计算ROT13哈希（0xD=13）