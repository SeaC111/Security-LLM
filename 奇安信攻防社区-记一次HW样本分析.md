0x01 20113852 @C.exe
====================

原始样本使用UPX加壳，需要脱壳分析。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-8aed96b7264b26d03c80f7d7a3ef3695c3dff956.png)

1.1 修复程序
--------

首先程序不是从main函数开始，而是从Strat开始，从exports可以看出。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-95b604735a1dc0587a1add4435fca7fb28378388.png)

进入start后出现两个函数，一个是类似CANARY的一种防御缓冲区溢出攻击的手段，重点是第二个函数。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-c447007895ee8319e3e43c3cd2e6f959ee9d0cec.png)

进入`__scrt_common_main_seh`函数，首先做了两个结果判断。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-42c143bd753dcdde6e2735fddf1f61cc98253eaa.png)

进入`__scrt_initialize_crt`查看。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-98f338ec20c85ab020a44c7b948a0fe6f3fc0aad.png)

`sub_5B3F24`通过`IsProcessorFeaturePresent`判断CPU的信息。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-ab26fdf464a7ea1aa14b5d17e8f7534f65c8afdf.png)

`sub_5B3C1B`返回值1，因为调试器会在第一个调用处设置断点，导致子函数第二次被调用时返回0，所以是一种反调试技术，来达到退出或终止调试的目的。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-95bc2a1142ed7d4cb4fc4d9c1a3960a69fa272b5.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-ec8c6970753705ab7bf183a587f007bfbcd82249.png)

第二个函数`__scrt_acquire_startup_lock`实现了自旋锁功能。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d0229a4dc2b371ff20594ad71f394b6002edd3d5.png)

接着看下一个函数`sub_5B3C83`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-e37bd981e4e34b23f34a1b54ae56d0d5303303ef.png)

也是反调试，通过`IsDebuggerPresent`检测是否被调试。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-dac2d1f9de0d6f37160fa0c1dfba17e6ae27f102.png)

如果被调试就退出程序。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7cb0f892be1d4f870feb86387850c296bd86e484.png)

如果不是调试，就在执行一系列操作之后进入main函数。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-cce53133ef8d067ac5383590494522fe50a80d0e.png)

自此，逻辑就清楚了，那么修复程序，只需要将`goto LABEL_20`的时候改成跳转到`get_initial_narrow_environment`就行。因为main函数需要三个参数：`v8`、`v9`、`v10`，而这几个函数不需要传入其他参数，所以我们跳转到`v8`就行。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-c9a7c5808426c4ac39c199a83ecfff80fc93e13f.png)

首先找到`goto LABEL_20`的地址为`005B362A`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7cdc1c3c0165bd09afbd9819753393dff2cd925b.png)

接着找到`v8`的地址为`005B36F2`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-098311fe6111b19b9121cb6d6b76b526ac7eff6a.png)

打开x32dbg，`ctrl+g`跳转到`005B362A`下断点。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-edba8d0cfce451c0216d6f7c3ede1b4246730d16.png)

F9执行到断点，将命令改为`jmp 0x005B36F2`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-eb152c7aee96ddf484955a72bd87eb0ff0edf944.png)

ctrl+p修补文件。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-6c23444adc0a9ca7f585601cf659735b37c8c22b.png)

1.2 main
--------

IDA可以看到main函数的地址是`005B3709`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-5cb2e52e303b2da130c7332ed389713e278b607d.png)

程序main函数前半段会解密出一个程序内嵌的dll，`xor key`为`0x70AB96A`在`To_Big_Function`中以字符串拼接的方式组合出原始的内容，然后在`sub_404920`中先`string`转`int`，在右移三位，与key异或，最后传入`sub_405B60`中的两个参数分别为dll的`buffer`和`length`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-f5962e75760be6129c629a278c6db57c7a3fb8df.png)

### 1.2.1 main→To\_Big\_Function\_4063F0

字符串拼接的方式组合出原始的内容。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-5351af069c0e5fc469f859f9042ff9dfec8af997.png)

### 1.2.2 main→sub\_404920

xor解密。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d556a97cfe33bd75b408cd4cf5599b0b2662c359.png)

1.3 dump dll
------------

通过动态调试在内存中dump出解密后的DLL。

### 1.3.1 0040608D下断点

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-926c7b7909660c442da744703688e6328aa20dd0.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-f966b262f4af6cf5113d6952abedf5ac50dc50e3.png)

运行到断点处。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-071facdb68558121cd4e25a4b65da016db492471.png)

### 1.3.2 dump

寄存器eax是文件开始的地址，edx是长度。

- LoadLibraryA等函数加载DLL到内存时,会返回加载的DLL在内存中的起始地址,该返回值通常存放在eax寄存器中。
- DLL或其他文件的大小长度参数也经常通过调用约定存在edx寄存器中。

dump命令：`savedata "E:\\1.dll",00A9BEC0,0019FF0C`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d9a19a535b4261f82185900fb22a91dc727d1020.png)

在日志中可以看到写入成功，文件夹中可以看到保存的1.dll文件。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-b90203cdfec32af7660b443f1c39f98989f70a4b.png)

之后大马做的就是调用DLL中的导出函数`CustomFunction`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-681a21e2e2360348f41ea9545f016c465510369c.png)

接下来看看1.dll。

0x02 1.dll
==========

先shift+F12从字符串开始看。

DLL中存在BlackMoon等关键词，说明是使用黑月编译器编译的易语言程序。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-63821a7f5682cda0482d91aa8bb9dfc8f636e4d6.png)

一些原始信息，如DLL名为NCJZ.dll，编译日期为2023年8月15日12点。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d13ef8eb8b4e3c4a162f19e047bd5563bb2387fc.png)

HTTP相关字符串。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-6e74b5aaeaa4081eba5c981e9763e294ef8217cd.png)

通过交叉引用，找到DLL中的网络数据请求相关代码。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-1ffee4cc192be3bfc27989c08d801fd480c4aac1.png)

现在回到刚才dump的地方，F8让程序从内存加载dll。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-430a2c299018c87af74dfacc50a05203a1c9beb2.png)

然后从符号表中找到`WinHttpConnect`下断点。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-5aa58014fa1259a6961d238c0adf31b6d0b428f8.png)

运行到断点，可以看到从远端下载。

aliyundownyi.oss-cn-hongkong.aliyuncs.com/libcef.exe

aliyundownyi.oss-cn-hongkong.aliyuncs.com/libcef.dll

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-91df6b41a4599ff51c3ec491519fd6f0ebab1648.png)

0x03 libcef.dll
===============

根据经验，既然已经下载了下一层payload，且存在exe程序，那此二层DLL后续的动作应该就是启动三层exe（libcef.exe）。 而三层exe又在导入表中依赖三层DLL，因此我们先看DLL。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7eb84966705e23210a6261ba4dc72b5738740d82.png)

DLL用aspack加壳，需要手动脱壳后分析。这个脱壳就不说了，老版ESP定律直接定位OSP。

0x04 libcef.exe
===============

将脱壳后的dll重命名为libcef.dll，放在libcef.exe同一目录下。

在隔离环境中运行三层样本时会发现网络数据请求。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-afbb5f52046a4b20c27c9113adba9d21b262fc47.png)

因此我们使用调试器并将断点放在`connect`函数上，观察调用栈。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-dc6938d4f4025465cb9d9c8d3e7f1dcab8a8f255.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-b8ff95b80d3f68a10600227616bbba94d334ddfc.png)

可以看到一个奇怪的地址，这个地址不属于任何模块，非常明显的shellcode特征。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-19ac7f2cb1ceb20ff6357b4d9b709b5f211ef05a.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-eac61e0723b98a8bee632e456e1994bd47d85a09.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7528b191ce8c4e30a270d816784b4e8993a8e670.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-266d86750f5e98abaecaa75d6e6605db797f2776.png)

关闭其他断点，只留下该地址的硬件断点。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-1d03a8a2b936872bd1b90f2be00f85aac60e0f82.png)

重新启动程序，可以看到断点断在了libcef.dll中。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-a54385ee7d2a2220ee13347a66193923c0551f0e.png)

4.1 IDA和xdbg基址同步
----------------

libcef.exe中加载的libcef.dll的地址为`0x6EB00000`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-4904db656d9ef9b26ac7ecd03b55cc903f6a7ec7.png)

在IDA中更改地址。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-a4c2435398968de5c950d69cf356c552a090be71.png)

4.2 shellcode
-------------

在脱壳后的libcef.dll查看调用地址附近的代码，发现样本使用AES加密shellcode。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-c21265f548e2a2c41019efc62c3a34f14ec5b1d3.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-6aa9ce90c4e66e46068158367f9f69e3b00b7cc2.png)

双击dword查看，如下分别为数据长度、AES密钥:`JqZpcsR4FX4X0nBG`、待解密内容。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7dab4f63a6be24438943bf90aa369352ea7bdec2.png)

解密方式为AES-ECB，可以在线静态测试。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-f6edfe2dfb9fbed91b5849e8e263345bc0a1f369.png)

4.3 dump shellcode
------------------

内存中dump的方式获取4层DLL。

解密函数地址：`6EB05BE6`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-ffc0d9e5244728caceac72be2b64fc0a3592a2c6.png)

跳转到该地址，执行解密函数后，dump shellcode。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-880b3ed5af15650ffc9aff125e73bf89187c272d.png)

dump命令：`savedata "E:\\shellcode.dll",6EE5A428,0x17A400`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-86801c43438b39917c554b27eb48dbf2edd15210.png)

libcef.dll会调用这个dll中的`fuckyou`导出函数。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-565353ac68fd0e3d8915a0f4d78937615d9162b6.png)

0x05 shellcode.dll
==================

功能如下：

创建windows服务，名称为`Ykamgo soouukua`。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-a68e7258f819f4e14885026e50b51e74bfa6de6a.png)

获取系统信息、网络连接、执行命令、权限维持、修改注册表等等。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-21de88e4c8f5f8a7b28aa2858a59e9c6751f0633.png)