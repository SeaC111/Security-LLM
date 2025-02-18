0x00 概述
=======

在周末闲暇无聊网上冲浪的时候，发现了有人求助分析一款木马的帖子，这不得来分析一手？我随即下载文件，放入虚拟机，然后。。。。开了一把游戏。

虐菜局，作为菜菜的我，很被虐。打完开始分析。

待分析的木马是BLADABINDI，也称为njRat/Njw0rm，是一个远控，功能上也是很强大，从键盘记录到DDos。样本的信息如下：

**样本名称**

c46a631f0bc82d8c2d46e9d8634cc50242987fa7749cac097439298d1d0c1d6e-1603075107

**样本类型**

PE32 executable (GUI) Intel 80386, for MS Windows

**样本大小**

1178304

**MD5**

62c01f1b2ac0a7bab6c3b50fd51e6a36

**SHA1**

cfc301a04b9a4ffeb0dc4578c1998a4eb4754f7b

**SHA256**

c46a631f0bc82d8c2d46e9d8634cc50242987fa7749cac097439298d1d0c1d6e

**SSDeep**

24576:HRmJkcoQricOIQxiZY1iagI+bpJBIAkPcJCqbVvi1N:sJZoQrbTFZY1iagTpVkybVqT

0x01简要分析
========

然后执行程序，看一下样本执行行为。

1、执行其他程序：样本在执行后，会创建Tr.exe 子进程并在执行一段时间后退出子进程。

![a.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-46f26be1db69c4eec400d51c6ddeaee95eb69093.png)

2、创建文件：样本在执行后会在%TEMP% 路径下创建Tr.exe 文件和x.exe 文件。

![b.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2d90f73a5511f3d949e72ec72d183b2928c38e97.png)

![c.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-57e9276bcfbe17ddf2f8f40eb16ec1e577c0be41.png)

3、注册表修改：在注册表写入数据实现无文件自动执行。

![d.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4f35b526490043c606c654f67f6ff8771f9a152b.png)

4、创建启动项链接：创建名为Microsoft.lnk 的快捷方式指向恶意文件。

![e.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d9d959c5e919d18d106b3ace63c02411ea7a8898.png)

0x02详细分析
========

1、将文件托到Exeinfo 查壳

![f.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b0621155b927cb9a38407fbd404b4e226cbe0764.png)

显示是Autoit v3 脚本编译。

2、使用Exe2Aut 工具对样本进行反编译（此处需要反编译的程序有x.exe(样本复制体)，Tr.exe）

2.1、对样本x.exe的反编译，很清晰地看到脚本代码。

![g.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-8401483f009381daf7c8d4b5d07cb946166a5182.png)

2.2、对样本Tr.exe的反编译，这里使用的是base64 对数据进行加密。

![h.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-9d99fb6f492053953759e6a8c81f6b641a0362e9.png)

先对 x.exe 进行分析
-------------

1. 首先程序会删除原本的Tr.exe 文件并重新创建Tr.exe，在完成创建后会判断目标文件是否真的已经创建并在返回正确结果后执行Tr.exe.

![i.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-664c31b4427fbd3b63a1647f734b4de162dc7813.png)

2. 接着程序会将自身复制为x.exe并于%TEMP% 路径下生成，然后创建指向x.exe 的快捷方式Microsoft.lnk

![j.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b329ec8d7e29c42e5dd78d75b4516d8e46ee190a.png)

3. 这里实现了恶意文件横向传播的方法，首先定义一个while true 循环，然后在通过检测可移动磁盘是否存在，在确定插入U盘后，获取U盘状态并在确定U盘插好的情况下将恶意文件复制并设置为隐藏。同时，还会对U盘内的文件进行删除等操作。

![k.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-20f43b812c5f21d783ad77e6b702804593ccf947.png)

对Tr.exe 的分析
-----------

**样本名称**

25bc108a683d25a77efcac89b45f0478d9ddd281a9a2fb1f55fc6992a93aa830

**样本类型**

PE32 executable (GUI) Intel 80386, for MS Windows

**样本大小**

915456

**MD5**

4d3b21451ed0ee3ee65888d4c8944693

**SHA1**

dcfec58ec8d9d8ec45d0b033db4462f1dafe5ab3

**SHA256**

25bc108a683d25a77efcac89b45f0478d9ddd281a9a2fb1f55fc6992a93aa830

**SSDeep**

12288:pCdOy3vVrKxR5CXbNjAOxK/j2n+4YG/6c1mFFja3mXgcjfRlgsUBga1T1W+MQ:pCdxte/80jYLT3U1jfsWahI+MQ

Tr.exe 功能相对较为单一，将加密后的数据写入到注册表

![l.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e933a958087c3b614d28b1e4e5e85c2395fe7f1f.png)

通过代码分析，得出加密方式使用Base64，数据应该是PE文件（通过Shell 命令可知）

解密：

![m.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0e266315d7dcce323cef34a09427e0cd5309e2db.png)

使用HxD32 将加密数据存放为exe，并且对exe 进行基础分析

对解密后的样本进行分析：
------------

**样本名称**

8dbe3fc1131346a2162d940d2b351c060282c9ae93351327535b5b19a394883f-1603099974

**样本类型**

PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows

**样本大小**

68096

**MD5**

56c0630998c7b8af19a2d72f3315ef4c

**SHA1**

9346ec06f152c2386f8ad639cb90eab85ebdfc58

**SHA256**

8dbe3fc1131346a2162d940d2b351c060282c9ae93351327535b5b19a394883f

**SSDeep**

1536:RRFJykxKeA8nOhfrEBEQ7Oykx2blKpNDJ:LD+cWbYOJx2bIr

**1、样本家族：njRat**

**2、样本功能**：

○注册表操作

○创建文件

○和服务器建立通信

○修改防火墙规则

○键盘记录

○获取计算机信息

○屏幕截图

○伪装为系统进程

**对解密后的样本进行详细功能分析：**

1. 通过查询注册表和调用系统函数获取计算机和操作系统信息

![n.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-b860314131bc0e9b35729f907ab0b1acc4973888.png)

2. 使用压缩算法将内存数据进行压缩，便于向服务器发送

![o.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-18b595c58b5e92c300bdbaf03c03851b11e1c60b.png)

3. 通过调用系统函数获取计算机驱动设备信息

![p.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-28893da901f9216dc7d946cfe34e7b2ebd1e832e.png)

4. 样本对自己进行复制并通过命令修改防火墙规则，同时修改注册表实现自动启动，创建开始菜单文件，实现自动启动

- 创建复制体  
    ![q.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0aa32e6b29a348ed94e9163b59925e51095ac50d.png)

\*修改用户环境变量、防火墙配置

![r.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-0f85a90e81766e58b4430d9289ced1d2bd624e88.png)

\*修改注册表，复制自己到开始菜单

![s.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-e258b5fd183588559307e6768dc70b7fb82fe049.png)

5. 实现截取屏幕操作

![x.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-09e4e9e681e269800f3541addde4f1d28c518a9d.png)

6\. 实现与服务器建立通信，并且接受服务器命令

![y.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-d70d5c6200beee01702d9b408a6409715928bba9.png)

7. 将进程设置为系统关键进程，进程一旦被杀，系统进入蓝屏进行错误检查，保证程序正常执行

![z.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-7d5fe48f889cd2e22ab5e2505bcf2f639d0ddd95.png)

8. 与服务器建立TCP连接，主机地址："water-boom.duckdns.org：1177"

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-4fc66318634a12cbcc86cb137d4a1eccae67d528.png)

9. 实现对程序的清除和退出

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-1705d7d79132273ffa6f99f0c4d1c776801c3518.png)

10. 获取当前活动窗口的标题，用于键盘记录器记录当前键盘操作所属的程序

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-51d08f10d91615954f65650d889ea6d89735f60f.png)

11. 将截取的键盘操作存放为文件

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-23ff5ca1f7023aad87fab8991a57c2258cc30422.png)

样本执行流程
------

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-baed5e0697a381e961895a2369caf19c87febb30.png)

0x03总结
======

这个样本总体上比较简单，也比较利于分析，本身没有多少反调试和混淆的操作。通过这个样本也可以看到，在日常工作中最常使用的U盘一不注意可能就是病毒木马传播的媒介。

IOC:

water-boom.duckdns.org

56c0630998c7b8af19a2d72f3315ef4c

4d3b21451ed0ee3ee65888d4c8944693

62c01f1b2ac0a7bab6c3b50fd51e6a36