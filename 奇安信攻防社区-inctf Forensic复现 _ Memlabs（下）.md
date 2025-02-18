**MemLabs Lab 4 | Obsession**
=============================

下载链接：[MemLabs\_Lab4](https://mega.nz/#!Tx41jC5K!ifdu9DUair0sHncj5QWImJovfxixcAY-gt72mCXmYrE)

Challenge Descryption
---------------------

My system was recently compromised. The Hacker stole a lot of information but he also deleted a very important file of mine. I have no idea on how to recover it. The only evidence we have, at this point of time is this memory dump. Please help me.

**Note** : This challenge is composed of only 1 flag.

The flag format for this lab is: **inctf{s0me\_l33t\_Str1ng}**

> 我的系统最近遭到入侵。黑客窃取了很多信息，但他还删除了我的一个非常重要的文件。我不知道如何恢复它。目前我们拥有的唯一证据就是这个内存转储。请帮我。

Progress
--------

### Flag

不多谈了好吧：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7dd1683e9083e2d4bc7ead66c1168b8a1fe79242.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8ac33d1a9f7cf3fa1839a014c0e999e3a6b15332.png)​

嗨嗨嗨，运气~

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f90a4505bab602ca20f38ad28c7ce93866517b22.png)​

结合描述，文件被删除了，尝试恢复一下。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a6c7c7b763920b117877e45648f977f2b6868c9f.png)​

说一下 MFT表：

> - **NTFS**文件系统包含一个叫**主文件表**（**Master File Table**）的文件，简称为**MFT**。对于在 **NTFS** 文件系统卷上的每个文件，在 **MFT** 中都至少会有一个条目。 **MFT** 条目会存储文件所有的信息，包括名称、大小、时间、时间戳、权限和数据内容，或者会存储在 **MFT** 条目所描述的 **MFT** 之外的空间。
> - 随着文件被添加到 **NTFS** 文件系统卷，会有更多的条目添加到 **MFT** ，并且 **MFT** 大小也会随之增加。但是当从 NTFS 卷中删除文件时，它们的 MFT 条目会被重新标记为空闲状态，并且可以重复使用。但是已为这些条目分配的磁盘空间是不会再重新分配的，并且 **MFT** 的空间不会减小。
> - 文件大小 **小于等于** **1024字节**的文件，会直接存储在 **MFT** 表中（称为 驻留文件），如果超过**1024字节**，**MFT** 表就会包含其位置信息，不会存储文件。（称为 非驻留文件）

在`volatility`中提供了`mftparser`插件来查看系统的 MFT表：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f8bf219914b848fa6991a99686ce5bf6d513c368.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7a1eca41883a38646c53ce393715e8733280f9a4.png)​

字符串分散开了：**inctf{1\_is\_n0t\_EQu4l\_7o\_2\_bUt\_th1s\_d0s3nt\_m4ke\_s3ns3}**

**MemLabs Lab 5** | **Black Tuesday**
=====================================

下载链接：[MemLabs Lab 5](https://mega.nz/file/Ps5ViIqZ#UQtKmUuKUcqqtt6elP_9OJtnAbpwwMD7lVKN1iWGoec)

Challenge Description
---------------------

We received this memory dump from our client recently. Someone accessed his system when he was not there and he found some rather strange files being accessed. Find those files and they might be useful. I quote his exact statement,

```plaintext
The names were not readable. They were composed of alphabets and numbers but I wasn't able to make out what exactly it was.
```

Also, he noticed his most loved application that he always used crashed every time he ran it. Was it a virus?

**Note-1** : This challenge is composed of 3 flags. If you think 2nd flag is the end, it isn't!! :P

**Note-2** : There was a small mistake when making this challenge. If you find any string which has the string " ***L4B\_3\_D0n3* !!** " in it, please change it to " ***L4B\_5\_D0n3* !!** " and then proceed.

**Note-3** : You'll get the stage 2 flag only when you have the stage 1 flag.

> 最近我们从客户那里收到了这个内存转储。有人趁他不在时访问了他的系统，客户发现一些相当奇怪的文件正在被访问。找到这些文件，它们可能很有用。客户的原话是这样：
> 
> 名字不可读。它们由字母和数字组成，但我不清楚它到底是什么。
> 
> **注 1** ：此挑战由 3 个flag组成。如果您认为第二个标志是结束，它不是！:P、
> 
> **注** **2**：挑战时有一个小错误。如果您发现任何包含字符串“ ***L4B\_3\_D0n3* !!** ”的字符串，请将其更改为“ ***L4B\_5\_D0n3* !!** ”然后继续。
> 
> **注意 3** ：只有当您拥有flag1时，您才会获得flag2。

Progress
--------

### Flag 1

不想说了：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-82f7fd0d10002911418e7b3b484c0bbfc0519443.png)​

`pslist`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-61aefb27b38ad9a6656c81ae1b799db56a155abd.png)​

看到了特殊的进程，查看了命令行历史：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-464dc1444c0cd86c75fffcd42d4b7a67130d1cf7.png)​

确实不可读?，提取出来：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a88fc6497a041aa0abf14a8b6d7e6371868c9c01.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-36e49fe96b00326c220f00657fb5ddd569fe00c5.png)​

emm，**Stage2.png** 看来是第二部分了，还得去找第一部分。

这个地方用到了`iehistory`（想不到吧:P）

> `iehistory`插件可以恢复IE浏览器的历史 index.dat 缓存文件的片段。`iehistory`可以提取基本的访问协议（如http、ftp等）链接、重定向链接（-REDR）和已删除条目（-LEAK）。此外，不仅仅是IE浏览器，它适用于任何加载和使用的 **winnet.dll库** 的进程，通常包括 **Windows** 资源管理器 甚至恶意软件样本。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cefd4d84cac3d041a7d11bf384ee84ecbed2a680.png)​

运气不错，熟悉的base64：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f350071a4492d3c02c1919c86be2a9c9257f73ec.png)​

**flag{!!\_w3LL\_d0n3\_St4g3-1\_0f\_L4B\_5*D0n3*!!}**

### Flag 2

有了第一个flag，去解密压缩包：

![Stage2](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ed4f7fe84b204ab88ebd68f92117d8e1354573e5.png)​

直接出了

**flag{W1th*th1s*$taGe\_2\_1s*c0mPL3T3*!!}**

### Flag 3

前面看到了 `notepad.exe`，提取文件，转储可执行文件，丢入IDA：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5370fc26c590e2be4b74e100cad53552f3092be5.png)​

![JO8DJR0SR06JOJUUH](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2fedf8b7f982ed39082df171439bc2fea4081e91.png)​

![XFEMYOO44F8AMYCGF57J](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-818e502cc277b7415fae4349d59b6c20d0ac42a1.png)​

**flag3：bi0s{M3m\_l4b5*OVeR*!}**

MemLabs Lab 6 | The Reckoning
=============================

下载链接：[MemLabs Lab 6 ](https://mega.nz/#!C0pjUKxI!LnedePAfsJvFgD-Uaa4-f1Tu0kl5bFDzW6Mn2Ng6pnM)

Challenge Description
---------------------

We received this memory dump from the Intelligence Bureau Department. They say this evidence might hold some secrets of the underworld gangster David Benjamin. This memory dump was taken from one of his workers whom the FBI busted earlier this week. Your job is to go through the memory dump and see if you can figure something out. FBI also says that David communicated with his workers via the internet so that might be a good place to start.

**Note** : This challenge is composed of 1 flag split into 2 parts.

The flag format for this lab is: **inctf{s0me\_l33t\_Str1ng}**

> 我们从情报局收到了这个内存转储。他们说这个证据可能包含黑帮 大卫**·**本杰明 的一些秘密。这个内存转储是从本周早些时候被 **FBI** 逮捕的他的一名手下那里获取的。你的工作是通过内存转储，看看你是否能找出一些东西。联邦调查局还表示，大卫通过互联网与他的手下交流，因此这个内存可能是一个很好的案件突破口。
> 
> **注意** ：此挑战由 1 个flag 组成，分为 2 个部分。
> 
> 本实验的**flag**格式为：**inctf{s0me\_l33t\_Str1ng}**

Progress
--------

### The first part of flag

。。。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e4f4445d992f13df1d1a4c237b47fa3f2fa2919e.png)​

排查一下可疑进程：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ed01a6375140bae1b612dc241a23ae65f61c68aa.png)​

先看`WinRAR.exe`吧

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7d0cba36dbd02ff87d87b418baa4bac2622ce882.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7cbc3a12d5ab0db27a4e27271e041700ea726d85.png)​

提取一下：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b626a8ce8b80020529ea08269813143ef867bebe.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a3a6a12790e6d33ac1a3a4dfbbea5833c84affa2.png)​

经典，又是加密。。。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-416e2c6b7f5b8f9e481a8f0548c76d6d037e01da.png)​

?emmm，有点生硬：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f4c05a5eb110826404c9b5e06335fdd1b3ade829.png)​

![flag2](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e9bb807d4244ac12de8d9af91a311dd73a743245.png)​

**First Part：aN*Am4zINg*!\_i*gU3Ss???*}**

### The second part of flag

还有浏览器历史，之前安装过了插件：<https://github.com/superponible/volatility-plugins>

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-18d8acc145535c3497d39a6f6dae443a396c8c32.png)​

向下翻，有这么一条：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d0e5b88c68cdc9f139900fbf612a2bda83e5ec6d.png)​

有一条回收站：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-eaac4d6921118ff63109354c865c429642eb25ff.png)​

看一下回收站的链接：

[Important - Google 文档](https://docs.google.com/document/d/1lptcksPt1l_w7Y29V4o6vkEnHToAPqiCkgNNZfS9rCk/edit)，google文档

额，全是拉丁语，不过幸好，有Google 翻译

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e4f9adfa5be398bf7799baddcf528fea6f83155b.png)​

有个网盘链接：[Mega网盘](https://mega.nz/#!SrxQxYTQ)

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8292dc7f5f7a3694ce1db1034b39cfee3e0e6d7b.png)​

emm又有加密

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4f753ac7e35352525408d5480039201990ad9a13.png)​

靠运气找Key果然还是行不通吗呜呜呜

直接 **strings** 全局搜：

```bash
strings Lab6.raw | grep "Mega Drive Key"
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f3f9a5ba9130303c9c6394a7929374335279e20b.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6e7e66fb173077dfe674d60321b3b17a16b51c6a.png)​

直接看是打不开的，拖进Winhex看看

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-36b91595a627026f9d105e500f352029526bf442.png)​

这个地方要大写的`IHDR`，修复一下，16进制从`69`改成`49`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-993ee0311c5e072fc7743b3254333b33a8e36157.png)​

![flag_](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c3a4e540baad51b07bf463636c7e491a02480c54.png)​

**Second part：inctf{thi5*cH4LL3Ng3*!s\_g0nn4*b3*?\_**

综上，**flag为：inctf{thi5*cH4LL3Ng3*!s\_g0nn4*b3*?\_aN*Am4zINg*!\_i*gU3Ss???*}**

MemLabs Lab 6 | The Reckoning
=============================

下载链接：[MemLabs Lab 6 ](https://mega.nz/#!C0pjUKxI!LnedePAfsJvFgD-Uaa4-f1Tu0kl5bFDzW6Mn2Ng6pnM)

Challenge Description
---------------------

We received this memory dump from the Intelligence Bureau Department. They say this evidence might hold some secrets of the underworld gangster David Benjamin. This memory dump was taken from one of his workers whom the FBI busted earlier this week. Your job is to go through the memory dump and see if you can figure something out. FBI also says that David communicated with his workers via the internet so that might be a good place to start.

**Note** : This challenge is composed of 1 flag split into 2 parts.

The flag format for this lab is: **inctf{s0me\_l33t\_Str1ng}**

> 我们从情报局收到了这个内存转储。他们说这个证据可能包含黑帮 大卫**·**本杰明 的一些秘密。这个内存转储是从本周早些时候被 **FBI** 逮捕的他的一名手下那里获取的。你的工作是通过内存转储，看看你是否能找出一些东西。联邦调查局还表示，大卫通过互联网与他的手下交流，因此这个内存可能是一个很好的案件突破口。
> 
> **注意** ：此挑战由 1 个flag 组成，分为 2 个部分。
> 
> 本实验的**flag**格式为：**inctf{s0me\_l33t\_Str1ng}**

Progress
--------

### The first part of flag

。。。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e4f4445d992f13df1d1a4c237b47fa3f2fa2919e.png)​

排查一下可疑进程：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ed01a6375140bae1b612dc241a23ae65f61c68aa.png)​

先看`WinRAR.exe`吧

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7d0cba36dbd02ff87d87b418baa4bac2622ce882.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7cbc3a12d5ab0db27a4e27271e041700ea726d85.png)​

提取一下：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b626a8ce8b80020529ea08269813143ef867bebe.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a3a6a12790e6d33ac1a3a4dfbbea5833c84affa2.png)​

经典，又是加密。。。

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-416e2c6b7f5b8f9e481a8f0548c76d6d037e01da.png)​

?emmm，有点生硬：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f4c05a5eb110826404c9b5e06335fdd1b3ade829.png)​

![flag2](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e9bb807d4244ac12de8d9af91a311dd73a743245.png)​

**First Part：aN*Am4zINg*!\_i*gU3Ss???*}**

### The second part of flag

还有浏览器历史，之前安装过了插件：<https://github.com/superponible/volatility-plugins>

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-18d8acc145535c3497d39a6f6dae443a396c8c32.png)​

向下翻，有这么一条：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d0e5b88c68cdc9f139900fbf612a2bda83e5ec6d.png)​

有一条回收站：

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-eaac4d6921118ff63109354c865c429642eb25ff.png)​

看一下回收站的链接：

[Important - Google 文档](https://docs.google.com/document/d/1lptcksPt1l_w7Y29V4o6vkEnHToAPqiCkgNNZfS9rCk/edit)，google文档

额，全是拉丁语，不过幸好，有Google 翻译

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e4f9adfa5be398bf7799baddcf528fea6f83155b.png)​

有个网盘链接：[Mega网盘](https://mega.nz/#!SrxQxYTQ)

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8292dc7f5f7a3694ce1db1034b39cfee3e0e6d7b.png)​

emm又有加密

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4f753ac7e35352525408d5480039201990ad9a13.png)​

靠运气找Key果然还是行不通吗呜呜呜

直接 **strings** 全局搜：

```bash
strings Lab6.raw | grep "Mega Drive Key"
```

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f3f9a5ba9130303c9c6394a7929374335279e20b.png)​

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6e7e66fb173077dfe674d60321b3b17a16b51c6a.png)​

直接看是打不开的，拖进Winhex看看

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-36b91595a627026f9d105e500f352029526bf442.png)​

这个地方要大写的`IHDR`，修复一下，16进制从`69`改成`49`

![image](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-993ee0311c5e072fc7743b3254333b33a8e36157.png)​

![flag_](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c3a4e540baad51b07bf463636c7e491a02480c54.png)​

**Second part：inctf{thi5*cH4LL3Ng3*!s\_g0nn4*b3*?\_**

综上，**flag为：inctf{thi5*cH4LL3Ng3*!s\_g0nn4*b3*?\_aN*Am4zINg*!\_i*gU3Ss???*}**