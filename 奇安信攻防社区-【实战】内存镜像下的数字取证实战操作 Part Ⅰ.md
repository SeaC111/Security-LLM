0x00 前言
=======

深入贯彻安全思想，守住安全防线。我没接触安全之前也许并不知道自己的信息和隐私多么重要，更多的时候只是为了自己方便就可以（隐私无所谓啦），也可能是因为在安全group中才发现安全有这么多可以获取信息的技术，才知道关于自己的言行隐私的安全的保护是有多么重要，接下来将真实分析内存镜像分析方面的教程。

0x01 内存镜像存在的意义：
===============

内存的增加促使整合水平的提高，内存的可靠性也影响该服务器上所有虚拟机（VM）的整体可靠性。因此，内存的功能就包括各种升级，比如容错内存镜像和内存备用，内存镜像文件格式有raw、vmem、dmp、img。

0x02 Volatility开源实现功能：
======================

Volatility是一款内存取证框架，能够对导出的内存镜像进行分析，通过获取内核数据结构，然后获取内存的详细情况以及系统的所有运行状态，只要你有拷贝好的内存镜像（约0.5G大小），就可实现很多实用的数字证据提取功能：**列出会话及窗口站atom表，打印TCP连接信息，显示进程命令行参数，提取执行的命令行历史记录（扫描\_COMMAND\_HISTORY信息），提取崩溃转储信息，提取内存中映射或缓存的文件，内存镜像中的shell，查看Windows帐户hash，查看进程列表。**

在官网的描述中，有关于Volatility的一句：在发布Volatility的稳定版本前，不仅是我们团队进步的一个里程碑，也是社区和取证能力整体发展的一个里程碑。虽然版本可能看起来很少，但我们努力发布不稳定版本之前对我们的新功能进行严格的测试。Volatility可以实现是对操作系统内部、应用程序、恶意代码和可疑活动进行侦察和深入研究。

使用特点是什么：

- 开源：Python编写，易于和基于python的主机防御框架集成。
- 支持多平台：Windows，Mac，Linux全支持
- 易于扩展：通过插件来扩展Volatility的分析能力

0x03 安装注意异常：
============

下载Volatility和dsitorm3
---------------------

解压后放在同一目录下，其中distorm3是一个反编译库，用来配合Volatility使用反汇编的的，先按照以下步骤安装（diStorm是用C写的，但对于快速使用，diStorm也有包装在Python / Ruby的/ Java和可以很容易地使用C语言也是如此，它是最快的反汇编库）

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3cf603ca1f26a4215af78917cc5c06e898db785a.png)

下载https://github.com/gdabah/distorm/releases 然后解压到目录中，使用命令 python2 setup.py isntall 编译程序：

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-58e02e7a2eb6872d7afcdff5bcfeb76ae87561d5.png)

推荐安装的插件，我们已经使用的包含前两个：

- Distorm3反编译库：pip isntall distorm3
- PyCrypto加密工具集：pip install pycryto
- Yara恶意软件工具：pip isntall yara
- PIL图片处理库：pip install pil
- UJson JSON解析：pip install ujson

安装Volatility
------------

在解压后的Volatility目录下进行编译：python2 setup.py install

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9c59b659d9bf1a449191af338a4e45236fbe2f7a.png)

安装完成之后显示vol.py已经生成了，所以验证是否安装成功，使用命令：vol.py，安装成功。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cf46b9d562ab639b0a428ce9701bb5ea432490b9.png)

安装pip2，然后通过pip2安装pip2 install pycryptodome依赖。
---------------------------------------------

建议在Kali中使用，首先使用pip -v 查看当前pip版本，一般是python3的pip3，所以我们使用命需要安装一个pip2，并不pip3冲突。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d5e521a96a02aee2625ae5f9f972ed8445c3eaeb.png)

直接输入pip2命令安装：

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d7f69d42ad256a8d733800854c5e87bd3f50a4d6.png)

接下里安装pycryptodome，因为Volatility是python文件，所以需要安装依赖。也可以建议直接使用：pip2 install pycryptodome -i <https://pypi.tuna.tsinghua.edu.cn/simple> -i 参数表示用来添加清华源

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8b01c19ff4c73221ffa2b7c856db76749f893a6b.png)

安装mimikatz的python文件
-------------------

使用方法是把mimikatz.py复制到volatility-master/volatility/plugins，代表插件目录，如下成功。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6b9e60f9431b2b8544a9c315d292f6c98e61edbc.png)

运行时需要添加参数 --plugins=./volatility-master/volatility/plugins，很可能出现下面错误，因为没有安装construct模块：

Volatility Foundation Volatility Framework 2.6

\*\*\* Failed to import volatility.plugins.mimikatz (ImportError: No module named construc)

ERROR ： volatility.debug : You must specify something to do (try -h)

使用命令安装contruct模块：

pip install construct==2.5.5-reupload

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ab69fd681f58e51e7881db4c9af1d4ff8ae34257.png)

简单来尝试下面命令来获取用户密码，先读取内存镜像文件后，使用命令 vol.py -f 内存镜像名 --profile=系统名 hashdump，就可成功得到所有用户的用户名和哈希值，然后就可以拿去cmd5.com破解，后面通过实战题来解析。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8979f7e30e9ace2be16f991b7c14f8ec593bae21.png)

一、CTF题：破解密码---湖湘杯2020 passwd
============================

需要我们寻找内存中的密码：

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5ee72a0b47d07eb1a543c3841b5549c1042b3543.png)

1.先获取内存基本信息
-----------

使用命令vol.py -f 文件名 imageinfo获取基本信息，得到profile为Win7SP1x86\_23418

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c9b0162f3568d5e1490ddc8f598cdb4bfbfad16e.png)

2.然后获取用户名和hashdump
------------------

使用命令 vol.py -f 文件名 --profile=Win7SP1x86\_23418 hashdump 获取用户名和哈希值，发现用户名CTF。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-59d56a8d5d7eb3fa5e2b586df54f7e0d6dbc241a.png)

3.最后获取和破解密码
-----------

根据获取的hash值到https://cmd5.com/ 破解密码。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-aa76edbe58f4498fb63894fa33574f346c779b7c.png)

二、CTF题：挂载转储---BMZCTF Suspicion
==============================

给出了一个内存镜像文件和可利用文件：

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-86e9f9b86e2852531b7fd38e3aa3a8bf7a9e47ba.png)

1.获取系统基本信息：
-----------

使用命令 vol.py -f mem.vmem imageinfo 获取基本信息，关注profile值，值为WinXPSP2x86。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e5c59db84c5f958991b3efd9a7717132892d3090.png)

2.查看运行进程
--------

使用命令 vol.py -f mem.vmem --profile=WinXPSP2x86 pslist 查看进程

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9565839d287e66b27e1387297be04d63f43fa872.png)

在众多进程中发现加密进程TruCrypt.exe ，于是采取和所给的第二个位置文件进行解密

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-33ad1e1faa6b40496770c2a4e074046fc5772764.png)

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-64388ea309f07df35b90baabb0a64d58088208c0.png)

3.转储进程得到文件
----------

因为我们需要这个进程的文件来解密，所以获取到的pid号可以使用命令：vol.py -f mem.vmem --profile=WinXPSP2x86 memdump -p 2012 -D ./ ，其中-p代表pid号，-D代表转储路径，转储出来得到pid号命名的2012.dump

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2015ac3bfc0c4baa0b6a480b47dffea9190cd98f.png)

接下里解密TrueCrypt的转储文件，这里我们使用EFDD，选择TrueCrypt（container），然后选择文件

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b86b03760935357b320d578ed92815a33a264e29.png)

然后上面选择file已经存在的加密文件，下面keys选择解密密钥，即刚刚dump下来的文件。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-84e33130d4e0048464cae201f2528a027f9bf484.png)

破解完成后是这样的，会生成一个evk结尾的内存文件，用于挂载内存文件，选择Mount Disk，然后打开我的电脑磁盘然后就可以看到多出一个挂载的内存文件，并且是明文解密形式的。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5712e1e99d63b250b037bb8f09702c8069e65f34.png)

挂载解密文件后成功得到答案。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f047067a285e19d5d735f4a98fcc9fdd583e9c40.png)

三、CTF题： 关键字查找---NEWSCTF2012 ez-dump
===================================

1.查看系统信息
--------

只有一个raw文件，而且题目描述和dump有关，首先查看基本信息。profile为Win7SP1x64，命令为vol.py -d mem.raw imageinfo

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-59d5d64b4390e88cf126e230a51dffed0eabe2ca.png)

2.从执行命令查看密码
-----------

这里查看cmd执行的命令，如果执行命令比较少很可能有密码可能性会更大，发现添加了用户，包含密码，这里发现用户mumuzi，密码(ljmmz)ovo，使用命令：vol.py -f mem.raw --profile=Win7SPx64 cmdscan 查看执行过的命令。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1cd5fa4e844e3f960f00bb33cfe591b81d4df90f.png)

3.查找flag关键字
-----------

这里filescan代表查找文件，使用管道符代表查找具有关键字flag的文件，并显示出来，这里发现一个压缩文件，因为都是内存里的文件，所以需要查看的话，都必须把它转储下来，

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0ecd6048d4eb67a37d9a82526a176c9b1957732a.png)

转储需要我们使用filedump的命令，使用命令：vol.py -f mem.raw --profile=Win7SPx64 dumpfile -Q 偏移量 -D 上一级目录，代表转储特定偏移量的文件flag.zip保存到桌面。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a44fcae1de8d3d3385b07a1b24cd03b9b4b2d7c1.png)

打开压缩包，发现已经加密，所以使用我们之前查到的密码，成功得到答案flag。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-82641e41d844177b1ff5669cc05aa65ec804de0e.png)

成功得到flag。

![img](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cfe6cf62fab47366e56a01654c71aeceb02ac605.png)

四、CTF题：可疑进程分析---福来阁殿下
=====================

只有一个内存镜像文件，考虑使用Volatility。

![image-20220906195027385](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5d2aa4a6f2095094193084122cbd162155ef632c.png)

1.查看系统信息和进程列表
-------------

查看profile为WinXPSP2x86，使用命令：vol.py zy.raw imageinfo。查看进程列表，使用命令：vol.py -f zy.raw --profile=WinXPSP2x86 pslist。

![image-20220906195750867](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c49ba718a94140a254075f0dc11cab77a68e7a0c.png)

发现一个进程叫smss.exe，可以进一步查看。

![image-20220906195655355](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0fd6c3e564190a149d2a2a26a29a21319e455894.png)

2. 转储进程查找关键字
------------

这里有一个关键的思路就是需要去使用grep关键字来获取的文件。记下pid号，使用命令：`vol.py -f zy.raw --profile=WinXPSP2x86 memdump -p 536 -D ./`。

![image-20220906201225607](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d764b78cda4a6f284c44bd8c4c2b80e9de3c385f.png)

对转储的文件使用grep，使用命令：`strings -e l 536.dmp | flag`，可以得到flag关键字相关信息。发现了很多图片，图片无法打开，可能是一条坑。

![image-20220906201710648](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-30a6d1fdd3e96d9050f726a65f5069f700951cb8.png)

3. 尝试获取浏览器历史记录
--------------

使用命令：`vol.py -f zy.raw --profile=WinXPSP2x86 iehistory`，发现了隐藏的hint提示文件，打算将这个文件从内存中转储出来。

![image-20220906202150012](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1ba87179355d3e76f3b63aa2fc3f04699f99ac6b.png)

使用grep扫描查看文件位置，然后保存文件下来，可以看到提示我们正确的flag关键词是fl4g，这也是常用的更换常见思路手段。

使用命令：`vol.py -f zy.raw --profile=WinXPSP2x86 filescan | grep hint.txt`，可以得到文件偏移量，根据偏移量获取文件。

使用命令：`vol.py -f zy.raw --profile=WinXPSP2x86 dumpfile -Q 偏移量 -D 存储目录`，打开hint.txt。

![image-20220906202500154](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b420a5b71310c342c5307aa7993b0945cc7d182b.png)

4.更换思路查找fl4g
------------

可以从这里找到正确的方向，发现了fl4g.zip文件，然后保存下载打开。

使用命令：`vol.py -f zy.raw --profile=WinXPSP2x86 filescan | grep fl4g`，查找到文件位置，下一步根据文件在内存中的偏移量保存dump下来。

使用命令：`vol.py -f zy.raw --profile=WinXPSP2x86 dumpfile -Q 偏移量 -D 存储目录`，得到fl4g.zip压缩包，一般打开压缩包的话可能还需要密码。

![image-20220906202944135](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-60f358ba80169883baece9ff448d913cba54e85c.png)

5.图片处理处理发现flag
--------------

两个不同格式的同样的图片，发现图片应该采用StegSolve来处理查看。

![image-20220906203739993](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-db28efaa291c8b1d30f52572c66a6ab45cad0005.png)

![image-20220906203754326](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-33b390f8986fcd91b2a2d4f157f50e6342792ce9.png)

看到的时候发现了图片隐藏下的二维码，你也可以扫码，基本上到这里应该flag大概就出来了。

![image-20220906203947475](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-47d0073c3d78e5669cb1ef6da63ba68fc5521411.png)

得到百度翻译链接：

```php
https://fanyi.baidu.com/translate?aldtype=16047&query=%E6%B0%9F%E5%BE%95%E6%A0%BC%E4%B9%83%E9%8C%B5%E6%89%A9%E5%8F%B7%E6%AC%B8%E5%BF%85%E8%A5%BF%E5%BC%9F%E4%BA%BF%E8%89%BE%E8%99%8E%E9%94%AF%E9%8C%B5%E6%89%A9%E5%8F%B7&keyfrom=baidu&smartresult=dict&lang=auto2zh#zh/en/%E6%B0%9F%E5%BE%95%E6%A0%BC%E4%B9%83%E9%8C%B5%E6%89%A9%E5%8F%B7%E6%AC%B8%E5%BF%85%E8%A5%BF%E5%BC%9F%E4%BA%BF%E8%89%BE%E8%99%8E%E9%94%AF%E9%8C%B5%E6%89%A9%E5%8F%B7
```

![image-20220906204215507](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-311c9a8220ae060f641904b3df295148b339e521.png)

成功得到谐音的flag，原来的文本只有上面的中文，我写出了最后的flag结果，如下。

![image-20220906204312454](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d94722eba1e19ca8d63ee21f57398c47fefd27ce.png)

五、CTF题： 千回百转AES---HDCTF
=======================

我们得到的仅仅只有一个镜像文件。

![image-20220906204649739](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5d02a774b8008fbece58dd076298acb21e487427.png)

1.获取系统信息和发现关键词
--------------

查看系统的镜像基本信息。使用命令`vol.py -f memory.img imageinfo`，发现第一个profile系统信息显示无任何信息，于是采取第二profile进行内存分析取证。

![image-20220906204750961](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-73976f094a1e262e016c01c9b49b975f4185b7bf.png)

在转而使用第二profile信息查看后，并且进行关键字flag的文件扫描，使用grep针对关键字flag信息针对查看，发现一个文件png，后面lnk是快捷方式。

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2a30f531349221a54731892597cd5796b6d4457b.png)

然后我们把图片保存转储出来，使用命令：

![image-20220906211528229](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f035f9b4de5372285924a35eabd926cd0eb141c8.png)

发现可以直接打开，是一个二维码信息，尝试使用https://cli.im/deqr草料二维码识别结果。

![image-20220906211920657](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2d1bdb35e647a0932bed59f0979b904559f95c75.png)

解码结果为发现是==结尾的base64编码，尝试使用base64解码，可是最后结果却大失所望，那么此时我们应该转向什么方向呢？也许还可以继续从内存镜像查找flag。

![image-20220906211945223](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-375d4f732dd5cdeb8c2be38faf4c125b8e4b0f09.png)

```php
jfXvUoypb8p3zvmPks8kJ5Kt0vmEw0xUZyRGOicraY4=
解码后结果:乱码
```

2.转向图片查看器的flag信息
----------------

这里最重要的是通过扫描windows来查看与flag相关的窗口，发现这个flag文件由窗口windows的图片查看器打开过，这也是理所当然，除了用资源管理器打开，一般情况还用啥打开呢？所以接下里我们转储explorer.exe资源管理器的文件，和可能与flag的关键信息有关。

这里类似于三步走操作：查找，然后找explorer.exe进程pid号，为了转储进程分析解密。使用命令`vol.py -f memory.img --profile=Win2003SP1x86 windows | grep flag`找到与flag相关联的窗口。

使用命令：`vol.py -f memory.img --profile=Win2003SP1x86 pslist | grep flag`找到与flag相关的进程，然后使用命令：`vol.py -f memory.img --profile=Win2003SP1x86 memdump -p 1992 -D ./` 生成的1992.dump文件。（PID号为1992）

![image-20220906215022870](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-edcd7ac1f3a049abfd3c5d20f0ecae222f056b77.png)

3. 处理保存后的Explorer.exe-&gt;1992.dump获取Flag
-----------------------------------------

这里考察了用forest工具自动分离几个不同格式和在一起的混合未知文件，然后根据格式之间的差异自动分开成已知有效文件，使用命令`forest 1992.dump`

![image-20220906221548913](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-48971b5e99bd2a744861086fbb6a2e1aa997801d.png)

发现了Key和IV代表AES加密中的密码和偏移量，联想之前的Base64也不是没有用，很可能就是密文，使用这三个来解密成明文，做题的思路一般就是多信息的查找和利用。

![image-20220906220058432](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bca8cda54187d88adff1fafa3a1bb0014898d629.png)

如图，显示AES加密工具，得到结果，注意编码选择Base64的就是正确的，使用网站搜索一个在线解密工具https://www.mklab.cn/utils/aes。成功得到答案：flag{F0uNd\_s0m3th1ng\_1n\_M3mory}

```php
key:Th1s_1s_K3y00000
iv: 1234567890123456
密文:jfXvUoypb8p3zvmPks8kJ5Kt0vmEw0xUZyRGOicraY4=
```

![image-20220906221311912](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-23ea0f96ac6f7fff32f1887ae0fe58098a98ad4e.png)

六、CTF题：风过留声---白帽子内存数字取证
=======================

1.查看被同学在记事本里偷摸留下的东西
-------------------

根据内存镜像系统信息，然后找到记事本，直接打开记事本相关信息。

使用命令`vol.py -f 镜像文件名 imageinfod`得到系统版本，根据版本信息分析得到notepad信息，使用命令`vol.py -f 镜像文件名 --profile=WinXPSP2x86 notepad`代表指定记事本查看。

![image-20220906223203143](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-35e477bb3b751a0a3a97cae7f2ff2b37d2557fbb.png)

![image-20220906223113758](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5d910ca5e2258aaa6cd39a9e144004790792b446.png)

最大以E结尾，所以考虑16进制编码，可以16进制转字符，成功获取结果：flag{W3lec0me\_7o\_For3n5ics}。

![image-20220906225703888](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-87aef87a791928ff42fc14f88acba1aa0362cbaf.png)

2.查看同学偷摸在你的电脑里执行命令
------------------

扫描使用的cmd命令，使用命令：`vol.py -f 镜像文件名 --profile=WinXPSP2x86 cmdscan`，发现查看了我的电脑网络信息，打开了netcat，下载了zip压缩文件到我的电脑里，现在考虑找到这个文件，然后filedump保存下来，查看转储文件。

![image-20220906223936729](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a3b869fe8dee77edb76fe90fe58c945604422f26.png)

使用命令filescan文件扫描，指定关键字p@ssw0rd\_is\_y0ur\_bir7hd4y.zip使用grep管道过滤出来，找到了就得到偏移量，根据偏移量可以使用dumpfile转储文件，成功得到源文件。

![image-20220906224320906](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-518a78745616966698113629a9d07a2bd67f1139.png)

注意要考工具中的暴力破解工具了，打不开文件的话，尝试命令`zip2john 压缩名 > hsash`使用zip2john工具暴力破解,得到hash名的文件，使用命令`john hash`成功获取结果

{19950101}

![image-20220906224948211](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-22393fa409912c4cee6ff8225df2061a8056d1de.png)

输入加密的压缩包，成功获取结果flag{Thi5\_Is\_s3cr3t!}。

&lt;img src="[https://shs3.b.qianxin.com/attack\_forum/2022/09/attach-351750c9d58e9708e760c0b908fb799264b0df0e.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-351750c9d58e9708e760c0b908fb799264b0df0e.png)" alt="image-20220906225152194" style="zoom: 80%;" /&gt;![image-20220906225259674](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b797afbaadb4594f1145b7f804548e27590537f7.png)

七、总结
====

本教程只能算是抛砖引玉，期间也参考过其他更好的一些思路，不过最后还是认为最初的选择和感觉更适合第一次看见时候的思考和理解的，所以教程比较详细一些。

> 参考链接：
> 
> 1. <http://volatility.tumblr.com>
> 2. <http://volatility-labs.blogspot.com>
> 3. <https://www.volatilityfoundation.org/>
> 4. <https://zing.gitbooks.io/kali-lunix/content/>
> 5. <https://github.com/volatilityfoundation/volatility>
> 6. <https://wiki.wgpsec.org/knowledge/ctf/Volatility.html>
> 7. <https://github.com/volatilityfoundation/volatility3/archive/refs/tags/v1.0.0.zip>