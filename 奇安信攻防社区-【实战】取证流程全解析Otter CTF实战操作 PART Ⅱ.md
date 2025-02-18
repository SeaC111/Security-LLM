0x00 前言
=======

故事背景是一个叫Rick瑞克的喜欢玩老式游戏的人，而且这人吧还总喜欢用比特彗星下载盗版电影种子，游戏种子，有一天他边玩游戏边下东西，突然电脑中了勒索病毒，文件被锁了，所有后缀变成了.locked，然后取证分析人员拷贝了内存镜像文件，来看看你能从被锁的文件中获取什么信息？

0x01 用户密码是多少？
=============

你得到了瑞克电脑内存的样本，你能得到他的用户密码吗？

![image-20220908142301578](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c687f19821b75eda85ed124938f2eae7e1fe23d5.png)

这是一个0.5G大小的镜像文件，来自数字取证网站的文件，我们只有这一个以vmem结尾的文件，因为要使用高级数字取证框架Volatility来针对每一个系统做适配各个系统的的操作（后面的每一个命令都和这个有关），所以我们需要获得基本信息，profile即代表镜像的系统版本，从图中我们可以看出来为Win7SP1x64，第一个最适合，无法加载出信息时，选其后。

此步使用命令：`vol.py -f OtterCTF.vmem imageinfo`，imageinfo代表查询镜像信息。

![image-20220908142415031](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b3421a82098ed208f0d302d22b6ec89ea2685115.png)

因为题目说试图寻找密码，那么目光我们先锁定内存的hash值，可以看出包含管理员，Guest，Rick账户，我们一般目标都是第三个，然后获取之后，根据得到的hash值使用mimikatz爆破，基本就能得到密码。

此步使用命令：`vol.py -f OtterCTF.vmem --profile=Win7SP1x64 hashdump`来获取密码的LM和NTML。

![image-20220908142623899](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f4fc728a58bdb5f1f3408f6efd6247999c352f31.png)

mimikatz通过对lsass的逆算获取到明文密码！只要有内存镜像，就可以通过获取到登陆密码。

此步使用命令：

```php
vol.py --plugins=./volatility-master/volatility/plugins -f OtterCTF.vmem --profile=Win7SP1x64 mimikatz
```

其中--plugins指定参数为插件路径，注意在这里mimikatz是一个py文件，然后mimikatz则代表指定的插件，可以看见成功获取密码。

![image-20220908142811378](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-74d48a2829a8880bf39f8193b081dd354c351fa2.png)

结果：`{MortyIsReallyAnOtter}`

0x02 发现目标：使用IP地址和电脑主机全称是多少？
===========================

题目分析我们仍然只有这个内存镜像文件，不过已经足够了，这个时候我们寻找关键字`netscan`代表对网络信息扫描，结果是连接的地址为192.168.202.131，接下来找主机名。

![image-20220908143027639](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5073a0c6f8fac332b146354dd0cc604fb434c6fc.png)

主机名呢，我们如果得到是一台电脑当然好找了，但是如果是内存镜像，那么我们就要深入一下了，了解到所有用户信息都会存储到注册表上，所以我们去查看注册表，找到注册表下的SYSTEM系统信息。

此步使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 hivelist
```

hivelist代表查看注册表第一级信息。

![image-20220908143200462](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c8f2641c0ee8de450af8b0344a12308d71b90a62.png)

那么第一级发现只是目录，而路径又代表文件的位置，所以文件的位置使用偏移量来表示，0x开头，使用参数-o，注意是小o，然后根据得到的偏移量，找到系统注册表包含的值，注意这里注意要使用printkey打印出来，显示出来。这里非常关键，看看我们得到了什么？

此步使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 -o 0xfffff8a000024010 printkey
```

![image-20220908143530355](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cd9a3e9f178869d68d0e865cddc1544c261894a1.png)

此刻我们发现并没有我们想要的值，现在可不能返回，想想我们的注册表，要想得到想要的值，得依次深入找到最后一级目录。所以接下里我们深入路径，知道看见ComputerName关键词.

![image-20220908231953453](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-50ef5824aac1ac2eebac9f1e35d3ae69300911ae.png)

这个是上图的第一个Subkeys，尝试从第一个开始解析，使用命令，子键意思是，每一个大键包含几个小键，然后每个子键含有多个子键，深入往下解析。

此步使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 -o 0xfffff8a000024010 printkey -K "ControlSet001\Control"
```

注意-K是大K代表指定路径的参数。

![image-20220908143648814](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d94c19a78d3b54d8f593c19fe88ece4c88115064.png)

注册表上图的操作，下面位置发现子键subkey含有computerName，使用命令，得到主机名称。

此步使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 -o 0xfffff8a000024010 printkey -K "ControlSet001\Control\ComputerName"
```

![image-20220908143919195](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-53f319529ec17b01831d2b5b9fdc91eb3b350abd.png)

所以这里通过持续跟进得到最终正确目录应该是：

此步使用命令：

```php
vol.py-f OtterCTF.vmem --profile=Win7SP1x64 -o 0xfffff8a000024010 printkey -K "ControlSet001\Control\ComputerName\ComputerName"
```

注意这里是含有目录两层\\ComputerName\\ComputerName，因为增加混淆。

![image-20220908161759552](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dac18ee4cce18843dc6939a95f62801a420e472d.png)

成功得到结果为{WIN-LO6FAF3DTFE}。

0x03 内存正在运行什么游戏？游戏连接到哪个服务器？
===========================

题目说是老式电子游戏，查看进程有没有什么游戏进程，知名的自己判别得出，不知名的陌生的进程可能是游戏，参考搜索引擎。所以根据题目信息，首先这是个游戏，其次是连接到服务器的，所以使用netscan网络扫描先直接查看与游戏相关的进程和通信地址，注意配合社工。

因为有服务器，所以可以查看有网络连接的进程，发现进程有BitTorrent.exe、svchost.exe、LunarMS.exe。

此步使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 netscan
```

发现只需要使用这一条命令即可以查看进程，也可以查看地址，netscan代表对所有网络连接进程扫描。

![image-20220908162208577](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-73bc7c365e67d43c0c886888867d92cb9ef4866f.png)

查看可疑进程，连接外部网络的进程，这里发现一个是种子下载器，另一个叫LunarMS，通过搜索发现这确实是一款老式游戏，成功得到答案。

![image-20220908162747608](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4541ba2dcca14864e6ed10aae36d0705e03fd0f7.png)

通过查询是这样一款游戏：

![image-20220908163457720](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b63ad22e92ece52032562ac5adb257886687ffbd.png)

0x04 机主登陆了游戏频道Lunar-3，找到登录账户名
=============================

题目分析，题目说电脑的主人有一个游戏，在玩耍的频道中使用什么游戏用户名需要我们找到，分析一下要找了游戏频道，我们应该从刚才得到游戏进程看，那我们如何查看进程中可能包含的数据呢？因为如何用户登录到进程中的话，那么内存中应该有登陆用户名，登录信息这里用string 过滤指定的字符串，使用grep过滤了含有关键字Lunar-3频道的字符串。

此处使用命令：

```php
strings OtterCTF.vmem | grep Lunar-3 -A 5 -B 5
```

注意-A参数代表显示匹配前5行，-B参数代表显示匹配到的后5行，这样在周围都能找出来了，然后这位的这几个都有可能性，所以最后尝试出来是{Ott3r8r33z3}，成功获取。

![image-20220908164412642](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-20222fd80ce3b548906391339fbcb08923681434.png)

0x05 通过用户名查找游戏角色名
=================

题目说，`0x64 0x??{6-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2} 登录用户名的后面总有这么一串字符出现`根据得到的信息，意思是用户名总在这个签名之后：0x64 0x??{6-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2}，所以使用的游戏角色叫什么？

将LunarMS.exe进程转出出来，使用命令：

```bash
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 memdump -p 708 -D ./
```

注意参数-p代表pid号，会生成一个708.dmp文件，后面使用插件过滤16进制字符。

![image-20220908164922049](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-61b108fa37327ee572373f374df815d4c0854148.png)

这里重点就是根据信息，组装正确的过滤语句，成功在给出的特定字串周围发现带有特定意思的字符，即ID号，得到结果{M0rtyL0L}。

此处使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 yarascan -Y "/\x64(.{6,8})\x40\x06(.{18})\x5a\x0c\x00\x00/i" -p 708
```

注意，此处使用插件yarascan是如上命令。

如果使用hexdump查找，则命令应该是这样：`hexdump -C 708.dmp | grep "5a 0c 00" -A 3 -B 3`。

![image-20220908165341068](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b09c846b5c126d59146abfd5a64eb799aafd1692.png)

0x06 寻找特定的电子邮件密码
================

题目给出电脑主人总是忘记他的密码，所以他所用在线存储密码服务，他总是复制和粘贴密码，这样他就不会弄错了，请问瑞克的电子邮件密码是什么？

关键是如何组装语句过滤信息，我们有密码关键字，更重要的粘贴板功能点，可以使用取证框架的clipboard查看剪贴板的信息。

此处使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 clipboard
```

![image-20220908165722289](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-71b28f8334c5d589e5f49982cada54e362679827.png)

0x07 找到恶意软件名称
=============

我们提取了瑞克电脑内存镜像的原因是有一个恶意软件感染，请找到恶意软件的进程名称，包括恶意扩展名，为下一步分析加密密钥做准备。

注意这里我们使用plist是看不到恶意软件进程的，因为可能被合法进程隐藏了，使用命令pstree可以查看进程树，可以查看所有进程和依赖关系。

此处使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 pstree
```

pstree代表查看带树结构的进程列表。

![image-20220908170941394](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4024dd42023f9317c4347e24c65f8eca420a77c9.png)

如何查找可疑的进程呢？这里发现最可疑的是PPID大于PID的进程，这里解释一下什么意思呢。PID（Process Identification）操作系统里指进程识别号，也就是进程标识符。操作系统里每打开一个程序都会创建一个进程ID，即PID。PID（进程控制符）英文全称为Process Identifier。PID是各进程的代号，每个进程有唯一的PID编号。它是进程运行时系统分配的，并不代表专门的进程，PPID则代表当前进程的父进程ID。

不过我们都可以尝试，毕竟不是绝对的。

此处使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 dlllist -p 3720
```

dlllist代表查看使用的动态链接库是否合法，-p指定pid号。

有意思的是这个dll被我们发现是在temp目录下面进行的，后面path路径存在Rick用户名，所以我们推测就是这个的结果可能性很大，因为temp这是一个临时目录，如果不是的话，需要根据名字继续类似查找。

![image-20220908171205915](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fc0d309d410798cb650e0b41d110ab178aa0347f.png)

成功得到结果{vmware-tray.exe}。

0x08 恶意软件是通过哪个网站进入电脑的？点击网站？
===========================

题目描述说哪个网站造成的，那么从恶意进程入手是没有用的，因为没有下载之前就存在网站了，所以我们在哪里下载的呢?猜测是种子，不过也可能是chrome。

过滤出Rick相关的文件，其实我们之前发现这人老喜欢用种子下东西了，我们过滤一下与他Rick有关的文件好好查看查看。

使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 filescan | grep Rick
```

![image-20220908172412039](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-67311737c8d521395a478a3fe46068675abcce73.png)

发现唯一一个含字符download下载的种子文件，接下来保存这个文件，看看。

使用命令，上图中获取的信息有0x开头的文件的偏移量，根据偏移量提取`0x000000007dae9350`对应文件

此处使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007dae9350 -D ./
```

![image-20220908172522122](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9a6492c44bb532d985d3921d7554d04fbed55ba7.png)

注意，这里转出之后的文件名是重新命名的，所以在strings 后面使用table键补齐才可以找到0x000000007dae9350.dat文件。

此处使用命令：

```php
strings file.None.0x000000007dae9350.dat
```

![image-20220908172755148](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c45f0436af52aa61de6e36e31077df9cc7d61e05.png)

我们从转储的文件中获得结果website{M3an\_T0rren7\_4\_R!cke}

0x09 恶意软件种子都是从哪里来的？
===================

torrent 文件从哪下载的，我们分析一下种子文件也有可能是游戏传播，不过我们在之间的进程list中发现，很多浏览器exe程序，有可能是从Chrome浏览器中下载的。考虑把所有的chrome进程转储下来，之后搜索关键字torret

此处使用命令：

```php
 -f OtterCTF.vmem --profile=Win7SP1x64 memdump -n chrome（指定所有chrome进程） -D ./chromeps(指定路径文件夹名)
strings ./dumps/* | grep "download\.exe\.torrent"
```

![image-20220908175105510](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1effc347728a176c462960af31cfe617077a8e7b.png)

搜索`download.exe.torrent`，通过-A与-B显示与这个文件相关的前后10行内容，答案关键字是以下划线为标志的字符串。

此处使用命令：

```php
strins ./chrmeps/* | gerp "download.exe.torrent -A 10 -B 10"
```

成功得到结果，当然如果这个没有，那就换其他进程转储下来，搜索下载字符串查找。

![image-20220908175451010](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b3d06a9a55e6659c4e614d36011ff4767dd5e056.png)

0x10 寻找虚拟货币地址
=============

题目描述说攻击者在恶意勒索软件中留下了比特币地址，是多少呢？

使用命令：

```php
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 procdump -p 3720 -D ./
```

进程转储到一个可执行文件，注意这里使用procdump命令代表可执行程序。

![image-20220908180436780](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f922a89e0ef54312e2bca455661b7d98fdf904b0.png)

这里也可以看到我们存储到电脑时报毒了，也可以注意LockFIle函数，这是一个开源强大的勒索软件。

![image-20220908180647131](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4b99a8dc45743fcafb01908bff50c6e264a071f9.png)

exe程序我们选择使用IDA来查看，找到比特币，钱包，支付，这些关键词是属于在比特币支付场景中的术语，所以可以迅速找到，成功找到答案{1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M}(勿支付)。

![image-20220908181531531](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-169cd69a4767a8e41872e893e57e3cb17db330ae.png)

0x11 恶意软件中图片泄露了攻击者信息，赶紧发现他
==========================

打开dnspy进行反汇编和查找资源，下载地址后附github，建议直接使用exe版本，然后打开我们保存的病毒程序，进行反汇编一次，发现了一个函数下的资源地区，存在一张图片，滚动查到发现含有攻击者信息答案。

![image-20220908182639463](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-49375497e5e5f0c9305f5d77f629dcb85196f3cc.png)

这里真是最简单的，但你至少需要对思路和实用工具有了解。

0x012 找到勒索加密使用的密钥
=================

总的来这题是最难的，要根据函数加密方法，然后发现加密是使用计算机全名和计算机用户名的信息然后得到明文，分析下面这个函数，其实并不复杂，但是思路很不好想，此时我们联系题目，多看看题目。发现密钥是由计算机名和用户名得来的，那么查找字符串位置，使用grep过滤。

![image-20220908183133000](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-71c57c826d1b9fc2466c6328cb4bb96109cf1e6d.png)

猜猜怎么输入命令？搜索过滤一下计算机全名关键词，发现了未知字符串，发现是密钥。

此处使用命令：

```php
strings -eb OtterCTF.vmem | grep WIN-LO6FAF3DTFE-Rick
```

注意这里就是计算机名"WIN-LO6FAF3DTFE"加上"-"加上"用户名"，得到password。

![image-20220908183312502](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3d59dc8bc11d56fbb9a18615fa0b913229a2ed21.png)

0x13获取密码后，自己解密勒索文件
==================

题目描述最后的关键文件有一个勒索文件被锁了，里面含有重要信息。

此处使用命令三步走：

```php
找到文件偏移量
根据偏移量保存
打开文件，打不开所以下一步考虑解密得到答案。
```

![image-20220908183354892](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6bf07650626e437bd88a602c2deb83fb4f8ddb67.png)

![image-20220908183542532](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3b6b49ad28cd0b1f16e710410ae314a4f23e1171.png)

![image-20220908183818916](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1cf81fde2399dec13f3bf63e3b03dc3b7731898e.png)

接下来目的就是解密密文了。本次所中恶意软件经分析是一款强大的开源勒索软件（来自github）是比较真实恶意勒索软件，会加锁文件，这里介绍这款软件，也算是针对勒索病毒的了解方面比较有针对性，HiddenTear Bruteforcer可以爆破密码，和实现文件解锁，也是著名的开源加密软件。

![image-20220908184340621](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-977deb203ab3a9dd5c5eaec07fa06858d1ecca28.png)

必须删除多余的数据为0的部分，这部分是无效的。

![image-20220908184417987](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1bd9b9ae15ca43fea0869f39400fc4cc5367cd90.png)

删除结果保存如图。

![image-20220908184447852](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-35bffe87112bb7eefd6ec8537033d3b073bfcc4d.png)

勒索工具解密Decrypt

![image-20220908184529945](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-882fd29b39c987901203314b93b93e2fa4577dfe.png)

先填写密钥，上一题已经获得，目录是被锁文件目录，注意不指定文件，最后直接可以得到结果，解密成功。

![image-20220908184727981](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9f509fa37bdb1e97ce0913a1b283f2839c916a75.png)

解密后直接打开成功，注意如果windows下打不开，就选择010编辑器以二进制形式打开。

![image-20220908184828281](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-58a9fa395353693bcd7dc5da32d3e5629db95fa2.png)

0x14数字取证方法总结
============

数字取证整个流程涉及识别、收集、获取、保存、分析和呈现数字证据的过程。数字证据必须经过验证，以确保其在法庭上的可采性。最终，所使用的取证工件和取证方法(例如，静态或实时采集)取决于设备、其操作系统及其安全特性。更复杂的是使用专有操作系统(调查人员可能不熟悉)和安全特性(例如加密)是数字取证的障碍。总之，数字取证仁道而重远。

0x15 资源资料
=========

1、<https://github.com/goliate/hidden-tear>  
2、<https://github.com/dnSpy/dnSpy/releases>  
3、<https://www.varonis.com/blog/memory-forensics>  
4、<https://docs.redis.com/latest/ri/using-redisinsight/memory-analysis/>  
5、<https://www.sciencedirect.com/topics/computer-science/memory-analysis>  
6、<https://resources.infosecinstitute.com/topic/memory-forensics-and-analysis-using-volatility/>