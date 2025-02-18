0x00 前言
=======

教程接上一篇，我们学习使用了一般的命令行工具Volatility Frame进行了分析内存镜像和数据提取，现在我们将引入GUI软件，包含了综合性的工具以及系统化的界面信息展示，在一期我们使用这些更全面，更强大的软件来分析更加有难度的题目，包括使用火眼仿真软件，雷电APK智能分析软件，APK反编译，MySQL语句综合查询的内容。本期使用镜像为实际场景镜像。

摘要：故事背景（纯属虚构）是网络监控发现嫌疑人正在售卖自己非法授权攻击网站获取的学生和员工隐私信息（一个数据库），其中包含了性别，薪资情况，身份证，地址，手机号码，相似亲人手机号码等等，发现本次数据库交易金额为1万余元，嫌疑人还追求热潮为此开发了诈骗类恋爱APP，如果只获得电脑文件情况下，通过侦察发现所拷贝的内存镜像文件获取资料，支持司法机关的证据认定和提供法律事实。

我们已有的文件：仅有一个E01后缀格式文件。如下图，然后我们进行下面的分析

![image-20220911183056458](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-70dc57851da71867f9e3903c9925aa37ff22cb77.png)

0x01 相关术语规范和鉴定原则
================

1.相关术语解释
--------

电子数据 Electronic Data ：基于计算机应用和通信等电子化技术手段形成的信息数据，包括以电子形式存储、处理、传输、表达的静态数据和动态数据。

存储介质 Storage Medium ：承载电子数据的各类载体或设备。 包括常见存储介质包括硬盘、光盘、闪存等。

检材 Material for Examination ：电子数据鉴定中的检验对象。

2.电子数据鉴定基本原则
------------

这样基本原则，看过这些可以帮助猜出为什么要这样做，方便后续的做题和取证。

- 原始性原则 电子数据鉴定应以保证检材/样本的原始性为首要原则，禁止任何不当操作对检材/样本原始状态的 更改。
- 可靠性原则 电子数据鉴定所使用的技术方法、检验环境、软硬件设备应经过检测和验证，确保鉴定过程、鉴定 结果的准确可靠。
- 可重现原则 电子数据鉴定应通过及时记录、数据备份等方式，保证鉴定结果的可重现性。
- 及时性原则 对委托鉴定的动态、时效性电子数据，应及时进行数据固定与保存，防止数据改变和丢失。
- 可追溯原则 电子数据鉴定过程应受到监督和控制，通过责任划分、记录标识和过程监督等方式，满足追溯性要 求。

0x02 使用工具介绍
===========

1.火眼证据分析软件
----------

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e4776dacd8590a67105735ec0206a44e109baaa6.png)

火眼证据分析可使用的功能非常的丰富：

- 操作系统版本、处理器信息、内存配置、硬盘信息、启动项、回收站等信息的自动解析;
- 支持常见文件系统的自动识别和解析，支持多种虚拟磁盘快照和多种云服务镜像的识别和解析；
- 支持文件删除恢复、特征恢复，支持恢复高级格式化磁盘内的文件;支持MacOS系统的基本信息、上网记录以及邮件等记录的分析;
- 支持Linux系统基本信息解析，获取Linux系统版本和用户等信息;
- 支持Windows微信通过扫码、密码多种方式，支持Windows钉钉、企业微信等即时通讯软件分析;

可以发现这个GUI软件真的非常好用，还可以直接提取微信消息记录，分析和谁的聊天记录最多。

![image-20220911011909251](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7602bed412ce5bfd9d15edf03f5bba95333d51e7.png)

2.雷电APP智能分析软件
-------------

雷电APP智能分析是一款针对Android APP应用进行深度分析的取证软件。用户通过简单操作，可以快速分析APK文件的基本信息、详细信息，后续可以分析该APK申请的所有权限，通过动态监控可以对APK获取用户信息、操作手机、网络信息等内容进行全程监控，支持对APK进行网络数据包抓包分析，提供了加固检测、一键脱壳、一键反编译等常用取证操作。

这里的反编译功能非常好用并且很常用，可以获得APP上网期间连接记录。

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a001a59bbaa226b6a22ea6b75ef9e319f77185cb.png)

3.火眼仿真取证软件
----------

火眼仿真区取证软件的功能是识别多系统通过虚拟机技术无痕启动Windows、Linux、 MacOS等多种操作系统硬盘和镜像文件，支持多种镜像格式包括qcow/qcow2/qcow3、VHD、VHDX等云服务器镜像格式的直接仿真，自动识别目标盘的操作系统类型，自动提取并显示系统信息，分区信息以及用户信息。

特别是内置的VMware虚拟机应用软件，支持Windows、LinuX、MacOS操作系统多种操作系统。

![image-20220911090357481](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-670fa2b8781e7a9eb5ef7b2e4e067e9bffb143de.png)

4.VeraCrypt
-----------

VeraCrypt的优点是功能强大且简单易用，既支持文件容器的加密、卷隐藏，也支持分区/设备加密，Windows下还支持系统盘启动加密。

![image-20220911090422514](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-65d3f3234f183b36f0b5a414d5d5afc34f3b32b8.png)

0x03 针对场景下的嫌疑人个体的取证分析
=====================

1.看看磁盘里的数据有没有有人修改过，该镜像对应磁盘的sha256值为多少？
--------------------------------------

关于sha256：对于任意长度的消息，SHA256都会产生一个256位的哈希值作为消息摘要。

我们需要找到这个系统中磁盘部分的sha256值，那么就要知道sha256去哪里找？

思路是要注意这里我们要寻找的sha256值（消息摘要的一种类型）是磁盘的，而不是整个镜像文件，找到磁盘的sha256值就行。先打开火眼证据分析，添加E01文件到检材目录中，代表要分析的这个系统，然后选择添加。

![image-20220911012316010](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5a2df3afac9f5f84d257cb42446559a51cfd6499.png)

添加后之后，我们选择快速分析，一般从快速分析我们可以得到的功能有检材文件大小，检材操作系统，检材使用分区情况，得到sha256值为：

 {4077F689A4D840DC462E1DC616FDDA73126EE48F97B8879C466ECDB36ABF9CBA}

![image-20220911084038657](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1047fc74f5b9204abff9df229658dac6ccda8487.png)

还可以通过扇形图提供我们从进一步发现关键信息的思路。显示查看主要都包含什么文件，发现这里最多的是图片。

2.嫌疑人什么时候安装的Windows系统，系统的具体安装日期为多少？
-----------------------------------

找到分析的基本信息，然后点击操作系统信息，这里重点关注操作系统版本号（查询版本漏洞），然后注册人发现是Bear。

![image-20220911085218251](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b90f62ba894dcbd6c2c9e07c73d975fe60b35737.png)

这里发现安装时间为{2022-04-13 15:27:32}。

3.嫌疑人Foxmail登录的邮箱账号是什么？
-----------------------

查看安装的软件，首先看到了Foxmail，注意如果这里没有客户端，打开思路，那就是在浏览器端登陆的，那么就可以查看历史记录。

![image-20220911090533835](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f55ca67e44d837de2186d4a740d09e44fa3d4b77.png)

根据题目，我们找到分析软件中应用，选择Foxmail，然后右边会显示账户名，在这里包括所有邮箱资源，包括收件箱，已删除邮件，每一封具体邮件信息。

![image-20220911091652462](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-954f4484a7f1807be1e382491daf2cd6bec76ab2.png)

这里收件箱和上图的已删除邮件都发现了一个Backup For EFS Certificate PWD，从名字的提示下手，是EFS备份文件的证书的密钥，但是在上图邮件中没有附件，所以选择有附件邮件，从视图中可以看到包含了附件。

![image-20220911093536372](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dd8900933ba0b47effe4a14967ebbcbe11dfeb62.png)

我们选择右键导出附件，得到结果。

![image-20220911093640422](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c016ad83b565ef1ecd600d33c02da41ae4a0ffd5.png)

得到附件：

![image-20220911093719827](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3a4f6ddd4c8741adb9a3dcb62c4ffdd6809ced10.png)

这是意外收获，但是肯定代表我们要用，所以思路就是先把能得到信息最快的保存下来，就可为之后的题目打开思路，做出铺垫。

4.嫌疑人通过PowerShell输入的所有命令是什么？
----------------------------

我们需要查找历史命令，这题提供两种方法。与Linux保存命令在文件.bash-history.txt类似，我们的powershell历史文件中也保存着所有的历史命令，注意文件位置在：

 %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Powershell\\PSReadLine\\ConsoleHost\_history.txt

根据这种我们使用txt文件查找可以得到。

![image-20220911095744541](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-99424c43554658926552a6778b8d821b934468d3.png)

第二种根据微软的Powershell文档中给出了直接查看历史命令，所以可以使用命令,第一个代表普通查看，第二条查看每一天是否执行成功。

 Get-History  
 Get-History | Format-List -Property \*

根据这种我们适用于可执行powershell命令。

![image-20220911094350891](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a64c83fdd2d7ea2e771434fe057832e0ab315bcc.png)

要查找文件，我们点击搜索，找到该路径下文件，然后找到文件位置，这里我们使用查看文件功能ConsoleHost\_hostory.txt，方便保存txt文件。

![image-20220910195551564](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5b9271b1cfebe7b48032c4975bef40e3f4c7a5c9.png)

搜索文件，成功得到获取结果，如下。

总共获得历史命令六条及解释。

 powercfg -h off  
 \\\\禁用电脑休眠  
 del Z:\\company\_info  
 \\\\删除Z盘下的company\_info文件，此命令执行与erase z:\\company\_info操作相同注意这里删除了一个公司文件，后面发现是交易的数据库sql文件。  
 ipconfig  
 \\\\查看网络配置信息  
 ping www.baidu.com  
 \\\\测试ping程序  
 dir  
 \\\\查看目录信息  
 ping 114.114.114.114  
 \\\\114.114.114.114是移动、电信和联通通用的DNS，干净无广告，解析成功率相对来说更高

![image-20220910195701222](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d47ff694fdecb9a77c4048267d1a0615a8735629.png)

验证路径位置，在全路径位置查看路径位置也是正确的，

![image-20220910195748027](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1b0b66fc89a9525284bb6f864708f5bfbf75fedb.png)

5.嫌疑人将自己保密文件加密了，所以镜像中存在一个名为PWDforVC的efs加密文件，其内容是什么？
---------------------------------------------------

什么是EFS加密？我先来介绍EFS加密程序吧，EFS 是仅适用于 Windows 10 的专业版、企业版和教育版，使用EFS的优点是快速简便的方法来保护 PC 上在多个用户之间共享的单个文件和文件夹，使用 EFS 加密不需要很长时间，而且很好用。注意我们之前查看了系统版本是Win10 Professional专业版。

一般加密流程就是右键属性，高级，加密内容，获取密钥。

- 打开“文件资源管理器”窗口，找到并右键点击需要进行EFS加密操作的文件，在弹出的菜单中选择“属性”
- 然后，在弹出的“属性”窗口中，选择“常规”选项卡，在下面找到并点击“高级”按钮
- 接着，在弹出的“高级属性”窗口中，找到并勾选“加密内容以便保护数据”，最后点击“确定”退出即可

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e0d3bc58575097e47c270c361db51b4b3a478b52.png)

先通过系统查找应用里都有哪些信息，系统的信息收集，所以这一题思路比较难，需要找到加密文件，还需要通过导入私人证书打开加密内容，而证书也需要密码，证书的密码需要去掉压缩包伪加密内容得到证书密钥，再下载证书导入，再打开EFS文件的加密内容。

首先我们看看浏览器里面有两个比较重要的书签记录，查看书签发现字符cowtransfer是奶牛快传的意思，我们右键复制文本，从连接中发现了一个文件。（文末给出链接）

![image-20220911091239152](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0d478aebeca46b7adb02f62dfa7111a7e0633802.png)

结果发现是奶牛快传文件，我们可以直接下载，E并且从名字来看是EFS备份。

![image-20220911091122193](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-75c5b85aa783b99dd1bd096929d075da038c173e.png)

下载出来是一个证书文件，这个证书文件就是解开加密文件的密钥。

![image-20220911091443124](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0d626cb11fe93571d2a8972adf4f83bfe4a19585.png)

但是我们发现安装证书文件也要密码，证书密码后面。

![image-20220911113443810](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-907559354cd283a05fcf1ce611be3895ad39c346.png)

我们从Foxmail邮件收件箱里发现了隐藏的文件，识别英文字母为证书口令，所以我们从压缩包文件要解密压缩包，不用爆破，下一步解开密码。

![image-20220911105854439](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e1232c9ee5c22acbaf2c70fac413261f2c4144bc.png)

选择修复压缩，可以校验压缩头信息，选择修复压缩文件：

![image-20220911110019175](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6a31a4e958459fec3dd5204403ec66445e52a8f6.png)

修复后成功得到压缩包，然后得到证书的密码，可以导入证书了，密码135790

![image-20220911110227967](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e946be6ed51fdc4d9d3dcfa881c15e7b00ff5acc.png)![image-20220911110300763](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-419a50828cfa252e86d259de9a05ad875d2b367e.png)

安装成功。使用火眼仿真软件把这个文件挂载到VMware上，进入系统我们就可以导入成功。注意后面我们将再一次在仿真到VMware的虚拟机中导入这个证书，所以记住证书密钥。

![image-20220911123359430](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8e74db8a5e4b46ef68f3a036f03a33b0230ba9b0.png)

之后因为这个文件无法找到，这种情况下，我们最好选择进入虚拟机操作，选择火眼仿真软件，添加我们的检材文件后，就会自动仿真一个一摸一样的虚拟机，挂载到软件上，然后选择我们继续使用。

![image-20220910203419230](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5b8949d35829bffbd0abad911bc40c4fcf33e2d1.png)

默认密码123456，登录成功进入系统后显示。

![image-20220910203450053](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7392b7c5070c5192626d075b6064b68738bd3911.png)

首先发现这是Win10 专业版，并且桌面没有显示任何系统图标，所以为了方便，打开设置中的桌面图标设置，选中关键的几个就可以了。直接看看有什么文件

![image-20220910203654271](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cff5496dd693df4b50ccb8e04e78d1ddae0a07ba.png)

打开虚拟机资源管理器E盘，还是没有文件，遇到这样找不到文件的思路是找回收站，和开启显示隐藏的项目。

![image-20220911132654775](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1aec09a88a0068cf43d00f244ee229d1fb93f26f.png)

发现文件被显示出来了，一个docx文件，名字一般就是提示，所以提示我们这是VC的密码，暗示我们要解密这个文件，并且这个是一个叫VC的解密密钥。

![image-20220911132744191](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-594e083c5fa18f3722f14531fdfb97fe5cc6ff75.png)

由于docx文件在efs加密前没有证书之前是无法解密的，所以注意这里重新导入一遍证书，然后右键属性选择取消加密，也就是说现在可以取消了，取消之后才可以看docx内容，不主动取消勾选那么导入证书之后仍然没有作用。

![image-20220911133224096](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fb7464cdc270659cf69b2378e1c2c8606508c323.png)

使用写字板程序打开docx文档，成功获取内容结果：{VCpwdis:156430t}。

![image-20220911133525833](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-91093ee411827f0b5502079fa40b62b8a7025f84.png)

6．发现嫌疑人使用MySQL数据库导入隐私安全信息，先看他的版本号是什么？
-------------------------------------

找到解析到的Mysql应用，点击解析，然后选择mysql表，发现存在数据库版本，版本号为8.0.28。

![image-20220910200323659](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-72b9c3a098cb110173fed68ff77483f493f70d23.png)

7.找到数据库MySQL的debian-sys-maint用户的密码是什么？
--------------------------------------

Debian的Readme这样描述解释这个debian-sys-maint用户，这个用户是Mysql中最特殊的一个用户，存储文件地址：/etc/mysql/debian.cnf，甚至包含root用户和密码。

![image-20220911124511273](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-81479e326a17784ecc8870e6ba3126f3cd709bc2.png)

我们可以使用火眼仿真软件（创建一个等效虚拟机）进入mysql数据库，这里我们还是使用简单快捷的查找文件和对应位置方式，在搜索文件栏搜索文件名关键词debian.cnf，就可以得到密码。

![image-20220910202217926](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-faefc95dbaff2fb581ee094edd9c76e823464fdf.png)

打开查看视图信息，并且显示是明文，没有加密，成功得到密码password。

 host = localhost  
 user = debian-sys-maint  
 password = 4x00183SOYkUNisN

![image-20220910202118732](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7c33fb23b51ad40e11c1b4404b401b54bfcc45b5.png)

8.嫌疑人有一台IOS设备iPad，请找到他的iPad密码是多少？
---------------------------------

点击分析，查看有没有相关的文件，记事本没发现，存储文本的发现便签，并且打开后只有一条数据，成功得到ipad密码{ipad}。

![image-20220911084428378](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a01efaab73639369852822b8a6ec1a5ce419d30e.png)

9.请分析IOS设备，获取序列号以方便查询和备案，序列号是多少？
--------------------------------

找到分析中的基本信息，在这里可以查看连接设备的基本信息，选择查看设备信息

![image-20220910202426151](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d73d1452207ad4ab712410db9e157c2c2ae41045.png)

打开后可以发现不止序列号，名称为Guan，版本号为15.4.1，序列号成功得到结果：

 JR43G07954

![image-20220910202529417](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2b7e950f3358d7c28c73465e43592d6c3ee9eff8.png)

10.嫌疑人使用某沟通软件，请找到交易中的买家微信ID（这个人）是什么？
------------------------------------

点击微信，发现个人昵称和个人微信号，关注好友消息最多的，然后查看微信记录信息，发现最多的消息记录，并且只有一个人交流，可能是单独交易账号。

![image-20220910202838439](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c4673542acbf22d3298bb170a5ea7897d8aecd18.png)

直接进入好游戏消息，可以看到聊天信息记录，其中双方微信ID都得到显示：

![image-20220910202953682](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-83d23850b57f3fc9f058896b90d6d6da9b2e6e04.png)

成功获取结果为{flame\_guan}。

11.嫌疑人与买方产生交易了，转账金额和交易时间是多少？
----------------------------

点击进入聊天消息查看，直接可以选择查看图片信息，在聊天记录中显示。

![image-20220910203117248](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-672b82b096b3199f4e148095cb1a46a5091b81f2.png)

点开转账截图，成功得到交易额为{16800.00}元，交易时间为{2022-04-07 16:43:46}。

![image-20220910203218796](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2448920b24a1a66d6aaaf9fa0e630aa74b9f47b0.png)

12.找回删除的数据库，统计出泄露的数据库表中共存在有多少种不同的职位？
------------------------------------

因为取证软件只能分析出信息，对于需要进入Mysql数据库还是需要我们挂载到虚拟机VMWare上去，然后使用火眼仿真软件进入虚拟机的所有密码都是123456。

### A.数据库发现

进入数据库后我们发现存放了一个XML描述文件，标准的xml文件是描述虚拟机信息文件，一般文件内容如下，但是这个XML有1G，所以我们修改为vhd后缀，vhd是Virtual Hard Disk虚拟机硬盘映像文件，然后使用VeraCrypt解密，密码我们从上面的题目中得到了，文件名VC即解密软件VeraCrypt，pwd即密码，is是{}

![image-20220911144239796](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-977bc5ed4bd885a4a95f610ebfadb14c8afe2f9b.png)

修改前后对比图：

![image-20220911144706045](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5aa09a2863f93b048d200a21183f45b8ae53f178.png)

![image-20220911144613039](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-014e220527fdd6b067a721c37df56f6e5965344a.png)

修改成vhd硬盘映像文件后，使用VeraCrypt打开：

![image-20220911143530069](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bc1e0c51df42a1880bca85683bc63a399bb0ab85.png)

把加密的vhd文件加入，点击选择目录，任选一个盘符，解密后会得到磁盘。

![image-20220911144931852](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ef4fae4ed26d9fd3cf6cbaa2679c6bf82084f444.png)

注意这里我们用分析软件分析，而不是，这里就需要我们输入密码了。输入VC的密码

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8f2ebd86d927c0422704057a8a5f7f4a43e82370.png)

挂载成功后显示结果，建议选择比较靠后的盘，不要与自己的盘冲突。

![image-20220911145955415](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bc1357bddc1fedb4f90f4f85441472bc7f456e05.png)

![image-20220911150108010](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3121a277bca673365684162513a61b6e250a8bb0.png)

可是奇怪的问题是外面显示有文件我们打开却没有任何文件，这时选择去火眼分析软件，方法把这个磁盘添加进入K盘，分析后结果为：全部隐藏和删除的文件。

![image-20220911150357426](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6a59b669cdbf784746b4cd674c0ec70e5160de03.png)

发现了数据库文件，找到了被删除无法显示的文件company\_info.sql，并且是一个sql文件。选择右键导出文件到我们自己的电脑里之后会看到这样一个文件。

![image-20220911150505500](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e833b7e0b346cc8309034c5397d73f5da860e5b5.png)

### B.数据库表信息提取：

得到交易的数据库文件后，进入数据库Mysql，搭建的时候启动一个phpstudy会自动启动一个Mysql，然后新建一个数据库名，把sql语句添加进去，选择导入sql文件就可以完整的从视图层面看到这个数据库。

注意这里需要新建一个数据库，所以要新建一个管理员账户和密码，因为在Mysql本身的自带的数据库中有自己的用处。

![image-20220911150650965](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-67057084619f9644632c107aba30f1c67efe983c.png)

我们查看写入的数据库，总共6个表，第一个表示雇佣员工和所在部门对应表。

![image-20220911150941111](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1cc4616f6c3ab38d719d06741396cccf6cbed7c5.png)

最后一个表是员工和职位对应表，我们直接在这里写入sql语句，查询不同的title个数，因为一种title对应一种职位。

获取这个表中，列为title的不同值得总数和为多少，就是职位统计数量，此处sql语句如下：

 select title,count(\*) as numers from titles group by title;

![image-20220911151200415](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-46af5ba188fb4343ce17a47ef743c3f597f47061.png)

刚才设计表的视图展现，下面看看具体表的信息。

![image-20220911151346130](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6cacf4e018352883a835727720cfc56c6bae767e.png)

执行sql语句后最终成功得到结果{numbers=8}行。

注意，连接到Mysql数据库后，可以使用Navicat功能实现右键导出到Excel，CSV表格格式功能，也可以实现手动统计，在这里提供另一种思路，导出成功会有如图所示，也能实现同样的功能。

![image-20220911152252968](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f30d9a74fa683088486a8911c76ee6c6e8e39533.png)

13.数据库中入职时间最早的员工的名（first name)是什么？
----------------------------------

hire\_date指雇佣时间。

![image-20220911153031616](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5cdd53d29bbeb73eae63b99bb4f2347f84853577.png)

14.查看数据库中员工编号为253406的员工总工资为多少元？
-------------------------------

分析一下题目，给出信息员工编号，问总共工资数目。找到薪水salary（薪水）数据表，发现可以直接通过员工编号筛选，从逻辑上来说也是这样，名字和编号只放在一张表中，其他的表都用编号ID来替代表示。

我们选择salaries\_lis数据表，因为我们发现工资表就是以员工编号发放工资，所以找到这个编号的人，所以emp\_no处输入{253406}，注意，选中该列点击筛选，输入筛选值。

![image-20220910214954672](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-828002f4eb9d19ef1e4593bd50301d83a97fd556.png)

结果得到分别在1999年，2000年，20001年，2002年获得工资，所以得到4年总工资为：{157331}元。

![image-20220910215207655](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fc5795d1553bcc173ea279942fe16f6a55d01297.png)

15.交易的数据库中员工姓(last name) 名 (first name) 缩写为W. W的员工数量为多少？
--------------------------------------------------------

首先找到表姓名和编号对应的表，是member\_info，发现要求我们对first\_name 和last\_name查询。缩写为W，其实应该是包含W字符的更加合适。

这里需要我们使用查询语句，条件是两列包含有W的字符，此处使用sql语句：

 select count(\*) from member\_info where first\_name like "W%" and where last\_name like "W%";

- count代表总和，包含结果是多少
- from代表从哪一张表，进行指定
- where代表的是对first\_name 和last\_name 字段筛选
- like的代表的是指定包含W的字符
- %代表不指定全字匹配，只要包含W就行

![image-20220910215409318](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1804703f74bab35e8a6554b802cc649e85ac867c.png)

执行OK的结果

![image-20220910220307352](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0445ce3f465de53230a1778ef30b9d005cf16667.png)

成功得到结果员工姓(last name) 名 (first name) 缩写为W. W的员工数量为{95}人。

![image-20220910220351600](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c3e599e762f4039b768bb522e90c7fdd06e16fb3.png)

16.交易的数据库中姓名为"Kazuhiro Kushnir " 所在部门的名称为
-----------------------------------------

我们要先找到员工编号，包含姓名的表。

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5d08c4df1626bddcc7cc0afda789a5d2c7a9f59f.png)

使用筛选的方法，填入first\_name对应Kazuhiro，last\_name对应Kushnir。

![image-20220910220745935](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-063b1bd9ece26237605dfdd113732f34da621eb2.png)

得到员工编号为10945，通过这个去寻这个员工分配表对应的部门编号，再通过部门编号找到编号对应的哪个部门。

![image-20220910220906397](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-55a42048d781073825c04df545ed75e82c22a2ff.png)

找到雇佣表

![image-20220910221313130](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-015536b130bfe27227989e802deccec13a763044.png)

选择筛选，然后输入10945，得到结果部门编号。

![image-20220910221419284](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-62be2814bfde5e8651a004794bc71f50b88558fb.png)

得到的结果d004代表部门编号。

![image-20220910221509897](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f208915c3b795441d541a57d0a3a41d8de4d42fc.png)

下一步根据的得到的部门编号打开其他表，找到对应的每一个部门名称。

![image-20220910205944690](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a85c18b656f52c4d0d9600a077088ba8bc1f0760.png)

成功得到结果为{Production}部门。

![image-20220910221609183](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fed81ec5918f6c211b27e77e343ad13b550e106f.png)

14.Production部门中在1999年1月1日当天和之后入职的人员数量是
---------------------------------------

刚才我们获得了D004是部门production的编号，在表员工编号对应着每个人的所属部门，并且包含有每名员工的入职时间，选择条件为所属部门编号为d004，且时间在1999年1月1日后入职总数。

select语句查询日期怎么查？

![image-20220910223632734](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-327a827472225af2c7232468da20892814c8d040.png)

15.发现非法APK，然后请获取该app安装包的SHA256校验值为多少？
-------------------------------------

回收站找到APK

![image-20220911132350775](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2b63348e58fbb0333ba4a4e72600c9bb2fc32096.png)

分析APK，使用雷电分析apk，可以直接查看系统信息。

![image-20220910210655099](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-195e67b94792beb329d41981d3934cd0dc7d0e8e.png)

SHA256: e15095d49efdccb0ca9b2ee125e4d8136cac5f74c1711f44c6347598ffb1bd7b

1. 19.请获取app运行后的进程名

打开adb连接安卓模拟器，使用命令：

 adb shell

然后连接成功后使用命令 ps 查看进程

![image-20220910223851413](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1bea9227df97ed30ec430b73a39c65683d618db9.png)

16.非法APK中安装包签名证书的签名序列号是什么？
--------------------------

详细信息包括签名证书，签名公钥，序列号，有效期这些，得到结果

![image-20220910224139094](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a372dc9ee4de91ec5b323fde215faae3623973e1.png)

17.请分析得出完整的非法APK安装后显示的APP名称？
----------------------------

现实的名称已经在之前的基本信息中显示了从图标和应用名称中都看出是{爱聊}。

![image-20220910210655099](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-195e67b94792beb329d41981d3934cd0dc7d0e8e.png)

18.请分析该非法APK是否具备读取短信的权限，得出结论？
-----------------------------

反编译，查看你包含获取权限函数内容，这里注意查找关键字SMS，选择源码分析中的反编译，进行反编译过程。关于SMS的权限关键词都有发送接收拉取，可以查找这些关键词。

 SEND\_SMS  
 ​  
 RECEIVE\_SMS  
 ​  
 READ\_SMS  
 ​  
 RECEIVE\_WAP\_PUSH  
 ​  
 RECEIVE\_MMS

选择源码分析，点击jadx反编译。

![image-20220910224657324](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b2bc34f8597017e5e5d965979de1a95edb320ad6.png)

在安卓开发者社区表示，权限申请需要在这个文件中添加这个元素，这可以帮我们快速精准的获取是否获取了

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4793a4b68f00e8024ab840e6322efb87a9042dfe.png)

反编译结果，这个AndroidMainfest.xml在res资源文件夹下，点击打开可以看到全部的权限申请清单，带元素&lt;uses-permission&gt;的，可以看到获取的权限有哪些，有4G、WIFI网络信息获取，读取存储权限获取等等。继续分析

![image-20220911172144808](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e6e01b08699789c96a5adf7966f1ef5d8ff49f46.png)

然后我们快速直接搜索SMS有没有包含在&lt;uses-permission&gt;中，发现并没有，所以最后成功得到答案没有获取短信权限。

![image-20220910225231723](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-69fbeda76b1136f8ec3570bdbe2e4dc37c637937.png)

注意，图中显示关于SMS的`sendSMS`方法并不代表有权限，是这个爱聊聊天软件，能确定的原因是没有显示包含xml文件下的&lt;uses-permission&gt;元素中。

19.请分析该非法APK调用的TencentMapSDK对应的KEY值为多少？
---------------------------------------

这属于SDK调用，属于第三方服务，所以可以直接在第三方服务中查看，可以看见真个过程全用雷电只能app分析，可见十分强大。

![image-20220910224907141](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ca549d89ca3f3e6eb109cca861584e81ef379a50.png)

得到结果为：ANQBZ-ELQW5-2EFIN-QLKQ2-RZU4O-KVB7I

![image-20220910225058690](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0a8df5bdde518eb04aa3d632121d7db5f73eeb50.png)

20.获取服务器地址，请获取该APP连接的URL是什么？
----------------------------

抓包获取了几个连接IP

![image-20220910225429479](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-83008a3703d23687da567461302e4da5cd23c4af.png)

打开访问连接

![image-20220910225652683](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6303cd2fd19b5b8cf17b5b5c903835a72ac68d80.png)

监控内容有发现。

![image-20220910225832985](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f519f9d8ae8cd907b92189480d3a4c22fa4107d4.png)

21.请分析该非法APP配置文件"app\_config.xml"，其加密内容时使用了什么加密算法和解密加密的结果是什么？
-------------------------------------------------------------

注意这里的加密算法刚好和前面也有一个加密算法，那个是apk软件签名证书的加密算法，这里则是指app内部实现配置文件的加密算法，所以需要进入函数内部，首先查看对配置文件做了什么处理，然后查看处理函数里面基本就会包含处理算法。

找到xml文件，查看加密内容

![image-20220910230812687](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7d9a0c2dbed27107cde4a859609ed894aba41505.png)

打开了一个xml文件，app\_config就是一个所有的相关配置信息，所以选择了加密，我们看看他在使用配置信息时对文件做了什么？

![image-20220910231116260](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ffb22e9bed53215da0fac0f3f7fed661e6a206e2.png)

发现一个解密关键词，说明这是一个解密过程，同时使open方法下的一个语句，然后我们进入如何处理这个字符串，故点击进入h的a方法。

![image-20220910231307060](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e8af1a9126cedda39672447df82ae7cafb8303c5.png)

发现这个方法静态公有访问性质加密，

发现了这就是包含加密包的实现，查看加密算法为AES，密钥空间为xx，IV向量为handsomehandsome，所有的东西找到了，注意第二个try还有一个base64编码过程，所以解密的时候逆向先base64解码，然后采用AES解密就行。

![image-20220910231738934](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f17e6509dcd4ceb741885838c8a386ae42dd3dd5.png)

使用网站CyberChef，分别按照函数中使用的方法，填入三个值进行解密Decrypt密文，最后得到了正确的Output输出。

![image-20220910235419879](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-347dda6edc98a26aab8f2f13e9c2de6538c6f771.png)

两步走，第一步Base64解码（编码算法），第二步AES高级加密标准解密，注意模式选择CBC，Output即为最终输出，最后成功解密，填写如图。

这个思路也可以提供去发现其他APP的加密内容。

![image-20220910234916235](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ec41785eb180b16783c4609219c4608f5f27fb47.png)

最终输出结果，这就是相关配置信息，成功解密，配置结果如下。

![image-20220910235251998](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bc51ca33a77787ecfc92e5e7291358e202674dc8.png)

![image-20220910235141475](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3ff78469e228aca0589d8f20361d59d318ad3436.png)

0x04 Forensics 取证总结
===================

文中涉及的相关链接我都会放在参考链接，提供一个参考，我觉得命令行形式以Volatility、DEFT数字取证工具箱和高级框架更加枯燥，使用GUI软件能帮助整体视觉感官的提升和系统的查看信息，用起来是感觉蛮高效的。

0x05 参考链接：
==========

> 1.<https://forensix.cn/>
> 
> 2.<https://serverfault.com/a/750363>
> 
> 3.<https://cowtransfer.com/s/9f0e527d92784d>
> 
> 4.<https://developer.android.com/training/permissions/requesting>
> 
> 5.<https://zh.freax.be/how-use-efs-encryption-encrypt-individual-files>
> 
> 6.<http://www.gjbmj.gov.cn/n1/2017/0316/c411145-29149427.html>
> 
> 7.<https://support.huawei.com/enterprise/zh/knowledge/EKB1001057813>
> 
> 8.<https://www.moj.gov.cn/pub/sfbgw/zwfw/zwfwbgxz/202101/1565869585542018751.pdf>
> 
> 9.<https://docs.microsoft.com/zh-cn/troubleshoot/windows-client/deployment/disable-and-re-enable-hibernation>
> 
> 10.[https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt\_1.25.9/VeraCrypt\_1.25.9\_Windows\_Symbols.zip](https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_1.25.9/VeraCrypt_1.25.9_Windows_Symbols.zip)