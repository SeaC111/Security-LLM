一、**基本信息**
==========

REvil，也被称为Sodinokibi或简称Sodin，它在2019年4月被首次发现。这种恶意软件会在感染了用户的电脑后加密文件，并删除任何留下的赎金提示信息。这些消息会告知受害者必须支付一定数额的比特币作为赎金，且如果受害者未能在规定时间内支付，要求的赎金金额会加倍。REvil最初主要攻击亚洲的目标，但随着时间的推移，其活动范围逐渐扩散到了欧洲和美国。有趣的是，俄罗斯似乎并没有受到REvil的攻击，因此被认为攻击来自于俄罗斯，并且美国对几名俄罗斯黑客发起了通缉令。到了2022年1月，俄罗斯政府宣称已解散了这个犯罪组织，但似乎REvil的坚韧生命力并未因此而终结，在不久后又重新活跃起来。值得注意的是，REvil和另一种恶意软件GandCrab有着高达40%的代码相似性，因此REvil常被认为是GandCrab的衍生版本。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-de34a68645d26a701f08affd0eb202e2a6535ca2.png)

REvil的Tor付款页面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-fcd0ade6a336a0eecaf05dfb6f5ca0791a5a1bf9.png)

二、**组织成员**
==========

美国司法部指控俄罗斯公民亚罗斯拉夫·瓦辛斯基（Yaroslav Vasinskyi）和叶甫根尼·波利亚宁（Yevgeniy Polyanin）是REvil勒索软件团伙的成员，并对他们提起了诉讼。据报道，瓦辛斯基参与编写了REvil勒索软件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-547dc930fef9842382547cd11085fb46fac152cb.png)

三、**静态分析**
==========

**脱壳**
------

信息熵是一种衡量数据随机性的指标，其值域从0到8。通常，熵值越高，表明写入的数据可能的无序程度越大，从而被视为更可疑。由于REvil样本熵值接近8，这意味着该程序包含了大量的加密数据，可能执行了加密操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-bf08a0ae5859285bde066a08bac41e29e70b0a0c.png)

在这次修复中，共处理了640个字节，分成160个步骤进行。通过观察熵值与导入表的数据，推断样本采取了措施来隐藏IAT。样本可能会在动态调试的过程中执行IAT的解密操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-491730a0cba711cde506a782c08dd9add5e9ae03.png)

第一个函数整体逻辑在修复IAT表，修改变量名。在动态解析api的函数处下断点，动态调试解密iat：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-a9a91c5d32b968b0138d6ffe9aca47e71c915b86.png)

接着让他自动走完整个iat填表的操作之后将修复后的程序dump下来。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-159e9fd792f4c409a0abfb6be40b4a5eb2526612.png)

Iat表修复成功后，接下来进行静态分析。

**逻辑分析**
--------

Iat修复完成第一步，创建com组件所需接口。COM组件通常是在运行时动态加载的，这使得恶意软件可以避免在静态分析时被发现。通过尝试获取COM接口，可以借此动态加载和执行代码，增加对其行为的难以察觉性。许多系统服务和应用程序通过COM进行通信。恶意软件可能试图利用这个通用的机制，以便执行更多的操作，如横向移动、持久性维持、或者利用系统功能进行进一步的攻击。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-0295e38a54d6eb9b61b9d44487a1c013ebaab162.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-59fa720a553ff4eccfcd197a31932f03f98dc198.png)

Sub\_112545A是病毒第一个执行逻辑函数，执行过程如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-8fe16b9f1835618f24e56ca4a6bc07f36f3b8b53.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-a9e2c3b28a7a85044be30851d6abee1de0cce996.png)

Sub\_112545A是病毒第二个执行逻辑函数，静态分析发现该函数主要是在对字符串数组进行解密，反调试部分位于该函数中。该部分将在动态分析及算法部分进行详细拆解。

**反调试**
-------

REvil 使用rdtsc指令，恶意软件可以使用读取时间戳计数器 （RDTSC） 指令来确定 CPU 执行程序指令的速度。如果差值低于 0xFFFFFFFFh，则找不到调试器，如果它高于或等于，则调试应用程序。实现代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-7393e996a173398d209cac5e5304f92ce7c4f555.png)

四、**动态分析**
==========

**创建互斥体**
---------

创建一个名为"Global\\01EB1FCA-9835-27F4-DB93-6F722EB23FB4"的互斥体，作用：防多开，如果已存在该互斥体则退出进程。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-5a8dd75ff0e65d3a3c8882833e4a01b02fd351b7.png)

**提权**
------

根据动态解密结果可以看出逻辑函数一在判断当前程序是否具有管理员权限，如果不是则提权：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-d3037f0cc79494d33683cf4a5ddb5c69668eb9e7.png)

**解密配置文件**
----------

配置文件解密：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-64f01d9d890ab4e7cecfc9c742102c0245f722f7.png)

配置文件是json格式：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-5f86121f9380414bbb2e1d5ea4ccce363e3acf7a.png)

字段提取如下：

|  |  |  |
|---|---|---|
| 字段 | 值 | 含义 |
| pk | eYcrYel20DnrtDgbF+CMLcyGSeW+Skw8zYCRL91/fWo= | 密钥 |
| pid | $2a$10$im/.HUJruXn5zDUN5iaUJ.wzfvGY6tVJHuIxHOzhQ5nbuKGAkAlLy | windows版本id |
| sub | 3152 | 标签编号 |
| dbg | false | 是否是dbg模式 |
| et | 1 | 加密类型 |
| wipe | false | 擦除文件夹标志 |
| fld | \["msocache","intel","$recycle.bin","google","perflogs","systemvolumeinformation","windows","mozilla","appdata","torbrowser","$windows.~ws","applicationdata","$windows.~bt","boot","windows.old"\] | 不加密的文件夹列表 |
| fls | \["bootsect.bak","autorun.inf","iconcache.db","thumbs.db","ntuser.ini","boot.ini","bootfont.bin","ntuser.dat","ntuser.dat.log","ntldr","desktop.ini"\] | 不加密的文件列表 |
| ext | \["com","ani","scr","drv","hta","rom","bin","msc","ps1","diagpkg","shs","adv","msu","cpl","prf","bat","idx","mpa","cmd","msi","mod","ocx","icns","ics","spl","386","lock","sys","rtp","wpx","diagcab","theme","deskthemepack","msp","cab","ldf","nomedia","icl","lnk","cur","dll","nls","themepack","msstyles","hlp","key","ico","exe","diagcfg"\] | 需要加密的后缀 |
| wfld | \["backup"\] | 文件目录移除 |
| prc | \[\] | 终止的进程列表 |
| dmn | &lt;见IOC附录&gt; | 潜在C&amp;C列表 |
| net | true | 通信 |
| svc | \["vss","veeam","sophos","svc$","backup","memtas","sql","mepocs"\] | 要停止的服务名 |
| nbody |  | base64加密的勒索信 |
| nname | {EXT}-readme.txt | 勒索信名 |
| exp | false | 提权 |
| img |  | 图片形式显示勒索信 |
| arn | false | 持久化 |

**获取敏感信息**
----------

获取用户名、计算机名、网络通讯信息、键盘列表获取、系统版本、uuid、驱动器类型等用户敏感信息：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-ee1465ff6bdd61ab9a9360aeb4e9b442ac936367.png)

勒索信解密后填入{EXT}-readme.txt中，后续还会将获取到的用户名等敏感信息补充到勒索信中：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-ffee8d03f43cddb6bd1972fa5cf26c5a6646cd52.png)

**删除备份文件**
----------

创建线程，在线程回调函数里面调用com接口。随后枚举数据库服务，检索指定服务，检查系统版本，如果版本小于Windows Vista则执行cmd命令，执行指令 "/c vssadmin.exe Delete Shadows /All /Quiet &amp; bcded"删除备份文件，否则获取本地系统信息。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-81a90e280b596fcf1ef4b5d63d630439a7c0b69b.png)

五、**算法分析**
==========

REvil使用了四种算法进行加解密，分别是rc4、Salsa20对称流算法、CRC-32、TEA算法，主要作用是解密样本中的配置文件、key等字符串，验证反调试等。

**rc4**
-------

RC4算法是一种基于非线性数据表变换的序列密码，包括密码调度算法（简称KSA）和伪随机生成算法（简称PRGA）。在RC4中，关键的部分包括初始化阶段和伪随机生成器。此样本中REvil使用rc4算法对配置文件进行解密操作。

REvil使用rc4对配置文件进行解密，该样本中将SBOX和KSA分别放到了两个函数中。

下图所示包含一个指向缓冲区的指针，该缓冲区包含 RC4 密钥、加密字符串和偏移量RC4 钥匙。Rc4的ksa：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-2c611a5a9ca96700c2002fad044522b7fad5371d.png)

下面是rc4算法初始化 SBOX 和密钥调度：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-b142bb9cb07b781ca698426da103562ae7f542fd.png)

下面的代码片段是数据的实际解密：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-280eaf861b68ef56439acd46854d8cc8ed797bd3.png)

**椭圆算法**
--------

REvil使用Salsa20对称流算法，通过椭圆曲线非对称算法对文件内容及其密钥进行加密。REvil 能从许多其他勒索软件程序中脱颖而出，是因为REvil利用椭圆曲线 Diffie-Hellman 密钥交换作为 RSA 的替代方案，以及 Salsa20 代替 AES 来加密文件。这些加密算法在正确实施时非常有效且不可破解。

与椭圆算法源码（算法来源：<https://github.com/openssl/openssl/blob/master/crypto/ec/curve25519.c>） 进行比较，发现具有很高的相似性：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-4577d80d6049af284f6228823acb5cfdb3c5e350.png)

**CRC算法**
---------

样本使用crc算法对数组进行解密操作。具体实现方法如下：

待解密数组：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-6deb032f43d722d6ee33b136d381d6d602843843.png)

在每个循环迭代中，v3减一，v4\_byte与从a2中取出的字节执行异或操作，然后进入一个嵌套循环，该循环执行8次，对v4\_byte进行CRC-32计算。最终对最终结果执行按位取反。算法如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-7d634d2dd0c5bb16d879db459419020589d49bd8.png)

a3是数组长度：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-01905e8987f5939562390c2b89f4b3394af5662f.png)

**TEA算法**
---------

使用TEA算法对rdtsc指令的差值进行计算。TEA\_DELTA 是TEA算法中使用的常量值，其选择是为了增加加密的安全性和混淆性。在TEA算法中，TEA\_DELTA的值是 0x9e3779b9，这个值被广泛接受并在实践中使用。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-004a80750ba3c470959a253b876095a566365aa8.png)

六、**攻击流程**
==========

Sodinokibi勒索软件是通过暴力攻击和服务器漏洞传播的，但通过恶意链接或网络钓鱼感染的情况并不少见。总结如下：

**渗透和感染\*\***：\*\*
------------------

### 1、**钓鱼邮件**

攻击者发送包含恶意附件或者链接的钓鱼邮件给受害者。一旦受害者下载了附件或点击了链接，恶意软件就会被安装到他们的系统中。

### 2、**漏洞利用**

攻击者利用未打补丁的软件中的漏洞来传播勒索软件。Sodinokibi攻击者经常利用像是Oracle WebLogic服务器这样的企业级软件中已知的漏洞进行初始入侵。

### 3、**供应链攻击**

通过侵入软件供应链，攻击者可以使Sodinokibi勒索软件传播给使用受感染软件更新的所有用户。这种方式可以使得勒索软件迅速且广泛地传播。

### 4、**勒索软件即服务（RaaS）**

Sodinokibi可以作为一种服务供有不良动机的潜在客户使用，这些客户不必自行开发勒索软件，而是可以通过分成的方式使用Sodinokibi进行攻击。

### 5、**社交工程：**

攻击者可能通过假装是合法的软件支持团队成员来诱骗受害者安装软件，或者诱导他们通过社交工程手段暴露有价值的认证信息。

### 6、**远程桌面协议（RDP）攻击**

未受保护或弱密码保护的RDP是另一种常见的感染途径。攻击者会扫描并尝试破解弱密码的RDP会话，从而获得系统访问权限。

### 7、**网站注入脚本**

通过注入恶意脚本到不安全的网站上，攻击者可以利用浏览该网站的用户作为勒索软件的潜在目标。

**横向移动**
--------

攻击者可能会在获得初始访问权限后尝试访问网络上的其他系统和账户，以提高其对受害者环境的控制。

**提权**
------

通过诸如利用本地漏洞等手段提升在受感染系统上的权限，通常是为了获取管理员级别的访问权限。

**环境勘察**
--------

1、收集信息：识别网络结构、重要的数据位置和备份系统。

2、禁用安全措施：包括杀毒软件的停用，以及尝试禁用或删除备份，制造更多的压力迫使受害者支付赎金。

**文件加密**
--------

使用强加密算法对系统上选定的文件或整个目录进行加密，使得受害者无法访问它们。

**赎金提示**
--------

在受影响的系统上留下赎金说明（通常是一些文档文件），告知受害者他们的文件已被加密，并提供支付赎金以换取解密密钥的指令。

七、**ATT&amp;CK**
================

MITRE ATT&amp;CK™框架是一个全面的策略和技术矩阵，用于更好地对攻击进行分类和评估组织风险，包含了许多关于攻击者战术、技术和过程的信息。对此样本行为的ATT&amp;CK提取如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-81d83f39d3888d807d60408b9b050ca745680ee8.png)

八、**总结**
========

REvil 分发的勒索软件会破坏目标和受感染机器上的各种进程，如电子邮件客户端、SQL 和其他数据库服务器、Microsoft Office 程序、浏览器和其他可能将重要文件锁定或备份到 RAM 中的工具。此外，它会删除文件的 Windows 卷影副本和其他备份，以防止文件恢复。防范建议如下：

1、及时升级系统和软件版本，revil会根据系统版本判断是否删除备份

2、离线备份： 将备份存储介质（硬盘、磁带等）离线，避免与网络连接，以减小被勒索病毒直接访问的可能性。定期执行备份后，将存储介质物理隔离，使其对在线系统不可见。

3、定期备份检查： 定期验证备份文件的完整性和可用性。如果备份文件被删除或损坏，及时发现并修复问题。自动监控备份文件的完整性，并在发现问题时发送警报通知。

4、分层备份策略： 使用分层次的备份策略，包括完整备份和增量备份。确保有多个备份点，而不是仅依赖于最新的备份。这样即使一个备份被删除，其他备份仍然可用。

5、访问控制： 限制对备份存储的访问权限。只有授权人员才能访问和修改备份文件，这可以通过强化身份验证和访问控制机制来实现。

6、加密备份： 在备份过程中使用强加密算法，以确保即使备份文件被访问，也无法轻松解密。此外，确保加密密钥的安全存储。

7、离线存储备份： 将备份存储在离线存储设备上，例如脱机硬盘或冷藏的磁带。这样可以减小被网络攻击访问的风险。

8、监控异常活动： 设置监控系统，实时监测备份存储区域的活动。如果发现异常的文件访问或删除行为，立即采取措施进行调查和阻止。

9、教育培训： 对组织内的员工进行安全意识培训，提高他们对勒索病毒和其他安全威胁的警觉性，减少被社交工程攻击的风险。

支付赎金后的危害：

1、很大概率会在一个月内会被再次攻击

2、有一半的概率解密后数据仍被损坏

防范勒索病毒删除备份文件的关键在于实施多层次的备份策略和加强对备份环境的安全控制。

九、**附录-IOC（部分）**
================

boulderwelt-muenchen-west.de  
outcomeisincome.com  
zewatchers.com  
kafu.ch  
bauertree.com  
lenreactiv-shop.ru  
vannesteconstruct.be  
tux-espacios.com  
gporf.fr  
heurigen-bauer.at  
aakritpatel.com  
michaelsmeriglioracing.com  
braffinjurylawfirm.com  
tstaffing.nl  
musictreehouse.net  
campusoutreach.org  
klusbeter.nl