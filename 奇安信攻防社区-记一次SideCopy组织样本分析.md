前言
--

SideCopy 是一个从 2019 年初开始至今的APT组织，由于在基础设施上与Transparent Tribe APT有重叠，并且一直模仿Sidewinder APT 组的 TTP，直到2020年才由安全公司Quick Heal披露并独立出来.本次分析起源于跟踪到一次针对印度的攻击活动，初始入侵链为一封与印度电讯部门相关的docm文件，在诱惑受害者启动宏后通过嵌入的 VBA 脚本连接远程服务器下载第一阶段的远控木马，进而窃取信息并与另一个指定C2进行通信操作以实施下一步控制。

### **IOC信息如下：**

|  |  |  |
|---|---|---|
| MD5 | 文件名 | 关联URL和C2 |
| ffa2e6f6a7a8001f56c352df43af3fe5 | Cyber Advisory 2023.docm | http\[:\]//luckyoilpk\[.\]com/vlan.html |
| 0baa1d0cc20d80fa47eeb764292b9e98 | Vlan.exe&lt;br&gt;&lt;br&gt;UserView.exe | http\[:\]//185.174.102\[.\]54:443 |

开始分析
----

docm文件为伪造的印度通讯部分下发的关于”Android 威胁和预防措施” 的一份通知，该文件通过醒目的标题 “Reminder: Enable Macros to view Premium Recommendations” 来诱惑受害者启动并执行嵌入的宏代码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2bfd35f72c7a0f9acbbc475c456719c432c85486.png)

宏代码执行后会连接一个被攻陷的服务器，读取上面的页面信息并写入到开机启动的 Startup 目录下的 vlan.exe 文件中进行持久化操作。被指定的页面是显示着下一阶段载荷的字节码形式，以 ‘|’ 作为连字符，在拆分并写入到本地后发现其为 .NET 文件，其为一个远控木马。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-600f29e6822d83340a4274026e2b238aac0fc5b1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-38f6d3b7ed1b6715fc626eb2fcb08771897afdcc.png)

### 特征总览：

用 dnspy 逐步分析，发现在该木远控马中存在两大特征：

l 第一个是大量的时间干扰操作，有些则为等待命令执行并返回的时间。

l 第二个就是在每个关键字符串前后用不同的连字符 \_ # !等拼接无意义的混淆字符串，在使用的过程中再以分组的形式获取，用以规避检测。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3357f1d14b5718fccd94af22fa8b1e72ef48c585.png)

由于变量名和所需数据均经过混淆，致使每个类和方法变量等名称都无法直接阅读。但是透过这种拼接混淆字符串的思路来重新审视的话可以发现一些有实际意义的方法名会在开头出现，其含义符合内容逻辑，但仍无法确定具体使用的混淆器。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3267690b0210e2c15ba449900b48ac96dc6ebc40.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c7af57c09c1b2c07fc3405258f6c19e0798f6c2f.png)

### 信息收集：

在执行过程中，代理先进行受害者机器上的信息收集。通过 Windows Management Instrumentation (WMI) 获取以下组件信息：

l MAC地址

l 设备上的物理内存转换为 Mbs

l 有关处理器的信息

² 转换为 Ghz

² 数据宽度转换为bit

² 名称（例如 Intel ® Core ™ i7-8565U CPU @ 1.80GHz）

还使用 .NET 框架获得以下内容：

l 计算机名称

l 操作系统

l IP地址

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-39dedea86ab192ef5314df11604708b447fa301a.png)

然后通过键值索引的方式把这些信息和预定义的键组织成如下所示：（部分值为预定义）

|  |  |
|---|---|
| **key** | **value** |
| “mode” | “Info” |
| “id” | "E05xxxxxx" |
| "compname" | "DESKTOP-xxxxx" |
| "os" | "Microsoft Windows NT 6.2.9200.0" |
| "ip" | "192.168.32.130" |
| "memory" | "12500" |
| "processor" | "1.992GHz 64bit Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz" |
| "webcam" | 0 |
| "interval" | "5000" |

### 数据发送

收集到的数据经过RC4加密后把数据发送给对应的C2 节点。其中 C2 IP 和加密key 早已写入在构造的回传数据中了。（[http://185.174\[.\]102\[.\]54:443/](/) 和12121）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a1a1f1f1da83a6cb882a4ffbdfb185f9220ba463.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-82f83658d3827a69bba8d0bf354cfa05530d6640.png)

由于SideCopy的行动具有高度针对性，对连接的IP或受害者相关信息猜测是进行了地域限定等条件处理，这里并没有获取到有价值的返回数据。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-6fba6b81a5cf53d8b1e77d01372b0b031d16a871.png)

### C2通信命令解析

庆幸的是根据对后面代码的静态分析同样可以剖析出与 C2 的通信命令部分，回传的数据是使用相同密钥进行RC4加密的，解密后通常是C2的一个简短命令，以 command \[para1\] \[para2\] 的形式提供。参数的数量和类型是可选的，具体取决于命令的类型。有趣的是该木马一开始通过计算 hash 的方式进行比较验证，但后来又以明文的方式进行匹配，这是代码中的一个逻辑失误，比较的hash和明文是一一对应的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-876c0a8d19be8b59c0cbad0e168ff6beb1a4840e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4eb04deae1f3e79f939d0780e0afd01354483c83.png)

通过简单的验证后可以把控制命令提取如下：

|  |  |  |
|---|---|---|
| Hash | Command | Describe |
| 718098122U | Run | 运行指定的文件 |
| 119888179U | downloadexe | 下载C2文件到AppData目录下并执行 |
| 217798785U | List | 获取特定目录下特定文件的信息 |
| 667630371U | close | 结束当前进程 |
| 1012663644U | upload | 上传指定文件到C2 |
| 822653945U | download | 从C2中下载文件 |
| 1438993425U | screen | 获取当前屏幕快照 |
| 1740784714U | delete | 删除目录或文件 |
| 1954351473U | regdelkey | 删除注册表指定的键\|值 |
| 2145929105U | reglist | 列出指定注册表目录下的所有键值 |
| 2015180183U | clipboardset | 设置剪贴板内容 |
| 2180167635U | rename | 重命名目录或文件 |
| 2406331304U | programs | 从下面的注册项中检索安装程序的相关信息。&lt;br&gt;&lt;br&gt;\\HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall |
| 2632535418U | process | 获取运行进程的信息 |
| 2754241439U | pkill | 结束指定名称的进程 |
| 2636022033U | clipboard | 获取剪贴板数据 |
| 3648963048U | regnewkey | 创建注册表项并指定键值 |
| 4108394737U | creatdir | 创建指定目录 |
| 4178259752U | shellexec | 调用cmd执行传输过来的命令 |

在每个命令执行过程中，为了确保命令执行状态，其通过对 text 赋值三种状态缩写字符串来拼接在返回数据的开头。其中RS 表示 Return Successful、RF表示Return Fail、LF 猜测是 Loaded successfully.

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f41c6820b09af032a8b4e950fb2b3894a964fa62.png)

归属研判
----

### 攻击目标

**此次攻击活动归属于 SideCopy 组织主要从两个方面考虑：**

第一个是攻击的目标是印度，从 Quick Heal’s 威胁情报团队在报告 [“Operation SideCopy!”](https://www.seqrite.com/blog/operation-sidecopy/) 中把SideCopy组织从Transparent Tribe中划分出来的时候，其就一直针对印度国防军和武装部队人员。近年来其虽不断演变，但目标仍局限于南亚和中亚地区。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8938167d6352a749acec90e73c357aba07892c80.png)

### 特制木马

第二个是本次样本中下发的 vlan.exe 在经过比较后发现其实质上是SideCopy在 2021 年中一次针对印度电力公司攻击活动中使用的ReverseRat的升级版本，最先由Lumen 的黑莲花实验室披露——[“Suspected Pakistani Actor Compromises Indian Power Company With New ReverseRat”](https://blog.lumen.com/suspected-pakistani-actor-compromises-indian-power-company-with-new-reverserat/)

关联的报告显示， ReverseRat从最初 Reverse1.0 的数字参数匹配到 Reverse2.0 的命令匹配再到本次样本的hash匹配，命令也从最初的15个增加到现在的19个。由此可以看出 SideCopy 的活动一直在继续，并对其武器库进行这频繁的更新。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e65c6fdb7c2779505fcbf41710e7bc344bf2d71f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e44f61387a65e33826059d23bac5863c89852342.png)

此次分析的vlan.exe可以看成是Reverse3.0，因为在2022年间并没有任何关于SideCopy使用ReverseRat的报告发布。间隔了一年多的时间后，相比于ReverseRat 1.0和2.0，其在变量名和操作数据上的拼接混淆处理，以及hah匹配验证的方式都是以往不具备的。并且相比于依旧是Lumen 的黑莲花实验室披露的ReverseRat 2.0的报告——[“ReverseRat Reemerges With A (Night)Fury New Campaign And New Developments, Same Familiar Side-Actor”](https://blog.lumen.com/reverserat-reemerges-with-a-nightfury-new-campaign-and-new-developments-same-familiar-side-actor/)，其除去了连接到受感染机器的 USB 设备后检索指定后缀文件并上传的功能。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-bc5e074cf2bfb7674f210ebbcf3b973fe77f1fa1.png)  
由此可以把本次攻击活动归属于SideCopy组织。

后记
--

样本第一次看到是在 1 月 31 日 [why2try 的 twitter 博文上](https://twitter.com/JVPv5sIM3eFmGyi/status/1620242089861849089)，当时他怀疑是 APT36（Transparent Tribe），当时没多想，也没去看。后来第二次看到是在 2 月 1 日 [souiten\_4t\_FuYingL4b 的 Twitter 博文上](https://twitter.com/souiten/status/1620629752863404032)，这时他怀疑是 SideCopy ，并且也给出了样本是 REVERSERAT 的判断。

然后我 2 月 2 号开始入手，2 月 14 号就写出这篇稿子了（当然并不怎么正规），本来想压着看看有没有社区的活动什么的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-541c7b8d42ecdf1b56d12f47261ce77ce6e9f0bd.png)

后来在日常情报浏览中发现大家好像都看到了，并且很多厂商已经发出来了，比如 2 月 16 号 threatmon 的 [APT SideCopy Targeting Indian Government Entities](https://threatmon.io/apt-sidecopy-targeting-indian-government-entities/)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-abcd5c01fbebeb674c96125a974ce9e5e4c60412.png)

比如 2 月 24 号 绿盟的 [近期APT组织SideCopy针对印度政府的钓鱼攻击活动分析](http://blog.nsfocus.net/sidecopyphishinganalysis/)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d2614d2577be366ec0ed3f057b04916b042b7563.png)

最后由于要审核，所以现在才过审并展现。所以挺感慨的，大家都在争分夺秒。而且他们写得都比我详细得多，很多新颖的点都值得学习，所以自己还得加把劲啊。