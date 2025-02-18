0x00 概述
=======

在报告“Bvp47-美国NSA方程式组织的顶级后门”（参考1）的描述中，Bvp47本身像是一个巨大的壳或压缩包，共包含了18个分片，盘古实验室展示了对于Bvp47后门程序的归属分析和部分技术细节的描述，比如BPF隐蔽隧道，但依然还有部分其他模块值得深入探究，这些模块既可以作为Bvp47的一部分一起执行任务，也可以被独立使用。

在2015年对国内某国家重要关键信息基础设施的Solaris系统取证中，盘古实验室提取到了一份独立存活于Solaris平台看起来与Bvp47关系密切的样本，后经确认，样本文件内容与“影子经纪人”（The Shadow Brokers）揭露出的“饮茶”（Suctionchar\_Agent）木马程序原文件一致。该木马程序搭配Bvp47中的Dewdrop、Incision等模块和控制程序tipoff，可以轻松窃取目标系统用户在执行ssh、passwd、sudo等命令时的账号密码，随即将其隐蔽保存在目标系统中。这些被加密隐藏的密码文件同样也需要RSA算法的私钥来解密。

基于特征的入侵分析取证发现，国内大量重要组织机构受到了这个美国国家安全局（NSA）来源的“饮茶”（Suctionchar\_Agent）木马程序的侵袭，其中就包括了近期披露的被网络渗透的西北工业大学。有证据显示， NSA利用“饮茶”（Suctionchar\_Agent）木马程序窃取了世界各国难以确切估量的账号密码，在美国各地建立了多个高度机密的账号密码海量数据存储中心，供NSA的行动部门TAO随时查询并“合法”进入受害者的信息系统。

追踪Bvp47的过程更像是在摸索一张迷雾下的拼图，在奇安盘古实验室与国家计算机病毒应急处理中心的通力合作下，这份报告将会通过对“饮茶”（Suctionchar\_Agent）、Dewdrop、Bvp47\_loader等程序和系统模块的技术分析来进一步理解Bvp47这个顶级后门平台的部分工作方式和执行逻辑。

0x01 “饮茶”嗅探木马（Suctionchar\_Agent）攻击场景还原
=======================================

1.1 攻击场景
--------

经过全面而深入的技术模拟分析，盘古实验室还原了“饮茶”嗅探木马（Suctionchar\_Agent）与Bvp47后门程序其他组件配合实施联合攻击的场景，具体执行过程如下图所示:

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3ae5b2f769d55e8f561290814faa85b995876798.png)

1. 运行于内核层的sum会辅助“饮茶”嗅探木马（Suctionchar\_Agent）窃取passwd、telnet、su等进程中的账号密码；
2. 窃取到的账号密码会同步发送给运行于Ring3的“饮茶”嗅探木马（Suctionchar\_Agent）;
3. “饮茶”嗅探木马（Suctionchar\_Agent）会将账号密码保存到名为“/var/tmp/.xxxxxxxx”的隐藏目录中；
4. 美国国家安全局（NSA）的攻击实施者远程发送执行ish反弹的触发包到内核层的BPF过滤程序；
5. BPF过滤器捕获到特征包后传送给Ring3的Dewdrop程序模块；
6. Dewdrop进行数据包解密并收到ish反弹指令，随即转送给Incision程序；
7. Incision程序主动回联到callback地址，美国国家安全局（NSA）的攻击实施者利用ish接受窃取的密码文件；
8. 美国国家安全局（NSA）的攻击实施者将被RSA公钥加密的密码文件进行私钥解密并还原密码文件；

1.2 场景复现
--------

1. 运行tipoff控制端程序，功能列表如下:

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e65c22b6972bfa487c9adce49a33d50d00cf27d7.png)

2. | 具体功能列表如下: |  |  |
    |---|---|---|
    | **类别** | **功能说明** |
    | 触发协议支持 | 支持TCP、UDP、ICMP协议 |
    | 非常规TCP标志支持 | syn、fin、ack、rst、push、urg |
    | 防火墙穿透支持 | PIX或其它；默认支持防火墙穿透，ACL穿透； |
    | 支持应用协议 | SMTP、SIP、DNS等应用层协议 |
    | 后门功能1 | 支持远程启动文件进程 |
    | 后门功能2 | 支持远程Shell查看 |
    | 支持各协议的扩展定制 | 包括SMTP、DNS、TCP等协议的标记位自定义 |
3. 支持UDP包的远程shell获取

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c0395977604c9a8913b407123a2c03243509a261.png)

4. UDP报文如下

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-da320130a21f758aa06a6ca2b762f5c988758c9f.png)

5. 在获取到的shell中可以看到被隐藏的进程和文件

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-620199463bbc1df09bdbd0095b169e947c0680cb.png)

6. “/var/tmp/”目录下被加密的文件如下：

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-23482c1489f9736e97f40dd9bdbec5f05edb7000.png)

7. 使用suctionchar\_decode对“/var/tmp/”目录下被加密的文件解密：

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f9adcb699fce4796cdd4e8c0d7b304a6c202a854.png)

0x02 “饮茶”嗅探木马（Suctionchar\_Agent）技术细节
=====================================

2.1 文件信息
--------

| 样本关联溯源发现，盘古实验室2015年提取到的样本为“影子经纪人”（The Shadow Brokers）泄漏的文件之一，即suctionchar\_agent\_\_v\_\_3.3.7.9\_sparc-sun-solaris2.9 ，文件相关信息如下： |  |  |
|---|---|---|
| **样本信息概要说明** |  |
| **文件名称** | 未知 |
| **文件哈希(MD5)** | a633c1ce5a4730dafa8623a62927791f |
| **文件大小(字节)** | 47,144 |
| **The Shadow Brokers具体包名称** | suctionchar\_agents.tar.bz2 |
| **原始文件名称** | suctionchar\_agent\_\_v\_\_3.3.7.9\_sparc-sun-solaris2.9 |
| **功能目标** | 窃取SSH、TELNET、FTP、PASSWD、SU、RSH、LOGIN、CSH等程序中的账号密码信息。 |
| **CPU架构** | SPARC |
| **隐藏路径2** | /var/tmp/.xxxxxxxxxxxx |

鉴于盘古实验室提取的样本本身为SPARC架构，比较少见，为方便读者理解并采取有效措施进行防范，我们选择基于x86架构、功能相同的木马程序样本进行分析，具体x86架构的文件信息如下：

|  |  |
|---|---|
| **样本信息概要说明** |  |
| **文件名称** | suctionchar\_agent\_\_v\_\_2.0.28.2\_x86-linux-centos-5.1 |
| **文件哈希(MD5)** | 4a5b7a9c5d41dbe61c669ed4cf2975e5 |
| **文件大小(字节)** | 31,649 |
| **The Shadow Brokers具体包名称** | suctionchar\_agents.tar.bz2 |
| **原始文件名称** | suctionchar\_agent\_\_v\_\_2.0.28.2\_x86-linux-centos-5.1 |
| **功能目标** | 窃取SSH、TELNET、FTP、PASSWD、SU、RSH、LOGIN、CSH等程序中的账号密码信息。 |
| **CPU架构** | X86 |
| **Bvp47对应分片** | 0x0E |
| **隐藏路径2** | /var/tmp/.xxxxxxxxxxxx |

2.2 样本关联
--------

根据盘古实验室提取的“饮茶”嗅探木马样本（Suctionchar\_Agent），研究人员从“影子经纪人”（The Shadow Brokers）揭露出的文件中找到了对应的原始文件为“linux/bin/suctionchar\_agents.tar.bz2/suctionchar\_agent\_\_v\_\_3.3.7.9\_sparc-sun-solaris2.9”，二者几乎完全一致。相关压缩包中还包含了适合多个平台和版本的“suctionchar”木马程序，文件最早可追溯到2007年:

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c1d693351e53e5d07bb7377c4cb909c44d780e53.png)

2.3 技术分析
--------

### 2.3.1 字符串解密

如下图所见，字符串加密也就是“Bvp47”研究报告中所描述的0x47函数加密：

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-59afb6e1efd061577314d9fd911ea97c343769bf.png)

解密后的字符串列表如下：

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bffb2d4be0fdcc1a094d8b9ac4673954d0b1516e.png)

相关解密脚本如下：

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e1fba2c5003f848409caf5185901b8f98cb42371.png)

### 2.3.2 功能模块设计

文件“Linux\\etc\\opscript.txt”中对Suctionchar\_Agent的功能作了相关说明，即驻留窃取SSH、TELNET、FTP、PASSWD、SU、RSH、LOGIN、CSH等程序中的账号密码信息。“饮茶”（Suctionchar\_Agent）程序是这个木马程序的应用层代理，它与相关联的内核模块通信，接收所需信息并加密写入文件。内核模块sum文件（The Shadow Brokers Leaks未包含该文件）可由modload程序加载，成功加载内核模块后会清空落地的文件，防止内容被恢复：

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1e8285c2285e479a9e5b87797f795405a9f06d4d.png)

“饮茶”（Suctionchar\_Agent文件本身既可以使用默认配置，也可以从外部读取配置文件，文件格式主要包括3.x以上版本的xml格式和早期的conf格式。

3. x以上版本的xml格式（“Linux\\bin\\suctionchar\_configure.xml”）：

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fb1babe5c150cc39ad83bfa0ff090baba6593f55.png)

“Linux\\doc\\old\\etc\\suctionchar.sample.filter.conf” ：

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eed5009d826102d2fb53be409e96e6112ce2216b.png)

“饮茶”（suctionchar\_configure）将生成“dc9cb44a723d0e75201d933159834173“文件，该文件供Suctionchar\_Agent使用：

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a86480b49f15df8061fcc999d76300b6654f4193.png)

### 2.3.3 密码获取线程

在“饮茶”（Suctionchar\_Agent）中存在一个独立的线程，与内核模块sum保持通信，接收账号密码并写入到/var/tmp/文件夹中，即sub\_8049EF0函数内部：

![16.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-65e0461533aa3ca011949a097217d99fdc6687cc.png)

回调函数sub\_8049A00：

![17.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-58a1144c6abc64987299c441d248f7b8687bbb69.png)

### 2.3.4 密码保存文件的路径生成算法

在函数get\_hidden\_path\_0804BDF0中描述了隐藏文件” /var/tmp/.e33ff11cb8e3b4ff/a0b973925e397d9acd80e85e2eaa6e60/d5373a146ff9f200a2376054dde25677”的生成算法：

![18.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-83c8cdcf5617cfb7417310a05de121817012c5a8.png)

还原的代码大致如下：

![19.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-63fc0f894609fe5fa19d611cc66181d32dbcc7ad.png)

### 2.3.5 “饮茶”木马（suctionchar\_decode）程序中的私钥

正如攻击场景一章中所描述的那样，文件“/var/tmp/.e33ff11cb8e3b4ff/a0b973925e397d9acd80e85e2eaa6e60/d5373a146ff9f200a2376054dde25677”可以被“linux\\bin\\suctionchar\_decode”程序所解密，加密算法需要用RSA私钥解密RC6对称密钥后才能解密出文件，同Dewdrop模块中的私钥一样，这个RSA私钥也可以佐证该后门与“影子经纪人”（The Shadow Brokers）泄露数据包的关联关系。

![20.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d6e10a686946edd6a49f652a4f08c009646950a5.png)

0x03 Dewdrop version 3.x 技术细节
=============================

Dewdrop模块承担了最主要的隐蔽后门功能，即BPF过滤功能，本章节主要讨论BPF引擎通信对应的实现过程。

3.1 BPF隐蔽通信初始化过程
----------------

1. BPF隐蔽后门的初始化是从函数\_554a7941开始的；

![21.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-009de798683ea1fb216b9e93fa0c3406fc14b267.png)

2. 其中sec\_bpf\_init返回了bpf\_program的结构体

![22.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7c005cef0c7bc5f16818d86064c1b565f336cbfd.png)

3. stru\_8008300结构具体值如下：

![23.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8a2b69fbd11816a7cdb949661386d5b3d2dab7a4.png)

4. bpf\_program和bpf\_insn结构分别如下：

![24.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fdec8ff76334d128efafcd886bf5fff3f37a5a9a.png)

5. 经过bpf反汇编过后的代码如下：

![25.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a8bbc93228f2878018f74826f7ca16d51b19208d.png)

6. 实际运行时的bpf伪代码如下，即满足该规则的payload数据会被捕获进入到下一个处理流程；

![26.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8baf2ef885cdf473e4f0f3caf6895244b1b76c1f.png)

3.2 BPF隐蔽通信数据处理过程
-----------------

在满足BPF的捕获规则后，数据包会进入下一个流程来进行处理。

1. 在函数sec\_f\_9b510b03中可以看到Dewdrop使用select模型来处理对应的数据包

![27.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4cf6f25b7694685a6dac99a210e779b0ea1cc479.png)

2. sec\_f\_6a42f4c9\_allinone执行伪代码如下：

![28.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-05e21e99b68595509c333b9087cc651ae24dbaf1.png)

3. 在 sec\_decode\_packet 中就开始了payload数据包的解密工作，内部涉及到一处作了变形处理的RSA解密算法。

![29.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-d89bf77c39fa7beb4f8fe3be5993374f3122ae39.png)

3.3 BPF隐蔽通信数据格式与加密算法
--------------------

1. Dewrop模块v3系列的载荷（payload）数据包格式如下：

![30.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c27200bff4abfb23de592555968f029591aa0c04.png)

2. tipoff中对Dewdrop模块的载荷（payload）数据包流程如下：

![31.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fac408d99dd8d40a55b829dbf96272c0647b0a00.png)

3. payload数据包中的RSA数据加密

![32.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fcf0a44db7bb7e7b5913c10225a3910ad5f5dc14.png)

0x04 Bvp47\_loader技术细节
======================

loader模块的入口函数图具体如下，中间会涉及到：

1. 检测运行时环境是否正常；
2. 读取文件尾部的payloads；
3. 映射和校验payload有效性；
4. 解密payload，如果需要解密；
5. 解压缩payload，如果需要解压缩；
6. 装载内核模块；
7. 调用通知隐藏内核模块的ELF文件头；
8. fork执行Dewdrop模块后门；
9. fork执行“饮茶”（Suctionchar\_Agent）程序后门；

![33.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-b64f9593ab5cad86cf3be8c48ea17d0192f14580.png)

4.1 字符加密函数
----------

在样本分析过程中，首先需要处理应对的是一系列的字符串加密函数，共8处。

1. 异或0x47函数类型1：

![34.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a878708c77b7de00b787fc0b3baf3d617e0cbee1.png)

2. 异或0x47函数类型2：

![35.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-bb71f59e53007eb6f3172896db0df943b6501182.png)

3. 变序加密函数：

![36.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2cb9b8cc031b310859fe3669f670dc8d875eb817.png)

4. 异或0x47函数类型3：

![37.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-90a12513c1d802df765fcc81d0c06c402e0bd629.png)

5. 异或0x47类型4：

![38.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3c6eff6ecc7306674c360282e1ca8d332d918204.png)

6. 异或0x47

![39.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7a290cd559f3e543e425ee84245548ee7e02d843.png)

7. 加密函数

![40.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1a2f02ccffb89abcf89275c4b773f0c3d0352c92.png)

8. 异或0x47函数类型5

![41.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e8d26a29ea5ebe331d702fba388f298d0555bf99.png)

4.2 载荷（payload）相关的加密方式
----------------------

载荷（payload）在被装载过程中主要有5种解密方式。

方式一：

![42.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-13ce2b3ba53c97f4ff74cde8bddbeaa112f76140.png)

方式二：

![43.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4b1ff40142f6ee5f1cde848e4a6ba2349a6375dc.png)

方式三：

![44.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e00c7e8badb07f9dc451fccf4439788535a62e19.png)

方式四：

![45.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-32be16e3a75a1e8ba7ba1d9227155e9eac742246.png)

方式五：

![46.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0c7499fba4499ab58a3d970612bc68946316dd2d.png)

4.3 载荷（payload）解密流程
-------------------

如前面所见到的main函数主体流程，载荷（payload） 解析过程是一个相对复杂的循环体流程，且伴随了诸多加密对抗。

映射和加载：

![47.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5e1933134586d6394fdf9e16a13257e5a760c976.png)

解析流程：

![48.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-14a3d00cb3fa9c021b45706c2fae53e18eac38b4.png)

涉及到的解压缩流程：

![49.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-512cd0d0cc9d0ca9bc06f92e3ba48dacde250db9.png)

linux\_gzip函数:

![50.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9f376933f75ab8a31a0f90b2154ba76852920851.png)

linux\_gzip\_inflate\_fixed函数：

![51.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-27426aa9ea5c6821a14c88bd76862d01bcbc7416.png)

linux\_gzip\_inflate\_dynamic函数：

![52.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-0b41d6c26234c4f236142a969e47f36dd05de674.png)

linux\_gzip\_inflate\_codes函数：

![53.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ca8750d360316e3f7286d9f0215e7cb98eab59c6.png)

linux\_gzip\_fill\_buf函数：

![54.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a8ec164c46aa973c81b1bf410537b3685d1a834a.png)

linux\_gzip\_huft\_build函数：

![55.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-10771f7081ff6b5e002b146cbd9b972af7197034.png)

整体抽象出来的大致C语言代码如下（未能完全覆盖）：

![56.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a2d3007278ff88c76cb1075d04701160aa2bb841.png)

已知的payload文件格式如下：

![57.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3153a219fd99b85a940e4f4e0330df064af29196.png)

在实际样本运行过程中，在上述Decode回调调用过程中也会直接开始尝试加载so类型的文件：

![58.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-715c946c51c4c811d5beb00f48355b5a6e1527ef.png)

在试图加载后也会去尝试补丁elf文件格式的plt：

![59.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-15c2f9935e317acbf39499c53ac08e168f993fe9.png)

4.4 Bvp引擎初始化与内核模块加载
-------------------

内核模块的解密与加载也会在main流程里执行，会经历如下的几个步骤：

1. 解密payload包；
2. 初始化Bvp引擎，适配对应内核版本结构；
3. 开始尝试装载ko模块，主要用于进程、文件、网络的隐藏等；

具体如下：

1. 尝试解密ko的payaload；

![60.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e737f4528c8794b1e8a4841dfb776370a63f3a71.png)

2. Bvp整体处理函数；

![61.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c1fd653f3152e3fb09d4b67cc9cd51b52ae66466.png)

对应的伪代码：

![62.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-91cf9b23990f0d069b74f8c6b15d2aa5fcc7228f.png)

3. Bvp引擎的初始化serial\_bvp函数

![63.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e1f42e9ccf4b357f88251c90a18a3bd690f72dfb.png)

对应的伪代码：

![64.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4db1f3d345b1b7b97d8e3f33435a19c2ff1f7902.png)

4. serial\_bvp流程

![65.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-cd65be059c48f38a02af8fbde8408bff4040f531.png)

5. 加载第一个模块qmr

![66.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-96748b584d22d4e1dfa965fa281240c705cba6da.png)

6. 校验发行版：

![67.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4ac20321a1ce875d179ed51d68275207f23dd604.png)

7. 该发行版对应了TSB中的版本：

![68.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-73bca2d06da1b19235312f2c1adb79faecc0b728.png)

8. 校验2：

![69.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-1b6ab47ac77f986668ea8a4d7b15b0206c454f4f.png)

9. 内核模块加载时的参数验证1：

![70.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9066cd30ea9e3dbbf3dcc8f4a6290069ca57daf5.png)

10. 内核模块2加载时的参数验证2：

![71.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eae080e310493badf0cfc6cb48ee125870567456.png)

11. 最终开始装载内核模块：

![72.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fde846edd6633ff338d63768ad889726f5bdb103.png)

4.5 自删除的一种绕过手段
--------------

在main函数中有2处unlink函数的调用，实际调试过程中可以暴力修改流程绕过unlink所出现的自删除：

![73.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-eb82f63b960ff18eb87e9b9528e82c9bf8520b74.png)

4.6 基于Hash的API函数调用
------------------

在Bvp47的运行过程会有制作一张类似作基于Hash值的API函数查找的查找表。

1. 面对如下的一张Hash表；

![74.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-80e52af755c5def21b05c6a0ea32bad4c8bccd86.png)

2. 在sub\_804C2E0函数中尝试初始化

![75.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-8c329987cb9dcacb4441abfa5f5209b9c9967bf5.png)

3. 在serial\_bind\_0x7bbf2c88\_函数中进一步初始化

![76.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-401ac6f52085952c81e61a9261c43205b4c32673.png)

伪C语言代码：

![77.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f1111f57df717298ba637f2d935757e7db3ca898.png)

4.7 部分shellcode
---------------

在loader模块中还有部分是部分不太完整的加密ELF文件，经过解密后是几个shellcode形式的代码。

1. 对应的ELF头部格式定义如下:

![78.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-6361de09234d2f32294d1575941322a2bb3e031f.png)

2. 中间的几段shellcode会互相跳转

![79.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-db97668545ce5835641c20b3e3da25382b5e4f09.png)

3. 共6段 shellcode

![80.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-fcb38d08c3e1b228e0f8afec45418fe8c5655f6a.png)

0x05 结论
=======

“饮茶”嗅探木马（Suctionchar\_Agent）程序的功能专一，综合分析Bvp47\_loader、Dewdrop等模块可以看出，“电幕行动”（Bvp47）在设计上体现了良好的架构能力。美国国家安全局（NSA）的攻击实施者可以通过Bvp47各个功能模块的灵活组合，隐蔽完成攻击任务，同时大幅降低该木马程序的暴露几率。尽管美国国家安全局（NSA）实施的攻击窃密活动具有高度的隐密性，但盘古实验室通过自有数据视野范围内的分析取证材料，结合对来源数据的深度挖掘，仍然完整地还原了世界顶级黑客组织“方程式”的攻击窃密手法。

0x06 参考
=======

1\. Bvp47-美国NSA方程式组织的顶级后门

[https://www.pangulab.cn/post/the\\\_bvp47\\\_a\\\_top-tier\\\_backdoor\\\_of\\\_us\\\_nsa\\\_equation\\\_group/](https://www.pangulab.cn/post/the%5C_bvp47%5C_a%5C_top-tier%5C_backdoor%5C_of%5C_us%5C_nsa%5C_equation%5C_group/)

2\. The Shadow Brokers: x0rz-EQGRP

[https://github.com/x0rz/EQGRP/blob/master/Linux/up/suctionchar\\\_agents.tar.bz2](https://github.com/x0rz/EQGRP/blob/master/Linux/up/suctionchar%5C_agents.tar.bz2)

4\. jtcriswell/bpfa

<https://github.com/jtcriswell/bpfa>

5\. bpf-asm-explained

<https://github.com/Igalia/pflua/blob/master/doc/technical/bpf-asm-explained.md>

6\. cloudflare/bpftools

<https://github.com/cloudflare/bpftools>

文章转载自公众号：奇安盘古实验室  
原文链接：<https://mp.weixin.qq.com/s/uLdP8sNbZDZ4TOLv3bFitw>