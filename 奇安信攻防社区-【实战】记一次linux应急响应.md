挖矿事件
====

说明:百度的应急文章很多，在此不在介绍如何按照手册进行排查，只针对实战进行分析和排查。

**事件背景**：
---------

我司主机存储组报告发现服务器CPU占用异常，超负荷运行，我司安全人员开始介入调查。

**调查过程：**
---------

1.上机排查CPU占用情况发现，PID为6184,占用CPU内存为398%，超负荷运行，初步可以确定是挖矿病毒导致  
**命令：查看CPUC异常占用**  
top -c -o %CPU

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-09fad1400d0378a63d5ca9d4595ff729d8d1d887.png)

查看管理设备2023年x月x号就出现服务器超负荷运行，至今已经8个多月。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-41580eb237afa37c8d0fd5dd484f0dae7f7e396e.png)

查看PID对应的进程  
命令：  
查看进程 ps -aux

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-3dece771529437c79697760fe3bb17c3dd335519.png)

2\. 进入对应的PID查看具体路径信息  
命令：  
查看具体的PID信息： ps -aux | grep PID

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-b4e9c335bdefa0913a6010a460441f93febfedfb.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-34ba46984d0fd26232ef77152c53894926255108.png)

拷贝文件，本地分析 MD5：4499165a5b0f7ac6ddf9dcbbe1f5a4f1  
这里说明一下，不是非要用腾讯，类似还有很多，比如：微步，腾讯等等吧。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-4b6794901e1f0b906527bb5af8694916cbb72a6b.png)  
在微步进行进一步核实

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-1f98e9c628661e905970a81486adf67fb255c0ba.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-a0f4a1bc7391f244b458b4bea191ce7003e5b14a.png)

确认为恶意远控文件，然后进行查杀进程和查杀文件，发现无法直接查杀，查杀进程后会立即重启该服务进程，且会一直存在。这个时候就有点小麻烦了。不是正常的操作，且隐藏的守护进程不好找。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-02e205d62d54df82d7c1e04e53a6efdd83bf697a.png)

2\. 怀疑有守护进程

### 什么是守护进程

Linux系统启动时会启动很多系统服务进程，这些系统服务进程没有控制终端，不能直接和用户交互。其他进程都是在用户登录或运行程序时创建，在运行结束或用户注销时终止，但系统服务进程(守护进程)不受用户登录注销的影响，它们一直在运行着。这种进程有一个名称叫守护进程(Daemon)。  
守护进程也被称为精灵进程，是运行在后台的一种特殊进程，它独立于控制终端并且周期性地执行某种任务或等待处理某些发生的事件。

### 守护进程的特点

(1)在Linux中，每个系统与用户进行交流的界面成为终端，每一个从此终端开始运行的进程都会依附于这个终端，这个终端被称为这些进程的控制终端；

(2)当控制终端被关闭的时候，相应的进程都会自动关闭。但是守护进程却能突破这种限制，它脱离于终端并且在后台运行，(脱离终端的目的是为了避免进程在运行的过程中的信息在任何终端中显示并且进程也不会被任何终端所产生的终端信息所打断)，它从被执行的时候开始运转，直到整个系统关闭才退出(当然可以认为是杀死相应的守护进程)；

(3)如果想让某个进程不因为用户或中断或其他变化而影响，那么就必须把这个进程变成一个守护进程。

### 如何杀死守护进程

1.首先`ps axj | grep 守护进程名字`，找到相应的守护进程，然后使用`kill -9 守护进程名`杀掉；

2.利用`ps -ef`命令查找相应的守护进程，再用`kill -9`命令将其杀死；

3.创建shell脚本对进程的启动、关闭、重启进行自动管理。

下面我们继续寻找守护进程  
进一步排查，计划任务没有  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-52f1b0e8dda9e2c74acaad1c8cd943d8820c1333.png)

排查运行的服务中发现所有者为1001的还有一处服务指向crun.service文件，时间为2022年，比较可疑。

![e97e6a30749d9d6544074ce0fafefc5.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-16388a80c5f0e98a7a9ab108ce2808de769e3186.png)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-edc8c808595552a7f55fdfb90961cdcfd3bcd809.png)

查看最早日期为23年9月7号就已经存在服务器中

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-46b88b3cc48bdc1cfdc98f604e9c8bd2c6a9f667.png)

打开crun.service

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-8fdf8baee1f44d9261554af9b511425a2e58d5fd.png)

病毒样本分析如下：  
样本为重启策略，优先执行指向文件地址的目录执行，如关闭该文件或者进程后，会一直尝试服务重启，导致进程任然存在，服务进程无法删除。

这样找到问题所在，直接删除这个crun.service文件，查杀进程后（按照上述的方法查杀文件，进程）然后在删除之前的挖矿文件后

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-eff382687b7b986840de1339b73cd029f4af7277.png)

没有之前的超负荷运行了。服务器恢复正常，删除/usr/lib/updated下文件即可。

4.排查同网段有没有类似问题，结果都没有此类情况。应急响应结束。

### 修复建议：

1、定期查杀服务器中可疑的文件

2、禁止在服务器中搭建服务对外映射到公网

3、禁止上传未知文件到服务器中

4、定期查看管理器运行情况，及时发现问题及时处理