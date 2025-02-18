一、概述
----

```php
上一篇文章主要介绍了windows应急响应的基础技术分析能力，那么本章继续对linux操作系统中应急响应的基础技术分析能力做一下介绍，希望能对有需要的同学有帮助。
```

二、技术分析
------

### 1、准备工作

在正式实施应急响应之前，需要先进行以下工作，  
第一、信息收集，先对安全事件进行详细的了解，包括系统、服务以及业务类型  
第二、思路梳理，通过以上信息收集初步梳理自己的分析思路  
第三、工具准备，提前准备好需要用到的工具脚本等资料  
第四、数据备份，所有涉及到分析以及证据的材料都需要提前进行备份，这样也方便之后还有分析人员或者防止数据被篡改或者覆盖。  
1）备份passwd文件  
cat /etc/passwd &gt; passwd.txt  
[![![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5da7f8f3ed1a8cd97995e50e62626587e4f12544.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5da7f8f3ed1a8cd97995e50e62626587e4f12544.png)\[\](https://shs3.b.qianxin.com/attack\_forum/2021/10/attach-3f6d3c601f33b3334a620db85ef5a4bc24bc376b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3f6d3c601f33b3334a620db85ef5a4bc24bc376b.png)  
2）备份shadow文件  
cat /etc/shadow &gt; shadow.txt  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f64464868d0eed5cba9fa07e0f73d682849a914f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f64464868d0eed5cba9fa07e0f73d682849a914f.png)  
3）备份当前网络连接  
netstat -anp &gt; netstat\_anp.txt  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ab0b09e3453c1ae76ed2795a6282fa414a2941aa.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ab0b09e3453c1ae76ed2795a6282fa414a2941aa.png)  
4）备份历史命令  
cp ~/.bash\_history history.txt  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3fce43c36b98b5f1176ab08acbb95baa0d32e934.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3fce43c36b98b5f1176ab08acbb95baa0d32e934.png)  
5）备份用户登录信息  
w &gt; users.txt  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-eff7c787d9305d54ef4419fd4b6cbd5b6a39ca6d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-eff7c787d9305d54ef4419fd4b6cbd5b6a39ca6d.png)  
6）备份进程信息  
ps aux &gt; ps.txt  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-983897d0e0b6f22177cf0c1a28d5d6546071677e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-983897d0e0b6f22177cf0c1a28d5d6546071677e.png)  
第五、时间校准，查看系统时间和北京时间是否同步准确，如果不准确那么系统日志等信息的事件可能会存在误差，所以必须提前校准时间。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6bc31dc13d41f022aa94c5c3f8835515b63227d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e6bc31dc13d41f022aa94c5c3f8835515b63227d.png)

### 2、用户信息分析

1）查看当前用户  
whoami  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ef574362ca1baa4f6be4ea1b3349bcfea7e2c2b1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ef574362ca1baa4f6be4ea1b3349bcfea7e2c2b1.png)  
2)查看当前登录系统的所有用户  
who（tty：指的是主机的图形化界面的面板,pts/x:指的是ssh远程连接的窗口）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-74ce7a5c371b112973e61863251ef8cbc1a24ee6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-74ce7a5c371b112973e61863251ef8cbc1a24ee6.png)  
3)主机上一次启动的时间  
who -b  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68c6250313bc3bc641241d7d6d599958b3aab3f0.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68c6250313bc3bc641241d7d6d599958b3aab3f0.png)  
4)显示已经登陆系统的用户列表，并显示用户正在执行的指令  
w  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a89e3ded3ba59d6339f4a24a1e0e71e001f5ae76.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a89e3ded3ba59d6339f4a24a1e0e71e001f5ae76.png)  
5)显示当前登录系统的所有用户的用户列表  
users  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a2f9cc6d7e3ac5357ab4f29b46b8e678decee68d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a2f9cc6d7e3ac5357ab4f29b46b8e678decee68d.png)  
6)查看最近登录成功的用户及信息  
last  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6702dc9d48b95378109e2f3bddd2d99456f85320.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6702dc9d48b95378109e2f3bddd2d99456f85320.png)  
7)查看用户信息  
cat /etc/passwd[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-559be1422b6c0986e7551450d52203ef304ea6bc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-559be1422b6c0986e7551450d52203ef304ea6bc.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8b8bb4738da969df25271474861cd8fb8a9d16be.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8b8bb4738da969df25271474861cd8fb8a9d16be.png)  
8)查看可以登录系统的用户  
cat /etc/passwd | grep /bin/bash  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-12c8025f1f086647e9116921ede16a51921e12e8.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-12c8025f1f086647e9116921ede16a51921e12e8.png)  
9)查看超级用户(uid=0)  
awk -F: '$3==0{print $1}' /etc/passwd  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a0f57d73978f5ff6445b7c8a16126a6d610ba3d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a0f57d73978f5ff6445b7c8a16126a6d610ba3d9.png)  
10)查看可以远程登录的用户（无密码只允许本机登陆，远程不允许登陆）  
awk '/\\$1|\\$6/{print $1}' /etc/shadow  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-740186092f6f8fa6c6361f67517266fca7b5b96c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-740186092f6f8fa6c6361f67517266fca7b5b96c.png)  
11)查看拥有sudo权限的用户  
more /etc/sudoers | grep -v "^#|^$" | grep "ALL=(ALL)"  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cc00abe1dbcf656ba53b584833c8cd59ac9b2b93.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cc00abe1dbcf656ba53b584833c8cd59ac9b2b93.png)  
12）查看历史命令  
cat ~/.bash\_history  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-54bb6193e4a4a0fe27e51857720656e8742414c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-54bb6193e4a4a0fe27e51857720656e8742414c6.png)

### 3、进程信息分析

1）动态查看进程  
top  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f953387531db58d0593223a6f8e37ebefba1c8a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f953387531db58d0593223a6f8e37ebefba1c8a4.png)  
2）查看PID为xxx的进程的可执行程序  
ls -l /proc/pid/exe  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4f446bc00a3b41d174259d70f4897cd6009feb8f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4f446bc00a3b41d174259d70f4897cd6009feb8f.png)  
3）查看PID为xxx的进程打开的文件  
lsof -p pid  
4）查看进程sshd打开的文件  
lsof -c sshd  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4ce636de339bfc3d09b73eeba05b6ec520ac758e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4ce636de339bfc3d09b73eeba05b6ec520ac758e.png)  
5）查看xx端口对应的一些进程  
lsof -i:port  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-af40a4c0816a91bb6bc0c98190bc4b81bb14d503.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-af40a4c0816a91bb6bc0c98190bc4b81bb14d503.png)  
6）查看pid为2091进程的启动时间点  
ps -p PID -o lstart  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3f1db32f8f9ef705cbbb76133da2af85e17fbd3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3f1db32f8f9ef705cbbb76133da2af85e17fbd3d.png)  
7）查看网络连接情况，通过过滤pid查看连接的端口  
netstat -pantu | grep pid  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2587d61f389f77efb214775158f03c6ac755ffcc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2587d61f389f77efb214775158f03c6ac755ffcc.png)  
8）查看端口对应的进程pid  
fuser -n tcp port  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-13ce897fcb064a80840a2b42a547f1f11280f2c2.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-13ce897fcb064a80840a2b42a547f1f11280f2c2.png)  
9）查看进程  
ps aux （ps -ef）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-56b13ab3e3f51b1d206824aa2c8caca05b0733f9.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-56b13ab3e3f51b1d206824aa2c8caca05b0733f9.png)  
10）查看进程树  
pstree  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7b2004691d740f07efbae5af33ab67a2d6b4db3b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7b2004691d740f07efbae5af33ab67a2d6b4db3b.png)  
11）查看进程，根据cpu使用从高到低  
ps aux --sort -pcpu  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9163088c40388f5180b4fb5291a2c290e0a433d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9163088c40388f5180b4fb5291a2c290e0a433d2.png)  
12）查看进程，根据内存使用从高到低  
ps aux --sort -pmem  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dbc073c1217622aac6dc29c1c31f762c1c3f0bdd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dbc073c1217622aac6dc29c1c31f762c1c3f0bdd.png)

### 4、网络连接分析

1）netstat命令用来打印Linux中网络系统的状态信息；  
netstat -an  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-21c72cf9d2bc26cd596e141e8aa90d3c0930bec0.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-21c72cf9d2bc26cd596e141e8aa90d3c0930bec0.png)  
2）查看TCP连接状态  
netstat -nat | awk ‘{print $6}’| sort | uniq -c | sort -rn  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bb8db6472fd93b6aaeef611d80f6f5ca2d80694f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bb8db6472fd93b6aaeef611d80f6f5ca2d80694f.png)  
3）查找请求数请10个IP  
netstat -anlp | grep 80 | grep tcp | awk ‘{print $5}’ | awk -F: ‘{print $1}’ | sort | uniq -c | sort -nr | head -n 20  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-111932d7d3a58107a70fd02992cad6932ba0a33a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-111932d7d3a58107a70fd02992cad6932ba0a33a.png)  
4）根据端口列进程  
netstat -ntlp | grep 80 | awk ‘{print $7}’ | cut -d/ -f1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-74d3181919780de72282d70296183a369ab307cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-74d3181919780de72282d70296183a369ab307cf.png)

### 5、异常文件分析

1）查看指定目录最近被修改的文件(查看var目录下3天内被修改的文件)  
find /var/ -type f -mtime -3 | xargs ls -la  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-01112623c695d03982852481cb001ad566f66e5a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-01112623c695d03982852481cb001ad566f66e5a.png)  
2）按时间排序，查看var目录下最近是否有命令被替换，可以结合rpm -Va命令  
ls -alt /var/ | rpm -Va&gt;rpm.log  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-412a5f4dcba746f7c5741377b01fd2a7fcc7935b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-412a5f4dcba746f7c5741377b01fd2a7fcc7935b.png)

### 6、开机启动项分析

1）查看是否有异常开机启动项  
cat /etc/rc.local | chkconfig --list  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e129502cd66b57b3a28feb6c383e0433c7be2a51.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e129502cd66b57b3a28feb6c383e0433c7be2a51.png)

### 7、定时任务分析

1）查看定时任务  
sudo vi /etc/crontab  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-154ed7ed0a2ba9423ad8392fa92e76151aa30878.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-154ed7ed0a2ba9423ad8392fa92e76151aa30878.png)  
m、h、dom、mon、dow、command分别是(minute; hour; day of month; month; day of week)的缩写  
minute： 表示分钟，可以是从0到59之间的任何整数。  
hour：表示小时，可以是从0到23之间的任何整数。  
day：表示日期，可以是从1到31之间的任何整数。  
month：表示月份，可以是从1到12之间的任何整数。  
week：表示星期几，可以是从0到7之间的任何整数，这里的0或7代表星期日。  
command：要执行的命令，可以是系统命令，也可以是自己编写的脚本文件

### 8、系统日志分析

1)Linux下常见的一些日志：  
/var/log/boot.log：录了系统在引导过程中发生的事件，就是Linux系统开机自检过程显示的信息  
/var/log/lastlog ：记录最后一次用户成功登陆的时间、登陆IP等信息  
/var/log/messages ：记录Linux操作系统常见的系统和服务错误信息  
/var/log/secure ：Linux系统安全日志，记录用户和工作组变坏情况、用户登陆认证情况  
/var/log/btmp ：记录Linux登陆失败的用户、时间以及远程IP地址  
/var/log/syslog：只记录警告信息，常常是系统出问题的信息，使用lastlog查看  
/var/log/wtmp：该日志文件永久记录每个用户登录、注销及系统的启动、停机的事件，使用last命令查看  
/var/run/utmp：该日志文件记录有关当前登录的每个用户的信息。如 who、w、users、finger等就需要访问这个文件  
/var/log/auth.log 或 /var/log/secure 存储来自可插拔认证模块(PAM)的日志，包括成功的登录，失败的登录尝试和认证方式。Ubuntu 和 Debian 在 /var/log/auth.log 中存储认证信息，而 RedHat 和 CentOS 则在 /var/log/secure 中存储该信息。  
2)查看登录成功的记录(auth.log/secure)  
cat /var/log/auth.log *| grep Accepted  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dacafabdbd2279321daad9c2d815b44e68577cac.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dacafabdbd2279321daad9c2d815b44e68577cac.png)  
3)查看登录失败的记录  
cat /var/log/auth.log* | grep Failed  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e050bd82ac760b9d633d947a5325da6a8dac83fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e050bd82ac760b9d633d947a5325da6a8dac83fd.png)  
4)目前与过去登录系统的用户相关信息  
last  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3928d1bafa0ab5252ea5e4a809ce28e22e1ad4d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3928d1bafa0ab5252ea5e4a809ce28e22e1ad4d6.png)  
5)查看最近登录失败的用户及信息，查看的是 /var/log/btmp 文件  
lastb  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cc5c98fd670ba011656452e0e6a95e8cebb4391f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cc5c98fd670ba011656452e0e6a95e8cebb4391f.png)  
6)last命令查看系统中最近的五次用户登录记录  
Last | head -5  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9ab61d93760a2a387e3964accd558d9e3401be3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9ab61d93760a2a387e3964accd558d9e3401be3f.png)  
7)显示系统中所有用户最近一次登录信息，读取的是 /var/log/lastlog 文件  
lastlog  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b996a393282600ccbf81558a70ab8dcc42c8121f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b996a393282600ccbf81558a70ab8dcc42c8121f.png)

### 9、web日志分析

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4a8f8710b4bdd57cea497e9e87612e782a4e94dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4a8f8710b4bdd57cea497e9e87612e782a4e94dc.png)  
在针对日志分析的过程中，会使用的一些其他的脚本和过滤语法，因此在开始之前需要补充一下一些关键词的意义，具体如下：  
awk 首先将每条日志中的IP抓出来，如日志格式被自定义过，可以 -F 定义分隔符和 print指定列；  
sort进行初次排序，为的使相同的记录排列到一起；  
upiq -c 合并重复的行，并记录重复次数。  
head进行前十名筛选；  
sort -nr按照数字进行倒叙排序。  
1）通过日志查看当天ip连接数  
cat apache\_access\_2021-10-23.log | grep "23/Oct/2011" | awk '{print $2}' | sort | uniq -c | sort -nr  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-10271f8cc309ee49bf95201fa447fe58d3639756.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-10271f8cc309ee49bf95201fa447fe58d3639756.png)  
2）在日志中找出访问次数最多的10个IP。  
awk '{print $1}' apache\_access\_2021-10-24.log |sort |uniq -c|sort -nr|head -n 10  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d9ff3c2d958d7429644ae285ee81284b6d09f15a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d9ff3c2d958d7429644ae285ee81284b6d09f15a.png)  
3）当天ip连接数最高的ip都在干些什么:  
cat apache\_access\_2021-10-24.log | grep "24/Oct/2021:00" | grep "192.168.5.1" | awk '{print $8}' | sort | uniq -c | sort -nr | head -n 10  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-35d127048d806cb476b8bc2b5d2d22323469ff55.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-35d127048d806cb476b8bc2b5d2d22323469ff55.png)  
4）当天访问页面排前10的url:  
Cat apache\_access\_2021-10-24.log | grep "24/Oct/2021:00" | awk '{print $8}' | sort | uniq -c | sort -nr | head -n 10  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-eb97c0516c97e2427caa29962f151f7d07bd536a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-eb97c0516c97e2427caa29962f151f7d07bd536a.png)  
5）查看日志中访问次数最多的前10个IP  
cat apache\_access\_2021-10-24.log |cut -d ' ' -f 1 |sort |uniq -c | sort -nr | awk '{print $0 }' | head -n 10 |less  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-042ce4508e2b1be9608dba1981408b1aa795f882.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-042ce4508e2b1be9608dba1981408b1aa795f882.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4e3b65ca0ea75b9b8c3fa2e9b702785d58ceb7fa.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4e3b65ca0ea75b9b8c3fa2e9b702785d58ceb7fa.png)

### 10、查杀rootkit

```php
 Rootkit是一个恶意软件，它可以隐藏自身以及指定的文件、进程、网络、链接、端口等信息。Rootkit可通过加载特殊的驱动修改系统内核，进而达到隐藏信息的目的。Chkrootkit是一款用来检测rootkit的软件，针对上述的一些分析完成之后可以考虑利用Chkrootkit对系统进行一次检测。
```

Chkrootkit扫描结果后面如果是：not infected/not tested/nothing found/nothing deleted 之类的就表示正常。如果是INFECTED那么就需要针对其进行分析。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3ecb3dafaace9068b11074fb6e4e78deeee763db.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3ecb3dafaace9068b11074fb6e4e78deeee763db.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-43b03dbcbed7a2732fbc523f2b78638dd07091a8.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-43b03dbcbed7a2732fbc523f2b78638dd07091a8.png)  
也可以通过chkrootkit | grep INFECTED 命令直接找到可能被感染的文件。

三、总结
----

以上便是我对linux系统中应急响应过程中常用的一些功能和分析方法，从10个方面进行了描述。当然往往一些安全事件的复杂性可能超出了这些范围，但是当我们将基础的一些思路和方法都掌握了，对于一些变化上的分析灵活运用和实操便可。