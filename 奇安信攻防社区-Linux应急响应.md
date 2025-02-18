前言
--

身为一名网络安全从业者，很清楚安全总是相对的，再安全的服务器也有可能遭受到攻击，除了定期的备份数据外，还需定期对服务器进行安全检查，在实际的安全和运维工作中，应该在网络和系统被攻击之前，做好充分的准备，才能在网络被攻击时能够从容的应对。

入侵排查流程
------

### 账号安全

#### 基本使用

##### `/etc/passwd`

用户信息文件

![image-20211021133555029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6827927b628bedce315d78458eba0468f2831fca.png)

对应关系:

```php
用户名:密码:用户ID:组ID:用户说明:家目录:登陆之后shell 
```

注:无密码只允许本机登陆，远程不允许登陆

##### `/etc/shadow`

影子文件

![image-20211021133628507](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ff45988da9e17ecbf391bd67a18f9715c81b46a4.png)

对应关系:

```php
用户名:加密密码:密码最后一次修改日期:两次密码的修改时间间隔:密码有效期:密码修改到期到的警告天数:密码过期之后的宽限天数:账号失效时间:保留 
```

##### `who`

查看当前登录用户

注：tty本地登陆、pts远程登录

![image-20211021133654545](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c49d0bce4ec1a6371cdd184b09512d98763e4b71.png)

##### `w`

查看系统信息

![image-20211021133723660](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7959a220c03562cc4b339761f2da5f74d633891e.png)

##### `uptime`

查看登陆多久、多少用户，负载

![image-20211021133750804](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6cb7d9e799c3e5df8d9fed3d7e18cc0baa94558f.png)

#### 入侵排查

##### 1、查询特权用户特权用户(uid为0)

```php
[root@localhost ~]# awk -F: '$3==0{print $1}' /etc/passwd 
```

![image-20211021133853541](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-28c85cc71a9d265f0cea270833f8133f0a1e68e8.png)

##### 2、查询可以远程登录的帐号信息

```php
[root@localhost ~]# awk '/\$1|\$6/{print $1}' /etc/shadow 
```

![image-20211021133909453](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b8a5e96a8c5f10823fce237e3f7f0045add486e9.png)

##### 3、其他帐号是否存在sudo权限。

注：如非管理需要，除root帐号外，普通帐号应删除sudo权限

```php
[root@localhost ~]# more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)" 
```

##### 4、禁用或删除多余及可疑的帐号

```php
usermod -L user 禁用帐号，帐号无法登录，/etc/shadow第二栏为!开头 

userdel user 删除user用户 

userdel -r user 将删除user用户，并且将/home目录下的user目录一并删除 
```

### 历史命令

#### 基本使用：

##### 1.查看帐号执行过的系统命令

通过.bash\_history

```php
root的历史命令:histroy 

打开/home各帐号目录下的.bash_history，查看普通帐号的历史命令 
```

![image-20211021134034338](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d35986e9fbd65ae9df9713fc9e895599cd1c746f.png)

![image-20211021134020190](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-21f0078e4a96bd95845fca6c750e0bef23e9ceba.png)

##### 2.增加设置

历史的命令增加登录的IP地址、执行命令时间等信息：

- 保存1万条命令

```php
sed -i 's/^HISTSIZE=1000/HISTSIZE=10000/g' /etc/profile 
```

- 在`/etc/profile`的文件尾部添加如下行数配置信息：

```php
####historyUSER_IP=`who -u am i 2>/dev/null | awk '{print $NF}' | sed -e 's/[()]//g'` if [ "$USER_IP" = "" ] then USER_IP=`hostname` fiexport HISTTIMEFORMAT="%F %T $USER_IP `whoami` " shopt -s histappend export PROMPT_COMMAND="history -a" 
```

![image-20211021134150850](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-88d20dc8325245fa6c243aa5afe13c0cea005beb.png)

- source /etc/profile让配置生效

生成效果：

```php
1 2021-010-22 19:45:39 192.168.1.1 root source /etc/profile 
```

##### 3、历史操作命令的清除 问题

使用命令：`history -c`

但此命令并不会清除保存在文件中的记录，因此需要手动删除.bash\_profile文件中的记录。

#### 入侵排查

进入用户目录下

```php
cat /home/用户/.bash_history >> history.txt 
```

### 可疑端口

使用netstat 网络连接命令，分析可疑端口、IP、PID

```php
netstat -antlp | more 
```

![image-20211021134405494](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-073a36cd340e4a231f4f69fc54ce0bfc2b626cca.png)

查看下pid所对应的进程文件路径， 运行

```php
ls -l /proc/$PID/exe或file /proc/$PID/exe
```

### 可疑进程

使用ps命令，分析进程

```php
ps aux | grep pid 
```

![image-20211021134353675](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1145e3fb5bbea67416bfc46d0f1cced08ad695d.png)

### 开机启动项

#### 基本使用

##### 系统运行级别示意图：

![image-20211021101935556](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d55b8fe757170588c9c28918632f772bdaf55e3b.png)

##### 查看运行级别命令

使用命令：`runlevel`

![image-20211021134425196](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3b3ebcdd6d47cc7b71550900da24a22648ddc141.png)

系统默认允许级别

```php
vi /etc/inittab id=3:initdefault 系统开机后直接进入哪个运行级别 
```

开机启动配置文件

```php
/etc/rc.local /etc/rc.d/rc[0~6].d 
```

例子:当我们需要开机启动自己的脚本时，只需要将可执行脚本丢在/etc/init.d目录下，

然后在`/etc/rc.d/rc*.d`中建立软链接即可

```php
root@localhost ~]# ln -s /etc/init.d/sshd /etc/rc.d/rc3.d/S100ssh对应关系sshd:具体服务的脚本文件S100ssh:软链接，S开头代表加载时自启动,如果是K开头的脚本文件，代表运行级别加载时需要关闭的。
```

#### 入侵排查

查看启动项文件：

```php
more /etc/rc.local /etc/rc.d/rc[0~6].d ls -l /etc/rc.d/rc3.d/
```

### 定时任务

#### 基本使用

##### crontab

利用crontab创建计划任务

基本命令

```php
crontab -l:列出某个用户cron服务的详细内容

Tips:默认编写的crontab文件会保存在:/var/spool/cron/用户名 
例如: /var/spool/cron/root

crontab -r:删除每个用户cront任务(谨慎：删除所有的计划任务)

crontab -e:使用编辑器编辑当前的crontab文件
```

##### anacron

利用anacron实现异步定时任务调度

使用案例,每天运行 /home/backup.sh脚本：

```php
vi /etc/anacrontab @daily 10 example.daily /bin/bash /home/backup.sh
```

当机器在 backup.sh 期望被运行时是关机的，anacron会在机器开机十分钟之后运行它，而不用再等待 7天。

#### 入侵排查

重点关注以下目录中是否存在恶意脚本

```php
/etc/crontab 

/etc/cron.d/* 

/etc/cron.daily/* 

/etc/cron.hourly/* 

/etc/cron.monthly/* 

/etc/cron.weekly/ 

/etc/anacrontab 

/var/spool/anacron/* 
```

Tips:

```php
more /etc/cron.daily/* 查看目录下所有文件
```

![image-20211021134600371](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-645f8dbd0308aaaa229a5ea10ba812e3e157e771.png)

### 服务

#### 基本使用

##### 服务自启动

- 第一种修改方法：
    
    问题 chkconfig安装

```php
chkconfig [--level 运行级别] [独立服务名] [on|off] chkconfig –level 2345 httpd on 开启自启动 chkconfig httpd on (默认level是2345)
```

- 第二种修改方法：

```php
修改/etc/re.d/rc.local 文件 加入 /etc/init.d/httpd start
```

- 第三种修改方法：

使用ntsysv命令管理自启动，可以管理独立服务和xinetd服务

#### 入侵排查

##### 查询已安装的服务：

- RPM包安装的服务

```php
chkconfig --list #查看服务自启动状态,可以看到所有的RPM包安装的服务 ps aux | grep crond#查看当前服务 系统在3与5级别下的启动项 中文环境 chkconfig --list | grep "3:启用\|5:启用" 英文环境 chkconfig --list | grep "3:on\|5:on" 
```

- 源码包安装的服务

```php
查看服务安装位置,一般是在/user/local/ service httpd start 搜索/etc/rc.d/init.d/,查看是否存在 
```

### 系统日志

#### 基本使用

日志默认存放位置：`/var/log/`

查看日志配置情况：`vi /etc/rsyslog.conf`

![image-20211021134731233](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2f2686c79a43a0b6246b9afea43abd84d155494.png)

#### 日志文件说明

![image-20211021104609295](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-13b890131be728c5dc86a9a531661ff04e5c2a1a.png)

日志分析
----

### 前言

日志默认存放位置：`/var/log/`

查看日志配置情况：`vi /etc/rsyslog.conf`

![image-20211024160400268](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c8b025fdae3c22026aa5ea2603a7981bfd041283.png)

### 日志文件对应的说明

![image-20211024160518386](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5fbffb048d89448fce81ac8e570c0b36fa49dc43.png)

### `/var/log/secure`

```php
1、定位有多少IP在爆破主机的root帐号： grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort - nr | more 定位有哪些IP在爆破:grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\. (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"|uniq -c 爆破用户名字典是什么？ grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|uniq -c|sort -nr 2、登录成功的IP有哪些： grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more登录成功的日期、用户名、IP： grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}' 3、增加一个用户kali日志： Jul 10 00:12:15 localhost useradd[2382]: new group: name=kali, GID=1001 Jul 10 00:12:15 localhost useradd[2382]: new user: name=kali, UID=1001,GID=1001,home=/home/kali,shell=/bin/bash Jul 10 00:12:58 localhost passwd: pam_unix(passwd:chauthtok): password changed for kali #grep "useradd" /var/log/secure 4、删除用户kali日志： Jul 10 00:14:17 localhost userdel[2393]: delete user 'kali' Jul 10 00:14:17 localhost userdel[2393]: removed group 'kali' owned by 'kali' Jul 10 00:14:17 localhost userdel[2393]: removed shadow group 'kali' owned by 'kali' # grep "userdel" /var/log/secure 5、su切换用户:Jul 10 00:38:13 localhost su: pam_unix(su-l:session): session opened for user good by root(uid=0) sudo授权执行: sudo -l Jul 10 00:43:09 localhost sudo: good : TTY=pts/4 ; PWD=/home/good ; USER=root ; COMMAND=/sbin/shutdown -r now
```

### `/var/log/yum.log`

软件安装升级卸载日志：

```php
yum install gcc [root@bogon ~]# more /var/log/yum.log Jul 10 00:18:23 Updated: cpp-4.8.5-28.el7_5.1.x86_64 Jul 10 00:18:24 Updated: libgcc-4.8.5-28.el7_5.1.x86_64 Jul 10 00:18:24 Updated: libgomp-4.8.5-28.el7_5.1.x86_64 Jul 10 00:18:28 Updated: gcc-4.8.5-28.el7_5.1.x86_64 Jul 10 00:18:28 Updated: libgcc-4.8.5-28.el7_5.1.i686 
```

挖矿事件
----

### 1.获取异常进程pid

#### CPU占用

```php
top -c -o %CPU 
```

![image-20211024152733519](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bcd933b44f0840dd6f42a81ff7434f20ead00eb8.png)

CPU占用前5的进程信息

```php
ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%cpu | head -n 5
```

![image-20211024152756297](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e472067fce575409ec17debaa63198f18856bc78.png)

#### 内存占用

```php
top -c -o %MEM
```

![image-20211024152812797](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-190f337f80b7efc2f558b304b147fc9715a16c50.png)

内存占用前5的进程信息

```php
ps -eo pid,ppid,%mem,%cpu,cmd --sort=-%mem | head -n 5
```

![image-20211024152853048](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4a1a484f77a4a6983ef7803f0615979ca871ac72.png)

#### 网络占用

安装nethogs

```php
apt-get install nethogs
```

然后以root权限运行nethogs即可

### 2.寻找恶意文件样本

#### 进程名字或者部分字符串获取pid

```php
pidof "name"ps -aux | grep "name"ps -ef | grep "name" | grep -v grep | awk '{print $2}'pgrep -f "name"
```

#### pid获取程序的详细信息

```php
lsof -p pidpwdx pid #获取该pid的进程启动的时候的目录，并不一定是恶意文件所在的路径，只是启动恶意文件的路径systemctl status pid #获取这个进程的 status信息cat /proc/pid/mapsls -al /proc/pid/exe
```

#### pid查看由进程起的线程

```php
ps H -T -p pidps -Lf pidtop -H -p pid -H#-H:选项可以显示线程htop#较为全面的展示线程,默认未安装pstree -acU#推荐,全面展示进程与线程间的关系
```

注：SPID就是线程ID，而CMD栏则显示了线程名称

![image-20211024153325234](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-12aed8a9242c1aa4a255530f13778c55fc21103d.png)

### 3.处理异常进程

#### 恶意文件样本采样

```php
scp -P 4588 remote@www.xxx.com:/usr/local/a /home/kali
```

注：

-P：指定SSH端口  
从远程服务器将a下载到本地的/home/kali

#### 进程查杀

进程有子进程

```php
ps ajfxsystemctl status
```

进程无子进程

```php
kill -9 pid
```

这样会直接杀死指定进程，但是，由这个进程产生的子进程不会被杀死

杀掉这个进程组

```php
kill -9 -pid
```

#### 守护进程

挖矿病毒为了保障挖矿程序的运行，通常会为挖矿程序设置守护进程，杀死守护进程与杀死普通进程并无区别

#### 线程查杀

很多木马病毒将恶意代码执行做到了线程级别，也就是说附到了现有正常业务的进程中，做一个线程，目前查杀一个进程中的线程风险比较大，**极可能会把进程搞崩掉**，需要与客户确认好再进行，杀死线程的方法和杀死进程一样

#### pid查看由进程起的线程

```php
ps -T -p pidps -aLf pid
```

#### 查看全部线程

```php
ps -eLFa
```

#### 4.删除恶意文件

#### 通过进程pid以及`/proc/`

我们已经定位到了文件的具体位置，接下来就是删除恶意文件  
查看文件占用

```php
lsof eval.sh
```

#### a和i属性导致文件不可删除

`a`属性文件：只能增加内容，不能修改之前的文件，不能删除文件

`i`属性文件：内容不能改变，文件不能删除  
可以使用 `chattr -a`和 `chattr -i`

案例分析
----

### SSH隐蔽登录

```php
ssh -T root@192.168.1.1 /usr/bin/bash -i
```

#### 分析

上面这条命令在日常渗透中，是红队的小伙伴进行登录操作会经常使用

因为这条命令它不分配伪终端的方式而不会被`w`和`lastlog`等命令记录

所以在某些时候，如果防守方在上机排查时，仅查看日志发现没有异常登录，却没有注意到是否存在异常网络连接时，就会判断为误报，给攻击者可乘之机

#### 处理

只要连接SSH端口就一定存在记录

可以从

```php
lsof -i 22
```

```php
ss -nt
```

这两条命令结果中发现了连接服务器的恶意IP地址

### 惯性密码

#### 分析

```php
aaRedis63090329
```

像这个密码，不难猜测密码为前后缀固定格式，中间四位为本机端口号，然后重新组合登录，会有很大的风险

#### 处置

密码复杂化和不可捉摸性

### pid查询失败

#### 分析

有些时候，我们无法通过top、ps命令查看进程pid

可能是攻击者

将`/proc/pid/`进行了隐藏

隐藏方法

```php
mkdir .hiddenmount -o bind .hidden /proc/PID
```

#### 处置

这个时候，我们可以查看挂载信息

```php
cat /proc/$$/mountinfo
```

### 文件删除

#### 分析

有时候，奇怪的文件名导致文件不可删除

从Windows向 Linux传输的文件或者攻击者恶意制造的文件，很多会有文件名乱码，无法直接通过乱码的文件名进行删除

#### 处置

##### 使用 inode进行删除

查看 inode

```php
ls -li xxx.sh
```

删除文件

```php
find ./* -inum inode -deletefind ./ -inum inode -exec rm {} \;find ./* -inum inode -exec rm -i {} \;(会有步确认是否删除)find ./* -inum inode -exec rm -f {} \;(强制删除)find ./* -inum inode |xargs rm -frm `find ./* -inum inode`
```

总结
--

不同事件有不同的角度去处理问题，一次事件可能包含多种类型的事件

希望可以帮到各位师傅！