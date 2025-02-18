一、Linux日志简介
-----------

Linux系统拥有非常灵活和强大的日志功能，可以保存几乎所有的操作记录，并可以从中检索出我们需要的信息。

Linux 日志都以明文形式存储，所以用户不需要特殊的工具就可以搜索和阅读它们。还可以编写脚本，来扫描这些日志，并基于它们的内容去自动执行某些功能。Linux 日志存储在 /var/log 目录中。这里有几个由系统维护的日志文件，但其他服务和程序也可能会把它们的日志放在这里。大多数日志只有root账户才可以读，不过修改文件的访问权限就可以让其他人可读。

### 1.日志文件

**日志默认存放位置：/var/log/**

**查看日志配置情况：more /etc/rsyslog.conf**

| 日志文件 | 说明 |
|---|---|
| /var/log/boot.log | 记录了系统在引导过程中发生的事件，就是Linux系统开机自检过程显示的信息。 |
| /var/log/syslog | 默认RedHat Linux不生成该日志文件，但可以配置/etc/syslog.conf让系统生成该日志文件。它和/etc/log/messages日志文件不同，它只记录警告信息，常常是系统出问题的信息，所以更应该关注该文件。 |
| /var/log/cron | 该日志文件记录crontab守护进程crond所派生的子进程的动作，前面加上用户、登录时间和PID，以及派生出的进程的动作。CMD的一个动作是cron派生出一个调度进程的常见情况。REPLACE（替换）动作记录用户对它的cron文件的更新，该文件列出了要周期性执行的任务调度。RELOAD动作在REPLACE动作后不久发生，这意味着cron注意到一个用户的cron文件被更新而cron需要把它重新装入内存。该文件可能会查到一些反常的情况。 |
| /var/log/cups | 记录打印信息的日志 |
| /var/log/dmesg | 记录了系统在开机时内核自检的信息，也可以使用dmesg命令直接查看内核自检信息 |
| /var/log/mailog | 记录了每一个发送到系统或从系统发出的电子邮件的活动。它可以用来查看用户使用哪个系统发送工具或把数据发送到哪个系统。 |
| /var/log/message | 记录系统重要信息的日志。这个日志文件中会记录Linux系统的绝大多数重要信息，如果系统出现问题时，首先要检查的就应该是这个日志文件 |
| /var/log/btmp | 记录错误登录日志，这个文件是二进制文件，不能直接vi查看，而要使用lastb命令查看 |
| /var/log/lastlog | 该日志文件记录最近成功登录的事件和最后一次不成功的登录事件，由login生成。在每次用户登录时被查询，该文件是二进制文件，需要使用**lastlog**命令查看，根据UID排序显示登录名、端口号和上次登录时间。如果某用户从来没有登录过，就显示为"\*\*Never logged in\*\*"。该命令只能以root权限执行。 |
| /var/log/wtmp | 该日志文件永久记录每个用户登录、注销及系统的启动、停机的事件。因此随着系统正常运行时间的增加，该文件的大小也会越来越大，增加的速度取决于系统用户登录的次数。该日志文件可以用来查看用户的登录记录，**last**命令就通过访问这个文件获得这些信息，并以反序从后向前显示用户的登录记录，last也能根据用户、终端 tty或时间显示相应的记录。 |
| /var/log/utmp | 该日志文件记录有关当前登录的每个用户的信息。因此这个文件会随着用户登录和注销系统而不断变化，它只保留当时联机的用户记录，不会为用户保留永久的记录。系统中需要查询当前用户状态的程序，如 **who、w、users、finger**等就需要访问这个文件。该日志文件并不能包括所有精确的信息，因为某些突发错误会终止用户登录会话，而系统没有及时更新 utmp记录，因此该日志文件的记录不是百分之百值得信赖的。 |
| /var/log/secure | 记录验证和授权方面的信息，只要涉及账号和密码的程序都会记录，比如SSH登录，su切换用户，sudo授权，甚至添加用户和修改用户密码都会记录在这个日志文件中 |
| /var/log/xferlog | 该日志文件记录FTP会话，可以显示出用户向FTP服务器或从服务器拷贝了什么文件。该文件会显示用户拷贝到服务器上的用来入侵服务器的恶意程序，以及该用户拷贝了哪些文件供他使用。 |
| /var/log/kernlog | RedHat Linux默认没有记录该日志文件。要启用该日志文件，必须在/etc/syslog.conf文件中添加一行：kern.\* /var/log/kernlog 。这样就启用了向/var/log/kernlog文件中记录所有内核消息的功能。该文件记录了系统启动时加载设备或使用设备的情况。一般是正常的操作，但如果记录了没有授权的用户进行的这些操作，就要注意，因为有可能这就是恶意用户的行为。 |

（/var/log/wtmp、/var/run/utmp、/var/log/lastlog）是日志子系统的关键文件，都记录了用户登录的情况。这些文件的所有记录都包含了时间戳。这些文件是按二进制保存的，故不能用less、cat之类的命令直接查看这些文件，而是需要使用相关命令通过这些文件而查看。其中，utmp和wtmp文件的数据结构是一样的，而lastlog文件则使用另外的数据结构，关于它们的具体的数据结构可以使用man命令查询。

who：who命令查询utmp文件并报告当前登录的每个用户。Who的缺省输出包括用户名、终端类型、登录日期及远程主机

w：w命令查询utmp文件并显示当前系统中每个用户和它所运行的进程信息

users：users用单独的一行打印出当前登录的用户，每个显示的用户名对应一个登录会话。如果一个用户有不止一个登录会话，那他的用户名把显示相同的次数

last：last命令往回搜索wtmp来显示自从文件第一次创建以来登录过的用户

### 2.日志优先级

| 级别 | 英文单词 | 中文释义 | 说明 |
|---|---|---|---|
| 0 | EMERG | 紧急 | 会导致主机系统不可用的情况。紧急情况，系统不可用（例如系统崩溃），一般会通知所有用户。 |
| 1 | ALERT | 警告 | 必须马上采取措施解决的问题。需要立即修复，例如系统数据库损坏。 |
| 2 | CRIT | 严重 | 比较严重的情况。危险情况，例如硬盘错误，可能会阻碍程序的部分功能。 |
| 3 | ERR | 错误 | 运行出现错误 |
| 4 | WARNING | 提醒 | 可能影响系统功能，需要提醒用户的重要事件 |
| 5 | NOTICE | 注意 | 不会影响正常功能，但是需要注意的事件 |
| 6 | INFO | 信息 | 一般信息 |
| 7 | DEBUG | 调试 | 程序或系统调试信息等 |

### **3.比较重要的几个日志**

后面是查看的命令

```php
登录失败记录：/var/log/btmp                //lastb 
最后一次登录：/var/log/lastlog             //lastlog   
登录成功记录: /var/log/wtmp                //last 
目前登录用户信息：/var/run/utmp             //w、who、users
登录日志记录：/var/log/secure  
历史命令记录：history  
仅清理当前用户：history -c
```

二、常用检查命令
--------

Linux下常用的shell命令如：find、grep 、egrep、awk、sed

**grep显示前后几行信息**

```php
标准unix/linux下的grep通过下面參数控制上下文：
grep -C 5 foo file 显示file文件里匹配foo字串那行以及上下5行
grep -B 5 foo file 显示foo及前5行
grep -A 5 foo file 显示foo及后5行
查看grep版本号的方法是
grep -V
```

**grep 查找含有某字符串的所有文件**

```php
 grep -rn "hello,world!" 
 * : 表示当前目录所有文件，也可以是某个文件名
 -r 是递归查找
 -n 是显示行号
 -R 查找所有文件包含子目录
 -i 忽略大小写
```

**显示一个文件的某几行**

```php
 cat input_file | tail -n +1000 | head -n 2000
 #从第1000行开始，显示2000行。即显示1000~2999行
```

**系统完整性**

通过 rpm 自带的 -Va 来校验检查所有的 rpm 软件包，查看哪些命令是否被替换了

```php
rpm -Va > rpm.log

# 如果一切均校验正常将不会产生任何输出，如果有不一致的地方，就会显示出来，输出格式是8位长字符串，每个字符都用以表示文件与RPM数据库中一种属性的比较结果 ，如果是. (点) 则表示测试通过。
验证内容中的8个信息的具体内容如下：
- S         文件大小是否改变
- M         文件的类型或文件的权限（rwx）是否被改变
- 5         文件MD5校验是否改变（可以看成文件内容是否改变）
- D         设备中，从代码是否改变
- L         文件路径是否改变
- U         文件的属主（所有者）是否改变
- G         文件的属组是否改变
- T         文件的修改时间是否改变
```

![image-20210423143121878](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-054c621c782a0052883a7f4baea6db71be935e2c.png)

**查看对外开放端口**

```php
ss -tnlp
ss -tnlp | grep ssh
ss -tnlp | grep ":22"

netstat -tnlp
netstat -tnlp | grep ssh
```

**防火墙**

```php
firewall-cmd --state                    # 显示防火墙状态
firewall-cmd --get-zones                # 列出当前有几个 zone
firewall-cmd --get-active-zones         # 取得当前活动的 zones
firewall-cmd --get-default-zone         # 取得默认的 zone
firewall-cmd --get-service              # 取得当前支持 service
firewall-cmd --get-service --permanent  # 检查下一次重载后将激活的服务

firewall-cmd --zone=public --list-ports # 列出 zone public 端口
firewall-cmd --zone=public --list-all   # 列出 zone public 当前设置
```

**用户**

```php
awk -F: '{if($3==0||$4==0)print $1}' /etc/passwd            # 查看 UID\GID 为0的帐号
awk -F: '{if($7!="/usr/sbin/nologin")print $1}' /etc/passwd # 查看能够登录的帐号
lastlog                                                     # 系统中所有用户最近一次登录信息
lastb                                                       # 显示用户错误的登录列表
users                                                       # 打印当前登录的用户，每个用户名对应一个登录会话。如果一个用户不止一个登录会话，其用户名显示相同次数
```

**计划任务和启动项**

```php
chkconfig                   # 查看开机启动服务命令
chkconfig --list | grep "3:启用\|3:开\|3:on\|5:启用\|5:开\|5:on"
ls /etc/init.d              # 查看开机启动配置文件命令
cat /etc/rc.local           # 查看 rc 启动文件
ls /etc/rc.d/rc[0~6].d
runlevel                    # 查看运行级别命令
crontab -l                  # 计划任务列表
ls -alh /var/spool/cron     # 默认编写的 crontab 文件会保存在 /var/spool/cron/用户名 下
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

**可疑文件**

查看敏感目录，如/tmp目录下的文件，同时注意隐藏文件夹，以“..”为名的文件夹具有隐藏属性，针对可疑文件查看创建修改时间。

```php
find / -ctime -2                # 查找72小时内新增的文件
find ./ -mtime 0 -name "*.jsp"  # 查找24小时内被修改的 JSP 文件
find / *.jsp -perm 4777         # 查找777的权限的文件
ls -a /tmp                      # 查看临时目录
strings /usr/sbin/sshd | egrep '[1-9]{1,3}.[1-9]{1,3}.'    # 分析 sshd 文件，是否包括IP信息
```

三、日志分析技巧
--------

### **A、/var/log/secure**

Red Hat 系的发行版是/var/log/secure。Debian 系的发行版是/var/log/auth.log。

定位哪些IP在爆破主机的root帐号和次数统计：

```php
# Red Hat 系的发行版
sudo grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
# Debian 系的发行版
sudo grep "Failed password for root" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | more
```

![image-20210423135508314](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b94c62e7621d0a49106106ac0d44e9f95ebd889.png)

定位有哪些IP在爆破（太长了）

```php
grep "Failed password" /var/log/secure|grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"|uniq -c |more
```

![image-20210423140254737](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d4f735d3b660d3ebd847ec7d9d2d98f8d89daec7.png)

爆破用户名有哪些（太长了）

```php
grep "Failed password" /var/log/secure|perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|uniq -c|sort -nr | more
```

![image-20210423140328361](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f2deabbcf2fb745482168d4d7757a3c37a1b40b.png)

爆破失败的次数

```php
grep -o "Failed password" /var/log/secure|uniq -c
```

![image-20210423135933551](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-218674f45ecaede6abdb5845f38410b18d0c6c16.png)

爆破失败的用户名次数统计

```php
grep "Failed password" /var/log/secure | awk {'print $9'} | sort | uniq -c | sort -nr
```

![image-20210423140155583](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4af7c323497fa64f575a8483dfafd3da92e57939.png)

爆破失败的ip次数统计

```php
sudo grep "Failed password for invalid user" /var/log/secure | awk '{print $13}' | sort | uniq -c | sort -nr | more
```

![image-20210423134858336](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-54fabc0e01b5a959aaa4fd0738493b1a544cfb24.png)

登录成功的IP有哪些：

```php
grep "Accepted " /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more
```

![image-20210423140532880](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9e62e45da2934948424bb1fab366626c10b0cacc.png)

登录成功的日期、用户名、IP：

```php
grep "Accepted " /var/log/secure | awk '{print $1,$2,$3,$9,$11}'
```

![image-20210423140600362](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e0a0d8f21311f4270ac177c93208b0bbe373470f.png)

```php
grep "Accepted " /var/log/secure* | awk '{print $1,$2,$3,$9,$11}'
```

![image-20210423142834565](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-287ea8615872338c7fabf248139be96cd4a34748.png)

增加一个用户：

```php
grep "useradd" /var/log/secure
```

![image-20210423142349705](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a960c68c5aadea39a15fe1cc4f2116415dc2d7c.png)

删除用户

```php
grep "userdel" /var/log/secure
```

![image-20210423142404851](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-abeefda440f1c68f72549a7c649876dc4d9988ba.png)

root权限用户、查看 UID\\GID 为0的帐号

```php
awk -F: '{if($3==0||$4==0)print $1}' /etc/passwd   
```

![image-20210423144409588](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b41fa022a72d55b33741b254236a657e9855d7b9.png)

查看能够登录的帐号

```php
awk -F: '{if($7!="/usr/sbin/nologin")print $1}' /etc/passwd
```

![image-20210423144552704](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87260e3f8b410d16c3e878a10ff2251274e83423.png)

### **B、/var/log/yum.log**

软件安装升级卸载日志：

```php
yum install gcc

[root@bogon ~]# more /var/log/yum.log

Jul 10 00:18:23 Updated: cpp-4.8.5-28.el7_5.1.x86_64
Jul 10 00:18:24 Updated: libgcc-4.8.5-28.el7_5.1.x86_64
Jul 10 00:18:24 Updated: libgomp-4.8.5-28.el7_5.1.x86_64
Jul 10 00:18:28 Updated: gcc-4.8.5-28.el7_5.1.x86_64
Jul 10 00:18:28 Updated: libgcc-4.8.5-28.el7_5.1.i686
```

四、日志工具
------

### 1.分割日志工具-logrotate

logrotate 程序是一个日志文件管理工具。用于分割日志文件，删除旧的日志文件，并创建新的日志文件，起到“转储”作用。可以节省磁盘空间。

日志转储也叫日志回卷或日志轮转。Linux中的日志通常增长很快，会占用大量硬盘空间，需要在日志文件达到指定大小时分开存储。

syslog 只负责接收日志并保存到相应的文件，但不会对日志文件进行管理，因此经常会造成日志文件过大，尤其是WEB服务器，轻易就能超过1G，给检索带来困难。

大多数Linux发行版使用 logrotate 或 newsyslog 对日志进行管理。logrotate 程序不但可以压缩日志文件，减少存储空间，还可以将日志发送到指定 E-mail，方便管理员及时查看日志。

如果你在服务器上面安装了mysql，httpd 或者其他应用服务后，logrotate 它会自动在 /etc/logrotate.d/ 下面创建对应的日志处理方式，基本是继承 logrotate.conf. 因此，不论是你服务器上面系统日志还是应用日志，面对日志量太大的问题，都可以使用 logrotate 进行设置处理.

#### **1、配置文件介绍**

Linux系统默认安装logrotate工具，它默认的配置文件在：

```php
/etc/logrotate.conf
/etc/logrotate.d/
```

logrotate.conf 才主要的配置文件，logrotate.d 是一个目录，该目录里的所有文件都会被主动的读入/etc/logrotate.conf中执行。

另外，如果 /etc/logrotate.d/ 里面的文件中没有设定一些细节，则会以/etc/logrotate.conf这个文件的设定来作为默认值。

Logrotate是基于CRON来运行的，其脚本是/etc/cron.daily/logrotate，日志轮转是系统自动完成的。

实际运行时，Logrotate会调用配置文件/etc/logrotate.conf。可以在/etc/logrotate.d目录里放置自定义好的配置文件，用来覆盖Logrotate的缺省值。

```php
[root@huanqiu_web1 ~]# cat /etc/cron.daily/logrotate
#!/bin/sh

/usr/sbin/logrotate /etc/logrotate.conf >/dev/null 2>&1
EXITVALUE=$?
if [ $EXITVALUE != 0 ]; then
    /usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"
fi
exit 0
```

如果等不及cron自动执行日志轮转，想手动强制切割日志，需要加-f参数；不过正式执行前最好通过Debug选项来验证一下（-d参数），这对调试也很重要：

```php
# /usr/sbin/logrotate -f /etc/logrotate.d/nginx
# /usr/sbin/logrotate -d -f /etc/logrotate.d/nginx
```

logrotate 命令格式：

```php
logrotate [OPTION...] <configfile>
-d, --debug ：debug模式，测试配置文件是否有错误。
-f, --force ：强制转储文件。
-m, --mail=command ：压缩日志后，发送日志到指定邮箱。
-s, --state=statefile ：使用指定的状态文件。
-v, --verbose ：显示转储过程。
```

根据日志切割设置进行操作，并显示详细信息：

```php
[root@huanqiu_web1 ~]# /usr/sbin/logrotate -v /etc/logrotate.conf

[root@huanqiu_web1 ~]# /usr/sbin/logrotate -v /etc/logrotate.d/php
```

根据日志切割设置进行执行，并显示详细信息,但是不进行具体操作，debug模式

```php
[root@huanqiu_web1 ~]# /usr/sbin/logrotate -d /etc/logrotate.conf

[root@huanqiu_web1 ~]# /usr/sbin/logrotate -d /etc/logrotate.d/nginx
```

查看各log文件的具体执行情况

```php
[root@fangfull_web1 ~]# cat /var/lib/logrotate.status
```

#### **2、切割介绍**

比如以系统日志/var/log/message做切割来简单说明下：

- 第一次执行完rotate(轮转)之后，原本的messages会变成messages.1，而且会制造一个空的messages给系统来储存日志；
- 第二次执行之后，messages.1会变成messages.2，而messages会变成messages.1，又造成一个空的messages来储存日志！

如果仅设定保留三个日志（即轮转3次）的话，那么执行第三次时，则 messages.3这个档案就会被删除，并由后面的较新的保存日志所取代！也就是会保存最新的几个日志。

日志究竟轮换几次，这个是根据配置文件中的dateext 参数来判定的。

看下logrotate.conf配置：

```php
# cat /etc/logrotate.conf
# 底下的设定是 "logrotate 的默认值" ，如果別的文件设定了其他的值，
# 就会以其它文件的设定为主
weekly          //默认每一周执行一次rotate轮转工作
rotate 4       //保留多少个日志文件(轮转几次).默认保留四个.就是指定日志文件删除之前轮转的次数，0 指没有备份
create         //自动创建新的日志文件，新的日志文件具有和原来的文件相同的权限；因为日志被改名,因此要创建一个新的来继续存储之前的日志
dateext       //这个参数很重要！就是切割后的日志文件以当前日期为格式结尾，如xxx.log-20131216这样,如果注释掉,切割出来是按数字递增,即前面说的 xxx.log-1这种格式
compress      //是否通过gzip压缩转储以后的日志文件，如xxx.log-20131216.gz ；如果不需要压缩，注释掉就行

include /etc/logrotate.d
# 将 /etc/logrotate.d/ 目录中的所有文件都加载进来

/var/log/wtmp {                 //仅针对 /var/log/wtmp 所设定的参数
monthly                    //每月一次切割,取代默认的一周
minsize 1M              //文件大小超过 1M 后才会切割
create 0664 root utmp            //指定新建的日志文件权限以及所属用户和组
rotate 1                    //只保留一个日志.
}
# 这个 wtmp 可记录用户登录系统及系统重启的时间
# 因为有 minsize 的参数，因此不见得每个月一定会执行一次喔.要看文件大小。
```

由这个文件的设定可以知道/etc/logrotate.d其实就是由/etc/logrotate.conf 所规划出来的目录，虽然可以将所有的配置都写入 /etc/logrotate.conf ，但是这样一来这个文件就实在是太复杂了，尤其是当使用很多的服务在系统上面时， 每个服务都要去修改 /etc/logrotate.conf 的设定也似乎不太合理了。

所以，如果独立出来一个目录，那么每个要切割日志的服务， 就可以独自成为一个文件，并且放置到 /etc/logrotate.d/ 当中。

其他重要参数说明：

```php
compress                            #通过gzip 压缩转储以后的日志
nocompress                          #不做gzip压缩处理
copytruncate                        #用于还在打开中的日志文件，把当前日志备份并截断；是先拷贝再清空的方式，拷贝和清空之间有一个时间差，可能会丢失部分日志数据。
nocopytruncate                      #备份日志文件不过不截断
create mode owner group             #轮转时指定创建新文件的属性，如create 0777 nobody nobody
nocreate                            #不建立新的日志文件
delaycompress                      #和compress 一起使用时，转储的日志文件到下一次转储时才压缩
nodelaycompress                    #覆盖 delaycompress 选项，转储同时压缩。
missingok                          #如果日志丢失，不报错继续滚动下一个日志
errors address                     #专储时的错误信息发送到指定的Email 地址
ifempty                            #即使日志文件为空文件也做轮转，这个是logrotate的缺省选项。
notifempty                         #当日志文件为空时，不进行轮转
mail address                       #把转储的日志文件发送到指定的E-mail 地址
nomail                             #转储时不发送日志文件
olddir directory                   #转储后的日志文件放入指定的目录，必须和当前日志文件在同一个文件系统
noolddir                           #转储后的日志文件和当前日志文件放在同一个目录下
sharedscripts                      #运行postrotate脚本，作用是在所有日志都轮转后统一执行一次脚本。如果没有配置这个，那么每个日志轮转后都会执行一次脚本
prerotate                          #在logrotate转储之前需要执行的指令，例如修改文件的属性等动作；必须独立成行
postrotate                         #在logrotate转储之后需要执行的指令，例如重新启动 (kill -HUP) 某个服务！必须独立成行
daily                              #指定转储周期为每天
weekly                             #指定转储周期为每周
monthly                            #指定转储周期为每月
rotate count                       #指定日志文件删除之前转储的次数，0 指没有备份，5 指保留5 个备份
dateext                            #使用当期日期作为命名格式
dateformat .%s                     #配合dateext使用，紧跟在下一行出现，定义文件切割后的文件名，必须配合dateext使用，只支持 %Y %m %d %s 这四个参数
size(或minsize) log-size           #当日志文件到达指定的大小时才转储，log-size能指定bytes(缺省)及KB (sizek)或MB(sizem).
当日志文件 >= log-size 的时候就转储。 以下为合法格式：（其他格式的单位大小写没有试过）
size = 5 或 size 5 （>= 5 个字节就转储）
size = 100k 或 size 100k
size = 100M 或 size 100M
```

#### 3、示例

**nginx日志切割一例**

```php
[root@huanqiu_web1 ~]# cat /etc/logrotate.d/nginx
/Data/logs/nginx/*/*log {
    daily
    rotate 365
    missingok
    notifempty
    compress
    dateext
    sharedscripts
    postrotate
    /etc/init.d/nginx reload
    endscript
}

[root@huanqiu_web1 ~]# ll /Data/logs/nginx/www.huanqiu.com/
..........
-rw-r--r-- 1 root root      1652 Jan  1 00:00 error.log-20170101.gz
-rw-r--r-- 1 root root      1289 Jan  2 00:00 error.log-20170102.gz
-rw-r--r-- 1 root root      1633 Jan  3 00:00 error.log-20170103.gz
-rw-r--r-- 1 root root      3239 Jan  4 00:00 error.log-20170104.gz
```

**php脚本切割一例：**

```php
[root@huanqiu_web1 ~]# cat /etc/logrotate.d/php
/Data/logs/php/*log {
    daily
    rotate 365
    missingok
    notifempty
    compress
    dateext
    sharedscripts
    postrotate
        if [ -f /Data/app/php5.6.26/var/run/php-fpm.pid ]; then
            kill -USR1 `cat /Data/app/php5.6.26/var/run/php-fpm.pid`
        fi
    endscript
    postrotate
        /bin/chmod 644 /Data/logs/php/*gz
    endscript
}

[root@huanqiu_web1 ~]# ll /Data/app/php5.6.26/var/run/php-fpm.pid
-rw-r--r-- 1 root root 4 Dec 28 17:03 /Data/app/php5.6.26/var/run/php-fpm.pid

[root@huanqiu_web1 ~]# cd /Data/logs/php
[root@huanqiu_web1 php]# ll
total 25676
-rw-r--r-- 1 root   root         0 Jun  1  2016 error.log
-rw-r--r-- 1 nobody nobody     182 Aug 30  2015 error.log-20150830.gz
-rw-r--r-- 1 nobody nobody     371 Sep  1  2015 error.log-20150901.gz
-rw-r--r-- 1 nobody nobody     315 Sep  7  2015 error.log-20150907.gz
```

**tomcat日志切割一例**

```php
[root@huanqiu-backup ~]# cat /etc/logrotate.d/tomcat
/Data/app/tomcat-7-huanqiu/logs/catalina.out {
rotate 14
daily
copytruncate
compress
notifempty
missingok
}

[root@huanqiu-backup ~]# ll /Data/app/tomcat-7-huanqiu/logs/catalina.*
-rw-r--r--. 1 root root     0 Jan 19 19:11 /Data/app/tomcat-7-huanqiu/logs/catalina.out
-rw-r--r--. 1 root root 95668 Jan 19 19:11 /Data/app/tomcat-7-huanqiu/logs/catalina.out.1.gz
```

**系统日志切割一例**

```php
[root@huanqiu_web1 ~]# cat /etc/logrotate.d/syslog
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    sharedscripts
    postrotate
    /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}

[root@huanqiu_web1 ~]# ll /var/log/messages*
-rw------- 1 root root 34248975 Jan 19 18:42 /var/log/messages
-rw------- 1 root root 51772994 Dec 25 03:11 /var/log/messages-20161225
-rw------- 1 root root 51800210 Jan  1 03:05 /var/log/messages-20170101
-rw------- 1 root root 51981366 Jan  8 03:36 /var/log/messages-20170108
-rw------- 1 root root 51843025 Jan 15 03:40 /var/log/messages-20170115
[root@huanqiu_web1 ~]# ll /var/log/cron*
-rw------- 1 root root 2155681 Jan 19 18:43 /var/log/cron
-rw------- 1 root root 2932618 Dec 25 03:11 /var/log/cron-20161225
-rw------- 1 root root 2939305 Jan  1 03:06 /var/log/cron-20170101
-rw------- 1 root root 2951820 Jan  8 03:37 /var/log/cron-20170108
-rw------- 1 root root 3203992 Jan 15 03:41 /var/log/cron-20170115
[root@huanqiu_web1 ~]# ll /var/log/secure*
-rw------- 1 root root  275343 Jan 19 18:36 /var/log/secure
-rw------- 1 root root 2111936 Dec 25 03:06 /var/log/secure-20161225
-rw------- 1 root root 2772744 Jan  1 02:57 /var/log/secure-20170101
-rw------- 1 root root 1115543 Jan  8 03:26 /var/log/secure-20170108
-rw------- 1 root root  731599 Jan 15 03:40 /var/log/secure-20170115
[root@huanqiu_web1 ~]# ll /var/log/spooler*
-rw------- 1 root root 0 Jan 15 03:41 /var/log/spooler
-rw------- 1 root root 0 Dec 18 03:21 /var/log/spooler-20161225
-rw------- 1 root root 0 Dec 25 03:11 /var/log/spooler-20170101
-rw------- 1 root root 0 Jan  1 03:06 /var/log/spooler-20170108
-rw------- 1 root root 0 Jan  8 03:37 /var/log/spooler-20170115
```

### 2.日志分析工具-logwatch

安装

```php
yum -y install logwatch
```

安装完成之后，需要手工生成 logwatch 的配置文件。默认配置文件是 /etc/logwatch/conf/logwatch.conf，不过这个配置文件是空的，需要把模板配置文件复制过来。命令如下：

```php
cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/logwatch.conf
#复制配置文件
```

这个配置文件的内容中绝大多数是注释，我们把注释去掉，那么这个配置文件的内容如下所示

```php
[root@localhost ~]# vi /etc/logwatch/conf/logwatch.conf
#查看配置文件
LogDir = /var/log
#logwatch会分析和统计/var/log/中的日志
TmpDir = /var/cache/logwatch
#指定logwatch的临时目录
MailTo = root
#日志的分析结果，给root用户发送邮件
MailFrom = Logwatch
#邮件的发送者是Logwatch，在接收邮件时显示
Print =
#是否打印。如果选择“yes”，那么日志分析会被打印到标准输出，而且不会发送邮件。我们在这里不打印，#而是给root用户发送邮件
#Save = /tmp/logwatch
#如果开启这一项，日志分析就不会发送邮件，而是保存在/tmp/logwatch文件中
#如果开启这一项，日志分析就不会发送邮件，而是保存在/tmp/logwatch文件中
Range = yesterday
#分析哪天的日志。可以识别“All”“Today”“Yesterday”，用来分析“所有日志”“今天日志”“昨天日志”
Detail = Low
#日志的详细程度。可以识别“Low”“Med”“High”。也可以用数字表示，范围为0～10，“0”代表最不详细，“10”代表最详细
Service = All
#分析和监控所有日志
Service = "-zz-network"
#但是不监控“-zz-network”服务的日志。“-服务名”表示不分析和监控此服务的日志
Service = "-zz-sys"
Service = "-eximstats"
```

这个配置文件基本不需要修改，它就会默认每天执行。它为什么会每天执行呢？logwatch 一旦安装，就会在 /etc/cron.daily/ 目录中建立“0logwatch”文件，用于在每天定时执行 logwatch 命令，分析和监控相关日志。

如果想要让这个日志分析马上执行，则只需执行 logrotate 命令即可。命令如下：

![image-20210423165245733](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3045e8274c76f3ce5822fba7d5184994261b1db.png)

之前创建又删除的用户backdoor可以监控到

![image-20210423165346399](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-50f59b7bebdad268ad7aa220ae245d7b94d4b16f.png)

五、日志清除
------

清除历史命令

```php
histroy -r          #删除当前会话历史记录
history -c          #删除内存中的所有命令历史
rm .bash_history   #删除历史文件中的内容
HISTZISE=0          #通过设置历史命令条数来清除所有历史记录
```

完全删除日志文件（下面任意一个即可）

```php
cat /dev/null > filename
: > filename
> filename
echo "" > filename
echo > filename
```

删除当天日志

```php
sed  -i '/当天日期/'d  filename
```

篡改日志

```php
将所有170.170.64.17ip替换为127.0.0.1
sed -i 's/170.170.64.17/127.0.0.1/g'
```

日志一键清除脚本

```php
#!/usr/bin/bash
echo > /var/log/syslog
echo > /var/log/messages
echo > /var/log/httpd/access_log
echo > /var/log/httpd/error_log
echo > /var/log/xferlog
echo > /var/log/secure
echo > /var/log/auth.log
echo > /var/log/user.log
echo > /var/log/wtmp
echo > /var/log/lastlog
echo > /var/log/btmp
echo > /var/run/utmp
rm ~/./bash_history
history -c
```

参考（站在巨人的肩膀上登高望远）:

[https://mp.weixin.qq.com/s/fWlux47luH\_zvYpXcZXeYA](https://mp.weixin.qq.com/s/fWlux47luH_zvYpXcZXeYA)

<https://mp.weixin.qq.com/s/SWMWVezAVzykkjTuRRDxJw>

[https://mp.weixin.qq.com/s/TlCyifwRrzKFx7jJkJlF\_A](https://mp.weixin.qq.com/s/TlCyifwRrzKFx7jJkJlF_A)

<https://mp.weixin.qq.com/s/dDErpPwEw3ZiN4LlkaWO0Q>

<https://mp.weixin.qq.com/s/vy8hoALDiQdN16iRFawAZQ>

<https://www.cnblogs.com/llife/p/11478952.html>

<https://mp.weixin.qq.com/s/14R7VS9eSD3cNNNpRlR3bg>

<http://www.found5.com/view/1010.html>

<https://mp.weixin.qq.com/s/YHo4YSSF4BQ6Yrd3O3IrqA>