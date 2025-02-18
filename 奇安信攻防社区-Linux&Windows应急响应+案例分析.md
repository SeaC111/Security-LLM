应急响应
====

Linux
-----

### 文件

> ls -alt #查找72小时内新增的文件
> 
> find / -ctime -2 #文件日期、新增文件、可疑/异常文件、最近使用文件、浏览器下载文件
> 
> /var/run/utmp #有关当前登录用户的信息记录
> 
> /etc/passwd #用户列表
> 
> /tmp #临时目录
> 
> find / \*.jsp -perm 4777 #查找777的权限的文件(可以将文件名进行修改`php`、`py`、`html`、`sh`等)
> 
> 隐藏文件`.xxxx`
> 
> 命令目录：`/usr/bin`、`/usr/sbin`

### 日志

/var/log/messages 包含整体系统信息，其中也包含系统启动期间的日志。此外，mail，cron，daemon，kern和auth等内容也记录在var/log/messages日志中。  
​  
/var/log/dmesg 包含内核缓冲信息。在系统启动时，会在屏幕上显示许多与硬件有关的信息。可以用dmesg查看它们。  
​  
/var/log/auth.log 包含系统授权信息，包括用户登录和使用的权限机制等  
​  
/var/log/boot.log 包含系统启动时的日志  
​  
/var/log/daemon.log 包含各种系统后台守护进程日志信息  
​  
/var/log/dpkg.log 包含安装或dpkg命令清除软件包的日志  
​  
/var/log/kern.log 包含内核产生的日志，有助于在定制内核时解决问题  
​  
/var/log/lastlog 记录所有用户的最近信息。这不是一个ASCII文件，因此需要用lastlog命令查看内容  
​  
/var/log/maillog /var/log/mail.log 包含来着系统运行电子右键服务器的日志信息。  
​  
/var/log/user.log 包含所有等级用户信息的日志  
​  
/var/log/secure 包含验证和授权方面信息。例如，sshd会将所有信息记录(其中包括失败登录)在这里  
。  
/var/log/faillog 包含用户登录失败信息。此外，错误登录命令也会记录在本文件中  
​  
/var/log/lastlog 文件记录用户最后登录的信息，即lastlog

**查看爆破主机的ROOT账号的IP：** `grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort`

**查看登录成功的日期、用户名及IP：** `grep "Accepted " /var/log/secure* | awk '{print $1,$2,$3,$9,$11}'`

### 用户

`/etc/shadow` **密码登陆相关信息**

`uptime` **查看用户登陆时间**

`/etc/sudoers` **查看sudo用户列表**

`awk -F: '{if($3==0)print $1}' /etc/passwd` **查看UID为0的帐号**

`lastb` **用户错误的登录列表**

### 进程

> lsof 查看当前全部进程
> 
> lsof -i:1677 查看指定端口对应的程序
> 
> lsof -p 1234 检查pid号为1234进程调用情况
> 
> lsof -g pid
> 
> strace -f -p 1234 跟踪分析pid号为1234的进程
> 
> ps -aux或ps -ef

### 端口

> netstat -anpt

### 自启动

~/.bashrc  
rc.local  
/etc/init.d  
chkconfig  
chkconfig --list | grep "3:on|5:on"  
/etc/init.d/rc.local  
/etc/rc.local  
/etc/init.d/ 开机启动项  
/etc/cron\* 定时任务

### 计划任务

crontab -l  
crontab /etc/cron\*  
crontab -u root -l  
cat /etc/crontab  
ls /etc/cron.\*  
/var/spool/cron/\*  
/etc/crontab  
/etc/cron.d/\*  
/etc/cron.daily/\*  
/etc/cron.hourly/\*  
/etc/cron.monthly/\*  
/etc/cron.weekly/  
/etc/anacrontab  
/var/spool/anacron/\*  
/var/log/cron\*

### 别名

可以使用`alias`命令来查看当前用户所定义的别名

### MISC

#### `stat`

> `stat` 可以显示文件的大小、创建时间、修改时间、访问时间、权限、所有者等等信息
> 
> `-c`：指定输出格式
> 
> `-f`：指定输出文件系统相关信息。
> 
> `-L`：对符号链接解引用。
> 
> `-t`：指定时间格式。

![image-20230321163307688.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ee0e13e1cf10a8a492336bcc0502346ee756669a.png)

`Size`表示文件大小，`Access`表示访问时间，`Modify`表示修改时间，`Change`表示属性修改时间，`Uid`表示所有者的用户ID，`Gid`表示所有者的组ID等等。

#### echo $PATH

用于显示当前用户的环境变量`PATH`的值。

![image-20230322092351230.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-849da896a61f25f89213cffc69d5f951bfb994a5.png)

#### ./rpm -Va &gt; rpm.log

是一个在Linux系统中常用的命令，用于检查系统中已安装的软件包的完整性，并将检查结果输出到指定的日志文件中

#### kill -9

`kill -9`是一个在Linux和Unix系统中常用的命令，用于强制终止一个正在运行的进程。

`kill`命令用于向指定的进程发送信号，以改变其状态或终止其执行。

`-9`参数表示发送`SIGKILL`信号，该信号可以强制终止进程的执行，即使进程正在执行一些关键任务或者处于死锁状态，也可以强制终止它的执行

`ps aux`查看当前系统中正在运行的进程列表

#### chattr –i

用于修改文件或目录的属性，将其设置为**不可修改**（immutable）。

#### rm

`rm`是一个在Linux和Unix系统中常用的命令，用于删除文件或目录。

`-r`参数,删除一个目录及其下面的所有文件和子目录

#### setfacl

用于设置文件或目录的访问控制列表（ACL）。

`getfacl`命令查看文件或目录的ACL信息

#### lsattr

`lsattr`是一个在Linux系统中常用的命令，用于显示文件或目录的属性。

`lsattr`命令会列出文件或目录的特殊属性信息，其中每个属性用一个字符来表示。常见的属性包括：

- `i`：不可修改属性；
- `a`：只追加属性；
- `c`：压缩属性；
- `e`：扩展属性；
- `s`：安全删除属性；
- `u`：未分配块属性。

### 实例1：

**ssh**

ssh后门快速判断：

> string /usr/bin/.sshd | egrep '\[1-9\]{1,3}.\[1-9\]{1,3}.'

检查SSH后门：

> 1. 比对ssh的版本 `ssh -V`
> 2. 查看ssh配置文件和/usr/sbin/sshd的时间 `stat /usr/sbin/sshd`
> 3. `strings` 检查/usr/sbin/sshd 是否有邮件西信息
> 4. 通过strace监控sshd进程读写文件的操作
>     
>     `ps axu | grep sshd | grep -v grep`查看sshd服务的进程号
>     
>     ## root `65530` 0.0 0.1 48428 1260 ? Ss 13:43 0:00 /usr/sbin/sshd
>     
>     `strace -o aa -ff -p 65530` 对进程进行监控

windows
-------

### 文件

`C:\Documents and Settings\Administrator\Recent`是Windows系统中存储最近使用的文件和文件夹的目录。该目录下存储着用户最近打开或使用过的文件和文件夹的快捷方式，便于用户快速访问。

`%UserProfile%\Recent`是Windows系统中存储当前用户最近使用的文件和文件夹的目录。该目录下存储着当前用户最近打开或使用过的文件和文件夹的快捷方式，便于用户快速访问。

### 日志

打开`事件查看器`：`win`键 + r，输入`eventvwr.msc`

#### 服务器日志

FTP连接日志和HTTPD事务日志：`%systemroot%\system32\LogFiles`

IIS日志默认存放在`System32\LogFiles`目录下，使用`W3C`拓展格式

#### 操作系统日志

登录成功的所有事件：

> LogParser.exe -i:EVT –o:DATAGRID “SELECT \* FROM c:\\Security.evtx where EventID=4624″

指定登录时间范围的事件：

> LogParser.exe -i:EVT –o:DATAGRID “SELECT \* FROM c:\\Security.evtx where TimeGenerated&gt;’2018- 06-19 23:32:11′ and TimeGenerated&lt;’2018-06-20 23:34:00′ and EventID=4624″

提取登录成功的用户名和IP：

> LogParser.exe -i:EVT –o:DATAGRID “SELECT EXTRACT\_TOKEN(Message,13,’ ‘) as EventType,TimeGenerated as LoginTime,EXTRACT\_TOKEN(Strings,5,’|') as Username,EXTRACT\_TOKEN(Message,38,’ ‘) as Loginip FROM c:\\Security.evtx where EventID=4624″

登录失败的所有事件：

> LogParser.exe -i:EVT –o:DATAGRID “SELECT \* FROM c:\\Security.evtx where EventID=4625″

系统历史开关机记录：

> LogParser.exe -i:EVT –o:DATAGRID “SELECT TimeGenerated,EventID,Message FROM c:\\System.evtx where EventID=6005 or EventID=6006″

### 账号

`lusrmgr.msc` 查看账户变化

`net user` 列出当前登录账户

`wmic UserAccount get` 列出当前系统所有账户

在Windows系统中，可以使用**命令行**或**注册表编辑器**来隐藏或克隆账户

**隐藏账户**：

- 使用命令行
    
    > net user username\[要隐藏的用户名\] /active:no

这样的操作会将指定账户的状态设置为不活动状态，从而在登录界面中隐藏该账户

- 使用注册表编辑器(`win`键 + r，再输入`regedit`)
    
    > 打开注册表找到以下路径
    > 
    > `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`

在`UserList`下创建一个新的DWORD值，命名为要隐藏的账户名称，值设为0即可。

**克隆账户**

- 使用命令行
    
    其中`oldusername`为要克隆的账户名称，`newusername`为新建账户的名称
    
    > - net user newusername /add
    > - net localgroup administrators newusername /add
    > - reg copy "HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\SID-from-oldusername" "HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\SID-from-newusername" /s

这会创建一个新的账户，并将其添加到管理员组中。然后，将旧账户的注册表信息复制到新账户中，从而复制其设置和配置

- 使用注册表
    
    找到以下路径：
    
    > HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList

复制要克隆账户的SID子项，将其命名为新建账户的SID，并修改以下键值：

> ProfileImagePath：将其值修改为新建账户的用户文件夹路径；
> 
> Sid：将其值修改为新建账户的SID；

然后在`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`下创建一个新的DWORD值，命名为新建账户的名称，值设为0即可。

### 进程

**tasklist /svc | findstr pid**

- `tasklist`命令用于列出当前正在运行的进程及其相关信息。
- `/svc`参数用于显示与每个进程相关联的服务信息。
- `|`符号是管道符号，用于将前面命令的输出作为后面命令的输入。
- `findstr`命令用于在输出中查找包含指定字符串的行。
- `pid`是一个占位符，表示需要替换为要查找的进程ID。

**netstat -ano**

用于显示当前计算机的网络连接状态和进程信息

- `netstat`命令用于显示当前计算机的网络连接状态。
- `-a`参数用于显示所有的网络连接，包括监听连接、已连接和未连接。
- `-n`参数用于显示IP地址和端口号，而不是域名和服务名。
- `-o`参数用于显示与每个连接相关联的进程ID。

**会列出所有当前计算机的网络连接状态，包括本地和远程IP地址、端口号、连接状态以及与每个连接相关联的进程ID**

**wmic process | find "Proccess Id"**

是一个Windows命令行命令，用于查找当前正在运行的进程ID

- `wmic process`命令用于列出当前正在运行的进程信息。
- `|`符号是管道符号，用于将前面命令的输出作为后面命令的输入。
- `find`命令用于在输出中查找包含指定字符串的行。
- `"Process Id"`是要查找的字符串，表示需要查找包含进程ID的行。

**msinfo32**

`msinfo32`是Windows系统中的一个系统信息工具，用于查看计算机硬件和软件配置信息

- 运行`msinfo32`之后，会打开“系统信息”窗口，其中包含了很多关于计算机的详细信息，包括操作系统信息、硬件设备信息、系统组件信息、软件环境信息等。

**wmic process get caption,commandline /value**

用于获取当前正在运行的进程的名称和命令行信息

- `wmic process`命令用于列出当前正在运行的进程信息。
- `get caption,commandline`参数用于获取进程的名称和命令行信息。
- `/value`参数用于以键值对（Key=Value）的形式显示输出结果。

### 端口

**netstat -ano**

- `-a`参数用于显示所有的网络连接，包括监听连接、已连接和未连接。
- `-n`参数用于显示IP地址和端口号，而不是域名和服务名。
- `-o`参数用于显示与每个连接相关联的进程ID。

![image-20230322092351230.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-62b9d90ba23fc6989c29206a85d1c745d2dfa456.png)  
`状态的类型`

`CLOSED`：无连接活动或正在进行 `LISTEN`：监听中等待连接 `SYN_RECV`：服务端接收了SYN `SYN_SENT`：请求连接等待确认 `ESTABLISHED`：连接建立数据传输 `FIN_WAIT1`：请求中止连接，等待对方FIN `FIN_WAIT2`：同意中止，请稍候 `ITMED_WAIT`：等待所有分组死掉 `CLOSING`：两边同时尝试关闭 `TIME_WAIT`：另一边已初始化一个释放 `LAST_ACK`：等待原来的发向远程TCP的连接中断请求的确认 `CLOSE-WAIT`：等待关闭连接

### 自启动

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx(ProfilePath)\Start Menu\Programs\Startup` 启动项
    
    msconfig 启动选项卡
    
    gpedit.msc 组策略编辑器
    
    开始&gt;所有程序&gt;启动
    
    msconfig-启动

### 计划任务

- C:\\Windows\\System32\\Tasks\\
- C:\\Windows\\SysWOW64\\Tasks\\
- C:\\Windows\\tasks\\
- schtasks
- taskschd.msc
- at

开始-设置-控制面板-任务计划

### misc

- 查看指定时间范围包括上传文件夹的访问请求：
    
    `findstr /s /m /I “UploadFiles” *.log`
- 关键信息是x.js
    
    `findstr /s /m /I “x.js” *.asp`

被感染后的临时处置办法
-----------

**被感染主机：**

（1） 立即对被感染主机进行隔离处置，禁用所有有线及无线网卡或直接拔掉 网线，防止病毒感染其他主机；

（2） 禁止在被感染主机上使用 U 盘、移动硬盘等可执行摆渡攻击的设备； **未被感染主机：**

（1） 关闭 SSH、RDP 等协议，并且更改主机密码；

（2） 备份系统重要数据、且文件备份应与主机隔离；

（3） 禁止接入 U 盘、移动硬盘等可执行摆渡攻击的设备；

⭐事件排查\[知识点\]
------------

### windows排查

#### 文件排查

- 开机启动有无异常文件

`开始`-&gt;`运行`-&gt;`msconfig`

- 各个盘下的temp(tmp)相关目录下查看有无异常文件：windows产生的临时文件

![image-20230322164743261.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d291123517bddfb213a04fdc6b55da1a12117c21.png)

- Recent是系统文件夹，里面存放着你最近使用的文档的快捷方式，查看用户recent相关文件，通过分析最近打开分析可疑文件：

\\==`开始`-&gt;`运行`-&gt;`%UserProfile%\Recent`\\==

- 根据文件夹内文件列表时间进行排序，查找可疑文件。当然也可以搜索指定日期范围的文件夹文件

![image-20230323142647363.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7d42b3d67ccc7ffa9217465289b5af3f3f92b114.png)

查看文件时间，创建时间、修改时间、访问时间，黑客通过菜刀类工具改变的是修改时间。若以如果修改时间在创建时间之前明显是可疑文件

![image-20230324104029889.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e533134ba0ec88f17ce1d2ae1bee59350b782ee5.png)

#### 进程排查

- netstat -ano 查看目前的网络连接，定位可疑的ESTABLSHED
    
    netstat 显示网络连接、路由表和网络接口信息；
    
    > -a 显示所有网络连接、路由表和网络接口信息 -n 以数字形式显示地址和端口号 -o 显示与每个连接相关的所属进程 ID -r 显示路由表 -s 显示按协议统计信息、默认地、显示 IP
    
    常见的状态说明：
    
    > LISTENING 侦听状态 ESTABLISHED 建立连接 CLOSE\_WAIT 对方主动关闭连接或网络异常导致连接中断

![image-20230324104353265.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f90e37e2ca9920c6c55bb84ed9dd40ea400d57a7.png)

- 根据netstat定位出的pid，再通过`tasklist`命令进行进程定位
    
    tasklist 显示运行在本地或远程计算机上的所有进程

![image-20230324104528684.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ea847d4a760927ddfc11c5649f22de88452eb54c.png)

- 根据`wmic process`获取进程的全路径\[任务管理器也可以定位到进程路径\]

![image-20230324104651721.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5ef010ed6a4952e7eae42ba29553b4c7b2c72df8.png)

![image-20230324104700411.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9212dc29d1ae79998a0fb45ba9caddeadb1f3d75.png)

#### 系统信息排查

- 查看环境变量的设置
    
    \\==我的电脑==-&gt;==属性==-&gt;==高级系统设置==-&gt;==高级==-&gt;==环境变量==

![image-20230324104953539.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-53bc2f00e79b931b28c353ae52fe1fa3072e54f9.png)

```php
排查内容：

> temp变量的所在位置的内容；后缀映射PATHEXT是否包含有非windows的后缀；有没有增加其他的路径到PATH变量中（对用户变量和系统变量都要进行排查）；
```

- windows计划任务
    
    ==程序==-&gt;==附件==-&gt;==系统工具==-&gt;==任务计划程序==

![image-20230324105226948.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-433891844822c998c5ecb4e5bc9d7fc307d45874.png)

- windows账号信息，如何隐藏账号等

\\==开始==-&gt;==运行==-&gt;==compmgmt.msc==-&gt;==本地用户和组==-&gt;==用户==

（用户名以`$`结尾的为隐藏用户，如：admin$）

![image-20230324105834103.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a9ce0fcf7adcf673353ddbd848b0802e643b9590.png)

命令行方式：net user，可直接收集用户信息（此方法看不到隐藏用户），若需查看某个用户的详细信息，可使用命令==-&gt;net user username==

![image-20230324105955037.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5e1a2c3269e6097d910d19eeb203b2e66a6e53ff.png)

- 查看当前系统用户的会话
    
    使用==-&gt;query user==查看当前系统的会话，比如查看是否有人使用远程终端登录服务器；

![image-20230324110110732.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3864150c72fa1e5a17ed4decda9948bdadded310.png)

```php
\==logoff==踢出该用户；
```

![image-20230324110136136.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-28075bd7e00599f1ff2b965ba83ec7f2361f3cf3.png)

- 查看==systeminfo==信息，系统版本以及补丁信息

![image-20230324110330425.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3221ac8c9dc2c1e8ca5da54405ae2596cbc6f666.png)

#### 日志排查

> 打开事件管理器

\\==开始==-&gt;==管理工具==-&gt;==事件查看==

\\==开始==-&gt;==运行==-&gt;==eventvwr==

![image-20230328104930942.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5a0494c1f051a6cf43622269976b8e8ef48ef545.png)

> 主要分析安全日志，可以借助自带的筛选功能

![image-20230328105152945.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7e28b2ac07867a52d528142089ce61fee4a3d5c9.png)

![image-20230328105158870.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3983448d832ab1c52d1e0ecac7ff5e7b5c6fc02d.png)

![image-20230328105206098.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-021941a641877dd768259a4c4701968605e3c7e3.png)

> 可以把日志导出为文本格式，然后使用`notepad++`打开，使用正则模式去匹配远程登录过的ip地址，在界定事件日期范围的基础

正则：

\\==((?:(?:25\[0-5\]|2\[0-4\]\\d|((1\\d{2})|(\[1-9\]?\\d))).){3}(?:25\[0-5\]|2\[0-4\]\\d|((1\\d{2})|(\[1-9\]?\\d))))==

![image-20230328105404236.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a17c4f2054f53c0c844dee96fea1a7d545361f19.png)

这样就可以把界定事件日期事件快速检索出来进行下一步的分析

### Linux排查

#### 文件排查

- 铭感目录的文件分析\[类/tmp目录，命令目录/usr/bin /usr/sbin等\]
    
    ls 用来显示目标列表
    
    > -a 显示所有档案及目录（ls 内定将档案名或目录名称为“.”的视为影藏，不会列出）； -C 多列显示输出结果。这是默认选项； -l 以长格式显示目录下的内容列表。输出的信息从左到右依次包括文件名，文件类型、权限模式、 硬连接数、所有者、组、文件大小和文件的最后修改时间等； -t 用文件和目录的更改时间排序；
- 查看tmp目录下的文件-&gt;==ls -alt /tmp/==

![image-20230328134301891.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-deb9de497315fffd09e87c202e784d412e5c9e71.png)

如图发现当前目录下出现了异常文件，疑似挖矿程序病毒：

![image-20230328134421650.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f5abcbfdf9da45424284f2a76c7a5a904ba14ec3.png)

对已发现的恶意文件进行分析，查看`559.sh`脚本内容：脚本先是杀掉服务器上cpu占用大于20%的进程，然后从远程27.155.87.26（福建，黑客所控制的一个IDC服务器）下载了病毒程序并执行；

![image-20230328134757735.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-87b7e57356f7d56eaea6143353dc6e5499a3f3a4.png)

- 查看开机启动项内容-&gt;==ls -alt /etc/init.d==，/etc/init.d是/etc/rc.d/init.d的软链接

![image-20230328135021168.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7a7807126b8edc1d4bc6064208856c9b9588e60d.png)

- 按事件排序查看指定目录下文件-&gt;==ls -alt | head -n 10==

![image-20230328135104761.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f8537bdb7f47fe982e4cd1daa361ce4c9aef0564.png)

针对可疑文件可以使用stat进行创建改事件、访问时间的详细查看，若修改时间距离事件日期接近，有线性关联，说明可能被篡改或者其他

![image-20230328135505986.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3d5ec60e02f92357a5f7c3f7f0b61471b5a299a4.png)

![image-20230328135514634.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b1da9e25dd5f7cff3ce16892f668f4aaaed25177.png)

- 查看历史命令记录文件==~/bash\_history==
    
    查找==~bash\_history==命令执行记录，主要分析是否有账户执行过恶意操作系统；命令在linux系统里，只要执行过命令的用户，那么在这个用户的HOME目录下，都会有一个==~bash\_history==的文件记录着这个用户都执行过的命令

![image-20230328140059571.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-20d21aedd22c9dbb5a9ffd756103d7a77f8da053.png)

所以若是出现了安全事故，可以通过查看用户的历史记录来排查用户是否执行过恶意命令，然后再往下进行排查

- 查看操作系统用户信息文件==/etc/passwd==

/etc/passwd 这个文件是保存着这个 linux 系统所有 用户的信息，通过查看这个文件，我们就可以尝试查找有没有攻击者所创建的用 户，或者存在异常的用户

主要关注的是第 3、4 列的用户标识号和组标识号，和倒数一二列的用户主目录和命令解析程序

一般来说最后一列命令解析程序如果是设置为 nologin 的话，那么表示这个用户是不能登录的，所以可以结合我们上面所说的 bash\_history 文件的排查方法

> 首先在/etc/passwd 中查找命令解释程序不是 nologin 的用户，然后再到这些用户的用户主目录里，找到bash\_history，去查看这个用户有没执行过恶意命令。

![image-20230328140504636.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0e30b613f6c59a19ef73df1411a71225f6c0a05d.png)

/etc/passwd 中一行记录对应着一个用户，每行记录又被冒号(:)分隔为 7 个字段， 其格式和具体含义如下：

\\==用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录 Shell==

- 查看新增文件
    
    find：在指定目录下查找文件

![image-20230328140708673.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9cb9f1b7542bde3798746aa74d5629cdd45c33ac.png)

\\==find ./ -mtime 0 -name "\*.php"==（查找 24 小时内被修改的 php 文件）

![image-20230328140734942.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0e0541ce278684fa66a166b568febce026b51e95.png)

\\==find / -ctime 2==（查找 72 小时内新增的文件）

![image-20230328140805204.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2de1b03373f1abc5057e611e59d46d1f1dc1e607.png)

> ps：-ctime内容未改变权限时候也可以查出

- 特殊权限的文件查看

查找777的权限文件-&gt;==find /\*.jsp -perm 4777==

![image-20230328141013799.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7d2b35c8b85143c378a78a251e33af189290c49b.png)

- 隐藏的文件（以“.”开头的是具有隐藏属性的文件）

![image-20230328141056264.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-db168786e4ee36671054bf66ed55422b1a444fe4.png)

> ps：在文件分析过程中，手工排查频率较高的命令是`find、grep、ls`核心目的是为了关联推理出可疑文件

- 查看分析任务计划

\\==crontab -u &lt; -l，-r，-e &gt;==

![image-20230328142833048.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-21cfa29891f24f7f9e05cdc52ce3ef5795736859.png)

通过crontab -l查看当前的任务计划有哪些，是否有后门木马程序启动相关信息

查看etc目录任务计划相关文件，ls /etc/cron\*

![image-20230328143430131.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3f508c5d3e64b2cdc2df9dda29dea08a314cdbdf.png)

#### 进程排查

\\==top==

（1）使用 top 命令实时动态地查看系统的整体运行情况，主要分析 CPU 和内存 多的进程，是一个综合了多方信息监测系统性能和运行信息的实用工具

![image-20230328144111895.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-8c9eb7771f16f741e9c64f056e4ce1e6fbc6ea29.png)

字段含义如下表：

| 列名 | 含义 |
|---|---|
| PID | 进程id |
| PPID | 父进程id |
| UID | 进程所有者的用户id |
| USER | 进程所有的用户名 |
| GROUP | 进程所有者的组名 |
| TTY | 启动进程的终端名 |
| PR | 优先级 |
| NI | nice值；负值表示高优先级，正值表示低优先级 |
| RES | 进程使用的、未被换出的物理内存大小，单位kb。RES=CODE+DATA |
| SHR | 共享内存大小，单位 kb |
| S | 进程状态： D=不可中断的睡眠状态 R=运行 S=睡眠 T=跟踪/停止 Z=僵尸进程 |
| %CPU | 上次更新到现在的 CPU 时间占用百分比 |
| %MEM | 进程使用的物理内存百分比 |
| TIME | 进程使用的 CPU 时间总计，单位秒 |
| TIME+ | 进程使用的 CPU 时间总计，单位 1/100 秒 |
| COMMAND | 命令名/命令行 |

\\==netstat==

（2）**用 netstat 网络连接命令，分析可疑端口、可疑 IP、可疑 PID 及程序进程** netstat 用于显示与 IP、TCP、UDP 和 ICMP 协议相关的统计数据，一般用于检验 本机各端口的网络连接情况

选项参数:

![image-20230328144832763.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-da49413671ecf1d8a8a4df2f02d276510ebb2571.png)

> netstat –antlp | more

![image-20230328144905239.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-93c1ef9a117abe62002cc02b0dd6716a4744e407.png)

说明：

a） `"Recv-Q"`和`"Send-Q"`指的是接收队列和发送队列。

b） `Proto` 显示连接使用的协议；`RefCnt` 表示连接到本套接口上的进程号；`Types` 显示套接口的类型； `State` 显示套接口当前的状态；`Path` 表示连接到套接口的其它进程使用的路径名。 c） 套接口类型： `-t` TCP `-u` UDP `-raw` RAW 类型 `--unix` UNIX 域类型 `--ax25` AX25 类型 `--ipx` ipx 类型 `--netrom` netrom 类型 d）状态说明： `LISTENING` 侦听状态 `ESTABLISHED` 建立连接 `CLOSE_WAIT` 对方主动关闭连接或网络异常导致连接中断

如图，可查看到本地 mysql 数据库有外部连接行为：

![image-20230328145103948.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d3d1813d9822cd1b995d877785cd3aa2e2bf892c.png)

（3）根据 netstat 定位出的 pid，使用 ps 命令，分析进程

![image-20230328145121481.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-573857b235502c69602b5cb4dd529cb640ab982f.png)

\\==ps aux | grep pid | grep –v grep==

![image-20230328145145791.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d726cb602f1d999a24665768a906ee7970dd8249.png)

将 netstat 与 ps 结合：

![image-20230328145204539.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7e54bf3d3023f87800245a6f39f5cfc3b36f5b93.png)

发现了3个可疑进程1742、1677、1683

看一下这些可执行程序在什么地方

![image-20230328145303755.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cc94fe83eac7c1d607136d293b2593738e5d0b75.png)

可以使用 `lsof -i:1677` 查看指定端口对应的程序；

\\==lsof==

lsof（list open files）是一个列出当前系统打开文件的工具。

在 linux 环境下，任何事物都以文件的形式存在，通过文件不仅仅可以访问常规数据，还可以访问网络连接和硬件

所以如传输控制协议 (TCP) 和用户数据报协议 (UDP) 套接字等，系统在后台都为该应用程序分配了一个文件描述符，无论这个文件的本质如何，该文件描述符为应用程序与基础操作系统之间的交互提供了通用接口。因为应用程序打开文件的描述符列表提供了大量关于这个应用程序本身的信息。

\\==lsof filename== 显示打开指定文件的所有进程

![image-20230328145435559.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c8e5b3487054ac741adb410bbc2a24f47ffc1671.png)

![image-20230328145443446.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-001b2e2880f86b30621601c81fbbf46bc590086a.png)

`COMMAND`：进程的名称

`PID` 进程标识符 `USER` 进程所有者 `FD` 文件描述符，应用程序通过文件描述符识别该文件。如 cwd、txt 等 `TYPE` 文件类型，如 DIR、REG 等 `DEVICE` 指定磁盘的名称 `SIZE` 文件的大小 `NODE` 索引节点（文件在磁盘上的标识） `NAME` 打开文件的确切名称

（4）使用 ls 以及 stat 查看系统命令是否被替换

两种思路：

- 查看命令目录最近的时间排序
- 根据确定时间去匹配

> ls -alt /usr/bin | head -10 ls -al /bin /usr/bin /usr/sbin/ /sbin/ | grep "Jan 15"

![image-20230328145651637.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-f928540776554bee6b6cd17e5601010dbc0937bb.png)

`备注：如果日期数字<10，中间需要两个空格。比如 1 月 1 日，grep “Jan 1”`

（5）隐藏进程查看

> ps -ef | awk '{print}' | sort -n | uniq &gt;1 ls /proc | sort -n |uniq &gt;2 diff 1 2

#### 系统信息排查

（1）查看分析 history (cat /root/.bash\_history)，曾经的命令操作痕迹，以便进一 步排查溯源。运气好有可能通过记录关联到如下信息：

> a) wget 远程某主机（域名&amp;IP）的远控文件； b) 尝试连接内网某主机（ssh scp），便于分析攻击者意图; c) 打包某敏感数据或代码，tar zip 类命令 d) 对系统进行配置，包括命令修改、远控木马类，可找到攻击者关联信息…

（2）查看分析用户相关分析

> seradd userdel 的命令时间变化（stat），以及是否包含可疑信息 b) cat /etc/passwd 分析可疑帐号，可登录帐号 查看 UID 为 0 的帐号`➜➜➜awk -F: '{if($3==0)print $1}'/etc/passwd` 查看能够登录的帐号`➜➜➜cat /etc/passwd | grep -E "/bin/bash$"`

![image-20230328150232932.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2136d1736942258dc1f744325f37e6f22d342ffd.png)

> PS：UID 为 0 的帐号也不一定都是可疑帐号，Freebsd 默认存在 toor 帐号，且uid 为 0.（toor 在 BSD 官网解释为 root 替代帐号，属于可信帐号）；

（3）查看分析任务计划

`crontab -u <-l, -r, -e>`

![image-20230328150726389.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c8dc7b9ad916b65ef3b18f71b3c96472f6f9e570.png)

- 通过 crontab –l 查看当前的任务计划有哪些，是否有后门木马程序启动相 关信息
- 查看 etc 目录任务计划相关文件，ls /etc/cron\*

![image-20230328150803104.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-aea22c62edc6f4f9743cff4324259c5e2bdbd5a5.png)

（4）查看 linux 开机启动程序

- 查看 rc.local 文件（/etc/init.d/rc.local /etc/rc.local）
- ls –alt /etc/init.d/

![image-20230328150825094.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c6ae3eb76b99ffdaa9675253fbaba7d9ef0ab843.png)

\\==chkconfig==

chkconfig 是管理系统服务(service)的命令行工具，对开机启动的可疑程序进行更改

设置 service 启动信息： `chkconfig name on/off/reset`

设置 service 运行级别： `chkconfig --level levels`

（5）查看系统用户登录信息

a）使用 lastlog 命令，系统中所有用户最近一次登录信息。

![image-20230328150936515.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4507638627bc1a955ea51c404e28ea9ce78e4085.png)

b) 使用 lastb 命令，用于显示用户错误的登录列表；

c) 使用 last 命令，用于显示用户最近登录信息（数据源为/var/log/wtmp，var/log/btmp）；

![image-20230328150955249.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ace94e7eb806356f17f390758138ea7c3c97d849.png)

utmp 文件中保存的是当前正在本系统中的用户的信息。 wtmp 文件中保存的是登录过本系统的用户的信息。 /var/log/wtmp 文 件 结 构 和 /var/run/utmp 文 件 结 构 一 样 ， 都 是 引 用 /usr/include/bits/utmp.h 中的 struct utmp

![image-20230328151011133.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-fc15a43f4d0753c4b87b60d841915a593f450e9c.png)

（6）系统路径分析

`echo $PATH` 分析有无敏感可疑信息

![image-20230328151030244.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bb4b47bf6b492889b60dfe1e2a1338b7bf0609fc.png)

（7）指定信息检索

![image-20230328151040458.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-eb127b7f4c7877de6f34b8910f3b194e0a49781d.png)

（8）查看 ssh 相关目录有无可疑的公钥存在

![image-20230328151136501.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-de50e6b1bd82de200ad8d947e0a9ed3626e916c7.png)

![image-20230328151145017.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0ae107f4382ef28ba07d7c06c50daedf4c195768.png)

#### 后门排查

（1）系统后门排查

\\==➜chkrootkit==：

chkrootkit 是用来监测 rootkit 是否被安装到当前系统中的工具。

rootkit ，是一类入侵者经常使用的工具。这类工具通常非常的隐秘、令用户不易察觉，通过这类工具，入侵者建立了一条能够常时入侵系统，或者说对系统进行实时控制的途径。

下载链接：<https://www.chkrootkit.org/>

chkrootkit 主要功能：

- 检测是否被植入后门、木马、rootkit
- 检测系统命令是否正常
- 检测登录日志

![image-20230328151504625.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-430ed65e51c5ddb7404191a5ebf650e008e2cec9.png)

a)chkrootkit 安装：

> rpm -ivh chkrootkit-0.47-1.i386.rpm

b)检测

> chkrootkit –n；如果发现有异常，会报出“INFECTED”字样

![image-20230328151549039.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-99638cf3ef196093ac07e58a969c8a42b30c01f0.png)

c)定时检测 chkrootkit 自带的脚本并没有包括定时检测部分，而考虑到该工具的作用。 建议编写一个脚本，并加入计划任务中。并把脚本加入 crontab 中：`cp -p ./chkrootkit.sh /etc/cron.daily/`

![image-20230328151611158.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7145379471c18a050725b9aa3f2d85c2e5820a68.png)

\\==➜Rkhunter==： rkhunter 是 Linux 系统平台下的一款开源入侵检测工具，具有非常全面的扫描范围，除了能够检测各种已知的 rootkit 特征码以外，还支持**端口扫描、常用程序文件的变动情况检查**

rkhunter 主要功能：

- 系统命令（Binary）检测，包括 Md5 校验
- Rootkit 检测
- 本机敏感目录、系统配置、服务及套间异常检测
- 三方应用版本检测

![image-20230328151714779.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-022ba0651fef68ea700399853b62cc3bc44993c0.png)

\\==➜RPM check 检查==

系统完整性也可以通过 rpm 自带的-Va 来校验检查所有的 rpm 软件包,有哪些被篡改了,防止 rpm 也被替换,上传一个安全干净稳定版本 rpm 二进制到服务器上进行检查。

> ./rpm -Va &gt; rpm.log

如果一切均校验正常将不会产生任何输出。如果有不一致的地方，就会显示出来。输出格式是 8 位长字符串,c 用以指配置文件, 接着是文件名. 8 位字符的每一个 用以表示文件与 RPM 数据库中一种属性的比较结果 。 . (点) 表示测试通过。.下面的字符表示对 RPM 软件包进行的某种测试失败：

`5` MD5 校验码 `S` 文件尺寸 `L` 符号连接 `T` 文件修改日期 `D` 设备 `U` 用户 `G` 用户组 `M` 模式 e (包括权限和文件类型)

下图可知 ps, pstree, netstat, sshd 等等系统关键进程被篡改了：

![image-20230328152757625.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3969c5755f38badd58abc124d7e40abaeb3d6d60.png)

\\==➜Webshell Check==

Webshell 的排查可以通过文件、流量、日志三种方式进行分析，基于文件的命名特征和内容特征，相对操作性较高，在入侵后排查过程中频率也比较高。

![image-20230328152845703.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-64a9e54fbe80b4bca2321c51a567da20ba03d475.png)

综上所述，通过 chkrootkit 、rkhunter、RPM check、Webshell Check 等手段得 出以下应对措施：

![image-20230328152906292.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-062312a929f741c665695e24453b309de006a6fc.png)

2）手工 Webshell 排查

通过文件内容中的危险函数，去找到网站中的 web 后门。最常见的 Webshell文件内容中常见的恶意函数：

PHP `Eval、System、assert、……` JSP `getRunTime、 FileOutputStream、……` ASP `eval、execute、 ExecuteGlobal、……`

\\==➜➜➜find /var/www/html/ -type f -name '\*.php'|xargs grep 'eval' |more==

![image-20230328153041705.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1dae9af39c19d4a166c6bc37dd32e0e0bca3150a.png)

除了通过 grep 去找 webshell，我们还可以用类似 D 盾之类的 webshell 查杀工具，把源码拖下来在本机查杀。

#### 日志排查

Linux 系统拥有非常灵活和强大的日志功能，可以保存几乎所有的操作记录，并可以从中检索出我们需要的信息。大部分 Linux 发行版默认的日志守护进程为syslog，位于 /etc/syslog 或 /etc/syslogd或/etc/rsyslog.d，默认配置文件为/etc/syslog.conf 或 rsyslog.conf，任何希望生成日志的程序都可以向 syslog 发送信息

Linux 系统内核和许多程序会产生各种错误信息、警告信息和其他的提示信息，这些信息对管理员了解系统的运行状态是非常有用的，所以应该把它们写到日志文件中去。完成这个过程的程序就是 syslog。syslog 可以根据日志的类别和优先级将日志保存到不同的文件中。

（1）日志类型

下面是和排查相关的常见日志类型，但并不是所有的 Linux 发行版都包含这些类型：

| 类型 | 类型 |
|---|---|
| auth | 用户认证时产生的日志，如 login 命令、su 命令。 |
| authpriv | 与 auth 类似，但是只能被特定用户查看。 |
| console | 针对系统控制台的消息。 |
| cron | 系统定期执行计划任务时产生的日志。 |
| daemon | 某些守护进程产生的日志。 |
| ftp | FTP 服务。 |
| kern | 系统内核消息。 |
| mail | 邮件日志。 |
| mark | 产生时间戳。系统每隔一段时间向日志文件中输出当前时间，每行的格式类似于 May 26 11:17:09 rs2 -- MARK --，可以由此推断系统发生故障的大概时间。 |
| news | 网络新闻传输协议(nntp)产生的消息。 |
| ntp | 网络时间协议(ntp)产生的消息。 |
| user | 用户进程。 |

（2）日志优先级：

| 优先级 | 说明 |
|---|---|
| emerg | 紧急情况，系统不可用（例如系统崩溃），一般会通知所有用户。 |
| alert | 需要立即修复，例如系统数据库损坏。 |
| crit | 危险情况，例如硬盘错误，可能会阻碍程序的部分功能。 |
| err | 一般错误消息。 |
| warning | 警告。 |
| notice | 不是错误，但是可能需要处理。 |
| info | 通用性消息，一般用来提供有用信息。 |
| debug | 调试程序产生的信息。 |
| none | 没有优先级，不记录任何日志消息。 |

（3）常用日志文件

| 日志目录 | 作用 |
|---|---|
| /var/log/message | 包括整体系统信息 |
| /var/log/auth.log | 包含系统授权信息，包括用户登录和使用的权限机制等 |
| /var/log/userlog | 记录所有等级用户信息的日志 |
| /var/log/cron | 记录 crontab 命令是否被正确的执行 |
| /var/log/vsftpd.log | 记录 Linux FTP 日志 |
| /var/log/lastlog | 记录登录的用户，可以使用命令 lastlog 查看 |
| /var/log/secure | 记录大多数应用输入的账号与密码，登录成功与否 |
| var/log/wtmp | 记录登录系统成功的账户信息，等同于命令 last |
| var/log/faillog | 记录登录系统不成功的账号信息，一般会被黑客删除 |

（4）日志配置

linux 系统日志相关配置文件为/etc/rsyslog.conf（syslog.conf），以下是对配置文件各项配置；

![image-20230328153857667.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e0cf3e24aab633829a89bc7dac8672c477c6986a.png)

（5）日志分析

日志查看分析，主要为 grep,sed,sort,awk 的综合运用；

##### 5.1、基于时间的日志管理：

5.1.1、`/var/log/wtmp` /var/log/wtmp 是一个二进制文件，记录每个用户的登录次数和持续时间等 信息； `last` 命令 last 命令用于显示用户最近登录信息。单独执行 last 命令，它会读取 `/var/log/wtmp` 的文件，并把该给文件的内容记录的登入系统的用户名单全部显示出来；

> -f: &lt;记录文件&gt;：指定记录文件 -a: 把从何处登入系统的主机名称或 ip 地址，显示在最后一行

![image-20230328154011957.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0f1ce0276bd5990c40ec168d7dfe5ec80a0412a8.png)

5.1.2、`/var/run/utmp` /var/run/utmp 是一个二进制文件，记录当前登录系统的用户信息。可用 who 命令显示当中的内容，Who 的缺省输出包括用户名、终端类型、登录日期及远程主机；

![image-20230328154032277.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2dd41aa886c7484f66548d0d0b118e0912bcfd63.png)

5.1.3、`/var/log/lastlog(lastlog)` /var/log/lastlog 记录用户最后登录的时间和登录终端的地址，可使用 lostlog 命令查看；

![image-20230328154058728.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-012c7c4283415095b312b5a2b4c5474071d1c30d.png)

5.1.4、`/var/log/btmp(lastb)` /var/log/btmp 记录错误登录的日志，可使用 lostb 查看，有很多黑客试图使用密码字典登录 ssh 服务，可以使用此日志查看恶意 ip 试图登录次数；

![image-20230328154119132.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-508440ca970e819417cb563b36c43794ef30cdb8.png)

> PS：登录日志可以关注 Accepted、Failed password 、invalid 特殊关键字；

##### 5.2、系统日志

`/var/log/secure`

安全日志 secure 包含验证和授权方面信息，比如最常用的远程管理协议 ssh，就会把所有授权信息都记录在这里。

所以通过查看该日志，我们就能查看是否有人爆破 ssh，通过查看存在过爆破记录的 ip 是否有成功登录的行为，我们就能知道是否有攻击者通过 ssh 暴力破解的方式成功攻击进来了。

通过时间的纬度去判断，可以查看出是机器行为还是人为的，机器登录事件间隔特别密；

主要分析点：是否有 ip 爆破 ssh 成功；

![image-20230328154245304.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-df29acaf9f8b129d7310e011b798b91466cbb3b7.png)

定位有多少 IP 在爆破主机的 root 帐号：

\\==grep "Failed password for root" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr | more==

![image-20230328154313719.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-bf6d87c466994ce8ae9655e1113d0aa1a5ee8172.png)

登录成功的 IP 有哪些：

\\==grep "Accepted " /var/log/ secure | awk '{print $11}' | sort | uniq -c | sort -nr | more==

![image-20230328154347820.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-725386bef1cb6d6f6510d0bce5548ab60758e664.png)

##### 5.3、中间件日志

Web 攻击的方法多种多样，但是默认情况下 Web 日志中所能记录的内容并不算丰富，最致命的是 web 日志是不会记录 post 内容的

一般来说我们的分析思路都是先通过文件的方式找到 webshell，然后再从日志里找到相应的攻击者 ip，再去分析攻击者的整个攻击路径，来回溯攻击者的所有行为；

如黑客在入侵完了之后把 webshell 删除了，通过文件搜索的方式找不到 webshell 或者只能通过分析 web 日志去发现 webshell

比如这时候要排查的话，难度会稍大。Web 日志主要分析 `access_log`，本文以常见的中间件 apache 为例，其他中间件日志格式和分析思路大同小异；

Apache 默认自动生成两个日志文件，`访问日志 access_log` 和 `报错日志 error_log`；

![image-20230328154533459.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-49b97349d8cd6f1bfd10388ec5b5d3b8de0a375a.png)

Apache 日志字段说明：

![image-20230328154618817.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-25bef38b32db50f0d492881ae3318d1b4232f5da.png)

![image-20230328154628311.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-53d8f0e647b6a26b4e1dd373b6801a2761801d77.png)

在对 WEB 日志进行安全分析时，可以按照下面两种思路展开，逐步深入，还原整个攻击过程；

1）首先确定受到攻击、入侵的时间范围，以此为线索，查找这个时间范围内可疑的日志，进一步排查，最终确定攻击者，还原攻击过程；

![image-20230328154658538.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ea665031197d4ee7803eafb413a511da786d3276.png)

2）一般攻击者在入侵网站后，通常会上传一个后门文件，以方便自己以后访问。 我们也可以以该文件为线索来展开分析；

![image-20230328154717633.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-575dff0f0db0f57e36914359f00985a5e67a2374.png)

##### 5.4、数据库日志

数据库日志以常用的数据库 Mysql 数据库为例。Mysql 数据库有五种日志，`错误日志`、`查询日志`、`慢查询日志`、`更新日志`、`二进制日志`，重点关注查询日志；查看是否开启查询日志：

![image-20230328154836403.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3033bdbad1d827f2846076b2e6c89657a9a05067.png)

查看数据库文件：路径为`/var/log/mysql/`，记录一次数据库的连接、查询和退出中间的数据库操作；

![image-20230328154851288.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-11398fc0fc9cdf874baccd193bafd7a86e31b1df.png)

在查询语句中搜索所有关键词为“union”的请求，可以发现 172.24.123.120 在尝试 SQL 注入，类似，通过通过特殊的关键词搜索有无敏感的数据库操作。如读取/etc/passwd 敏感文件，写 webshsll 等；

![image-20230328154909903.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-cac50e4f36b5bad8f096c04e16e1b014db687f56.png)

### 处置建议与防御措施

#### 处置建议

- 断网或ACL隔离；
- 结束恶意进程；
- 提取木马样本；
- 删除木马；

#### 防御措施

- 安装杀毒软件，对被感染机器进行安全扫描和病毒查杀；
- 对系统进行补丁更新，封堵病毒传播途径；
- 制定严格的口令策略，避免弱口令；，
- 结合备份的网站日志对网站应用进行全面代码审计，找出攻击者利用的漏洞入口进行封堵；

#### 实际案例分享

##### 案例一：挖矿木马处置01

1. 事件概述
    
    发现多台服务器被植入挖矿木马；
2. 事件分析

登录被感染挖矿木马的服务器：x.x.x.x 首先通过本地DNS流量解析发现该机器确实存在挖矿木马；

![image-20230329151720254.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-791f8171c080f9463da5db7799b6089ebd65b931.png)

\\==-&gt;ipconfig/displaydns==显示DNS解析程序缓存的内容

登录的这台机器可以看到 DNS 解析过该域名，由此判断该机器中了挖矿木马，使用相关工具分析发现其中 csrss.exe 进程为伪装的系统进程

通过该进程有 2 个派生进程 sqlserver.exe 和mscorswv.exe，其中 sqlserver.exe 为 loader 程序负责加载 mscorswv.exe 和配置文件：

通过查看mscorswv.exe配置发现该程序会连接：xmr.crypt-pool.fr

![image-20230329160028127.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-48286f5be26c10caf0984f8e2656d5a14ac740b8.png)

![image-20230329155858300.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d5db845f32a4edde04f4250add70c3400e54e26c.png)  
通过对该木马分析后发现该木马会创建名称为：system\_updatea的系统服务

![image-20230329162451862.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-2be93aa2f57fa3529e72a6712df0ae71026d50e1.png)

3. 结论

最后清理后，统一查看网络连接、进程等是否正常

##### 案例二：挖矿木马处置02

1. 事件概述

某公司近期发信啊服务器运行速度变慢，主站无故出现打开缓慢甚至无法发开、http状态503错误等现象

登录服务器后发现CPU占用率在长时间保持100%断网后服务器CPU下降恢复正常，尝试结束进程删除文件后长期服务器进程自动恢复

2. 事件分析

通过查看系统进程后发现多个异常进程：`alg.exe、splwow64.exe`。通过对进程参数进行判断判定该进程是恶意挖矿程序

该程序在工作时，会导致CPU长时间高负荷运行

![image-20230329163223740.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-ff5a3f3c5f331464ac3618996f218d2bbba6cc12.png)

通过调用参数发现该挖矿程序会与远程矿池进行连接：==xmr.crypto-pool.fr==

![image-20230329163603454.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-794fcde3bfd790e918a7a0d2d9eaf897408e18e9.png)

![image-20230329163622788.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-eda6332171eaa78e03ba170e80f9473f7540f6ae.png)

结束程序以及删除启动项信息后重启发现，系统恢复正常该挖矿程序，没有自动加载。

通过对文件分析发现该文件是由`alg.exe`加载并运行的，通过`alg.exe`植入时间`2017/10/05`通过排查系统日志和安全日志发信啊已经被删除最早产生日志的时间为`2017/10/06`怀疑在黑客操作完成后删除了系统日志

![image-20230329164159896.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a0f919fb57c521985ba0ac9b90e7daf67a3905ac.png)

通过对服务日志排查发现在`2017/10/03`之后出现过多次登录记录账户为：`Support`。

发现该账户不属于自用账户怀疑为黑客建立的管理账户，该账户登录IP地址为：188.0.189.153，归属地为：俄罗斯。不排除为跳板主机

![image-20230329164423210.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-70cf49066791cd85a931957448b624783494ada8.png)

通过查看Sopport账户进行查看发现该账户建立时间为`2017/08/26`最后登录时间为`2017/10/05`

![image-20230329164529261.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7222b4f52c889ab10858db3ef55cdbd56621bb87.png)

通过查看系统发现该系统为`2008R2`，并且没有打过补丁，不排除时通过”永恒之蓝“漏洞或弱口令进入

发现该机器运行了`oracle`和`sqlserver`和`iis`服务，因为无法确定`oracle`和`sqlserver`管理密码所以无法判定数据库服务是否存在弱口令

通过对`iis`网站目录进行扫描发现多个`webshell`后门，最早后门时间可以追溯到`2014/10/17`

通过对后门文件路径的分析发现，应该是通xxx.com网站的`FCKeditor`的模块进行上传。删除`webshell`后发现IIS配置被破坏访问该服务器其他站点均可以访问，但是访问主站时会提示503错误。

通过新建网站配置解决该问题，但是访问时发现多个图片文件显示不正常通过。排查后发现网站目录下的upload文件被删除并且无法恢复

3. 结论

最后清理，统一查看网络连接、进程等是否正常

##### 案例三、挖矿木马处置03

1. 事件概述

某厂商外网服务器出现CPU异常，疑似挖矿程序病毒事件分析；

2. 事件分析

使用top查看到`wnTKYG.noaes`进程占用大量CPU资源，另外`ddg.2020`也是可疑进程，`wnTKYG.noaes`为挖矿病毒主进程

![image-20230330142609138.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9587e39368a5f359fffb0d1bdecc4b48f6690fd4.png)

使用lsof查看对外连接情况，发现`wnTKYG.noaes`对218.248.40.228:8443和163.172.226.218.rev.poneytelecom.eu:443发起TCP外连请求；

![image-20230411110900643.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-761baddec691e84abacae68acefe56c931d3c4c3.png)

使用 ps 查看挖矿程序进程，程序路径为/tmp/wnTKYg.noaes，被程序自身删 除前已经加载到内存中，可进行挖矿操作:

![image-20230411110917389.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-5e048252fb50e8ae6f4f964b2550c163eba62047.png)

ddg.2020 为挖矿病毒守护和传播进程，从运行记录的时间戳得知该操作存在 于 11 月 9 日 23 时 44 分，攻击者已于该时间进入服务器：

![image-20230411110929771.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a208b25a6423286e3a4f692faa7cdfba8fdfb533.png)

使用 lsof 查看对外连接情况，发现 ddg.2020 对 218.248.40.228:8443 发起 TCP 外连请求：

![image-20230411110938483.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-66a5d4a9c0570e1857655176d32c81a44e827fe3.png)

查看定时任务，发现攻击者在计划任务中留下了定时启动脚本，删除挖矿程 序后可通过每隔 5 分钟执行一次计划任务中的后门脚本重新下载启动；

![image-20230411110949067.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3514d3a091d9962aed5a51b86087101a71539f23.png)

![image-20230411110953874.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-41ee9cf9693fea0bf6f7f7c25fc781adafefb2d1.png)

云端 i.sh 脚本内容如下：

![image-20230411111022882.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-157eb19d4ec069f659a131b17a0693ba399e6acb.png)

云端木马样本地址可访问:

![image-20230411111033560.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-67b965ed99c8ec54c26b97cd71bd52f7c107e579.png)

经反编译分析 ddg 样本后，发现此样本有弱口令爆破的功能，使用内置账户 /口令字典，对 ssh 和 rdp 进行批量登录尝试，爆破成功后继续横向传播。该挖 矿木马还可通过 redis 未授权访问漏洞进行传播；

![image-20230411111047424.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-669a2c611163b49e2e87d00c02f28100a036b0a1.png)

3. 结论
    
    中招服务器临时解决方案：
    
    
    - 清除挖矿后台任务
        
        > linux 下例如： rm –rf /var/spool/cron/root rm –rf /var/spool/cron/crontabs/root
        > 
        > windows 下例如： 移除 Microsoft.NET\_Framework\_NGENS 挖矿服务 安装杀毒软件，进行全盘杀毒。
    - 终止挖矿进程
        
        > linux 下例如： pkill AnXqV pkill ddg.222 pkill ddg.2020 pkill wnTKYg
        > 
        > windows 下例如： 停止 Microsoft.NET\_Framework\_NGENS 服务
    - 清理挖矿相关文件
        
        > /tmp/wnTKYg.noaes /tmp/ddg.2020 /root/.ddg/2020.db /tmp/ddg.222 /tmp/AnXqV.yam /tmp/AnXqV /tmp/AnXqV.noaes 等及 ~/.ssh/中未知授权 C:\\Windows\\debug\\wk1xw
    - 防火墙上封禁挖矿样本下载和外连地址：
        
        > 218.248.40.228 163.172.207.69 163.172.226.131 163.172.226.201

继续分析，保证业务系统安全运行：

1. 修改操作系统用户密码，同时密码应严格使用复杂口令，避免密码的重用情况，避免规律性，定期进行修改；
2. 加强访问控制策略，限制粒度达到端口级，如 SSH、redis 白名单策略，对于业务无需外网访问的情况下，禁止对外网直接提供访问；
3. 开启登录事件检测，对大量登录失败的源 IP 进行登录限制，防止服务口令爆破；
4. 开启 SSH 证书登录，避免直接使用密码进行登录，同时禁止 root 用户直接远程登录，对于需要 root权限的操作，使用 sudo 等权限管理工具进行分配；
5. Redis 数据库增加密码访问认证；
6. 定期对系统日志进行备份，避免攻击者恶意删除相关日志文件，阻断溯源能力，同时加强日常安全巡查，防范于未然；