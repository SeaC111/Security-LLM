**应急响应概述**  
随着网络安全的快速发展，各种各样的安全事件以及入侵事件在不断的上演。应急响应就是为了在意外事件发生的时候所做的一切准备（例：事前模拟演练），以及在事件发生后所采取的一系列措施（例：溯源，追究责任）。  
常见的应急响应：系统被黑客入侵、重要信息被窃取、系统出现拒绝服务攻击（DDOS）、系统网络存在流量异常、防火墙等防护软件/硬件设备被攻破等。  
应急响应要达成的目标：

> （1）事前：采取安全加固，采取应急措施和行动，恢复业务到正常状态。  
> （2）事中：溯源调查此次安全事件发生的原因和经过，避免相同的事情再次发生。  
> （3）事后：如果造成财产损失等，需要司法机关介入时，需要提供证据材料，以作为法律认可的资源证据。

**应急响应流程**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6845203b4bc21b66e9f709203fcd245a228882bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6845203b4bc21b66e9f709203fcd245a228882bb.png)  
**（一）调查**  
某linux系统服务器，对外开放WEB环境，在某一天发现网站异常卡顿，对外不断发送异常数据流量导致内网的网络也变得拥堵。  
**（二）评估**  
针对此环境作应急响应，可以初步评估推测系统可能中了DDOS攻击或者系统中了挖矿病毒，也有可能有攻击者正在用其他方法攻击系统服务器。  
**（三）抑制**  
如果发现了系统存在异常的流量向外发送，初步判断是攻击者入侵了本台linux服务器，工作人员应该做断网操作，先把服务器的网络断掉，然后在内网的环境下进行逐一排查。  
**（四）分析**  
**windows系统排查思路：**  
（1）首先监测系统的账号安全，例如新增的账号、可疑账号、克隆账号等、隐藏账号，或者查看账号是否存在弱口令。  
（2）netstat -ano查看端口详情，查看异常端口的网络连接状态或者不必要的端口开启。  
（3）查看进程状态，有没有占用很多资源的进程，有没有异常的进程。  
（4）查看启动项，检查启动项的文件是否增添异常的启动项。  
（5）查看系统日志，查看安全日志，对日志id进行筛选。  
（6）使用自动化的查杀工具检查，如D盾、火绒、360、河马、webscan等  
**linux系统排查思路：**  
（1）首先监测用户账号安全，比如新增的账号、可疑账号，重点查看可以远程登录的账号以及高权限账号。  
（2）利用linux的history指令查看历史linux指令，uptime指令查看登录多久、多少用户。  
（3）检查异常端口和进程，netstat检查异常端口，ps检查异常进程，可以观看资源占用的进程id来判断是否有挖矿木马等嫌疑。  
（4）检查linux的启动项和系统的定时任务crontab，crontab -l查看是否有异常的任务编写进来。  
（5）检查linux的日志信息/var/log/一些系统日志信息、安全日志等。  
（6）自动化查杀软件，在线查杀工具，查杀脚本来查杀。  
**（五）恢复**  
如果存在挖矿病毒，管理员应该查杀并且删除在系统上的挖矿病毒或者其他木马病毒，可以利用自动化查杀工具查杀是否有病毒、木马、后门等恶意软件。如果WEB网页段被篡改网页或者挂链等恶意行为，管理员应该及时的恢复网页或者用备份数据恢复。  
**（六）报告**  
应急响应完之后，工作人员应该输出相应的相应报告。  
入侵排查例子(linux服务器)

\[========\]

**某linux系统卡顿，初步实行断网操作，接着在内网环境下对linux系统进行排查**  
**History查看历史命令**  
可以看大root用户执行wget等指令，初步判定攻击者登录该root账号  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e3f9ca67ff66b2eb1cd64b0654114312f74420dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e3f9ca67ff66b2eb1cd64b0654114312f74420dd.png)  
**linux检测系统用户安全**

1. 查询特权用户（uid 为0），查看是否新增异常账号。  
    awk -F: '$3==0{print $1}' /etc/passwd
2. 查询可以远程登录的帐号信息，黑客用来远程登录的账号。  
    awk '/\\$1|\\$6/{print $1}' /etc/shadow  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-499f8afd26e130d41e2c5f99817fcc5aee2e90f7.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-499f8afd26e130d41e2c5f99817fcc5aee2e90f7.png)
3. 除root帐号外，其他帐号是否存在sudo权限。如非管理需要，普通帐号应删除sudo权限  
    more /etc/sudoers | grep -v "^#|^$" | grep "ALL=(ALL) "  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1ff94eedbf13955c8294dfb39bce7b162f749473.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1ff94eedbf13955c8294dfb39bce7b162f749473.png)  
    **Crontab -L命令检查系统定时任务**  
    可以看到每天2：00获取安装脚本，sudo bash mservice.sh 10014是执行脚本（10014是注册的id）  
    检测结论为该服务器中了挖矿病毒，可以检测cron日志信息，删除异常的木马文件以及进程。  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fcdc12e98564ab6c66c2e801b0a4d4bb7e472ccf.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fcdc12e98564ab6c66c2e801b0a4d4bb7e472ccf.png)  
    **Top查看性能**  
    发现占了很大cpu的进程xig，尝试kill -9 pid把进程给干掉，如果进程再次出现的话，就去检测木马文件是否删除干净！最后清理后，统一查看网络连接、进程、等是否正常。  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2887e4e9da8fc6197dff670e64753886dfbd1676.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2887e4e9da8fc6197dff670e64753886dfbd1676.png)  
    **Wireshark分析流量**  
    分析各个ip的流量信息，逐一排查异常流量或者DDOS拒绝服务攻击  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bfd6cfe0c7f86746b7c5c280b92b94c8c1ad7217.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bfd6cfe0c7f86746b7c5c280b92b94c8c1ad7217.png)  
    分析120.220.32.186  
    大量的tls1.2协议文件，建立私密连接彼此发送数据  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b49e8f8de5f275e886e5c4818cf8229554082535.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b49e8f8de5f275e886e5c4818cf8229554082535.png)  
    分析210.28.130.3，发送大量ACK连接文件，初步怀疑是ack拒绝服务攻击。  
    [![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c08c2b286781b44557989d3cfe2eb7719d9b54f7.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c08c2b286781b44557989d3cfe2eb7719d9b54f7.png)  
    **安全加固**> （1）禁用或者删除无用的账号，检查特殊账户（可远程登录、用户权限高的账号），必要时禁止远程登录用户登录，只能本地登录，设置多次登录失败锁定账户。  
    > （2）检查重要的目录和文件的权限，chmod增加权限，防止篡改等。  
    > （3）关闭不必要的服务，跟企业无关的服务可以暂时关闭。  
    > （4）关闭不必要的协议，如ftp、ssh、telnet等，可能存在协议漏洞。  
    > （5）关闭不必要的端口，有一些端口可能存在端口漏洞。  
    > （6）时不时检查安全日志，观察日志信息。  
    > （7）可以使用安全厂商的设备来实时检查，或者使用系统杀毒软件查杀。