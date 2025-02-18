Windows应急响应
===========

前言
--

当企业发生入侵事件、系统崩溃或其它影响业务正常运行的安全事件时，急需第一时间进行处理，使企业的网络信息系统在最短时间内恢复正常工作，进一步查找入侵来源，还原入侵事故过程，同时给出解决方案与防范措施，为企业挽回或减少经济损失。

常见的应急响应事件分类：
------------

web入侵：Webshell，网页挂马，主页篡改  
系统入侵：病毒木马，远控后门，勒索软件  
网络攻击：ARP欺骗，DDOS攻击，DNS劫持  
针对常见的攻击事件，结合工作中应急响应事件分析和解决的方法，总结了一些Window服务器入侵排查的思路。

常见的异常特征：
--------

主机安全：CPU满负载，服务器莫名重启等  
网站安全：出现webshell，被植入暗链，网页被篡改等  
流量安全：网络堵塞，网络异常等  
数据安全：数据泄露，数据被篡改等  
文件安全：文件丢失，文件异常等  
设备告警：防火墙，杀软，检测平台IDS，态势感知平台等

以上就是常规的异常情况，这些异常情况之前大部分，可能还有一些没有涉及到，但是基本上存在异常，就是说明存在问题。关于这个异常，我们也区分几方面，有的是基于数据流量问题，有的是基于在主机上面出现了一些问题，那么每一个问题出现就是对应的一个安全事件。出现安全事件也不代表对方成功拿下服务器权限，有些安全事件，只是单纯的对方有了进攻行为，是否攻击成功还需要进一步分析才能确定。

如果说单纯的报警没有啥太大的意义，在平时只要对入侵报警分析，把入侵IP封掉，就行。但是，在一次被入侵成功的安全事件，我们肯定需要一系列分析溯源，尽可能把整个事件还原，还需要出个应急响应报告的。

入侵排查思路
------

检查系统账号安全  
检查异常端口、进程  
检查启动项、计划任务、服务  
检查系统相关信息  
杀软查杀  
日志分析

处置流程：
-----

准备阶段：获取整个事件的信息（比如发生时间，出现啥异常等），准备应急响应相关工具  
保护阶段：为了防止事件进一步扩大，可进行断网，防火墙策略隔离，关键数据备份，数据恢复  
检测阶段：技术分析  
取证阶段：确定攻击事件，确定攻击时间，确定攻击过程，确认攻击对象  
处置阶段：提出安全问题，提出解决方案，业务恢复  
总结阶段：完整应急响应事件报告编写

应急响应实战分析
--------

挖矿
--

随着虚拟货币越来越火，挖矿病毒已经成为不法分子利用最为频繁的攻击方式之一。病毒传播者可以利用个人电脑或服务器进行挖矿，具体现象为电脑CPU占用率高，C盘可使用空间骤降，电脑温度升高，风扇噪声增大等问题。  
正常的机器，cpu是正常情况

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f04ca9bda569be70f96f5264f7f8a3b1e42f7af1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f04ca9bda569be70f96f5264f7f8a3b1e42f7af1.png)  
当我们在浏览网页，或者下载了不正规软件，可能不经意间就会中了挖矿木马。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b224c14e6da45d333cc89a47e8335b420894ffff.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b224c14e6da45d333cc89a47e8335b420894ffff.png)

挖矿木马的特点，会占用大量cpu。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-83a68f1d8212dbbede5e679271a39811293e5fef.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-83a68f1d8212dbbede5e679271a39811293e5fef.png)

重启之后还是出现CPU占满情况。

检测启动项，发现未知的启动项，定位到文件所在位置。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f2b50264d99f425442b6841a9650672bc4e3289a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f2b50264d99f425442b6841a9650672bc4e3289a.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8c1516b77b07e0e524294707ffd7e745f5453894.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8c1516b77b07e0e524294707ffd7e745f5453894.png)  
可以定位到文件具体的所在位置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fd9277a231579b5a091ffb792e10fb8832cebd6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-fd9277a231579b5a091ffb792e10fb8832cebd6c.png)

这个里面的这些地址，都是矿池的地址。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a2a5010a9bcaf3e80fb5a50f9b646f7247152f50.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a2a5010a9bcaf3e80fb5a50f9b646f7247152f50.png)

挖矿木马也是有对外连接，看具体怎么写的，不一定一直连接，有的可以间断性的连接。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-43d3b2d38386ebebc713fe5021f7188ab8778a45.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-43d3b2d38386ebebc713fe5021f7188ab8778a45.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7b0fcc8795fab85055cd0edc4ba1cd17a6aa9f93.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7b0fcc8795fab85055cd0edc4ba1cd17a6aa9f93.png)  
通过威胁分析平台也可以看处，这个异常文件就是个挖矿木马。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dda3be2680f25be5a7baef65563b5ccb859dfc54.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-dda3be2680f25be5a7baef65563b5ccb859dfc54.png)  
通过分析此外连IP，可以看处

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8b7da6196c993d1870b151dd7734d0404edfdc76.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8b7da6196c993d1870b151dd7734d0404edfdc76.png)  
总结：处理方法有结束进程服务，删除启动项，删除挖矿程序文件。  
防范：  
1、安装安全软件并升级病毒库，定期全盘扫描，保持实时防护  
2、及时更新 Windows安全补丁，开启防火墙临时关闭端口  
3、及时更新web漏洞补丁，升级web组件

勒索
--

勒索软件是一种来自密码病毒学的恶意软件，会感染您的计算机并显示勒索消息，要求您付费才能使系统再次运行，若不支付赎金，它会威胁发布受害者的数据或永久阻止对其的访问。早期勒索软件攻击通常使用伪装成合法文件的特洛伊木马来进行，诱使用户以电子邮件附件的形式下载或打开该木马。当下比较常见的方式为暴力破解、漏洞利用的方式进行人工投毒。

当你中了勒索病毒之后，电脑的文件都会被加密，并且出现下面类似情况，问你索要赎金。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3cf69fbf0662837f08cc9e09fb345607f50de951.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3cf69fbf0662837f08cc9e09fb345607f50de951.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1ba8a07e6e92d4db0b7eb6619ef4620ea32c16a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1ba8a07e6e92d4db0b7eb6619ef4620ea32c16a6.png)  
以及文件后缀都被改变，文件内容被加密。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ec0ea524bb31710994c0708583c18a32f7d72c2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ec0ea524bb31710994c0708583c18a32f7d72c2a.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-76885077cf770c77bd5d201e0621219b3f334b43.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-76885077cf770c77bd5d201e0621219b3f334b43.png)  
出现这种情况，基本就是中招了。该怎么办呢？首先判断勒索病毒的种类，可以根据病毒样本，特征，后缀进行判断。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-62a5f8a4bc2d3c7f62572c6600682224361e0eef.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-62a5f8a4bc2d3c7f62572c6600682224361e0eef.png)

溯源思路：

1.排查当前系统、确定勒索时间线  
2通过时间线、排查日志及行为  
3.寻找落地文件及样本、进一步分析行为

绝大多数勒索病毒，是无法解密的，一旦被加密，即使支付也不一定能够获得解密密钥。在平时运维中应积极做好备份工作，数据库与源码分离（类似OA系统附件资源也很重要，也要备份）。

遇到了，试一试勒索病毒解密工具：  
“拒绝勒索软件”网站  
<https://www.nomoreransom.org/zh/index.html>  
360安全卫士勒索病毒专题  
<http://lesuobingdu.360.cn>

一旦中了勒索病毒，文件会被锁死，没有办法正常访问了，这时候，会给你带来极大的困恼。为了防范这样的事情出现，我们电脑上要先做好一些措施：

1、安装杀毒软件，保持监控开启，定期全盘扫描  
2、及时更新 Windows安全补丁，开启防火墙临时关闭端口，如445、135、137、138、139、3389等端口  
3、及时更新web漏洞补丁，升级web组件  
4、备份。重要的资料一定要备份，谨防资料丢失  
5、强化网络安全意识，陌生链接不点击，陌生文件不要下载，陌生邮件不要打开

后门
--

我们在这里使用CS上线机器，进行演示。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3cadca1778791b00abcecfa27b910089bed6884b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3cadca1778791b00abcecfa27b910089bed6884b.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8666f31468934e586c2efcc5a5321f2b1939cd99.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8666f31468934e586c2efcc5a5321f2b1939cd99.png)  
这里可以知道，机器已经上线。  
然后可以分析异常进程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ceb7cba10ce13619d17472906236a15a1e54495c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ceb7cba10ce13619d17472906236a15a1e54495c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-afb15b7b74a6cd7e295ce3f46fe6f3a453167d7c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-afb15b7b74a6cd7e295ce3f46fe6f3a453167d7c.png)  
一种是上传检测文件，另一种查看网络连接。

这边推荐的是奇安信的威胁分析平台。把异常文件拖出来进行检测，查看检测结果。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f190034c1d43799392d6e61c8ea2f26577b40f5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f190034c1d43799392d6e61c8ea2f26577b40f5d.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bb0740a06a81135f07af5d3061d23ea5d29b8d82.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bb0740a06a81135f07af5d3061d23ea5d29b8d82.png)  
这种异常文件可以直接分辨出不正常，但是如果入侵者对文件进行免杀处理过，混淆成很普通很正常的文件，这个时候我们该怎么办呢？

这个时候就需要检查网络信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cd5dcebc908732b9a61633df5fd418009772ee49.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cd5dcebc908732b9a61633df5fd418009772ee49.png)  
这边可以看处，异常进程的安全状态是未知文件。并且本地地址跟远程地址以及端口连接也有。

推荐使用火绒剑，方便便捷。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e042eff9ab3838d0c43db78a45ac27f6effa5e6c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e042eff9ab3838d0c43db78a45ac27f6effa5e6c.png)  
总结：所有说一般后门排查，他都有个进程，进程会有个连接，他会和远程攻击者地址进行连接。这样你就可以检查一下你的网络状态，看是否有异常连接。还有就是定位异常程序，把这个程序上传到威胁感知分析平台，进行分析，看是正常文件，还是恶意文件。

但这只是能发现这种常见的远控。其实在APT攻击里面，比较深层的攻击里面，有些后门并不在进程中显示，它会在内核里面，不是简单的杀毒，重装系统就能清理，这种东西常规检测不到，需要专门人员进行现场研究。

爆破
--

爆破事件一般通过一些协议爆破，Windows爆破RDP协议，Linux爆破SSH协议，通过远程爆破口令，来连接你的对应端口服务，以至于控制你的服务器，这都是常用的攻击手段。这种事件发生该怎么识别呢？

这是系统自带协议，一般会有相关的日志产生。如果是服务器上部署了防火墙，防护监控告警设备，这在发生入侵事件会告警。如果这些防护都没有，通过查看系统日志也是可以看出来的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-377217982bbd31b3392a463cb174bb637f0c250c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-377217982bbd31b3392a463cb174bb637f0c250c.png)

排查方式：基于日志事件成功失败，时间筛选进行排查。