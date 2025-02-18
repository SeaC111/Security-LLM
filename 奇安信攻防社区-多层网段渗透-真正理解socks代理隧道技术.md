多层网段渗透-真正理解socks代理隧道技术
======================

写在前面
----

在多层网段渗透时，我们经常会遇到各种代理隧道问题，而有些问题还是挺难理解，需要我们去思考，接下来我将主要介绍隧道代理技术，漏洞利用简单带过。

环境
--

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2811e6501f31970a9642f4b5784309c519bc0ae2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2811e6501f31970a9642f4b5784309c519bc0ae2.png)

大致过程：
-----

首先拿下Target1主机，以Target1为跳板，攻击Target2，攻击Target2后，再以它为跳板攻击Target3。

攻击Target1
---------

访问192.168.76.148这台主机的网站，发现他的网站是用thinkphp v5搭建的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-aa34b5ca6299a917c6efa00076bbf203e147a747.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-aa34b5ca6299a917c6efa00076bbf203e147a747.png)  
直接使用thinkphp v5的exp进行攻击,发现可执行命令。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b6461d1ead8812b77b756724bdfd17bea3fdad7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b6461d1ead8812b77b756724bdfd17bea3fdad7.png)  
写入一句木马到指定文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-96301a5b7d8f31bf14e245fa171234409df4f2fb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-96301a5b7d8f31bf14e245fa171234409df4f2fb.png)  
使用蚁剑链接后门  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-52041c7a28a1d2f16c2cad7f5b850e76b207d549.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-52041c7a28a1d2f16c2cad7f5b850e76b207d549.png)  
使用msfvenom，生成反向连接后门，让它反弹到msf上，何为反向连接后门？  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-085afff395de133b4c70fa114a2f21b75a28d368.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-085afff395de133b4c70fa114a2f21b75a28d368.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b28c75a310887602471ba5530c874abe17bd73a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b28c75a310887602471ba5530c874abe17bd73a4.png)  
设置攻击载荷  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-802a7486dc331974e7581422288475a1b47a7660.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-802a7486dc331974e7581422288475a1b47a7660.png)  
上传反向连接后门  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0649e3cac0ddc444145160f1c0ac5ed498a557a2.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0649e3cac0ddc444145160f1c0ac5ed498a557a2.png)

使用蚁剑进入虚拟终端，发现可以执行命令，执行t1.elf，第一开始权限被拒绝，赋予一个执行权限即可，t1.elf被成功执行。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9bed98bc4fed9bb03a084a36c44e2870114302af.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9bed98bc4fed9bb03a084a36c44e2870114302af.png)  
设置攻击载荷，Msf反弹成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b043f9d8ff3c72b5214c31e47830bcea46ec2f53.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b043f9d8ff3c72b5214c31e47830bcea46ec2f53.png)

获取网络接口信息，用于判断是否有内网，如下说明还有22网段的内网，于是想办法继续渗透。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6605940c094247c7c64d8717fda2fdf53fd80816.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6605940c094247c7c64d8717fda2fdf53fd80816.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b43de39f7e53a642fc40a62aa2b5567c7b1f5dda.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b43de39f7e53a642fc40a62aa2b5567c7b1f5dda.png)

首先查看路由，发现并没有通往22网段的路由，说明Target1 无法访问Target2，现在问题来了我们如何才能访问Target2呢？添加去网22网段的路由。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d000590b514fff372f134350b1a2f22e6d06e477.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d000590b514fff372f134350b1a2f22e6d06e477.png)

再次查看路由，确保去往22网段添加路由成功。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-26e69c2c18c295536a8a9a98d678009e9d726efa.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-26e69c2c18c295536a8a9a98d678009e9d726efa.png)

添加路由后，说明Target1与Target2可以通信，在msf会话中我们可以与它进行通信。这里思考一个问题，如果不在msf会话中操作，ping 192.168.22.128能否ping通？  
答案是不能，我们在msf中添加的这条路由只是写在msf中，只能用 msf会话进行操作，而其他工具并没有该路由规则，所以无法进行通信。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-10bfc6c770e90a089a0ce6f7e74dca2b36e45aa8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-10bfc6c770e90a089a0ce6f7e74dca2b36e45aa8.png)

使用socks代理隧道技术
-------------

利用 msf 自带的 sock4a 模块，开启2222端口建立socks4a协议  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-42e614ce9ba5432ea5d24242da49743621f427ea.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-42e614ce9ba5432ea5d24242da49743621f427ea.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f95c5e387ff79c094b9876fddaaf9d96faefeb20.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f95c5e387ff79c094b9876fddaaf9d96faefeb20.png)  
利用ProxyChains代理工具设置代理服务器  
修改配置文件 /etc/proxychains.conf 添加 socks4 192.168.76.132 2222  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9dcc4d80427e05a5dda0b8bab094f9eee191db65.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9dcc4d80427e05a5dda0b8bab094f9eee191db65.png)  
配置proxychains后，nmap借助proxychains代理服务器探针target2，这里需要重点掌握到底是如何进行攻击的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1175b78cad4a32ba0b1bd968bedb653f10aa7157.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1175b78cad4a32ba0b1bd968bedb653f10aa7157.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-089535404fb56c29ec5191ad93d480ba80d3cd71.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-089535404fb56c29ec5191ad93d480ba80d3cd71.png)

浏览器设置代理，协议一定要记得一致  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fc37f0a4bfde6aac15e69bb4abcf91dc614f9492.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fc37f0a4bfde6aac15e69bb4abcf91dc614f9492.png)

攻击Target2
---------

成功访问网站  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eced4171b446e809aa7910b044da5af3d60b69a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eced4171b446e809aa7910b044da5af3d60b69a4.png)  
发现存在sql注入

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-285289e9947d426b9ca6073d8b2d550c7b866ed5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-285289e9947d426b9ca6073d8b2d550c7b866ed5.png)  
通过注入得到的密码进入后台  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3c794c1c1d717ce6a78271c3a305dc450c7a9285.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3c794c1c1d717ce6a78271c3a305dc450c7a9285.png)  
在后台的功能中发现，可以写入一句话木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-36922ecf0b1462d99e4adbb8be1069c61a3f7f20.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-36922ecf0b1462d99e4adbb8be1069c61a3f7f20.png)  
这里思考一个问题，蚁剑设置代理服务192.168.76.148，并且使用蚁剑中的控制的target1虚拟终端进行添加去往22网段的路由，那么此时利用蚁剑能否对target2中的后门进行进行直接访问？  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e482ab7d0dbb385afce30038b06b212a7ab9cc88.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e482ab7d0dbb385afce30038b06b212a7ab9cc88.png)  
这样设置只能在蚁剑控制的target1中的虚拟终端能进行通信，而直接使用蚁剑去连接后门是无效的，因为在使用蚁剑进行设置代理时，我们并没有在target1设置代理服务。所以使用代理无效，只有在target1中设置代理服务此时才有效，但在目标主机设置代理服务本来就是一件很繁琐的事，而且会遇到各种问题，如权限问题。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cd4b268854afcadb9eed64b196dbbdbdd1d21ec3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cd4b268854afcadb9eed64b196dbbdbdd1d21ec3.png)  
在蚁剑上重新设置代理， 此时蚁剑访问192.168.22.128时，使用msf中设置的2222代理端口进行访问。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2d0bc524fa24fef48eaaa8d64b03b0df915743cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2d0bc524fa24fef48eaaa8d64b03b0df915743cc.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6c6ff7cf93389d3d73a992e70b3fff526984de3e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6c6ff7cf93389d3d73a992e70b3fff526984de3e.png)  
在这里还有一些问题，有些工具自身并没有代理设置功能，此时应该怎么办呢？  
这里介绍代理工具sockscap64，Windows网络应用程序通过SOCKS代理服务器来访问网络而不需要对这些应用程序做任何修改，设置代理服务的地址、端口、协议，与msf中的相同。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a6fec020257c0772c5cef888c367ef4d595c9c2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a6fec020257c0772c5cef888c367ef4d595c9c2f.png)  
添加程序，此时蚁剑可以直接通过sockes4协议进行访问target2，并不需要进行代理服务设置。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7411b12b3beb181041c68f686fcc5361077ba6bc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7411b12b3beb181041c68f686fcc5361077ba6bc.png)  
大致的通信过程：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e5c8fe41ea7eb719fb67a6f98a059d43616026cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e5c8fe41ea7eb719fb67a6f98a059d43616026cc.png)  
生成正向连接后门，Target2只能与target1 和target3进行通信，无法与kali进行通信，只能我们找他，不能他找我，因为我有去往他的路由，但是他没有我的路由，这就是正向后门的原理。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dfda21b1175bd5ebed019eec3c336eec2f22d3d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dfda21b1175bd5ebed019eec3c336eec2f22d3d8.png)  
生成后门  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-005db41f6bb50ca36821106e9c4b79f770024f93.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-005db41f6bb50ca36821106e9c4b79f770024f93.png)  
使用蚁剑连接Target2，并上传msf生成的正向后门  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f4f9f91d2e216a48e2b361594ac5b51abd4ce1c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f4f9f91d2e216a48e2b361594ac5b51abd4ce1c0.png)  
生成攻击载荷  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4b9734370f39ff2b92fc9e05ec554a2933d84e22.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4b9734370f39ff2b92fc9e05ec554a2933d84e22.png)  
执行t2.elf，攻击成功，此时可以看到是kali指向target2  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-13c5bb994300b714083a25a25eae94058ca6124a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-13c5bb994300b714083a25a25eae94058ca6124a.png)  
继续查看网络环境，添加去往33网段的路由。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8750ac269d39546cb75096a152ad603d0113356c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8750ac269d39546cb75096a152ad603d0113356c.png)

攻击Target3
---------

对target3进行攻击，发现有ms17\_010\_psexec漏洞，直接进行漏洞利用  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-676efb83b7a71c4147c7d6119dc2055a075c116e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-676efb83b7a71c4147c7d6119dc2055a075c116e.png)  
攻击成功，此时查看箭头所指方向，说明是hacker主动去连接它  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9dc002ae7ff32a8bf912df41abe4279f0c391643.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9dc002ae7ff32a8bf912df41abe4279f0c391643.png)

总结
--

以上就是在进行多层网段渗透中代理隧道技术中我一直思考的问题，我们在练习时不仅要知道怎么做，也要思考为什么要这么做，原理还是很重要的，当然我们可能在某一次实验中未发现问题，但要思考会可能今后在遇到类似的渗透时出现什么问题，不然很多时候我们换过一种渗透环境就会遇到各种问题。