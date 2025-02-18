前言：Nmap (“Network Mapper(网络映射器)”) 是一款开放源代码的网络探测和安全审核的工具。它的设计目标是快速地扫描大型网络，当然用它扫描单个主机也没有问题。Nmap以新颖的方式使用原始IP报文来发现网络上有哪些主机，那些主机提供什么服务(应用程序名和版本)，那些服务运行在什么操作系统(包括版本信息)，它们使用什么类型的报文过滤器/防火墙，以及一堆其它功能。虽然Nmap通常用于安全审核，许多系统管理员和网络管理员也用它来做一些日常的工作，比如查看整个网络的信息，管理服务升级计划，以及监视主机和服务的运行。  
官网：www.nmap.org

一、安装Nmap
========

Nmap是主机扫描工具，有图形化界面，叫做Zenmap，也可以用命令行直接打开,分布式框架为Dnamp。  
1、Windows  
下载地址：<https://nmap.org/download.html>  
安装过程很简单，双击安装包，按照它的默认设置（有需要可以改它的安装路径，其他就没什么了），一路next就可以。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a05f9bc06ff138b15239467d824ab21c3415de48.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a05f9bc06ff138b15239467d824ab21c3415de48.png)  
2、Linux  
kali自带Nmap，不用下载安装，直接用就行  
如果没有的话，可以在终端输入： sudo apt-get install nmap  
Ubuntu也适用： sudo apt-get install nmap  
Centos有点区别：yum install nmap

Nmap的使用帮助文档可以在终端输入：nmap –-help 查看

二、Nmap的作用
=========

1.检测存活在网络上的主机（主机发现）  
2.检测主机上开放的端口（端口扫描）  
3.检测到相应的端口（服务发现）的软件和版本（应用与版本侦测）  
4.检测操作系统，硬件地址，以及软件版本（操作系统侦测）  
5.检测脆弱性的漏洞（Nmap的脚本）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-39d5e1ab7dc1e2c9d9a3d647efcc7d61361d5418.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-39d5e1ab7dc1e2c9d9a3d647efcc7d61361d5418.png)  
（1）首先用户需要进行主机发现，找出活动的主机，然后确定主机上端口状况  
（2）根据端口扫描，以确定端口上具体运行的应用程序和版本信息  
（3）对于版本信息侦测后，对操作系统进行侦测  
在这四项基本功能上，nmap提供防火墙与IDS（IntrusionDetection System，入侵检测系统）的规避技巧，可以综合应用到四个基本功能的各个阶段；另外Nmap提供强大的NSE（Nmap Scripting Language）脚本引擎功能，脚本可以对基本功能进行补充和扩展。  
此处转载于Nmap扫描实战教程大学霸内部资料内容

三、Nmap常用扫描指令
============

主机发现
----

1.nmap简单扫描  
nmap 【目标】  
其中【目标】可以是IP地址也可以是一个主机名，扫描多个目标，可依次往后面加【目标】  
例：nmap 10.10.15.132  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2662b7a1b2e03a816979cfb6626d6fada8e9d96c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2662b7a1b2e03a816979cfb6626d6fada8e9d96c.png)  
2.只进行主机发现  
nmap -sn 【目标】  
例：nmap -sn 10.10.15.0/24  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-381ad17979a6da45943533c5a53746a44f69494c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-381ad17979a6da45943533c5a53746a44f69494c.png)

3.禁止反方向域名解析  
nmap -n -sL 【目标】  
使用该选项是nmap永远不对目标地址作方向域名解析（常用于单纯扫描一段ip，使用该选项可以大幅度减少目标主机的相应时间）  
例：nmap -n -sL 10.10.15.0/24  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d4c3cefd803270b037ab6a77fa6979664a6a1ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d4c3cefd803270b037ab6a77fa6979664a6a1ed.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b8a2a5b8a3b9bc9b97aff2b8e4547dbf8601e27.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b8a2a5b8a3b9bc9b97aff2b8e4547dbf8601e27.png)  
4.反方向域名解析  
nmap -R -sL 【目标】  
多用于绑定域名的服务器主机上，使我们更加了解目标的详细信息

5.ping扫描  
nmap -sP 【目标】  
该选项通过ping扫描同网段存活的主机IP地址  
例：nmap -sP 10.10.15.0/24  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-810a553d8ec930e18ee58ea188c976d388ffb946.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-810a553d8ec930e18ee58ea188c976d388ffb946.png)  
6.路由追踪  
nmap -traceroute 【目标】  
该选项可以帮助用户轻松计算出到目标之间所经过的网络节点，并可以看到通过各个节点的时间  
例：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-578f465811bfccdb71ad9dd8c6c5afa600e26660.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-578f465811bfccdb71ad9dd8c6c5afa600e26660.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eddcf2f5a18cff8942f98497e89659003924124d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eddcf2f5a18cff8942f98497e89659003924124d.png)

端口扫描
----

#### 常见的服务对应端口号

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1bb3200cf3c6fcb7649a063b20c6afb3017281c7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1bb3200cf3c6fcb7649a063b20c6afb3017281c7.png)

很多时候，我们把Nmap叫做端口扫描神器，借助Nmap去探测目标ip提供的计算机网络服务类型（网络服务均与端口号相关），从而发现攻击弱点所谓的端口，就好像是门牌号一样。客户端可以通过IP地址找到对应的服务器端，但是服务器端开放了很多服务，每个服务对应了一个端口，通过端口才能找到对应的服务来访问服务器

端口扫描的状态：  
Opend：端口开启  
Closed： 端口关闭  
Filtered：端口被过滤，数据没有到达主机，返回的结果为空，数据被防火墙  
Unfiltered：未被过滤，数据有到达主机，但是不能识别端口的当前状态  
Open|filtered：开放或者被过滤，端口没有返回值，主要发生在UDP、IP、FIN、NULL和Xmas扫描中  
Closed|filtered：关闭或者被过滤，只发生在IP ID idle扫描

1..扫描端口号并进行版本号检测  
namp -sV 【目标】  
该选项通过侦测开放的端口来判断开放的服务并检测他的版本  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dae662a1264b8862f82447cd5356882565528f55.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dae662a1264b8862f82447cd5356882565528f55.png)  
2.指定端口号  
nmap -p端口号 【目标】  
该选项用于对指定的端口进行扫描，注意端口在1-65535之间，p和端口之间可有空格  
例：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b86d057e71acb03730295e1c66c9e9619c7c4e41.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b86d057e71acb03730295e1c66c9e9619c7c4e41.png)

服务识别及版本探测
---------

1.Nmap 全面扫描  
nmap -A 【目标】  
该选项对目标主机实施全面扫描，结果中包括各种类型的信息  
例：nmap -A10.10.15.132/24  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f1fa8c8f328fda5b1c4aea373ce7bded7fff277c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f1fa8c8f328fda5b1c4aea373ce7bded7fff277c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-947bd0660ccc59caf1a9493c565488bc8128db34.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-947bd0660ccc59caf1a9493c565488bc8128db34.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-089d1b703a87d3e8edceca9ca7c8a8dbf7deb4d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-089d1b703a87d3e8edceca9ca7c8a8dbf7deb4d3.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a2841435c128f4aa96e4327640122805c4f56830.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a2841435c128f4aa96e4327640122805c4f56830.png)  
2.Nmap扫描并对结果返回详细的描述  
nmap -vv 【目标】  
例：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-57908410851e3f03104737ec7aab3e388d8dd23c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-57908410851e3f03104737ec7aab3e388d8dd23c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-16149bac1401ccd3ca5498283396fef7e2ce1635.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-16149bac1401ccd3ca5498283396fef7e2ce1635.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a57e61e63ce65bda07ba20527585e9fa4a0bf25.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a57e61e63ce65bda07ba20527585e9fa4a0bf25.png)

3.nmap操作系统侦测  
nmap -O 【目标】  
例：nmap -O 10.10.15.131  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e83b27226eb2c35de6543766dccd3acfd615ce54.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e83b27226eb2c35de6543766dccd3acfd615ce54.png)

防火墙/IDS逃逸
---------

1.穿透防火墙扫描  
命令：  
nmap -Pn -A 【目标】  
服务器禁止ping命令，试试-Pn，nmap参数配合使用  
例：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-00ac4b7f272d82fa481a1c49ea58d4169c7f6a96.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-00ac4b7f272d82fa481a1c49ea58d4169c7f6a96.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d046736ab9b9061c284bf2f200545f34847a6cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d046736ab9b9061c284bf2f200545f34847a6cf.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c090e5b02ab82a09ea82d5b36ac212c84c31c67b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c090e5b02ab82a09ea82d5b36ac212c84c31c67b.png)  
2.禁ping  
nmap -P0 【目标】  
0是零  
。。。。  
3.指定网卡扫描  
Namp -e 网卡 【目标】  
。。。。  
4.数据包分片  
nmap -f 【目标】/nmap -mtu mtu大小 【目标】  
。。。。

Nmap漏洞扫描
--------

下面都不添加演示了按着命令敲就好了  
1.命令:  
nmap –script=vuln IP地址  
使用vuln脚本进行全面的漏洞扫描指纹识别扫描  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-270d02964279198506e28ddbfaf877edfea1dca6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-270d02964279198506e28ddbfaf877edfea1dca6.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d6f161ce13b6857a8d286031d90091280b1f445.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d6f161ce13b6857a8d286031d90091280b1f445.png)  
2.命令：  
nmap -sV -v IP地址  
扫描系统和程序版本号检测，并且输出详细信息  
。。。

使用Nmap中的脚本进行信息收集
----------------

Nmap中的漏洞脚本扫描  
脚本保存位置：/usr/share/nmap/scripts

1.whois信息查询  
命令:  
nmap -–script=whois-domain 【目标域名】  
使用whois脚本对站点进行whois信息查询  
脚本保存位置脚本：/usr/share/nmap/scripts

2.DNS解析查询  
命令:  
nmap --script=dns-brute 【目标域名】  
使用DNS爆破脚本进行dns解析扫描  
。。。  
3.混合扫描  
常见端口扫描  
-sS：TCP SYN扫描  
-p: 指定端口号扫描  
-v： 显示扫描过程  
-F： 快速扫描  
-Pn：禁止ping后扫描: 跳过主机发现的过程进行端口扫描  
-A： 全面的系统扫描:包括打开操作系统探测、版本探测、脚本扫描、路径跟踪  
-sU：UDP扫描  
-sT: TCP扫描  
-sV：扫描系统版本和程序版本检测  
-n： 禁止反向域名解析  
-R: 反向域名解析  
-6: 启用IPV6扫描  
可任意指定混合扫描

Nmap报告输出
--------

-oN (标准输出)  
-oX (XML输出)  
-oS (ScRipT KIdd|3 oUTpuT)  
-oG (Grep保存)  
-oA （保存到所有格式）  
1.标准保存  
命令:  
nmap –oN text.txt IP地址或域名  
标准保存会把输出结果保存到指定文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-64486c8eb54ac77faac37af5a8c3c4991cf4935c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-64486c8eb54ac77faac37af5a8c3c4991cf4935c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf8a32467185aefb6fbe715ac65312fc9f7bdc61.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf8a32467185aefb6fbe715ac65312fc9f7bdc61.png)  
2.保存为Xml格式  
命令:  
nmap –oX test.xml IP地址或域名  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4548c6f19be2446483d89773ed7e844715f0f2e3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4548c6f19be2446483d89773ed7e844715f0f2e3.png)  
保存为xml格式需要用浏览器打开，查看结果，使用Zenmap时，XML非常有用。 Zenmap是用于nmap的提供GUI的工具。