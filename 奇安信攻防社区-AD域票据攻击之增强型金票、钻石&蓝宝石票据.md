0x00 前言
-------

黄金票据和白银票据作为AD域渗透中持久化阶段常用的方法，但是在利用时存在一定的局限性而且容易被检测出来，本文将分享增强型黄金票据如何突破限制以及新一代票据钻石票据和蓝宝石票据如何绕过检测。

0x01 Enhanced Golden Ticket
---------------------------

黄金票据(Golden Ticket，下文称为金票)是通过伪造域管理员权限的TGT，来换取任意服务的ST，相当于获取了域内的最高权限。

制作金票的前置条件：域名称、域SID值、krbtgt账户NTLM Hash或AES 256密钥(这些条件的获取方法很多，这里不赘述，提供下面一种复现方法)：

```php
# 获取域名称&SID值
net time /domain
whoami /user
# 获取krbtgt账户hash密码(dcsync需要域管权限、lsadump域管主机权限或者域管登录过)
mimikatz # lsadump::dcsync /user:domain\krbtgt
or
mimikatz # lsadump::lsa /user:krbtgt /inject
# 使用mimikatz制作金票并导入使用
mimikatz # kerberos::golden /admin:username /domain:domain /sid:sid /krbtgt:NTLM Hash
mimikatz # kerberos::ptt ticket.kirbi
```

普通金票有一个作用域的限制就是票据的使用权限被限制在当前域内，**不能跨域使用**，而增强型金票打破了这一限制，提升了票据的作用域。

我们可以使用导入的金票成功访问子域 `NO01.lee.com`的域控 `ChildDc` ，但无法访问根域`lee.com`的域控 `DC`：

![image-20230825180029211](https://shs3.b.qianxin.com/butian_public/f530349c379424177efc4e27acd9085d0b3239f354b2a.jpg)

根域和子域：在一个域林中根域作为域林中创建的第一个域，和其它域的最大的区别就是根域拥有对整个域林的控制权，根据 `Enterprise Admins` 组来实现权限划分的，该组是一个域账号组，只存在于一个林中的根域中，这个组内的成员，对域有完全管理控制权，增强型金票也就是通过给PAC增加该组的权限实现权限的提升。

![image-20230822165654736](https://shs3.b.qianxin.com/butian_public/f9423532b8e8ed16d79b1a58c0d2601cf26afadd84635.jpg)

我们可以看到在子域 `NO01.lee.com` 中是没有这个组的：

![image-20230822165905202](https://shs3.b.qianxin.com/butian_public/f7067648cc9fd6faaf0b3993abdf46692504f857a55b2.jpg)

在根域上可以看到 `Enterprise Admins` 组它的SID值为519：

![image-20230822170117946](https://shs3.b.qianxin.com/butian_public/f8727721e903029d35dc0b44d7a78e0459e75315e859e.jpg)

当我们获取了一个域的控制权限后就可以通过给金票添加SID来实现跨域攻击。因为不同域的SID标识值不同，那我们就需要获取根域的 `Enterprise Admins` 组的SID，这里我们可以使用 [user2sid](https://www.svrops.com/svrops/downloads/zipfiles/sid.zip) 工具来获取：

![image-20230822174504924](https://shs3.b.qianxin.com/butian_public/f299650bf7c8685bf7b42398f37a5fb6856b93250a4ac.jpg)

我们是不知道根域 `LEE.COM` 中krbtgt账户的密码Hash，使用的是子域 `NO01.LEE.COM` 中krbtgt账户的密码HASH，mimikatz的命令如下：

> mimikatz # kerberos::golden /admin:username /domain:domain /sid:sid /sids:xxx-519 /krbtgt:NTLM Hash /ptt

导入票据后再次访问根域的域控可成功访问，此时的票据票是拥有整个域林的控制权的：

![image-20230825175718352](https://shs3.b.qianxin.com/butian_public/f444791546d85a4aaf4f5c147ede159bd87f8f4bc29eb.jpg)

注：在一个域林中，如果创建的金票不包含该组，则金票不会向林中其他域提供管理权限，但在单个域的域林中，创建黄金票据不存在这个局限性，因为 `Enterprise Admins` 组驻留在此域中，所以不存在跨域问题。

**金票的异常行为：**

1. 金票是离线生成的TGT；
2. 金票的使用需要伪造用户(即使域内不存在该账号)。微软的MS-KILE解释：Kerberos V5不提供对TGS请求的账号撤销检查，只要TGT有效，即使该账号已被删除，TGT更新和服务票据也可以发布。

0x02 Diamond Ticket
-------------------

由于金票是离线生成TGT，所以不会在主机上产生4768事件(TGT请求)，注入金票后访问服务，主机日志会出现两次4769事件(TGS请求)，第一次请求的服务是主机名$，第二次请求的是具体的服务(如krbtgt服务)；钻石票据会通过域内用户请求合法的TGT后再使用krbtgt的AES256密钥对PAC进行解密、修改、重新加密，在Kerberos身份验证过程中就会有相对应的TGT请求，从而绕过检测。

制作钻石票据的前置条件：

```php
1、krbtgt账户的AES256密钥
2、域用户&密码
```

使用mimikatz获取krbtgt的AES256密钥：

> ```php
> mimikatz # privilege::debug
> mimikatz # lsadump::dcsync /user:domain\krbtgt
> ```

![image-20230829154902355](https://shs3.b.qianxin.com/butian_public/f424417ae73047578b78b5bb5b30ed922b712f9251b0b.jpg)

使用Rubeus制作钻石票据，该命令可分为两部分：首先由域内普通用户请求正常的TGT，然后解密TGT，修改PAC权限，重新计算签名，并重新加密生成新ticket，命令如下：

> ```php
> Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASSWORD /dc:DOMAIN_CONTROLLER /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /groups:GROUPS_ID(eg:512,518,519,520...)
> ```

![image-20230830145602738](https://shs3.b.qianxin.com/butian_public/f9001939907c23eded1ad6f480b344e533732ff6d7b6a.jpg)

接着导入获取的钻石ticket，成功在低权限主机上访问域控：

> ```php
> Rubeus.exe asktgs /ticket:ticket.kirbi /service:cifs/dc.domain.com /ptt
> ```

![image-20230829164510028](https://shs3.b.qianxin.com/butian_public/f8826293d640642602e0f039b89613dfbf0a7bb73a89f.jpg)

抓包可以看到钻石票据的利用是有完整的kerberos请求过程且已成功修改PAC中group权限：

![image-20230830145714707](https://shs3.b.qianxin.com/butian_public/f40195469c9ee799642c5a3c4e556318a5ad955b3eee1.jpg)

这种技术相比于金票更加隐蔽，因为过程中所申请的TGT是真实的，只是修改了PAC，但似乎只绕过了金票的第一个异常行为(离线生成TGT)，我们该如何对钻石票据做检测呢？钻石票据是对TGT中的原始PAC添加了特权组，此行为恰好可作为检测点；举个例子，如果要让一个低权限用户使用钻石票据访问Doamin上的各个服务，那么在过程中必须修改票据中的PAC才能实现访问，我们可以通过查找AD域中这个用户是否为特权用户组的成员做检测，具体日志事件如：

- 4672事件(特权登录)，日志中的账号与实际域管账号不一致；
- 4627事件(用户组信息)，该事件中的`Group Membership`字段为用户组信息，如果出现了低权限用户不该具有的高权限组信息，就判定为异常状况，为了避免误报(即用户被有意添加到高特权组时)，可与用户何时被添加到权限组的相关事件关联分析；
- 4624事件(账户登录)，记录了某用户在xxx.xxx.xxx.xxx地址登录，正常来说账号应该与SID值对应，伪造账号肯定与SID值无法对应；但如果攻击者伪造管理员的账号来伪造票据，我们就需要查看非常用的IP地址段出现了管理员登录的异常行为。

0x03 Sapphire Ticket
--------------------

蓝宝石票据和钻石票据的主要区别就是修改TGT中PAC的方式，蓝宝石票据避免了上面钻石票据提到的可能被检测的风险，利用kerberos的扩展S4U2self + u2u来取得高权限用户的PAC，替换原始的PAC，因为特权群组里确实有这个高权限用户，所以就认定该PAC是合法的，从而绕过检测。

利用域用户发起TGT请求，收到TGT请求后以administrator身份通过S4U2self发起自身的ST请求，由于用户账户默认情况下没有SPN，即KDC无法找到”用户“这个服务器，因此S4U2Self请求会失败，这里就需要使用Kerberos的U2U扩展，U2U支持用户到用户身份验证的机制，我们可以理解为委托用户administrator去申请目标用户(域用户)的权限；假设一个场景：某个员工（源用户，假设为员工A）需要临时访问另一个部门（目标用户，假设为部门B）中的一个文件，由于员工A没有直接访问部门B文件夹的权限，但目标用户的管理员（假设为管理员B）具有访问该文件的权限，那么我们就可以让A员工先去申请管理员B的权限得到权限后再去访问文件即可；所以我们就可以指定用于进行身份验证、执行U2U的用户，KDC 将代表用户向我们生成服务票据，现在我们有了目标用户的PAC，通过krbtgt账户密钥解密将这个合法的PAC附加到票据里，便可成功获取高权限票据。

攻击复现(域内一台linux主机)：

1、获取域的安全标识符(SID)和krbtgt账户密钥；

2、接下来使用的是 [impacket](https://github.com/ShutdownRepo/impacket/blob/sapphire-tickets/examples/ticketer.py)（这里使用[Charlie Shutdown](https://twitter.com/_nwodtuhs)修改后的版本）；

![image-20230831190530405](https://shs3.b.qianxin.com/butian_public/f194242dd8d4dcd698214218420dfd90a8c4f2eed038e.jpg)

3、在低权限主机上导入蓝宝石票据并成功访问域控

> kerberos::ptc ignored.ccache

![image-20230901094805543](https://shs3.b.qianxin.com/butian_public/f41382388835a9841bac6809974283689621090fbc752.jpg)

看下这个过程中的数据包有何不同？

![image-20230901182739644](https://shs3.b.qianxin.com/butian_public/f36794180da25f36877d13cac553a13b679235a48b1c7.jpg)

在这个数据包我们可以看到S4U2self请求的`PA-FOR-USER`内容，而且sname已经变成了域用户；U2U的实现必须指定选项`ENC-TKT-IN-SKEY`(该选项在`kdc-options`里，为true)并且具有附加票证`Additional-tickets` 包含在 req-body中，其实这个附加票证也就是获得的TGT(如图`ticket`和`additional-tickets`都是这个以bd2a6bb开头的)，之后KDC处理TGS-REQ请求时将会使用向其颁发附加票据的服务器的密钥(域用户密钥)解密附加票据，并验证它是TGT票据， 如果请求成功，来自附加票据的会话密钥将用于加密发出的新票据，S4U2self请求也会被赋予新的PAC权限，再通过krbtgt账户密钥解密并将这个合法的高权限PAC附加到票据里，便可成功获取高权限票据。

TGS-REP 阶段，域用户作为服务提供给administrator一张票据：

![image-20230901095809542](https://shs3.b.qianxin.com/butian_public/f190685da888b6dfa983d5dd9ae4845ecb55463c58864.jpg)

查看该票据中的PAC信息，已经成功拥有了域管理员的相关权限：

![image-20230901095946338](https://shs3.b.qianxin.com/butian_public/f7459199e73b6b5ec8b36d38ee7aeac7985ba364a8c71.jpg)

由于 Sapphire 票据具有合法的PAC，因此我们很难通过分析来检测其使用情况，我们似乎只能从主机的其可疑活动入手检测，比如：

- krbtgt密码hash被盗的行为，如环境中的DCSync攻击；
- 可疑工具的使用；
- 具有S4U2Self+U2U非常规的KRB\_TGS\_REQ请求；
- 高权限用户从某低权限主机发出KRB\_TGS\_REQ请求。

0x04 参考文章
---------

<https://www.rfc-editor.org/rfc/rfc4120>

<https://pgj11.com/posts/Diamond-And-Sapphire-Tickets/>

<https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/>

<https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/>