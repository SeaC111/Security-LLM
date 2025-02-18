0x01 序言
=======

 2021年国Hvv真实溯源过程，在流量设备告警能力弱的情况下，重人工介入分析整个过程总结，回顾当时整个溯源过程和0day的捕获过程，尝试把当时的心境和技术上的思考点梳理出来，给大家参考，批评。

0x02 溯源过程
=========

 事件起源于4月9日午后的一则来自EDR的webshell告警，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a0bb25732cc87d7b68352d480835547d96d81ae6.jpg)

 马上展开对该服务器的排查，该服务器为某信源VRV，纯内网环境。说明攻击者已经进入内网环境，分两条线分别对攻击入口和内网影响面进行排查。

2.1 向内溯源，确定影响面
--------------

### 2.1.1 某信源VRV溯源

#### 2.1.1.1 从日志分析

 因为某信源VRV的管理后台使用SSL协议，在协调厂商提供证书的同时，对access.log日志进行分析，尝试找出其中的攻击入口。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f09d964e618a0db9fa3fb3ede6cc2416f8d88302.jpg)

 从日志寻找入口的思路：

 （1）定位webshell访问接口，确认攻击跳板的IP

 （2）对webshell访问前后日志进行分析，确定漏洞URL

 （3）将可疑URL在其他时段日志中进行搜索，找出在其他时段没出现过的URL重点分析

 （4）对POST请求的日志重点分析。

 通过对日志分析，发现10.\*.\*.\*2在对VRV服务器尝试扫描，扫描日志符合fscan等类型内网扫描工具的流量，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9b43c901f2d702c0dcdc5277df1775beb78e3edc.jpg)

 此时已经定位了攻击某信源VRV的主机为10.\*.\*.\*2，同时安排其他同事对该IP进行溯源分析。

 该部分扫描无影响，然后继续分析，发现攻击队成功登陆了audit账号：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9383f5e13f573016d6ac577062eb281dd8d08c02.jpg)

 结合测试，发现audit账户为弱口令123456，同时在audit审计账户的后台中发现system也被登录过，同样为弱口令。（PS：此时猜测admin用户也是弱口令，经过测试并不是。）  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-72fad944ec15f927bc59060449dbe192545897ce.jpg)

 时间和IP都和攻击者路径对得上。但audit和system账户权限有限，并不会直接控制终端。

 此外，在审计用户的后台还发现，admin账户的密码被修改过,操作者时admin本人，登录IP为攻击队控制的跳板机，修改后密码后，admin账户成功登录。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-5ec2a25a94b7341faf1698e91cf50705f15aef0d.jpg)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0f6d52be2162b0ff49eed708a9bd76c210843d58.jpg)

 到这得到的信息，总觉得是因为admin账户密码被重置导致的整台服务器实现（如果是admin弱口令的话，就不会存在admin修改自己密码的操作了。）  
继续分析日志，发现在logo.aspx文件被访问前，还曾访问过logo.txt。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7c2112d12494b4781005225a5f5fb22fd519a879.jpg)

 而且logo.txt的访问中存在一次404的访问，说明马没写成功。那么比对两次logo.txt访问前被访问的接口，大概率可以定位到漏洞存在点。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-01f62e9babd51f83908bf2c2e72b85e13f38193a.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6fee1d7367f020e4ae0622ad5efa1104467efe91.jpg)

 成功定位/VRVEIS/SystemMan/GetNavUserByNavGuid.aspx就是漏洞文件，而该文件能写入shell，且从日志看，该路径应该需要admin权限才能访问。

 那么问题来了，admin账号权限咋来的？带着疑问，先分析GetNavUserByNavGuid.aspx被访问的日志：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-56b91bfaf195c41fbda80c56f9fc5c294b501de7.jpg)

 在admin用户登录前，已经出现了大量的接口调用和访问，里面奇迹般的记录了一个POST的body，把思路引向了注入（后话：最后证明pczq参数与漏洞利用无关）。

 恰好如果是注入的话，也解释的通admin账号的来源和写文件的操作。mssql支持堆叠注入，update操作可以改密码，xp\_cmdshell可以用于写shell。

 而在登录admin之前，登录audit、system账号的行为，原因大概是因为admin用户的密码复杂，cmd不可解。所以先解开audit和system的密码登录的。

#### 2.1.1.2 从流量分析

 从流量分析已经是几个小时以后的事情了，某信源厂家并不愿意提供证书对流量进行解密。但是在不经意间看到VRV根目录下有一个cert目录，在其中找到证书。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7f35db1862a3680855836eb7cccdaa4c862f0d97.jpg)

 证书有加密，尝试以后发现证书密码是123。

 此时终于有了明文流量了，直接搜索接口，验证上面从日志中溯源的结论，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f3dd44fef196ba274b6c7c04211c8c9882e67e9f.jpg)

 与日志分析结论一致，且在流量中有发现修改admin的密码。（时间久远，找不到数据包截图了，payload截图如下）  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0f552def0b12a3eedae3adf735d533b9263a9c2b.jpg)

#### 2.1.1.3 杂记

 某信源这个漏洞是0day，后来因为客户要求，将细节给了某信源，某信源还特地发了公告：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c8a2901ddc8060c8480b259eeb28390a13d7da9e.jpg)

 具体漏洞分析过程见3.1

### 2.1.2 某信源后台失陷的影响面

 shell在上传后，我们马上进行了处置，从某信源服务器进行拓展是来不及的，所以我们重点从某信源后台失陷后，攻击者都干了些什么来确定影响面。  
众所周知，某信源是终端管控系统，其最常用的攻击方法就是通过后台对管控的终端进行下发文件/执行命令等方式操作进行利用。于是在日志中找到相应的接口进行分析：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8dcc24d5a446a7bdc88003207c0793239b14a904.jpg)

 根据DeviceID可以确定出被攻击的机器具体是哪台，最终梳理出一个表，最后使用时间都在被攻击之前，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-164130bccb9be108a6cec9f036f438b3a29e2f95.jpg)

 也不敢大意，在流量侧重点监控了几个IP的流量，没有明显异常行为，对PC都进行了查杀、进程、启动项、注册表分析，确认未被攻击者控制。此时已经凌晨3点多。

 第二天与客户沟通后发现，该VRV是用于VPN接入时进行管控的，而VPN在4月8日晚上已经关闭。

### 2.1.3 10.\*.\*.\*2失陷后的影响面

 该失陷主机在DMZ区，且开放对互联网的访问，所以大概率这就是首台被攻破的机器了。

 凌晨3点多，我同事还没有完整的梳理出该机器的影响面，于是我参与其中一起梳理。（PS：客户第二天一早要看到影响面，不敢怠慢）。

 分析思路：  
（1）以10.\*.\*.\*2作为源IP，分析其对内网的整个访问流程中的异常流量。  
（2）分析10.\*.\*.\*2上的木马文件、攻击者工具等文件，在分析影响面的同时也寻找被攻击的点。  
（3）关联服务器分析

 整个分析展开时，由于流量设备告警能力弱（可以说连SQL注入都不怎么告警），分析依靠蛮力介入的比较大。整体看下来就是扫描流量非常多，但分析是否成功实在工作量太大了。

 在扫描文件的时候，发现服务器上仍存在攻击队未删除的fscan扫描结果，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-05636a83d4d08b73aa027e8ed328dd25b376218e.jpg)  
 整理后，结合流量进行分析，发现攻击队共计探测到28台内网机器（含10.\*.\*.\*2本身），其中存在漏洞的情况如下：

- 10.\*.\*.\*2 存在MS17-010漏洞（本机），DMZ区域做了策略优化，禁止了该区域内的445访问，所以其只能访问自己的445。
- 10.\*.\*.\*7 存在Druid未授权访问漏洞，未发现流量中有利用行为。
- 10.\*.\*.\*1 存在MySQL弱口令，未在流量中发现进一步漏洞利用。
- 10.\*.\*.\*5 存在某信源SQL注入0day
- 10.\*.\*.\*3 被成功登录了数据库

 其本身情况就是这样了，然后对其关联的服务器进行分析，因为该应用站库分离，用的是mssql，使用的是sa用户，IP为10.\*.\*.\*3，在流量中也证实该机器被成功登录了mssql。那极有可能通过xp\_cmdshell已经获取到了数据库服务器的权限。

 通过上机排查10.\*.\*.\*3，发现xp\_cmdshell已经被激活，但未从数据库日志里面找到xp\_cmdshell被调用的记录，无法得知攻击队用xp\_cmdshell做了什么。

 在流量侧对10.\*.\*.\*3进行分析，仅发现其与10.\*.\*.\*2（应用）有流量交互，不存在向内网扩散的行为。

2.2 向外溯源，查找入口点
--------------

 之所以把对DMZ区域的攻击过程溯源放的比较靠后，是因为该机器出现问题后一直处于断网状态，所以不急着分析。

### 2.2.1 寻找线索，发现端倪

 对于10.\*.\*.\*2的被攻击的路径是一点线索也没有，所以上去先对进程、文件、定时任务、启动项、网络连接进行检查，状况如下：

 （1）定时任务、进程、启动项里面没有驻留的后门

 （2）网络连接只有外网访问该应用的，并没有由内向外的C2回连（因为不出网）

 （3）文件方面只发现了fscan，竟然没有发现webshell。

 此时可以说是一头雾水，又整理了一下手里的信息：

 （1）服务器处于DMZ区，向外提供服务

 （2）服务是e-mobile，当时未暴出0day（ps：溯源到的第二天细节公开了）

 （3）无文件落地，可能是用了内存马（ps：不排除攻击过程中有文件落地）

 于是，使用cop对内存马进行检测，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6a79ba1cf69ba1bd073f28792b513a50017c7fc4.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9c76e9b8dad057999a5f9b53da7f554be957ddc6.jpg)

 果然发现了内存马，然后找到内存马对应的java文件，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6d87a48c29900ddcf3bd6c088367a8ef4543787d.jpg)

 根据对样本进行分析，发现该内存马的特征流量为返回包的set-cookie中包含eagleeye-traceid字段，对流量中包含该特征的流量进行检索，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4bb37636760b098df0315ad43e4024fe5b66df9d.jpg)

 发现两个IP有过webshell连接的请求，随后对两个IP的的流量进行分析，发现两个IP的交互都很有目标,直接就连接了webshell，未发现其进行其他攻击操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-9928ccd83ba7600a76a613160e38306eefb5ae03.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c30f03802ce4fe59e884f9abaa21177bdbaa6b5e.jpg)

 然后又开始了苦逼的分析。

### 2.2.2 深入分析，找到过程

 通过对内存马访问前后流量的排查，未发现直接上传webshell的操作（服务没shell文件，不排除内存马植入后删除了木马，所以排查了webshell上传行为）。

 想到可能是直接执行代码将内存马加载到内存中的，搜索关键字loadClass，截图如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4f65905dc7a93dbdbe76c36788db6c9a1828aea7.jpg)

从而定位到攻击IP和加载内存马的过程。根据攻击IP筛选，还原整个漏洞利用过程。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6faf01d13a242729f9ec907fb872d04391201664.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-618b3f39fed894ee3b1dc8b6ed8a6a6dfa25e83d.jpg)

 漏洞为SQL注入，通过创建别名的方式执行java代码，将内存马的字节码文件写入到tmp目录下的tmpD591.tmp中，字节码文件较长，所以进行了多次追加写入，然后在最后调用java.net.URLClassLoader类将tmpD591.tmp字节码文件加载到内存中。

 随后上机排查，在tmp目录下发现tmpD591.tmp,截图如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1213c729634802b03aa501489473f375b48ec835.jpg)

 通过对字节码文件进行分析，发现其中包含了一个名为resin.class的字节码文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e5d2cd2852e2e39a92b36443e45309d8c6873ccd.jpg)

 通过分析代码，证实该文件是Resion的内存马。至此，整个溯源过程结束，跨时2天。

0x03 漏洞分析
=========

3.1 E-moblie注入分析
----------------

 当我们在为发现两枚0day而窃喜的时候，第二天E-moblie这个漏洞就被公开了。下面是分析过程，看官们直接跳转，不赘述了。  
<https://forum.butian.net/share/84>

3.2 某信源SQL注入分析
--------------

 找到漏洞文件，代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a25404defd37ee3f135174554a35ca95458e8c7b.jpg)

 通过反编译VRV的dll文件，找到该方法的实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-675ef849cc08b6dea6d1fea09cf57866c04a01db.jpg)

 直接从request中拿到了navGuid参数，然后带入了GetListByNavGuid方法，跟踪该方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-66b2f14e11842975c6af72c29d0aa1f4a029a1c1.jpg)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c30894f8a7d8704a15c5fbbfc46c3ada1564adec.jpg)

 直接将参数拼接到SQL语句中产生的注入。

0x04 总结
=======

 时隔1年多，整理手中的材料时想拿出来做分享，部分过程没有找到相对应的截图。各位看官将就一下。站在上帝视角，回顾整个过程，颇有收获：

 （1）DMZ区的被攻破应用的数据库就在核心区域，而且核心区域访问关系不清晰，没有做严格的分级分域，里面全部互通。如果攻击队通过10.\*.\*.\*3进行资产扫描，我们早就退场了。这也给了我以后打红队的启发。

 （2）在分析过程中，对于漏洞攻击过程的追求远大于对事件影响的排查，也庆幸在甲方的督促下，我注意到了其中的重要性。

 （3）关于项目开发，某信源对0day的解释是某项目的定制需求，定制需求还放在标准产品中，显然是审计工作不够充分。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2150562c5aae72153e155501793017892d4390ab.jpg)

 （4）某信源系统多个不被人关注到的账号，都是123456这个弱密码。这类问题不止体现在某信源，其他产品也是，所以作为防守方应该注意这些问题。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a22293f25ba2bcfbec487c75a3f6ec71931163ac.jpg)