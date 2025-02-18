WaterDragon 水龙 v1.0
===================

和水一样 灵活多变 像龙一样 来去自如

### 核心

这个项目的**核心是NPS\[<https://github.com/ehang-io/nps>\] + Github Action**Github Action和SCF实现代理池的方式不一样：**SCF可以用网关触发，但是Action不是**，Action是给你提供了一台可出不可入的如同私人电脑一般的一个虚拟环境，所以我们如果要想用代理到Action然后去访问 就要我们的**vps 帮忙，先做个穿透，然后转发**

Tips:代理出去的IP是微软云的 而且IP众多 也不容易被ban
---------------------------------

使用方法
====

#### 1.在vps上装nps并配置

下载地址 [https://github.com/ehang-io/nps/releases/tag/v0.26.10下载合适的版本](https://github.com/ehang-io/nps/releases/tag/v0.26.10%E4%B8%8B%E8%BD%BD%E5%90%88%E9%80%82%E7%9A%84%E7%89%88%E6%9C%AC) 这里下载的是linux\_amd64\_server.tar.gz 执行`tar -axvf linux_amd64_server.tar.gz`进行解压

#### 2.然后去修改配置

`cd conf``vim nps.conf`我们修改一共2个东西

###### ①.首先是 web\_password

**这个改的越复杂越好** 是nps的管理面板 不过这里不用gui的 用的是webapi，用不

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-84720373075570e5ca3c51832d8fccc4d62204a5.png)

到gui的密码，如果是默认的123，会被有心人搞破坏

###### ②.然后是这里

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-52e7a3d814f80d87b5e06f360af8cb1f5e36dc0f.png)

把`auth_key`前面的注释去掉，然后修改auth\_key的值 然后把`auth_crypt_key`修改为别的16位长度的一个字符串 （默认也可以**然后把auth\_key 记住备用**

##### ③.http\_proxy\_port

可改可不改 **改了是防止http监听端口与apache，nginx这些服务冲突**

##### ④.web\_port

**api的地址**，监听的是8080端口 如果8080与本地软件有冲突则更改（按需更改）,如果改过就是 vps的ip:web\_port 然后回到上级目录`cd ..` 随后让nps运行 `./nps`如果正常未出现问题 就可以把nps挂后台然后进行 下一步了`nohup ./nps &`

#### 3.获取github\_token

##### 前往https://github.com/settings/tokens

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9632cea925e5a8e05f34440a02be746aa3df327e.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e9eb022bed631dee6cd1feb9643d1c15522ad8d1.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-81e8934a47e32c286793ca8e1fc7374d9e7c5c8e.png)

**记住备用**

#### 配置脚本

首先下载脚本`git clone https://github.com/sh3d0ww01f/WaterDragon.git`然后修改`main.py`文件

①**api的位置填上自己的api地址(<a href="">http://vps\\\_ip:web\\\_port，如果没改过前面的web\\\_port</a> 则就是http://vps\_ip:8080)**②**auth\_key 写上更改过的auth\_key**③**token写github获取的token**

运行脚本
====

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dce4666e81bc83a78e8d802ffe28a3ca236825cc.png)

`python3 main.py`

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-121e1b9c2dd98ad12f739d61da6191a83d9a69f5.png)

**①.输入socks5 进入隧道管理 我们需要先加一个**

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d2bbe800e7bb339372eba3a4b2966835dcc28ee1.png)

出现成功连接WebApi则说明api配置正确

**②.输入add 增加socks5隧道\*\***密钥随意写，端口只要外网能通就可以，加密的话1代表要加密，0代表不加密\*\*

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-73e5e3add5ebe2897d9ef841129d8fee518faa3e.png)\*\*

**③.配置好了新隧道，我们回到菜单使用**输入 `back` 回到菜单,然后**键入`manager`进入Github Action管理**

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6af556aaff18dd9763bf7a5eff6d8df182c0d8b7.png)  
输入`select`选择要连接的socks5隧道 这里选择新增的 客户端ID为21的

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e2dc2cd5b78b92339494c2d698253ecdd8281c88.png)

出现`start success`即为启动成功

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-47faf9a6e1c4f26ad866218f68078e274b69b5e0.png)

配置一下 配置好 就可以用这个代理了

效果
==

停止Action
========

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b170e7d8d7286bd9bb9bce1d3d5ba7924bc93143.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4dedcea0e2677595d51c5056d2ea7d298216e0c5.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fad46510820450bbf32e1deb12c217e7da9954fc.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3c70362ca1f884fc45795a141e70b5a58cd619d3.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c79c1bde563c126f55e48047723118e4eecf59df.png)

然后键入0 即可暂停现在运行中的GithubAction机子 出现“取消运行成功” 则代表成功暂停运行

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c8fc4eba4c941962e752862dbd363bdd35bf2429.png)

后序
==

Action和SCF不一样 没有多出口 但是可以**多开Action**，然后**实现多ip访问的目的**

项目地址:

<https://github.com/sh3d0ww01f/WaterDragon>

欢迎提issue 求个**star**