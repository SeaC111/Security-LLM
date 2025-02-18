### 0x01 web弱口令获取ssh权限

对公网的端口进行扫描后，发现443端口是某厂商的vpn管理平台，通过默认账号密码：admin/xxxxx进入平台，发现该平台可以连接内网中的机器，于是想着用该设备的ssh做一次代理，进入内网。（PS：一般情况下设备的web账号密码也是ssh的账号密码）。

telnet 22端口，端口开放，但是ssh连接则又显示不可达，如下:

![](https://shs3.b.qianxin.com/butian_public/f9695f4489cd91ea5b767ca92c9f7fd07.jpg)

咨询了团队大佬，说是有ACL限制了。刚好设备里面可以修改ACL，于是修改ACL允许我的IP进行连接。

![](https://shs3.b.qianxin.com/butian_public/f63a654d3cfbc11507d2f89e7b141351b.jpg)

里面有很多的ACL规则组，不知道该在哪个规则组里面添加，于是下载完整的配置文件：

![](https://shs3.b.qianxin.com/butian_public/fa20735b99f1778df63af720980a60b4b.jpg)

在配置文件中看到，与vty相关的是2001这条ACL规则，配置如下:

![](https://shs3.b.qianxin.com/butian_public/f9c41b2bb273f3564163179e1b523ce53.jpg)

所以将自己IP加到2001这个ACL规则库中。加了ACL规则以后，就可以连接了。

![](https://shs3.b.qianxin.com/butian_public/fc9003a4fc4655a9a8ce644b4eb2e9c26.jpg)

尝试用plink从ssh做转发进内网，但是安全设备不同于linux，没法代理。

![](https://shs3.b.qianxin.com/butian_public/f118998d534e50c89831f69dd88eb91b1.jpg)

### 0x02 添加vpn进入内网

设置L2TPVPN服务端：

![](https://shs3.b.qianxin.com/butian_public/f3351c4e9c8ca0abb146d4e584d4e4774.jpg)

然后，连接VPN，具体过程如下:

![](https://shs3.b.qianxin.com/butian_public/faa9978047d4206f7d94c94722f45e7ab.jpg)

![](https://shs3.b.qianxin.com/butian_public/fc41bb70023a84178eb2e931009e270db.jpg)

![](https://shs3.b.qianxin.com/butian_public/fb72a4ac1f5ddb9ee26612ed85f323055.jpg)

保存后，连接VPN，会报如下错误：

![](https://shs3.b.qianxin.com/butian_public/ff2a19da09d36c0fc1fb252201c42a327.jpg)

win10需要调一下才行，具体步骤如下：

进入“控制面板\\网络和 Internet\\网络连接”

![](https://shs3.b.qianxin.com/butian_public/fc19ea40ba3d11a59e4f3fae0780b860b.jpg)

找到刚添加的vpn，右击属性，在“安全”选项中调整如下：

![](https://shs3.b.qianxin.com/butian_public/f7291faa846c20624d400fe85fe9aa96b.jpg)

然后再连接，即可连接。

![](https://shs3.b.qianxin.com/butian_public/f0efc1e49091f3d9ddcf058f3f79fb9f9.jpg)

然后访问客户给的某个系统 10.0.2.1，无法访问，tracert一下跟踪一下路由，看通不通。

![](https://shs3.b.qianxin.com/butian_public/f7b6dfb6f27e6ecc522aabd5d28bc3887.jpg)

无法访问，但是路由能通，不知道是什么情况。又跟大佬们沟通了一下，才知道是因为没有做源地址转换，于是添加NAT转换：

选择Easy IP，不需要自己过多配置，关联的ACL选择新添加的名为SSH的acl规则。

![](https://shs3.b.qianxin.com/butian_public/fd3f162e8269cc863dd8a644942ce2f84.jpg)

选择10.227.9.89这个口子，依据是tracert的下一跳是10.227.9.90。

![](https://shs3.b.qianxin.com/butian_public/fb1a486b44b5ad4501a70f81f99c662c5.jpg)

然后还需要添加两个ACL，一个是以移动出口上网的ACL为了测试过程中能查资料，另外一个是刚才与源地址转换关联的ACL规则，以便访问到内网系统进行攻击。

移动出口上网的ACL对应2000，访问内网ACL对应ssh，如下:

![](https://shs3.b.qianxin.com/butian_public/fdea918a513bfa156035c35c32a0f3ce3.jpg)

![](https://shs3.b.qianxin.com/butian_public/feb1cdce0aca6ade2e45d2407b2adfdab.jpg)

然后再访问内网系统，即可访问到了。

![](https://shs3.b.qianxin.com/butian_public/ff2eeab38f7216738bb431ab326622a35.jpg)

### 0x03 内网资产发现

以前内网发现都是用timeoutsocket，而这次用timeoutsocket一个资产都没发现，包括已有的部分目标都没发现。后面使用F-NAScan扫到了很多存活主机。

主机里面应用类较少，设备比较多，弱口令也比较多，这里就不提了。主要说下集权类设备的发现。

内网共发现两台集权类设备，一个是某厂商的终端检测，如下：

![](https://shs3.b.qianxin.com/butian_public/f24d29588f24c11bfa9f9e7d0554d6525.jpg)

尝试了常用口令，没进去。

第二个是另外某厂商的的终端检测系统，通过弱口令进了后台。

![](https://shs3.b.qianxin.com/butian_public/f83944119340f6186b58736aa929b8268.jpg)

### 0x04 获取内网服务器权限

这个设备里面，支持执行命令，文件分发、查看用户等内容。所以有以下思路：

1、激活guest用户，设置密码，加入管理组

2、powershell+cs上线

#### **方案选定-进行尝试**

由于内网机器不能出网，所以不考虑方案2,显然方案1更成熟一点。

尝试激活guest用户，等一系列操作，如下：

![](https://shs3.b.qianxin.com/butian_public/ff2ab0607d42ab3babaef3965a3c8d90f.jpg)

命令执行以后，查看如下:

![](https://shs3.b.qianxin.com/butian_public/f0cae3fef9f383470ce03c6f001b01f99.jpg)

纹丝不动，无奈问了厂商的售后，才知道正确的执行方法如下:

![](https://shs3.b.qianxin.com/butian_public/f7099f23e559e02c1c29652afc717044a.jpg)

然后编写bat,通过文件分发，下发到目标上。bat内容如下：

```php
net user guest /active:yes && net localgroup administrators guest /add && net user guest qax@1234567qwert
```

![](https://shs3.b.qianxin.com/butian_public/f2ecc1fc8089713811da6067fbaf81e96.jpg)

这里不能选择`接收后执行`选项。只有exe才行，但是会在服务器上提示，这都是后面才发现的。

选择系统根目录就是`c:`。

然后命令执行，如下：

![](https://shs3.b.qianxin.com/butian_public/f76f9d112e397e4b1e8dbf7604ef28e8e.jpg)

执行以后看用户，还是没变化...

#### **调试阶段-突破拦截**

没办法突破以后，就看了下首页还有啥没点过的

看到了客户端下载的地方，然后下载一个安装到虚拟机，执行加用户命令进行调试。

![](https://shs3.b.qianxin.com/butian_public/f56264a181f6d6474174c36804b8358e2.jpg)

这才发现原来是杀软给拦了，难怪一直不成功。

因为后台可以直接通过按钮激活guest用户，就想激活以后克隆用户，然后发现，克隆用户的exe也报毒了

后来看资料，看到net1，想试试net1能否加用户，如下:

![](https://shs3.b.qianxin.com/butian_public/f9c6cbbbd28a9d98279bc0902ce272c2d.jpg)

可以激活用户，可以改密码，无法加入administrators组。

于是想到先用mimikatz读取密码到本地，然后重置administrator的密码，登录服务器后再改回来。

### 顺利登录服务器

找朋友要了一个mimikatz，然后将mimikatz分发给目标，然后用2.bat读密码，2.bat如下：

```php
mimikatz.exe ""privilege::debug"" ""sekurlsa::logonpasswords full"" exit >> log.txt
```

然后再用3.bat重置administrator密码，3.bat如下：

```php
net1 user administrator xxxxxx@1234abcdxxx
```

之后登录服务器：

![](https://shs3.b.qianxin.com/butian_public/f66cab03139f0094b3e46cd2e00052a01.jpg)

到c:根目录下找到log.txt，然后把administrator的密码改回原来的密码。

至此成功获取服务器权限

### 0x05 扩大战果之内网横向

使用读取到的密码在内网扫描，最终获取10几台服务器权限。

![](https://shs3.b.qianxin.com/butian_public/fb37688c5a23716e29803d16327151f97.jpg)

![](https://shs3.b.qianxin.com/butian_public/f9b3cad414148d0994531eb67809f15eb.jpg)

RDP是用7kb的RDP-Sniper扫的，SSH是用超级弱口令工具扫的。超级弱口令工具扫RDP的结果并不准确，只扫出了两个通用密码。而RDP-Sniper扫出了10，效果还是很明显的。

### 0x05 技术总结

1. 通过设备web弱口令登录后台
2. 开启VPN添加ACL进入内网
3. 通过弱口令登录集权设备后台
4. 突破绕过杀软登录服务器
5. 获取密码横向移动
6. 获取更多服务器权限