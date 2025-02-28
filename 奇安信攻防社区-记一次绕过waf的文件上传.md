在某次渗透测试中，发现了一个通用上传的点，但经过测试发现，该网站存在waf，但是最终绕过waf，成功拿到shell

0x01 漏洞发现
=========

在对某网站进行渗透测试时，偶然发现一个未授权接口，并且通过接口名可以判断出该接口可能存在文件上传，

当上传正常后缀名时，会提示200，并且文件可以成功上传

![image-20231030113712502](https://shs3.b.qianxin.com/butian_public/f106771d3b6edce32139973b7b5d962de4f55d560ebb4.jpg)

当上传jsp等后缀时，会请求失败返回空

![image-20231030113540067](https://shs3.b.qianxin.com/butian_public/f7667485523f2c7c250c18c77f89da9dff04dc40cf1ac.jpg)

从这里可以判断出改网站存在waf，当检测到请求包检测到威胁时会自动拦截丢弃。

既然是从waf层面检测的，那我们绕过的思路就是构造一个畸形的语句或者其他无法被waf识别但是能够被后端解析方法，比如通过**MIME编码**进行绕过

0x02 MIME编码
===========

> （注意，这里说的MIME编码可**不是**将Content-Type修改为image/png等类似的方式进行绕过的，这种方式修改的是MIME type。而我们今天所说的是MIME编码。）

**Multipurpose Internet Mail Extensions** (**MIME**) ，通常也称为**多用途互联网邮件扩展**，从字面意思可以看出，他的出现是为了扩展了电子邮件的格式，支持 ASCII 字符集以外二进制数据（例如图像、音频、视频或其他文件）转换为文本数据，以便能够安全地传输和处理。从commons-fileupload库版本 1.3 开始，FileUpload 可以处理 RFC 2047编码的标头值。

对于后端的解析，不同的库对这一部分的解码大同小异但是都可以自动识别并对MIME编码后的数据进行解码，这里我们通过对commons-fileupload库的分析，来看看后端是如何自动解析MIME编码后的数据的

> Commons Fileupload是一个用于处理文件上传开源的Java库，可以在Apache官方网站上下载到最新版本。它的文档和示例代码也提供了详细的使用说明，方便开发人员快速上手，提供了一组简单易用的API，用于在Web应用程序中处理文件上传操作。它支持多种文件上传的方式，包括通过表单提交、通过HTTP POST请求以及通过Multipart请求等方式。

在ParameterParser中会对请求的参数进行解析

![image-20231101152519012](https://shs3.b.qianxin.com/butian_public/f1931830028b7a2e10c37bb2c983fe458e2c2c000067c.jpg)

其中这里调用了`MimeUtility.decodeText()`对参数进行解析，继续跟进`decodeText`方法

![image-20231101161825447](https://shs3.b.qianxin.com/butian_public/f70749688be8d7ceab9c34c09b3bc9f3ad255e216dfe6.jpg)

他会自动判断是否以`=?`开头的，如果不是直接返回原字符，否则进入else语句

![image-20231101161906026](https://shs3.b.qianxin.com/butian_public/f692711489b08bcc3ecdf012b9014a2336221a70450b9.jpg)

然后去除开头和结尾的`[space]\t\r\n`，继续判断是否以`=?`开头，接着进入decodeWord进行解码

![image-20231101161944180](https://shs3.b.qianxin.com/butian_public/f288859233e48f2cac50023515fe636ab7e6ff9cfd515.jpg)

在`decodeWord`中，会解析MIME编码，具体做法是通过`?`（ascii码值为63）进行分割，分别提取出charset(字符集)，encoding(编码方式)，encodedText(编码后的文本)

![image-20231101163054134](https://shs3.b.qianxin.com/butian_public/f721579f643b7212728b5afd3a86cff886cd3688b1d25.jpg)

然后判断编码方式，当编码方式为`B`时，是将`encodedText`的值进行base64编码，当编码方式为`Q`时，会进入`QuotedPrintableDecoder.decode(encodedData, out)`方法

![image-20231101173718283](https://shs3.b.qianxin.com/butian_public/f750864bfeedbba54d89f4d1ce3e8a4da41ad08172881.jpg)

取`=`后的两个两个十六进制数字，并将其转换为ascii码值对应的字符。

所以MIME编码的格式为`=?charset?encoding?encoded text?=`

下面是对这个格式的详细解释：

1. **=?**：编码的起始标记，表示编码的开始。
2. **charset**：表示字符集，即非ASCII字符所使用的字符编码集。这通常是一个标识字符集的文本字符串，例如UTF-8或ISO-8859-1。
3. **encoding**：表示编码方式，即用于将字符编码为ASCII字符的具体方法。常见的编码方式包括"Q"和"B"。 
    - "Q"表示Quoted-Printable编码，它将非ASCII字符编码为"="后跟两个十六进制数字的形式。
    - "B"表示Base64编码，它将数据编码为一系列ASCII字符。
4. **encoded text**：是实际编码后的文本，即包含非ASCII字符的原始文本的编码版本。
5. **?=**：编码的结束标记，表示编码的结束。

举个栗子：

如果将`shell.jsp`通过Quoted-Printable编码方式为`=?utf-8?Q?=73=68=65=6c=6c=2e=6a=73=70?=`

如果将`shell.jsp`通过Base64编码方式为`=?utf-8?B?c2hlbGwuanNw?=`

0x03 waf绕过
==========

这里的绕过waf的方式也是将文件名或将所有参数都通过MIME编码后发送：  
将filename和name的值进行MIME编码后进行发送：

![image-20231103105956372](https://shs3.b.qianxin.com/butian_public/f206788cf5e4c2b3016c6e0c9470a0e24446846a1ed85.jpg)

依然返回空被waf拦截了，难道是waf还会检测上传文件的内容？

于是将上传的内容修改为其他结果，上传成功，果然waf会对上传的内容也会进行检测，那我们还需要对内容进行免杀

![image-20231103110024581](https://shs3.b.qianxin.com/butian_public/f787226aaeb16e0f532705e5fbca7de5b697a21ddf488.jpg)

这里的绕过方法很多，这里用jspx利用命名空间进行绕过

由于jspx实际上是以xml形式编写的jsp，因此它继承了xml的各种特性，包括CDATA和HTML实体编码，同时也包括了命名空间的特性。

这是jspx的helloword

```php
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
    <jsp:directive.page contentType="text/html" pageEncoding="UTF-8"/>
    <jsp:scriptlet>
        out.println("Hello World!");
    </jsp:scriptlet>
</jsp:root>
```

这里使用yzddMr6师傅的方法，在`jsp:scriptlet`这个标签中，jsp就是默认的命名空间，但是实际上可以随意替换成其他名字，这样就绕过了对jsp:scriptlet的过滤

![image-20231103112735395](https://shs3.b.qianxin.com/butian_public/f345041dc529d1408acd0fc7142018afae50278f55bc7.jpg)

上传成功，然后访问上传的shell，成功解析

![image-20231103112853385](https://shs3.b.qianxin.com/butian_public/f20707697a143bb6747cdbb7d81a0c0ba982155f24140.jpg)