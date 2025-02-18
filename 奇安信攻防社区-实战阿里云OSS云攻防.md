0x00 写在前面
=========

现在，云服务器逐渐进入人们的视野，越来越受欢迎，由于云服务器易管理，操作性强，安全程度高，很多大型厂商都选择将资产部署在云服务上，但随之也出现了一些安全问题，接下来将介绍五个案例，由于以下的案例大多都是真实案例，所以打码会打得严重些。

0x01 案例演示
=========

从任意文件上传到任意文件覆盖
--------------

遇到一个文件上传点

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-12321be5603402e2a0b1765949f85670378f021d.png)

先上传一个图片，并抓包，成功上传，上传html文件看是否能xss，能够上传但是上传后不解析，继续更改Content-Type的值为text/html，上传后成功弹窗。

包如下:

```php
POST / HTTP/1.1

Host: xxxx.aliyuncs.com

Connection: close

Content-Length: 1077

Accept: application/json, text/plain, \*/\*

Origin: https://xxxxxx

User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36

Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryral5YOuPBEepOBbe

Referer: https://xxxx.cn/xx/

Accept-Encoding: gzip, deflate

Accept-Language: zh-CN,zh;q=0.9,en;q=0.8

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="name"

165027756922712.png

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="key"

20220418/3a7166a3063f7a82774bdd62727fb5fa251650277569228.png

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="policy"

eyJleHBpcmF0aW9uIjoiMjAyMi0wNC0xOFQxNzoyMzoyOFoiLCJjb25kaXRpb25zIjpbWyJjb250ZW50LWxlbmd0aC1yYW5nZSIsMCwxMDQ4NTc2MDAwXSxbInN0YXJ0cy13aXRoIiwiJGtleSIsIjIwMjIwNDE4XC8iXV19

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="OSSAccessKeyId"

xxxxx

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="success\_action\_status"

200

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="signature"

xxxxx

\------WebKitFormBoundaryral5YOuPBEepOBbe

Content-Disposition: form-data; name="file"; filename="12.png"

Content-Type: text/html

<script>alert(1)</script>

\------WebKitFormBoundaryral5YOuPBEepOBbe—
```

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dcd15a6bd087ccc2a26501c24cbc7b61eca0fcf5.png)

拼接上去就造成了存储xss，当然也可以挂黑页等操作，由于这是oss云服务器，并且域名太长没实际性危害。

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5b67fcfbcb3ebcff4c2e93754cf6a482df3b3baf.png)

在他的其他网站下static图片地址引起了我的注意，static不也是存放静态资源图片等信息的服务器吗？而oss也是一样的，那么两者是否会相通呢？

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-add0ebbdb57f11599e01770b8a34f17ad98af611.png)

我直接将oss服务器域名删除后替换为static服务器也直接弹窗。那不就造成了它的子域名存储xss吗？这其实是oss服务器和他的static静态服务器进行绑定的结果，所以我们上传的html也可以被static服务器接收并解析。

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-26ef15a49d5a648bb37800535179a31c2c81b3cf.png)

后面看了看文件名和路径是否可控，既然可控把我高兴坏了呀，尝试是否可以实现任意文件替换。

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1f5577b1d1be0f5e31c969ae30e1e9245a3db071.png)

我随意选择了一张图片将要替换的图片保存了一手，然后做个稍微小一点的标记进行上传，这样就能够证明危害，师傅们挖此类漏洞的时候也要注意。  
接着我更改了目录名和服务中图片名命名为同一个，成功上传

![16.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e30d3367b9de5e44343bac2d1072abb6bf287ca3.png)

可以看到我上传的图片中多了一个x，也就是我做的标记，由于该网站还有js等文件，那么也可以进行js等文件覆盖，那么将造成整个网站被我们所控制，可想而知危害有多大。

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6e23c3d04311fb898eca78920baa4161f7f01a27.png)

在我们遇到oss任意文件上传的时候，先判断文件的路径和文件名是否可控，接着去同厂商的其他网站查找静态图片或文件，看是否可以相互转换，实现任意文件覆盖，这样一个几乎毫不起眼的危害将直接提升为严重危害。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7a5f4e08f4b4b2e503f0cd9f22132f7ff5701b0d.png)

信息泄露
----

在oss渗透思路中我还遇到accessKeyId、accessKeySecret泄露，如果这两个泄露就能获取到oss对象存储的所有权限。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-35778712cf94e91a2b51503d7154d05df55014fa.png)

**常见泄露方式有以下四种：**

### 文件上传点

在文件上传点，抓包就直接泄露

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0f35e5139e14f6e6fe8286af0f5ade9945a95e1c.png)

### 源码文件中泄漏

反编译获取小程序的源码和APP的源码  
我还是喜欢用fileseek手工查找，需要注意的是很多时候都会对accessKeyId、accessKeySecret进行缩写

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-752560a50116bffc3769bea463a0440dbe6961f6.png)

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-209efd0de0b2281e8d650891484f97e995661e1d.png)

### 通过应用程序报错读取

该情况我没有碰到，但是朋友那遇到了，大概是这样，比如请求某个接口，返回包中报错出现accessKeyId、accessKeySecret敏感信息，这里只能打个比方如下：

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f2ee12962977e8d57d6629de3d08fbbbf8955aa7.png)

### 目标网站JS文件中获取

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9759bf3676c81828d6b44192acb62297d35c9b1a.png)

阿里云OSS存储桶接管
-----------

原理：管理员通过域名解析绑定了一个存储桶，管理员不需要这个存储桶将器删除后，由于没有将域名解析的CNAME删除，就会出现下面的NoSuchBucket情况，要想接管该存储桶还需要一个前提就是需要在传输管理配置绑定域名，下面的情况可以接管存储桶。

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1cea82547063af6e98628d7cd286d846636a723d.png)  
我们只需要创建同样的存储桶名称即可，这里我没有进行接管，先提交了和产商核对确实存在（提醒一下那个地域需要和目标的一样）

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-75db11e1a462a50d0b59de071e9f4fab8a91473b.png)

Bucket权限配置错误-导致信息泄露
-------------------

在进行Bucket桶创建时，默认的权限时私有权限，如果在配置成为公共读或者公共读写的情况下，这里配置成公开读

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cfecd26b5c85bffd31bf286e3b8cfc62d0a93fdb.png)

无法列出存储桶

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-22e856259a6dfb5d3b5880cc3dc7dbc4d661ef95.png)

但是如果创建了公共读并且Bucket授权策略设置成ListObject，将导致遍历存储桶

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e64521e401b3b5ac5c51b3140b67b086cc992aee.png)

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-886279c4ca9e217281d599f77a6090d06830ef69.png)  
以下存储桶由于配置错误，导致了整个存储桶遍历

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5fe93adbcddf7f894a65455bfe582bdc64b8a389.png)

接下来我们拼接key标签下的值，导致身份证信息泄露

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-76a70f2bc9555ac6f89541b61a38267ebc203af5.png)

Bucket权限配置错误-导致拒绝服务
-------------------

在我们遍历存储桶时，其实还可以增加一个漏洞就是拒绝服务（这个要根据情况具体分析）

原理：由于max-keys参数可控，我们通过更改max-keys的大小请求服务器，由于服务器接收到该请求要根据这个参数的大小返回数据给我们客户端，将占用服务器资源，这将经历一个漫长的过程，我们通过工具发送大量的该请求，就可以在短时间内使整个存储桶造成拒绝服务。（这里关键是要观看最大值返回的数据包大小和响应的时间）

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9aede4c2286653a06c393c6fb6f373b4755cc427.png)

更改max-keys的值，如果值在不断变大并且响应时间需要几十秒和数据非常大的话，说明存在拒绝服务漏洞。

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-84d68141a115ced861576b0910d6742f9bda1e55.png)

0x02 结语
=======

以上是阿里云OSS攻防的常见思路，欢迎大家关注公众号：**红云谈安全**