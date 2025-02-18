0x00 审计前的准备
===========

```php
以下相关漏洞已全部提交cnvd
```

![01.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c77cf926698216ab83d157053938f9affc8411cf.png)  
熟悉目录整体架构  
php目录为 代码的功能实现  
主要审计php目录

0x01 文件上传getshell
=================

`uplaod/mt_parser.php` 漏洞关键位置代码

![02.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4330ddfda3789f96bbb419d38ff3ddbe3f4fee4e.png)  
无任何过滤直接构造poc上传即可

```html
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title></title>
</head>
<body>
<form action="http://127.0.0.1/upload/my_parser.php" enctype="multipart/form-data" method="post">
    <input class="input_file" type="file" name="upload"/>
    <input class="button" type="submit" name="submit" value="upload"/>
</form>
</body>
</html>
```

漏洞证明截图

![03.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d260bb14bb430816e343d255acaa8a1dad7e1ac9.png)

0x02 查看文件
=========

开始审计php目录下的文件  
发现均包含了`conversion.php`

![04.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d6856a20f654265ce377a2d6bd19ebd64a6410aa.png)

进行查看 具体实现的功能  
共写了八个方法，一个个看一下

1、`function arrayRecursive(&$array, $function, $apply_to_keys_also = false)`

![05.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3c8022e6ecb68c65f4406c87fbb469a088aa1d9b.png)  
大体实现了  
第一个参数传`array` 第二个参数传`function` 分别对`array`的`value`进行`function`操作。  
如果`apply_to_keys_also`为`true`还可以对传入的`array`进行改变`key`值

2、`function JSON($array, $want_url_encode = true)`  
![06.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-197bc29eaea629d64d0b9ff51156bb5d004e7505.png)

大体实现了  
对传入的数组进行`json_encode` 然后`urldecode`操作（这里可能实现了中文字符的传入）

3、`function UdpSendJson($array, $msgType)`  
![07.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-18ee4971659b354b5baf91965ea25f3c13a2aabb.png)

大体实现了  
一个传送JSON数据的功能

4、`function UdpSend($msg)`

![08.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-94ab23432780b3a658ffe0c4c254e3af68fe106f.png)  
大体实现了  
对`8888`端口下的`AppWebService`的命令操作 具体干什么可能要看硬件设备了。

5、`function UdpSendAndRecvJson($array, $msgType)`

![09.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fe223269677d49a3ecbdea5a766922e703a70c5a.png)

大体实现了  
接收和发送JSON数据

6、`function UdpSendAndRecv($msg)`

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-53bc9974a6acee2f56ed606f0b5317c4864c14cd.png)

大体实现了  
发送和接收数据，对本地的`8888`端口发送一个`POST`请求 这里和`function UdpSend()`实现了一样的操作，只不过多加了一个Linux下的操作

7、`function phplog($data)`

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0b4701d8dee1fdd242a46678045ae5815b0572d5.png)

大体实现了  
写日志的功能

8、`function get_real_ip()`

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0b5aba98e0079371a8824f5f8dd0b34c33521e32.png)

大体实现了  
通过`Client_ip`头获取了`ip`  
接下来看php目录下文件实现的具体功能

0x03 任意文件上传
===========

php/addmediadata.php 漏洞关键位置代码

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0bcd8a384df125dda40845d74c90c8d6be1c3af9.png)  
满足`$subpath`、`$fullpath`可以自定义目录，然后进行了一系列的检查如文件大小等  
最后进入if条件中`move_upload_file`函数进行文件上传  
构造poc

![Pasted image 20220504155204.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3b390e68fd2121bcbb940e634ed6e8e174682c93.png)  
访问./upload/1/5.php成功访问

![Pasted image 20220504155243.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-96262811955d18233e40fc54a36ab90725f4c205.png)  
addmediadatapath.php存在相同问题  
收获两枚通杀漏洞  
`php/addscenedata.php` 漏洞关键位置代码

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-eafa445111d3c62416e7499de8308eb7bc6f019c.png)  
不多说了 自己看  
构造poc

![Pasted image 20220504160756.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f0715ba142bcced95fd6d4c123b70ff0d1407560.png)  
访问`./images/scene/5.php`

![Pasted image 20220504160941.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-054d8136e06388e4879d13002092f5cdf13037b0.png)

0x04 任意文件写入
===========

`$postData = $_POST['jsondata'];` 需要满足这个参数  
看一下传参方式

![Pasted image 20220504164650.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3944e20a3c64e827c49ecb6fba87a59bee2ad61a.png)

然后满足`$caller`，`$callee`、`$imagename`、`$imagecontent`这三个参数不为空

![Pasted image 20220504164718.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-347d463cfe31abfc824a9bb5628d7229b0a4c36b.png)

满足`$imagename`用\_分割后等于三个

![Pasted image 20220504164841.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-442acad2c1fe368400405c07d85acc9ed15e3d95.png)

`$callee`参与了目录拼接 这里跨目录上传 (需要知道根目录才能解析成功)

![Pasted image 20220504164952.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4b0483ef9eef245a42e93143d24830602b31a437.png)

只传入一串base64加密的内容  
进入else条件

![Pasted image 20220504165102.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1a554fb76f8397b84cf736a44fce74c38eef82a5.png)  
![Pasted image 20220504165046.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-84bc9ccec76b27c05531e2f193a13493e6c5b1dd.png)  
构造POC

![Pasted image 20220504165137.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7655db17d9e5df9d61be76a8cb5a9e460f855466.png)  
成功上传

![Pasted image 20220504165151.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bfbc04c1104f772514d52c3206160a83b062ed1d.png)

0x05 任意文件读取
===========

`php/exportrecord.php` 漏洞关键位置代码

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7ee6e37e49144918a14d1d597769a138ffe104ce.png)

获取了参数`downname` 需要下载的文件进行了`urldecode` 不用管 左思右想 想了半天也也不知道为什么要在37行加个basename  
直接在`41`行 执行了`fread`操作

![Pasted image 20220504172319.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-130e039679135672c6f8d132172c83d0223048fe.png)

类似操作还有 `exprottts.php`

![Pasted image 20220504173126.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b0827190e6c555d9fb2d484d06bc112d85feff6a.png)

0x06 总结
=======

此套代码几乎无过滤，这也是硬件设备的一个通病，很多厂商都以为不会"黑客"拿到源码。  
还有很多漏洞 都是无过滤的 此处不一一写出来了