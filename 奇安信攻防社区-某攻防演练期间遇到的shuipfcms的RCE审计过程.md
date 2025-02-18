背景
--

在某次授权的攻防演练项目中遇到了目标使用shuipfcms系统，接着对shuipfcms进行本地搭建后代码审计，最终获取目标权限。

思路介绍
----

1. 某一处泄露Authcode
2. 利用Authcode加密cloud\_token
3. thinkphp缓存getshell

代码分析
----

**Authcode泄露**

在shuipf/Application/Attachment/Controller/AdminController.class.php:37

![image-20210420110324447](https://shs3.b.qianxin.com/butian_public/f59131959b1a2362b1cde2e1bdf51d21029d6b911a2e3.jpg)

swfupload函数是不需要鉴权就可以直接访问到的，可以看到红色箭头处，当我们的密钥不对的时候，会直接打印出系统的AuthCode。

如图所示：

![image-20210730122738847](https://shs3.b.qianxin.com/butian_public/f75456547dc30f4fa0f7778501eb32503c4ea9d4c54ff.jpg)

我们得到这个AuthCode后可以干什么呢？

**cloud\_token解密**

在shuipf/Application/Api/Controller/IndexController.class.php:17

![image-20210420142803247](https://shs3.b.qianxin.com/butian_public/f973301ebd858bc95eef7563c9ac32e3078154a91df07.jpg)

这里我们POST进来一个token，然后调用authcode函数进行解密：

![image-20210420151446099](https://shs3.b.qianxin.com/butian_public/f3067253b075e1f109ca89a637282adf027d89cd278e3.jpg)

当key为空的时候，就会用authcode来解密了。

而这个CLOUD\_USERNAME默认是没设置的，属于云平台的配置选项，所以默认条件下，这个地方的解密是用authcode来解密的。

上文已经泄露了authcode，所以这里解密后的内容也是我们可控的了。

然后看一下解密后的操作：

![image-20210420151657740](https://shs3.b.qianxin.com/butian_public/f660150afbe304be98d377b0c62eade3dd2effef9add1.jpg)

调用了一个S函数，这个是TP3内置的缓存操作函数。这里的键值是getTokenKey函数的返回值，跟进一下：shuipf/Libs/System/Cloud.class.php:161

![image-20210420152031128](https://shs3.b.qianxin.com/butian_public/f6175356930582abdfb2369c39143b87477890a2c1317.jpg)

OK，这个值还是比较好计算的。

**thinkphp缓存getshell**

然后看一下缓存的处理：

shuipf/Core/Library/Think/Cache/Driver/File.class.php:120

![image-20210420153550946](https://shs3.b.qianxin.com/butian_public/f699219e380a88b16c15384bbaa73a8a1b8f339729bec.jpg)

首先是文件名的生成方式，第一个红色箭头处，跟进：

![image-20210420154451354](https://shs3.b.qianxin.com/butian_public/f18440985e53c8d332c29a82c2d45616bc10a2d3ae7dd.jpg)

这里的DATA\_CACHE\_KEY默认为空，不用管，但是$this-&gt;options\['prefix'\]是有的。看一下生成方式：

![image-20210420154550495](https://shs3.b.qianxin.com/butian_public/f668800a4c21c9b5efe45efaff1928bfe4f1efa19bf10.jpg)

![image-20210420154603612](https://shs3.b.qianxin.com/butian_public/f765969b1074a1633520443a73e4efe0477b5f55cbf64.jpg)

就是三个长度的随机字母加一个下划线。这个就比较有难度了需要猜测和爆破了。

然后就是一个写入反序列化数据的操作。

我在本地测了一下，数据像这样：

![image-20210420154735383](https://shs3.b.qianxin.com/butian_public/f5520623e431ff3e6a9cfd04a58a66f46bcd84e30cfff.jpg)

成功写入了webshell。但是实战中的前缀需要爆破,win不区分大小写，会很快，linux则稍微麻烦一点。比如我本地是rDe\_。

### 利用过程

首先我们发送报文获取authcode:

![image-20210730115910454](https://shs3.b.qianxin.com/butian_public/f304199621098ae455d155f2b3423a282762d0a475452.jpg)

然后我们生成token发送：

![image-20210730122534643](https://shs3.b.qianxin.com/butian_public/f7119453aa14fa76fbc497df7094c6c5edaac40cfaac8.jpg)

响应报文中有验证通过就证明成功了。然后我们就需要找到我们的缓存文件了。  
这次比较幸运，目标有列目录的漏洞。

然后我们访问缓存文件即可成功getshell。

![image-20210730122953760](https://shs3.b.qianxin.com/butian_public/f794653747f59695dcc695dd644402090b9d8abe335e4.jpg)

**注:zc.com解析为127.0.0.1为本地环境**