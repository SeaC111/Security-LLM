利用思路
----

1. 前台设置一个管理员的session
2. 后台远程插件下载文件包含getshell。

### 前台设置管理员session

在`application/api/controller/Ajax.php:219`

![image-20210401143608556](https://shs3.b.qianxin.com/butian_public/fe977eaf9b0792435cd71a6fd33e7fcfe.jpg)

get\_token函数是可以前台随意调用的，另外形参中的$name变量也是通过http传递进来的。跟进token函数，如下图所示。

![image-20210401143754804](https://shs3.b.qianxin.com/butian_public/f0d9f5abe31b69f4807d12c3d39d78326.jpg)

箭头处有一个设置session的操作，名字是可控的，而值是请求时间戳md5的值。不可控。

既然可以设置任意session名字了，那么我们是否可以给自己一个管理员的session呢？

然后我们梳理一下后台管理员的登录逻辑。

在`application/admin/controller/Base.php:61`

![image-20210401144246991](https://shs3.b.qianxin.com/butian_public/f8f1d30c2534ca3af9cdf8d1351c002d4.jpg)

这里涉及到了两个session，一个`admin_login_expire`，一个`admin_id`。

**admin\_id** （该session有就即可，不会验证其值）

**admin\_login\_expire** （该session会做减法的校验，需要满足一定条件）

而我们设置的session中是md5字符串，因此在设置**admin\_login\_expire**时，需要挑选一个前面是很长一段数字的**md5**，这样计算出来的结果就是负数，就满足该if条件了。

如图所示：

![image-20210401144806468](https://shs3.b.qianxin.com/butian_public/f3072b62d58d58e7d042c298c39fe4dfb.jpg)

设置完这两个session后，我们继续看到if条件判断里还有一个check\_priv函数，跟进查看：

![image-20210401144918777](https://shs3.b.qianxin.com/butian_public/f88f80c9e6bc9c5a6b0ac51d9ce960336.jpg)

这里就很简单了，继续设置一个**admin\_info.role\_id**。满足比较小于0即可。

设置完三个session后，就可以进后台了，如图所示：

![image-20210401145118680](https://shs3.b.qianxin.com/butian_public/fd89c3b0e7f0322adb107d82fd2580519.jpg)

### 后台远程插件下载getshell

在`application/admin/controller/Weapp.php:1285`

![image-20210401145400501](https://shs3.b.qianxin.com/butian_public/f8430572127595ae9c8ee93af20d64716.jpg)

这里传进来一个$url，然后做一个url解析，需要满足host为`eyoucms.com`。

也就是程序限制只能从官网下载插件安装，但是这个校验太简单了，可以绕。

然后下文就是请求这个下载链接，做解压操作，并包含进来`config.php`。

![image-20210401145933279](https://shs3.b.qianxin.com/butian_public/fd60e15c29069f15e2436ec750b47be14.jpg)

然后开始准备制作恶意压缩包，也就是如下图所示的目录结构：

![image-20210401150008559](https://shs3.b.qianxin.com/butian_public/f85593d83df77269eec17cc2c3b12d22c.jpg)

![image-20210401150029774](https://shs3.b.qianxin.com/butian_public/f745254b676393561aa059d37c9ee47ee.jpg)

然后去官网转一转，看看有没有上传的地方，还真有！在提问功能处可以上传图片

![image-20210401150124607](https://shs3.b.qianxin.com/butian_public/feed2255d6567482c096c76ce1a7fccfa.jpg)

然后我们把恶意压缩包改成图片后缀传上去，得到一个上传后的图片路径，在构造报文触发文件包含。

![image-20210401150421364](https://shs3.b.qianxin.com/butian_public/f2aaad2660d5fbd25c7e27ac105ec48d3.jpg)

生成webshell。

![image-20210401150558342](https://shs3.b.qianxin.com/butian_public/ff0f5579e2b9e1de8793da1273649b9de.jpg)