0x00 简单梳理
=========

在开始之前简单大概过了一下某项目管理系统的目录和路由模式，这对于理解整个原理个人认为有很大的帮助。下面对主要的几个目录做一个简答的说明。

![image-20220731223506693.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4d265503bd48927b7e215e5c896c07ef4dd7b20d.png)

```php
- config下面存放了运行的主配置文件和数据库配置文件。
- framework里面是php框架的核心类文件。
- module下面则是存放了具体的模块。control.php则是各个模块所有页面的入口，相关的方法都在其中。
- www目录则是存放了各种样式表文件，js文件，图片文件，以及禅道的入口程序，index.php是整个程序的入口程序。所有的请求都是通过这个程序进入的。
```

对于路由模式，它总共有两种，分别是`PATH_INFO、GET`方式，其中GET方式为常见的`m=module&f=method`形式传递模块和方法名，而`PATH_INFO`则是通过路径和分隔符的方式传递模块和方法名，路由方式及分隔符定义在`config/config.php`中。这里所有的采取默认配置也就是`PATH_INFO`伪静态路由，而实际上两种路由模式是可以同时使用的，具体感兴趣的可以去看看网上的文章讲解。

0x01 漏洞分析
=========

根据所知道的POC利用的请求路径，快速定位到了`/module/user/`文件夹，看了一下视图文件，主要是前端代码，以及前端参数的传递，对比了一下代码和站点登录界面符合。

直接看目录下的`control.php`,这里面有我们根据伪静态路由规则可以定位到的方法，在`#848行`的`login`方法

![image-20220731225315449.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c99b74c2a8fbfdcc65972206c8ef5f39f5ced2c1.png)  
可以看到`POST`或者`GET`来进行传递参数都是可以的，并不会因为默认配置影响参数的获取

首先会调用`checkLocked`方法，跟进查看代码，主要是对当前登录的用户是否被锁定做一个简单的判断，具体的判断方法就是计算当前登录时间和锁定时间的时间差是不是仍小于锁定的时间。

![image-20220731225748128.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-60488b4641e3f206f30c467142403e2269d8084b.png)

接着往下直接看到`identify`方法,该方法在同路径下的model.php文件中。看遍了整个方法，涉及到数据库查询的地方都采取了预编译的防御措施，并没有找到能注入的地方。

![image-20220731230715098.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-43578bb9204a1f01755ca7cf90e180443b85bb89.png)

![image-20220731230726550.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-ebe46a75d17315819091056de3af778f752825d2.png)

这个地方卡了挺久，一直没有找到漏洞产生点；漏洞的利用路径并没有错，不知道问题在哪里。后面重新梳理了一下目录，突然想到`/www/index.php`,作为所有请求的入口，说不定有点什么特殊的地方，果然，在全局搜索和`var_dump`全局打印下找到了点。

`/www/index.php`,作为入口，每一个请求都会调用它；来仔细看一下代码

![image-20220731231603429.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8145a9d878f3fef6abfb1b7653506ca9e128fd88.png)

首先会包含`framework`文件下的框架的核心类文件

之后就会调用`router`类中的`CreateApp`,跟进，定位到`/framework/base/router.class.php`,根据传入的参数会实例化一个`router`类对象，,又因为`router`类继承自`baseRouter`，所以在实例化`router`类的时候会调用`__construct()`魔术方法，也就是父类的构造方法。

![image-20220731232021488.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2bfd7439aac4a1cb2997534e54f91a3f69a82145.png)

![image-20220731232148945.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-3873a5a6d2d9c6f86dc6231251db7fd72673fa9b.png)

看一下该构造方法，在初始化的时候会调用很多本类中定义的方法，像设置目录的分隔符，基础目录等。在经过逐个方法跟进查看之后将视线放在了`setVision()`方法上面，跟进，一眼就看到了漏洞所在

![image-20220731232345775.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-002917ea39f66f88069a2526537f881a42060af3.png)

可以看到这里手先获取了`account`参数，只要已经安装过该系统，那么就会进入第一个`if`判断当中，这里虽然采用了预编译的方法和数据库进行了交互，但是其中的参数却是用了字符串的拼接方式，那么毫无疑问字符串拼接并且没有过滤的情况下，很轻易的就能够进行SQL注入的利用。

![image-20220731232608145.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-dcfe27ae4c58e3ada92b3cd60fb2bae122e01854.png)  
所以实际上这个漏洞的利用栈是：

```php
/www/index.php(34)
->/framework/base/router.class.php(433)
->/framework/base/router.class.php(410)
->/framework/base/router.class.php(702)
```

0x02 漏洞利用：
==========

事出匆忙，EXP简陋，后续有时间再好好写一下了。

![image-20220731233109959.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7d59f7e2b928976d2ee3b188991ed4bdf08afb6a.png)