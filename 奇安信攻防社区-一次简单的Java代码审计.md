开始
==

本次审计源码地址：

```php
https://gitee.com/jeecg/jeecg
```

该版本已经停止更新，官方已推出新版本。

```php
https://gitee.com/jeecg/jeecg-boot
```

环境准备
====

下载源码后直接在，IDEA 中打开（我用的是 IDEA）。

IDEA 运行配置
---------

点击右上角添加运行环境配置

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da77969155bd10b670e88ec497588f844a52c00b.png)

添加新的配置，选择 `Tomcat Server -> Local`

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-75247b347153f797d219778ee0ff2f032e32a5e7.png)

如果没有配置 `Tomcat Server` 选择路径添加一个即可

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e378533d55902bbeb817120dc9ae852ff4034218.png)

点击 FIx 修复

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4efd16b1c8a95c9c7fda4f4e44a8a0d97b5d6b79.png)

选择 `war exploded` (war exploded 模式是将WEB工程以当前文件夹的位置关系上传到服务器，即直接把文件夹、jsp页面 、classes等等移到Tomcat 部署文件夹里面，进行加载部署。因此这种方式支持热部署，一般在开发的时候也是用这种方式。)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7faf0b9564404eb8689579943ad45a3a66c2a06c.png)

初始化数据库
------

我这里是用的 `mysql` 所以选择 `jeecg_4.0_mysql.sql`, 添加创建数据库逻辑, 直接导入即可。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-869421af18cb746f2800a7c0ea0955ef8257498f.png)

就可以跑起来了

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-82e0be2935bb92c5ad9b7f9285c7659f07d84597.png)

基本信息
====

Springframework MultipartFile
-----------------------------

用了 `Springframework 4.0.9` 之前有写过文章测试过，在 `Springframework < 4.1.8` 之前哪怕手动设置了 `MultipartFile` 的处理对象 Windows 下也存在目录穿越（绕过）参考： [Spring MultipartFile 文件上传的潜在威胁](https://forum.butian.net/share/815)

这里手动设置使用 `CommonsMultipartResolver`，但版本 `< 4.1.8` Windows 下存在绕过

*src/main/resources/spring-mvc.xml*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-263a4e67143d0e4cdebd2024318caf1bbee46971.png)

Springframework Route
---------------------

这里配置了两种路由模式，一种是 `.do` 结尾，一种是 `/rest/` 开头

*src/main/webapp/WEB-INF/web.xml*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7c3706ae184fef8dc44fbd7782ac8251bbe59a2c.png)

Filter
------

收集 Filter 信息，这里并没有关于权限认证的 Filter

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cd1c5fd95a4b67185e09366ddc0ffb6f7434f30d.png)

Springframework Interceptors
----------------------------

查看拦截器, 这里设计到三个拦截器，且 mapping 都是 `/**`

*src/main/resources/spring-mvc.xml*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0fb433d5c36404b868eababad69d88137b34e08f.png)

### EncodingInterceptor

只是简单的编码

*org.jeecgframework.core.interceptors.EncodingInterceptor#preHandle*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-af3ab9420d19cdf826fc4a6c865a2cbdf2404ab7.png)

### RestAuthTokenInterceptor

这里存在绕过，后面再说。可以参考我之前发布的文章：[这个鉴权到底能不能绕](https://forum.butian.net/share/829)

*org.jeecgframework.jwt.aop.RestAuthTokenInterceptor#preHandle*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56b27f863a5fe8bfcc6f7a9e1fced496b9be14f9.png)

### AuthInterceptor

这里的 Mapping 也是 `/**` 但他不过滤URL 存在 `rest/` 的请求

*src/main/resources/spring-mvc.xml*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-72252e104566d5d2d71651b1174ce033fa3b6cb7.png)

而逻辑内也存在绕过, 可以参考我之前发布的文章：[这个鉴权到底能不能绕](https://forum.butian.net/share/829)

*org.jeecgframework.core.interceptors.AuthInterceptor#preHandle*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-57fbb7bd3f65368aff232e7f82d4b77701d47615.png)

权限认证绕过漏洞 1
==========

综合上面的信息，我们可以使用 `/api/../`，绕过 `AuthInterceptor` 的认证

正常访问，302 跳转到超时页面

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7ebf6b36d520533b8bec5177fb4a4f41e22f3beb.png)

超时页面只是通过 JS 跳转而已

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca0140bc82c6ebd9f112cd2a29d05b86fd56f087.png)

通过 `/api/../` 绕过

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92315733e4defe2db9c3b160bfa9d049d746cecd.png)

权限认证绕过漏洞 2
==========

`RestAuthTokenInterceptor` 拦截器中，使用了 JWT Token 进行认证。

*org.jeecgframework.jwt.aop.RestAuthTokenInterceptor#preHandle*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-330ae9d4797d19f39f37ad947425225004fdc890.png)

使用的 JWT 密钥是写死的， 也存在绕过。虽然存了 Redis，但基本信息是固定的，除了时间。也就是说只要他登录了，redis 中又记录可以爆破 Token。

*org.jeecgframework.jwt.service.RedisTokenManager#createToken*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-681372682727ed6f7d4fc7e14ecffca5e3d4cbda.png)

*org.jeecgframework.jwt.def.JwtConstants#JWT\_SECRET*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-10879f514d9e39c6233e8741d4c00706832661ac.png)

修改 Redis 配置，重启重新启动。

*src/main/resources/redis.properties*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0825e1d453b5f76d4e9a1880151a95fdffe22c82.png)

打上断点后，正常登录一次，获得 Token 样本。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f142ed076301b05f8abbc2dc63207da528ce9e19.png)

去 [JWT 官网](https://jwt.io/) 解密 ，可以看到对应的值。这里的 `iat` 是登录时的时间戳, 所以是不确定。

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4a5120784e67e3340e29c3474e37da466230cc40.png)

通过正常登录获取到的 Id 是可以正常访问站点的

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-512ac1221e83e15fcf3a16363928e2da022b4e3d.png)

修改一下时间戳（因为我们无法确定管理员是什么时候登录的）

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d7dbe7403995a1ea9746d77c8bfa3169f8f36e79.png)

状态变成了 401，未通过鉴权

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e325e4d6ce7cdc951e296d349ac69845b0a088be.png)

因为这里又一个步骤是通过 请求头中的解析出来的Id 字段(也就是用户名) 去查找响应的 Token 和请求头中的 Token 进行对比。响应的我可以通过当前时间往回递减去爆破`JWT Toekn`

*org.jeecgframework.jwt.aop.RestAuthTokenInterceptor#preHandle*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f93636c85a6cdfe1659848f2af960b87fa15ba5b.png)

*org.jeecgframework.jwt.service.RedisTokenManager#checkToken*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4871a72a7fdc66a74a4f4f9d2b79d5e5dbdfac75.png)

任意文件上传 (GetShell)
=================

有很多任意文件上传漏洞，没有任何的过滤/限制。这里随机挑一个来说

`iconController?saveOrUpdateIcon` 存在任意文件上传漏洞，设置了不重命名与上传。

*org.jeecgframework.web.system.controller.core.IconController#saveOrUpdateIcon*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f81e1705f10c98e7c770c6ad9424758c5e534188.png)

上传成功

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a3cd74f83adb497e6dada544ede890371203cbb6.png)

组件试用/修复不当造成的漏洞
==============

有几个因为组件试用或修复不当或没修复造成的漏洞

Xstream
-------

这里其实是俩个漏洞，文件上传和 `xxe` 漏洞, 该功能点是文件上传后试用 Xstream 文件，会造成反序列化漏洞

*org.jeecgframework.web.cgform.controller.build.CgformSqlController#doMigrateIn*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-520a90d095c7fb5ececba5a31dc0dcf249729436.png)

SAXReader
---------

这里其实是俩个漏洞，文件上传和 `xxe` 漏洞, 该功能上传好文件后对文件进行解析

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-55be339ec2b39ffd754b3a87e074c4f60453431d.png)

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a103cee2e2b81dce049a17e31de86e2ad3070c13.png)

Springframework MultipartFile
-----------------------------

前面说了在 `Springframework < 4.1.8` 之前哪怕手动设置了 `MultipartFile` 的处理对象 Windows 下也存在目录穿越（绕过）参考： [Spring MultipartFile 文件上传的潜在威胁](https://forum.butian.net/share/815)

*org.springframework.web.multipart.commons.CommonsMultipartFile#getOriginalFilename*

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de0b30584d42a73d2a9938600fcfb99040b8ef02.png)

Reference
=========

[这个鉴权到底能不能绕](https://forum.butian.net/share/829)

[Spring MultipartFile 文件上传的潜在威胁](https://forum.butian.net/share/815)