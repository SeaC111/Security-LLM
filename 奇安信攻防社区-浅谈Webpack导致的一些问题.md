0x00 前言
-------

Webpack 是一个前端资源加载/打包工具。它将根据模块的依赖关系进行静态分析，然后将这些模块按照指定的规则生成对应的静态资源。

![img](https://www.runoob.com/wp-content/uploads/2017/01/32af52ff9594b121517ecdd932644da4.png)

但一般情况下所有打包的文件都会被加载，导致了泄露一些敏感信息（如敏感的path，api接口等）

![image-20220707131208461.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-fdedfe1b423fd6cd50c80d563b05c8917d1226b8.png)

0x01 案例 - webpack打包加载导致后台接口未授权泄露管理员账号密码
---------------------------------------

某天EDU上了新证书，想着快人一步，立马就开始信息收集打点

![image-20220707132056358.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7494accefc6393f476a102e206a535eea68a5669.png)

习惯的打开F12查找一些有用的信息，看了一下明显是前后端分离的站点用了webpack进行打包，所以我的思路是重点找未授权，鉴权不完善等问题

![image-20220707132334473.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-d79e505139c5ceb1568134e87f61364dd017fed2.png)

app.js里的加载文件引起了我的注意，然后就是访问了/AdminManager，但鉴权了，记得看过一篇文章，”有些网站外部做的很好，登录后里面却出现了很多问题“

![image-20220707132701224.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-20b8a0a3bea5fc8652dff454e5d3d11487ccc271.png)

然后我就去试着构造链接，去访问他加载的文件，找到了两处接口

![image-20220707133217343.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-fb91a23d8ad39be9382625a688cf35bd517cf32f.png)

访问其中一处接口，发现未授权泄露大量普通管理员账号密码

![image-20220707133423374.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-36a1cb1112b0e0494f8243a55313ddb787c82d5b.png)

既然有了一处有问题，那么出现其他问题的概率还是很大的，看了看Cookie的存储值，看是否存在弱key的问题，其他的看起来没有这个问题，只是这个role的存储感觉有点问题

![image-20220707134005003.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6cd32cd539975e041d8fdf8ceec811606823aaea.png)

最后试着改成“管理员”，发现不管有没有其他的Cookie值，都可以访问后台进行操作，而且权限极大（在写这个文章的时候洞已经修了，这里就不放图了）

0x02 案例 - webpack泄露导致的敏感路径泄露进行文件上传
----------------------------------

眼馋上海某国语的证书，打点打点

![image-20220707135120366.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b334ed97e78d8942fe8d959da2f2b17ecca2c7c7.png)

习惯的F12，发现webpack泄露

![image-20220707135243027.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-07b10c60649cf524d8e0c0f7c5d71e6ae7f54196.png)

这个站可以注册账号，想到了鉴权不完善的问题，然后就直接去看router目录下的内容了，可惜没有什么关于权限的，只好找了一个看起来“顺眼”的瞅了瞅

![image-20220707135417756.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-938a0520ad028217a9a49b4d59a3a1098dcf11fa.png)

去看加载的vue，果然找到了一处件上传接口

![image-20220707135809943.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-c381531837df13130d389d33c583e4e1d93b0cc5.png)

然后就是构造数据包，这里虽然是白名单但是html会被防火墙拦截，但发现xml没有

![image-20220707140521921.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-588a09b5afeb571f495e8af8f6219781c3b414c3.png)

访问链接，alert(1)

![image-20220707140803352.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-81ca298b205c40739e7ccb6a2625067ca495eb28.png)

0x03 案例 - webpack泄露导致未授权文件上传
----------------------------

想换某济的水杯，努力打点

![image-20220707141221164.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-34a8ab35a6aba7a80e88b0041d1883ed3ab608f9.png)

都Vue框架了，当然还是要习惯的F12，三步一连，迅速收集

![image-20220707141612774.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2b8e3b8e411ee258850e52bd5fcd736b02685f7c.png)

没有登录（莫得某济统一账户），这个界面可以访问，试试上传一下

![image-20220707141733550.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1f6091c9766710914374edbddb9ae68c9530e7b1.png)

什么后缀都没有限制，但他是前后端分离的站点，可恶

![image-20220707142029423.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-b6d1f4bbd3984d4cdaf06b4713cf2d495442c9a4.png)

访问，alert(/xss/)

![image-20220707142309290.png](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0ed2674de1bd2bc688307be84925276ed084b467.png)

0x04 总结
-------

webpack的打包方便了我们，却也因为他的特性，使网站也存在了一些安全问题...... （最后也推荐一个微信公众号：浪飒sec 欢迎关注哦）