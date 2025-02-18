请出主角
====

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-02f1398be192fe16536d1119aec5eb3761c96b88.png)

又是登录框开局，先扫一下目录看看有没有未授权  
没扫出东西，其实这种301状态的路径也可以继续扫下去看看，我已经扫过了，没扫出东西，就不贴图了

![捕获.PNG](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-9d01ebec72b761f89afb0b9b8623fda54eb08daa.png)  
看到没有验证码，抓包跑一下弱口令

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-1fb78b5086e5955d77699bc16f25aa6bae608924.png)

爆破无果，尝试SQL注入万能密码也没反应，想随手尝试一下有没有别的测试账号弱口令，test/123456，system/123456之类的

SQL注入
=====

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-381e36fac4aa9e6f32ca81386d711a2095c8ddba.png)  
发现在准备输入密码的时候，下面提示了没有这个账号，猜测应该会有某个接口在我们准备输入密码时判断系统内是否存在该账号

把burp里的http历史清除，继续输入test，在要准备输入密码的时候，查看数据包记录

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-d7d01b1c166af597dfc7e9a34e20f62d4af4a581.png)

发现记录到一条数据包，根据接口名可以大致确定是在检查用户名

查看数据包

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-54b5d77d2f514be9a8460949f7f76866c9f46a12.png)

返回了没有这个账号，如果是一个存在的账号

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-25532d1e7456ac1c61697428e931dd4fcf1cb432.png)

会返回这个包

既然会判断用户是否存在，那肯定是带入到数据库进行了查询，放到重放器，往用户名后面打个单引号

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-6cc41d72d9512c9e179aad92176cf4bc4766bad3.png)

果然不出所料，这地方是有注入的，复制数据包保存到本地，sqlmap一把梭

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-6d421e52c766bc8b4a4ce160393aac0dfd213171.png)

成功跑出注入，可惜注入类型不是堆叠，不能--os-shell，直接跑密码

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-1dcfef384ce5e48fb694a51945a0520be531c01d.png)

这个时候是看到跑出admin了，这个时候已经在幻想进后台文件上传拿shell下播了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-5070dca302677ea55b16632d983bb4f726158e0a.png)

于是马上把程序给终止了，拿admin账号密码去登录系统

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-8bb582264c210755700200eba0a9a7eb4fd90e4c.png)

提示密码错误

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-45a36cbb1df7f022067b1ff353f1945cf2801501.png)

郁闷了好一会，拿其他账号密码去尝试登录，也都登不上，把其他几个库和表也都跑了一遍，都登不上，都准备下播了，但是作为严辉村第二台超级计算机，我觉得会不会是前面跑数据的时候出错了，于是我把最开始的那个表又跑了一遍，这次我没有终止程序，看能不能跑出其他的管理员账号

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-9059cc9ca158b90b8c5e6ca38b807cdd10e0226e.png)

跑完了发现竟然有3个admin，第一个已经登录过了，登不上，直接拿第二个来登

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-157faf96ca780acbb8b89577b6e1bbcddbfcd709.png)

这次成功跳转进了后台，进了后台首先把功能全点一遍，找找上传

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-32e98a6f39f72b339c9448bdeb4b2fc25ad158a6.png)

功能很多，鼠标都点烂了，才找到一处上传功能，而且只能上传xls格式的文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-ed8c961a68f16fcd880bad5c80cab6d28f21d5c6.png)

就算我本地建个xlsx，改成xls上传都不行，直接下载他给的范例进行上传

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-b2d2895eccd6d4b1f3f8adbef06472510193664c.png)

正常上传提示已执行过，改一下后缀和内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-6b15b0af0163c837c16c0405da14139c4d48f65f.png)

感觉应该是白名单，试过网上很多种绕过方式都不行

先把这个放一放，看一下刚刚点功能点的过程中burp里面记录的数据包

任意文件读取
======

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-5a01725263b840f11654f13c9e2cd4b43d36f917.png)

查看http历史记录，发现有很多这种数据接口，感觉像是在读取文件，参数里有一个xml的文件名，查看返回包，也有这个文件名，并且确实有xml格式的数据，尝试目录穿越读取文件

先尝试读一下根目录的default.aspx

../../逐个增加

经过测试，发现如果是7个以下../，会提示找不到路径

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-7c59e4ee15bb76fa479ca8808f9ab0df2edd2df1.png)

如果../是7个以上的话，会提示无法使用前置的..来离开至顶端目录的上一层目录

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-9dd5aab1df37421e63a341002a3ac53379b89968.png)

当../为7个时，根据提示可以发现已经开始报错代码错误的位置了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-1564ba4a994965e092708e07503157646c5af71d.png)

但是还是没有看到文件内容，试过很多方法，最后发现把最后一个参数&amp;name\_space=EditDetail给删掉，就能成功读取到文件内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-3d7993317443a64f9128357048f8bf14ebbe55d7.png)

成功读取到aspx代码，至于为什么是这样，问就是我也不知道

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-dded9f53bfaa411e802ae25ad9361c2b389b89ee.png)

既然有任意文件读取了，尝试读取一下刚刚文件上传的代码

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-6c3610a1dfdee950e9051ef37bed14cae0e6d328.png)

找到刚刚上传的数据包，发现上传是由Upload.aspx来处理的

读他！！！

也是7个../

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-175949c9f12a151c616615bed97cc6444eeae5f1.png)  
成功读到文件，但是没有关键代码，就读到一个声明，其他都是html

根据声明CodeFile="Upload.aspx.vb"可知：指定代码文件的位置。这意味着与当前页面关联的代码将位于名为"Upload.aspx.vb"的文件中，在Upload.aspx引用这个文件的时候，没有加../，说明Upload.aspx.vb文件也处于当前目录

继续读~

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-dc90697472c39980044521f52d91ccbc92ef59f1.png)

成功读到关键代码，格式虽然有点乱，但咱是严辉村超级计算机2.0

根据代码得知，上传的文件会保存到PL/PLB/PLB010/UploadFile/目录下，文件名设置为Upload+时间戳+.xls

这还玩个球球，直接把后缀写死

继续上传，由于系统是windows，尝试用特殊符号截断

经过测试，还是传不上

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-e5b9351486450fdfd5de186e5c479e8ba9d76b43.png)

于是我又把头扭向了SQL注入，因为后台功能点很多，大部分为查询，尝试在后台找一个能堆叠注入的点--os-shell

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-8fee690f3f9176406c361cb5e339de7f0b6dd210.png)

找到一个可以执行sql命令的地方，继续抓包丢sqlmap，还是不行，都是只能跑出报错注入

读一下配置文件web.config

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-074ff06c31d20536668eec3001369d36229bb31b.png)

读到了数据库账号密码，权限为sa，可惜数据库地址在内网。。。。

这时突然想到，既然--os-shell不行，数据库用户为sa，直接--sql-shell

sqlmap --is-dba

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-53633f632916dd7cd6bbbf2db203dbfc2fdcd181.png)

权限为DBA

\--sql-shell

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-5d9836786cd62d2d0afc5c3d1e91ca3d96d4db39.png)

尝试利用xp\_cmdshell执行命令

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-a3893b9678f9755850d8eea317151d4d20980c93.png)

发现当注入类型不是堆叠时，不支持查询以外的操作。害，还是基础知识不够扎实

正在想怎么办时，因为看数据包基本上都是xml格式传参，又试了试XXE注入

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-861349980d94438327448a866fd613ba2bb20778.png)

确实有回显，但是XXE没深入了解过，这玩意好像拿不了shell，也先不看了

看了看IP

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-bcddf7778900f7d4c8b226236d40cdc091e49fc7.png)

也没开别的服务

继续看后台，一个一个功能点再细细看一遍

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-02242a3aa66c6e026b995950ba0f2ba6e70c3ad2.png)

发现这里查询出来的内容包含图片

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-7da6db08302a779e1e6c27f2496c4f0f999572c4.png)

点开发现确实是有图片

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-fde09f0d8e15c217755f2b462b81d01ca2eaa3d4.png)

但是我无法对图片进行修改，此时想到之前跑出的账号密码，想试试能不能以用户的身份登录系统，然后上传资料图片试试上传webshell

登录一个新的账号

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-14be93b27c1cb5e02e8403e2c6604eeb2f0a6133.png)

发现这可能也是一个管理用户的账号，内部功能与admin不同，再把这些新的功能翻一遍

还是无果，通过对数据库的信息进行查看，发现用户表里是没有普通用户的账号的，这些用户的信息存在另外一个数据库里，而且刚刚上面看到的图片也都是存在数据库中的。。。

应该都是通过管理员账号导入的

对http历史记录里的所有aspx文件都读了一遍，发现还是没有能R的点

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/10/attach-47c4863feeb2f3076cfc062dc3e8be1183894f94.png)

下播下播