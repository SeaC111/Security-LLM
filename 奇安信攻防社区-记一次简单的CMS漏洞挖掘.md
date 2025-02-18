> 这是一个究极咸鱼对一个小型cms（飓风cms）的一次简单挖掘，已交CNVD

### 环境搭建

官网下载源码，利用docker搭建，由于需要php7的版本，这里利用的镜像是`mattrayner/lamp`。

一个docker的小tips，本地源码作为容器映射到docker上即可。

```bash
docker run -it -v $(pwd):/var/www/html -d -p8888:80 镜像ID
```

顺便把`phpmyadmin`也拖进源码目录，方便新建数据库。然后访问`x/install`目录，按步骤安装即可。

#### 漏洞复现

我们先尝试黑盒挖掘，访问`x/admin`，进入后台登录页面

![管理员登录](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-41ea7039d5d0cfa36e768015dad93d04998ad13b.png "管理员登录")

发现有文件管理功能，还可以进行文件上传

[![上传](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a31a10be60979a5ec2cac173c2a142310379437f.png "上传")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a31a10be60979a5ec2cac173c2a142310379437f.png "上传")

尝试上传最简单的webshell，提示我们`非法文件类型`，上传jpg文件，成功。

[![上传文件](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-13837b52f9fac6caae3bbf6e4bbb3b5fbe9363e7.png "上传文件")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-13837b52f9fac6caae3bbf6e4bbb3b5fbe9363e7.png "上传文件")

修改文件内容，以及文件名。

[![插入代码](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-918bdd6c128e0ce44f509fec36f5dc6a1649f49b.png "插入代码")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-918bdd6c128e0ce44f509fec36f5dc6a1649f49b.png "插入代码")

[![文件名修改](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-62f35b4827be8ed36ed92a1222175d0b29a3fab6.png "文件名修改")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-62f35b4827be8ed36ed92a1222175d0b29a3fab6.png "文件名修改")

由于我们上传的是网站根目录，所以直接首页访问`1.php`即可。

[![phpinfo](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5e01ea1cae5a5979a867b0013b8779ecf31d1d4f.png "phpinfo")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5e01ea1cae5a5979a867b0013b8779ecf31d1d4f.png "phpinfo")

成功执行php代码。

#### 具体原因&amp;代码分析

漏洞的复现总是简单的，接着让我们来剖析一下细节。

通过抓取上传文件的数据包可以看到路由触发位置。

[![路由位置](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-927520e4429eb8b240ec788ff0aec6eb060b6c49.png "路由位置")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-927520e4429eb8b240ec788ff0aec6eb060b6c49.png "路由位置")

接着跟进一下源码，在

`jufengcms/x/plugin/managefile/controller/index.php`

找到上传方法

[![upload方法](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-37b77d58badb7cf205cb5c08f025fb5358e38821.png "upload方法")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-37b77d58badb7cf205cb5c08f025fb5358e38821.png "upload方法")

主要操作是实例化`OnlineEditor`类，调用它的`uploadFile`方法，跟进`uploadFile`

[![upload](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5c27ec05401b71e3f6dbc506744938ffc7973a49.png "upload")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5c27ec05401b71e3f6dbc506744938ffc7973a49.png "upload")

能发现我们只能上传白名单的文件，事实确实如此。不过往下面看，在`OnlineEditor`类中还存在`renameFile`方法

[![rename](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-997aaf334154fa48591f1d63fe7cf00b0715be0c.png "rename")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-997aaf334154fa48591f1d63fe7cf00b0715be0c.png "rename")

并没有对更改文件名做类型限制，导致我们可以修改为php文件。通过抓包我们能发现在更改文件名的时候是否触发了`renameFile`方法

[![更改文件名](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-03644391b080cb3199c68c4371f7d532c75e5598.png "更改文件名")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-03644391b080cb3199c68c4371f7d532c75e5598.png "更改文件名")

能看到确实触发了`renameFile`方法，到这我们就能实现任意文件名修改，还差一步，任意代码插入。

通过抓取修改文件内容的数据包

[![数据包](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-445efb27886d2b3637164a927182572ea2585f00.png "数据包")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-445efb27886d2b3637164a927182572ea2585f00.png "数据包")

同样在`/Users/sw0r3d/src/jufengcms/x/plugin/managefile/controller/index.php`找到了文件内容修改的触发位置

[![触发位置](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2125a60e808739d5338b2c9ec84da233d6f42348.png "触发位置")](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2125a60e808739d5338b2c9ec84da233d6f42348.png "触发位置")

文件名可控，文件内容可控，就能成功写入任意代码了。（前面白分析了，到这基本等于白给

### 总结

这次是白盒结合黑盒挖掘的，所以在对于cms的漏洞挖掘建议大家用这种方法，白嫖漏洞。

（ps 如有错误希望各位大师傅指正 (pssss 有师傅有工作推荐推荐吗 '-'