前言
--

在近期的授权项目中，遇到了一个目标，使用了youdiancms，需要获取权限，进而进行审计，本次代码审计过程先发现SQL注入漏洞，继续审计发现getshell的漏洞，本文将本次审计过程书写下来,仅作为学习研究，请勿用作非法用途。

0x01 未授权SQL注入
-------------

首先拿到源码一看，发现该系统是基于THINKPHP3开发的。

在`App/Lib/Action/HomeBaseAction.class.php:16`

![image-20210514153103940](https://shs3.b.qianxin.com/butian_public/f333551fac165bdba75793cfd683956db2589f988ce1c.jpg)

cookie可控，然后赋值给了`$this->_fromUser`

跟踪一下`$this->_fromUser`的引用。

在`App/Lib/Action/Home/ChannelAction.class.php:732`

![image-20210514152830011](https://shs3.b.qianxin.com/butian_public/f7567058c8d14810004edb8b5d16fd7bba22df6738e34.jpg)

这里将`$this->_fromUser`带入到了`hasVoted`函数中，跟进该函数：

![image-20210514152908218](https://shs3.b.qianxin.com/butian_public/f2792563b8b1b8dab7b652445fa0aca49b05a525e9084.jpg)

很明显，TP3的where注入。

延时注入payload如下:

```php

GET /index.php/Channel/voteAdd HTTP/1.1
Host: localhost
Content-Length: 2
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: youdianfu[0]=exp;youdianfu[1]==(select 1 from(select sleep(3))a)
Connection: close
```

0x02 绕过登录到getshell过程
--------------------

### 0x0201 流程思路

1. 验证码处可以设置任意session
2. 碰撞md5让AdminGroupID==1（超级管理员）
3. 后台修改模板插入phpcode实现代码执行

### 0x0x202 任意session设置

在`App/Lib/Action/BaseAction.class.php:223`

![img](https://shs3.b.qianxin.com/butian_public/f414592c7bd280666e48605f20f885065ff34ac5adf3d.jpg)

这个函数挺有意思的，本来是个生成验证码的操作，但是没想到所有的参数都是用户可以控制的，特别是这个`$verifyName`还可控。跟进`buildImageVerify`看看如何设置的`session`。

![img](https://shs3.b.qianxin.com/butian_public/f313608df983faeac7428870406c91ef85f5ee9df3993.jpg)

红框处设置了session，并且session的键名我们是可控的，但是值不可控，是个md5值。

然后我们去看看管理员的校验函数。在`App/Lib/Action/AdminBaseAction.class.php:7`

![img](https://shs3.b.qianxin.com/butian_public/f78273975569c5e134345e4450f38fcde505dc19760b1.jpg)

起作用的就两个函数，`isLogin`和`checkPurview`。跟进第一个看看：

![img](https://shs3.b.qianxin.com/butian_public/f391095ad2d631a98f32fafcf39c76f9aaf552022e250.jpg)

这个函数很简单，就简单的判断session是否存在，我们可以通过上文的验证码函数来设置。

然后就是checkPurview函数。

![img](https://shs3.b.qianxin.com/butian_public/f976752702cb9a7e9bdccc1f09f4eb971235a69235559.jpg)

这里判断了`AdminGroupID`的值，当等于1的时候就是超级管理员，由于这里是个弱类型比较。所以上文设置session中的md5是可以碰撞的。

编写脚本得到超级管理员的session了，然后登录。

![img](https://shs3.b.qianxin.com/butian_public/f27e9483ee247452b1b9b00fc5afcbfdc.png)

### 0x0203 后台getshell

后台模板管理，可以修改模板，但是对&lt;?php有检测，如图所示：

![img](https://shs3.b.qianxin.com/butian_public/f331075d43c21babfdfdd9bfa9fad0e7484b3226f5866.jpg)

我们可以用`<?=?>`来绕过这个检测。

如图所示：

![img](https://shs3.b.qianxin.com/butian_public/f698706bb97cb4ea11a0bc51837a121ac013cc88a1180.jpg)

访问首页即可触发：

![img](https://shs3.b.qianxin.com/butian_public/f334758cd72d3248758cb156bc8851bfc06460734105f.jpg)

注：zc.cn为本地127.0.0.1的地址，并非zc.cn的域名