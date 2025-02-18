阿里云是我个人认为公有云最简单也是最容易上手的一个云服务，在很多我们挖洞或者是攻防的过程中会遇到一些ak/sk，习惯了使用cf工具一把梭，从而触发短信或控制台告警，导致目标响应过快，达不到渗透目的，所以本篇写一下自己个人的一些小技巧和心得，如何手动接管阿里云控制台，并且不触发短信告警。

如有不当之处欢迎各位师傅批评指正~

在线调试
====

首先看文档先调试一下  
[https://next.api.aliyun.com/api/Ram/2015-05-01/CreateUser?spm=api-workbench.API%20Document.0.0.6f991fc66Lk9cV&amp;amp;params={%22UserName%22:%22molitest%22,%22DisplayName%22:%22moli%22}&amp;amp;tab=DEBUG](https://next.api.aliyun.com/api/Ram/2015-05-01/CreateUser?spm=api-workbench.API%20Document.0.0.6f991fc66Lk9cV&amp;params=%7B%22UserName%22:%22molitest%22,%22DisplayName%22:%22moli%22%7D&amp;tab=DEBUG)  
我们在渗透或者是挖洞的过程当中，尽量不要留下痕迹以防止溯源之类的情况出现

对于RAM用户，概念不是很清楚的请参考：  
<https://help.aliyun.com/zh/ram/user-guide/overview-of-ram-users>

用官方一点的话来说， RAM用户就是一种轻量级的身份凭证，可以用于授权和管理访问阿里云资源的权限， 每个RAM用户都有自己的登录凭证（AccessKey ID 和 Secret AccessKey），可以用ak、sk去调用它的api进行身份校验

我这里是登录了我的控制台账号，创建一个RAM用户

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-aa95e17ba300ad9f53196ac0b49658a665d36ab1.png)

他这里有个在线调试的模块我个人感觉很不错，可以清晰的看到调用结果和返回的数据

星号是必填参数，其余的参数他也标出了是什么功能，我就不再赘述了，这里是创建了个molitest的用户

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-3b3d46b6105a74cb427b303976c2c4b18a4f6c19.png)

创建用户之后给他加一个能登录web控制台的权限，因为登录控制台肯定要密码，所以这里指定一个密码

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-720534856c909afd1e59729982a624980368f305.png)

然后我们查看一下云账号的别名，这里记一下，后续使用RAM用户登录控制台的时候会用到

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-5b1e19b41f4df9e2fb0d77b079098a12fffe8436.png)

然后我们查询一下所有RAM用户，确保账号添加成功

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-e887627ca8c2785083de576f4cfbc5a8a78dab63.png)

这里可以看到已经添加成功了，尝试去登录控制台

这里我们可以看到两种用户名登陆的办法，一种是用户名@《默认域名》一种是用户名@《别名》，这里的别名也就是我上文中提到的云账号别名

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-959f28e6fbcdc5a9a4cbd29045eb055c94d1f441.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-28ba8913eb8ed354a2ba5329310402c0232c4eb5.png)  
利用用户名和刚才查询到的别名登录，输入密码，可以看到登陆成功

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0175e0ce4b795c00a93789c0fcd2ce339d313469.png)

**但是！！！！**  
这里有个小问题，我们只是创建了这个用户，给他加了一个web控制台功能，但是并没有给他加权限

为什么呢？因为我的账号这里，其实我是有云上资源的，但是没有给这个molitest用户赋权，所以他看不到任何东西，账号资源如图

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-040f53984f37005c0ec7b9528dd0d05001269e4c.png)

所以我们要给这个molitest用户进行赋权，在这之前，我们要先查看一下权限策略

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-6354377042abff794cd17c36e95153aec7b004f6.png)

他的PolicyType是System，PolicyName是AdministratorAccess,这个是阿里云默认的，也就是管理所有阿里云资源的权限，其实和cf工具的命令一样，直接接管控制台的命令也是通过这些去调用的，不过云厂商现在研究了cf的特征，导致一用cf调用ak/sk就会产生告警

闲话不多说，我们给这个用户加上权限

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-44bb4aec0cf324fe57a32cff61db733c194e64c9.png)

返回Requesid就是赋权成功了

然后我们现在来调试一下，验证我们是否赋权成功

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-9511ee262f50b9363567c23dabfdf0d61dd75ede.png)

这样我们的账号就拥有权限了，我们再去登陆试试，

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0ceb709ce195877dfbd2d215e35b3b77a248ff8f.png)

ok，登陆成功

接管流程
====

现在整个接管流程就走完一遍了，大概分以下几步

创建账号——&gt;指定密码——&gt;查询别名——&gt;给用户赋权——&gt;登录web控制台

命令行接管控制台
========

但是在正儿八经渗透的过程中，只有一个aksk，我们可以用阿里云的cli，完成上文的操作

安装方法放这里，我用的是windows，其余的不放了，大家可以自行查询  
[https://help.aliyun.com/document\_detail/121510.html](https://help.aliyun.com/document_detail/121510.html)

安装配置好环境变量之后，验证下版本，如下图所示就是安装成功了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a44d237a84bfce37c2ef6cb854f9811696166421.png)

ok那么继续我们的操作，用命令行的方式来手动接管阿里云控制台  
输入ak、sk、Region就是地区，语言选择zh中文，配置好之后

出现下面这一坨welcome to use alibaba cloud就是配置成功了,上文已经讲了创建用户的流程，接下来就是用命令行操作一遍

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-13061e45e10807a86d281976d89fcd7978a91f62.png)

输入 `aliyun ram GetAccountAlias`查询账号别名

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f2bf0862e2c9ff011f9974828c597622a8f5b161.png)

接下来创建账号，输入`aliyun ram CreateUser --UserName molitest111`

出现下面这种返回值就是创建成功了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-62a5e80997e03016afc5b095b7fac441fbe71e33.png)

然后调用`CreateLoginProfile`接口给这个账号添加web控制台的权限，并加上密码

`aliyun ram CreateLoginProfile --UserName molitest111 --Password Poker安全`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-fb386f100c5fd0ab5c458dc3cd0f2eea05483dd5.png)

然后`aliyun ram ListUsers` 查看用户创建成功没

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-877f06b6b7d65daf6d79939d22b9fac2d0630a42.png)

添加好之后，接下来调用ListPolicies接口 列出权限策略 给刚才创建的用户加上权限

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-4ef04b93bce864c4d09d14bcdc7dba09567a2a8e.png)

记住这个PolicyName和PolicyType

调用AttachPolicyToUser 接口给用户加上权限

`aliyun ram AttachPolicyToUser --PolicyType System --PolicyName AdministratorAccess --UserName molitest111`

出现下图就是成功了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-58d3daaf9723c065565981df865d37e97f780288.png)

如果命令实在是不好记 可以直接用aliyun ram，会列出当前模块的功能（太多就不截全了）

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a197c7bc2f3e56aac8a68a4a663adb7ad8672bc4.png)

然后就是登录了，账号@别名，密码就是自己设置的密码，记不住就往上翻，这里不放登录的图了

说下怎么删除账号，因为我们是管理员权限，所以先要取消权限

`aliyun ram DetachPolicyFromUser --PolicyType System --PolicyName AdministratorAccess --UserName molitest111`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-afa4ab4e709fc001b65da045c10c3d23ff7a1e93.png)

然后删除用户

`aliyun ram DeleteUser --UserName molitest111`

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f8aa87bc35ab9d846ad4d9f1044ea215c3d6f422.png)

再次查询用户，就不存在molitest111了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2d036706beadc6a4fe927a82e04c89b0ccb35ca9.png)

到这可能看到我这有个crossfire的账号了，想必大家也不陌生，正是cf一键接管的默认用户，这个账号是我利用cf直接创建的，产生了告警

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-829900f3f6a44893efad1450947544ec311a0548.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-15f3dc73707f08dab4a47bfdd19730541ce189ae.png)

那么相同的，刚才利用cli工具完成了接管控制台的功能，产生的动静相对较小，只会显示最低级告警，不会出现这种紧急的程度

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-1e7a2d46fa5dfc382c2c8a2c7811dd9fc5fc9bc8.png)

那么这个告警的问题我们怎么避免呢

正常我们是没有办法直接结束进程阿里云的云盾的(ROOT用户也不行）

如果我们强制Kill就会收到短信告警，恶人还需恶人治，我们可以在云安全中心把所有的监控都关了，然后就可以kill掉这个进程了

![图片.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a11db1cd9f8e0d7e0a5f4ea20e77673a578b8573.png)