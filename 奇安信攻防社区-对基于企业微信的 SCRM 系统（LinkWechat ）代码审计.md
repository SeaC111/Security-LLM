LinkWechat 基于企业微信的 SCRM 系统
==========================

LinkWeChat 是基于企业微信的开源 SCRM 系统，文中漏洞均已修复，下载最新版即可

<https://gitee.com/LinkWeChat/link-wechat>

普通微信公众粉丝用户登录授权/越权
=================

简介
--

前置条件：

1. 管理员设置了公众号信息
2. 用户关注了相应微信公众号

程序提供了接口 ***@GetMapping("/wxLogin")***，可以通过微信登录，登录后可以操作后台功能，即使你不是内部员工，只要你关注了公众号就可以登录并操作后台功能，造成越权。

*com.linkwechat.web.controller.system.SysLoginController#wxLogin*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9f04762f2f69fdfbbaf9fd01f3a4bb3202122e05.png)

分析
--

该程序多个模块，其中 ***linkwe-gateway*** 作为网关会被映射到公网，所有的请求都会经过这个网关，再由网关进行转发请求。

### AuthFilter

身份校验会通过 ***AuthFilter***，使用了 ***JWT Token + uuid + redis*** 进行身份验证。

*com.linkwechat.gateway.filter.AuthFilter#filter*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-377d216a2fe995488d888ca3caa1332d93679469.png)

其中***linkwe-gateway.yml*** 中设置了 **\*/auth/\**\\*\\** 不做身份验证

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3d98dec0a8656fb6d59fa3f8799e0133c3886253.png)

提供了接口，可以进行微信登录

*com.linkwechat.web.controller.system.SysLoginController#wxLogin*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7bc4a03e8840041b57955a73da16d6da2d945920.png)

最后会创建 ***Token***

*com.linkwechat.web.service.SysLoginService#wxLogin*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3be869dd86cc633d1e393dcb35b02874dc19c5b3.png)

调用 ***refreshToken*** 刷新 ***Token***

*com.linkwechat.framework.service.TokenService#createToken(com.linkwechat.common.core.domain.model.WxLoginUser)*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1d4f0383867416d9f1938e3e31e2a756518fb961.png)

在这里就会存储 ***redis*** 缓存，通过 ***isLogin*** 的判断

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7fc3bca650b2e9e2056ff3653e9bdb85ea4c1cdd.png)

复现
--

### 公众号配置

需要设置好公众号配置，如果没有公众号的，可以 [申请微信公众平台接口测试账号](https://mp.weixin.qq.com/debug/cgi-bin/sandbox?t=sandbox/login)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-55e543a21d2bab47ba3d6090796acf2bab1813be.png)

### 授权连接

程序提供了接口 ***wxRedirect*** 可以获取到微信授权的连接

/auth/wxRedirect?redirectUrl=https://....

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0472b692cfdbabcf359f077c2688f9f9066a755e.png)

注意这里的 ***redirectUrl*** 参数，需要在后台设置好域名，这里我设置的跳转到官网，因为我自己没有域名

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7f857f35de1d1f9ebd978b86d2c061169e7c1eec.png)

请求接口获取地址

<http://localhost:6180/auth/wxRedirect?redirectUrl=http%3A%2F%2Fdemo.linkwechat.net%2F%23%2FauthRedirect>

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-e2bacb5d3d87d1535d0c923afcd4aa9bc3a26ec7.png)

打开连接之后就授权就会跳转到 ***redirectUrl*** 指定的连接中，并携带参数 ***code***

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-3197b6e9eeb87fa2d3a7c3ee221f0380f485c73c.png)

跳转后复制链接，就可以看到连接上的参数 ***code***

[http://demo.linkwechat.net/?code=001ZNf000QO5aP1I7S200cdEYB1ZNf03&amp;state=linkwechat#/authRedirect](http://demo.linkwechat.net/?code=001ZNf000QO5aP1I7S200cdEYB1ZNf03&state=linkwechat#/authRedirect)

### wxLogin

拿到 ***code*** 之后就可以调用 ***wxLogin*** 进行登录了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-1d5a3a1477ea8538c662a54c1dcb961f5fb65dc4.png)

往后的请求带上请求头 ***Authorization*** 设置未 ***Token*** 就可以了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-61e2c3efd3ffc603c1f623c52052bde296718f41.png)

修复缺陷
----

提交漏洞后，项目的负责人很快作出反应，对这个问题进行了修复，我大致看了一下 提交记录，在[修复微信token可以访问基础服务](https://gitee.com/LinkWeChat/link-wechat/commit/062a4af0d9d33ae5ce09b88d5b31bf1eb097ca42) 的代码变更中

多看一眼就爆炸了，发现不对劲，增加了判断 Token 中的 ***loginType*** 字段，来区分拦截 ***公众号粉丝登录授权*** 。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-0023098e2a0836a42be93b411b44a59f20b698c6.png)

在 ***gateway*** 的 ***AuthFilter*** 中，是从 ***Token*** 载体中的 ***login\_type*** 字段获取的。

*com/linkwechat/gateway/filter/AuthFilter.java*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-94315cda6b3107c9dbdc27ffac28a3edbe7e807f.png)

而 ***JWT Token*** 的密钥是固定的，这就导致了，可以控制 ***login\_type*** 字段

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d14f534fb1a57d27b447674f48604d6963bc48bf.png)

修改成 ***LinkWeChatAPI***

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-c2f32b8b393683eb7b3f037db6ee4b8dd648b0f8.png)

使用修改后的 ***Token*** 访问，成功绕过

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-d683996081bf8ad0a76c5ced6095213d246e38d5.png)

#### 修复方案

而我给出的修复方案也很简单：使用随机的 ***密钥*** ，确保每次启动都不一样。

SQL 注入漏洞
========

描述
--

程序使用了 ***mybatis***，并在 ***SysDeptMapper*** 配置了 ***${}*** 参数导致 SQL 注入漏洞，该漏洞为 ***update*** 型注入

漏洞详细
----

在 ***SysDeptMapper*** 中配置了 ***${ancestors}*** 参数

*/linkwe-auth/..../src/main/resources/mapper/system/SysDeptMapper.xml*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4b1c9ffc33f55ea44985754f1c31db47656aa29a.png)

该参数的类型为 ***String***

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-691dc07dbb83b6ae0e164fad722aabc31264b9e0.png)

该接口在 ***SysDeptController#edit*** 中使用

*com.linkwechat.web.controller.system.SysDeptController#edit*

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-a09e086a727b15397d129adf6f6ae62412a6dc85.png)

这里会根据传入的 ***newParentDept*** 获取信的父级部门，然后拼接旧的部门，这样会覆盖掉请求中的 ***ancestors*** 参数，所以我们的请求中父级已经要让他获取的值为空，不让他覆盖掉 ***ancestors***

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-94a1f09c8eda19e39c95c224dc6b4071f016d22a.png)

然后我们需要让他进入判断调用 ***updateParentDeptStatus*** 才能触发 ***SQL*** ，这里的 ***DEPT\_NORMAL = 0***

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-95dbb292f95a2d132a363b35d79dd2ae1f8d72ee.png)

漏洞复现
----

```json
{  
    "deptId": 1,  
    "parentId": 999,  
    "ancestors": "if(1, sleep(1), 0)",  
    "deptName": "24rewr",  
    "deptEnName": "3",  
    "orderNum": "4",  
    "phone": "5",  
    "email": "1@q.com",  
    "status": "0",  
    "parentName": "parentName"  
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-44ecf356e28b6f6ba7a8dee8b335c2abe9118bfd.png)

结果为 ***False*** 时，就没有阻塞。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b74f77da717e9e42b51324f9494255bea5337bf4.png)

修复方案
----

[SQL注入漏洞修复](https://gitee.com/LinkWeChat/link-wechat/commit/15cbe225a9da3cb2f5672af899ea6063da15d068)

在 ***修改部门*** 的逻辑中增加了操作操作权限的校验

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7ce6678bd179aba3e95bfd164527d5ac72818399.png)

此时就算还存在越权的问题，也无法访问 ***修改部门*** 的接口了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-015329193d240b67a5c23cce642709045a02f8ae.png)

但其他的接口似乎没有加上权限校验

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-b8188f633291142b3a4d5beb56567f6fd76d67b5.png)

针对于 Mapper.xml 也修复了问题

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-9234a8e5f7366e8ea716522f8392492477eba1c2.png)