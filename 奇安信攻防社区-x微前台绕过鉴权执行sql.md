0x00 如何搜索
=========

搜这个“public\\Wclass\\W\\w{0,}Action”。根据这样的搜索随机漏洞，有时候会出意料之外的洞，比如这次的任意sql执行

0x01 简单说明
=========

对登录的账号进行判断是否为admin/sysadmin账号，获取Action参数进行判断是否为getDatasBySql参数，然后直接调用getDatasBySql方法

geDatasBySql的方法是获取了http实例并获取http的sql和datasource的参数，并对这个datasource参数进行判断，当sql语句执行成功后就直接将bool参数赋值为ture，然后进行判断如果不为true的话就直接跳出回显空，否则就继续将sql返回的数据进行json数组的转换输出回显。

这时候思路应该很明了了，全局搜索这个类的路径“com.weaver.formmodel.mobile.mec.servlet.MECAdminAction”,但是这没前端代码只有js文件里面匹配到了，而且还是插件的js，但是默认是存在的，所以这个漏洞是存在的，可以构造http://127.0.0.1/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.mec.servlet.MECAdminAction&amp;action=getDatasBySQL&amp;datasource=&amp;sql=select%20\*%20from%20SystemSet来进行访问。

0x02 流程
=======

/formmodel/mobile/mec/servlet/MECAdminAction.java  
在37行对登录的用户进行了判断是否 admin sysadmin的权限

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-336490cf91d3fae94d64415a7216a8e400e64cda.png)

/formmodel/mobile/manager/MobileUserInit.java  
首先进行假设， 22行通过http请求获取sessionkey参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-7138068f8f989faabaa0b03f697a62419d6a9081.png)

/mobile/plugin/ecology/service/AuthService.java

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-18a6e69ef97e8483e82ba3e5fbff2d31735aa450.png)

在这个方法里是进行了查询userid的操作，也就是账号权限

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-efba4e553e51b27efbf340e5495ec2b538fa1389.png)

继续回到/formmodel/mobile/manager/MobileUserInit.java  
这里的①是空的 还不知道是什么直接跳过进行②步  
第②步是通过http请求获取Mobilemode\_UserKey参数的值并且去空格  
并在第③步进行了userid的查询

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-5ce7519ad5f8b8a648ca223c9d113719edab3a8b.png)

/mobile/plugin/ecology/service/HrmResourceService.java  
就是这里，根据id查询是否为管理员的权限

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-a94f4924b3d19e30f64f25fe76ed38534efa2863.png)

继续回到formmodel/mobile/manager/MobileUserInit.java  
这里的第②就是关键点所在了，是读取了这个str的值是否等于1就进到判断里面进行管理员赋值

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-706b99ff28a2809e6e31a4ceff7d143df8a0d18b.png)

再次回到最初的/formmodel/mobile/mec/servlet/MECAdminAction.java  
然后一直往下执行sql语句

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e728144872f3f040cc25b54407c63dd0274e5814.png)  
/formmodel/mobile/mec/servlet/MECAdminAction.java#getDatasBySQL()

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-81bc59336c955f002e2bed1a9e5743d4ef8a9d58.png)

/conn/RecordSet.java#executeSql()

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-dc3a83ab25e5df32d53170038fc01db661fcff21.png)

中间代码太长就不说了，有兴趣可以自己研究研究

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2e2cccce84e225dc85625cc2337b92f3449d737f.png)

/formmodel/mobile/mec/servlet/MECAdminAction.java#getDatasBySQL()

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-c49eb6b7edd6bb2423daba57443bf8bf1c0c610c.png)

/conn/RecordSet.java#executeSql()

中间代码太长就不说了，有兴趣可以自己研究研究

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-98a91b72670da6f3bfa8e91efca9abeffba815fd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-903e7cdb5dfcb417c348382cf870c104777506c5.png)

0x03 可用利用链/调用方式
===============

如何访问当前方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-2b5e52a5ac12b0c8eac9e87b5d807156166b7142.png)

寻找getAction  
访问方式  
url参数

getAction()怎么来的  
这里可以自行搜索全局的"getAction"  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-aa9547a0a8528ceadeedc39f83a43307edbc3f4b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-3a2fa658a2ad76cfcd4c3027e54f578d1111d27f.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-939be16dbab50b7450884fe134e4ff62d69644b4.png)

在这里找到了一处调用的地方  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-32d752d27d299e48bd6c39e99d66e48e115e0093.png)

最终利用：[http://127.0.0.1/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.mec.servlet.MECAdminAction&amp;action=getDatasBySQL&amp;datasource=&amp;sql=select%20\*%20from%20HrmResourceManager&amp;noLogin=1](http://127.0.0.1/mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.mec.servlet.MECAdminAction&action=getDatasBySQL&datasource=&sql=select%20*%20from%20HrmResourceManager&noLogin=1)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-9e2f42f5b330177aecf0d42f136c0e43ac396ef7.png)

0x04 回顾鉴权解密
===========

在前面的"formmodel/mobile/manager/MobileUserInit.java"地方说过 str不知道是什么

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-21870768c752c89da34f3af5845c83965e398acf.png)

/formmodel/mobile/manager/MobileUserInit.java#getUser()  
这里的userkey是url参数控制的，也就是用户可控的，那么能不能进行一个伪造key呢？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f80224729af092565ccfa69b152871069833bb32.png)

/formmodel/mobile/security/EDUtil.java#decrypt

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-4223470c0c2ac8643043e984870b6c42e4a6a11a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-73ff1f3098ccfc8a6d428ce92590dbcfe9fbf662.png)

/formmodel/mobile/MobileModeConfig.java#getSecurityKey  
去寻找到他的类，并且跟进之后发现配置文件所在的地方

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e400de1cbe8c9993e91ae668d959572741c91e99.png)

也就是这个文件的key值，所谓的硬偏码  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-75c2b1720fd37f99d4e43eb27ffc938a5dba2ba6.png)

/formmodel/mobile/security/EDFactory.java

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-ef4f75fe6d2e2df9259487c03b12881ee8be3d89.png)

回到/formmodel/mobile/security/EDUtil.java

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-f7dcf7115b9605be9b394cbb01eb1c7e781d8d9e.png)

回到/formmodel/mobile/manager/MobileUserInit.java继续重复的操作

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-490c0ef06aa0537d52c5653310a0166ded4779c6.png)

官方补丁：<https://www.weaver.com.cn/cs/securityDownload.html?src=cn>