经典开局一个登录框
=========

由于漏洞应该还未修复。对于数据和相关网址打个码见谅一下

常规思路（爆破）
--------

![Snipaste_2023-11-05_19-23-02.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c90bd334c7c4f1aa8f6edde50e4284cf39248bfb.png)  
常规操作进行一波  
尝试弱口令然后开始爆破  
对于此种有验证码的爆破，可以借用一个bp插件。  
captcha-killer-modified-jdk14.jar  
![Snipaste_2023-11-05_19-24-45.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-a2c05ec7a0009f3d3d2484f49340bd689befd7b5.png)  
具体使用我就不说了。有很多大佬的文章都有细讲。  
爆破常规并不可行。

思路不通就抓包
-------

登录之后抓取返回包  
![Snipaste_2023-11-05_19-28-24.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-2e6162829e641f66e4f768d2e095eabace39e290.png)  
发现有相关的编码返回。感觉是前端进行一些跳转的相关问题

### 搜索js

![Snipaste_2023-11-05_19-29-23.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-cbe888f739c522f7f9356d5352ef03910e695ee2.png)  
经典改包。00@#

### 绕过第一步检验 但是直接被强制退回

![Snipaste_2023-11-05_19-30-58.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-5d588be25762eebe201431053f6bc4e29bafe569.png)  
本来想直接放弃了。准备试试其他的靶标。  
但是越想越气，md继续打

### 再次js，感觉既然登录可以跳转。再次试试呢

抓包到这个强制返回页面。定住之后。因为很多网站是对于一个特定的页面加载特定的js。在那个页面查找相关js

![Snipaste_2023-11-05_19-33-33.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0ef405daa5524fb5969f724c6aca6dd0ec15bdc7.png)  
分析可知，几个id的参数进行验证

### 感觉是后端验证

感觉还是g了。完全不知道怎么办了。点了半天也不知道这个玩意是咋验证的。感觉像是后端验证，构造数据包也并没有成功。哎。准备放弃了。但是看见我队伍的排名已经不能在看了。md再来

### 遇事不决，继续抓包

发现返回包是html。感觉好像不是特定一些鉴权方式。然后翻啊翻啊突然在返回包之中看见。

![Snipaste_2023-11-05_20-06-20.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-39739868f72fe25ba928fe28313e9752d1781c3f.png)  
这不是上面那个js文件里的相关id吗。  
然后想了一下我的html垃圾基础。加一个value值是不是就可以。那么全加成1试试看

![Snipaste_2023-11-05_20-07-22.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-c46994afee4800bb463d9fc0a4921ff8e9da0052.png)

### 但是结合上面的js审计。必须保证roleid的值为1

成功进入后台。但是没有任何数据哎 任重而道远
======================

![Snipaste_2023-11-05_20-09-24.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-cc550f263f306665607186ecdcd40164958a6a3f.png)

带着bp开启点点点。点到一个功能点
-----------------

### 然后经典被重定向到登录框 哎（真g了吗）

截图当时没截图哎，当时确实没用任何的办法。

只能继续抓包康康了
---------

一看，又根据我的前端垃圾基础  
看到一个隐藏的返回包

![Snipaste_2023-11-05_20-36-15.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-f2461414a0fbdbcb08ca892dce72e5798d7be1d4.png)  
哎嘿，又是html返回。是一个js重定向在返回包里。  
哈哈哈哈  
直接删除。成功绕过。

成功获取接口
======

![Snipaste_2023-11-05_20-38-14.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-4422606c54487cda77f30a5ad71a0e858d0a262f.png)  
然后就是大家都会的。改参数。把schoolid改了。  
成功跳转下一个接口

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-7f27476c1fdaa7841b73562ea4f0a048dba85a1a.png)  
然后正常访问。没有任何数据。  
经典遍历参数进行看数据  
然后抓取返回包进行修改。成功吧数据返回到前端进行渲染

成功获取数据。哦吼
---------

![Snipaste_2023-11-05_20-42-38.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-0993d6873e06b14f6d174476dc2167c2848d179a.png)

哦吼。成功知晓整个验证逻辑。那么就开始吧所有功能点进行绕过即可
-------------------------------

然后就是抓接口遍历参数进行扩大数据量
------------------

![Snipaste_2023-11-05_21-29-24.png](https://shs3.b.qianxin.com/attack_forum/2023/11/attach-09db189a9654cfa3772794c9c166ab644a9948a1.png)  
里面是电话号码和密码  
数据量非常大。（基本上各个地区里面学生的信息泄露）基本上每个id后面都有相关的参数

成功通过此类。进入到老师等后台。后续就交给大佬进行getshell了
==================================

小结
==

对于现在很多网站。多抓包，多分析js和看接口的习惯一定要养成。  
通过分析，去理解整个的业务流程。并且造成组合拳才可以造成危害更加高的漏洞