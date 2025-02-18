***有请今天的主角登场，不难看出这是一个招聘系统***
----------------------------

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4c7724adb5e1ecd6610f099db12934233795e920.png)

**1.先尝试注册**
===========

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9afbb7d7a9729f2f069d1ebb85187cc1d790d7ba.png)

**2.但是！！我这种懒狗是懒得去注册的**!
-----------------------

**由注册的提示我们可知，密码最少为六位，那我们就直接上爆破吧**

**再想想，这里我们是选择爆破密码还是选择爆破用户名呢？**

**根据这个站的功能可知，这是个招聘网站，招聘网站那肯定以人名为用户名的多吧？**

**是吧是吧应该是吧**

**所以我们这里选择爆破用户名，密码设置为123456**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f4bf474068aa165f3a5fdd19c749a14649be6564.png)

、

**果然印证了我的猜想，还没有跑完整个字典我就暂停了**

**上图200返回的是登录错误，302是登录成功后跳转至/Manager页面**

**3.我们这里选择xxxxxx来继续进行测试**
-------------------------

**啊，点击修改简历，一眼我就看到了附件上传四个大字**

**以往的经验告诉我，这里挺有可能Getshell**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-867f6602cac703bf9f43984818080f68a1a0926d.png)

4.尝试上传
======

**这里先上传一张正常的图片试试水**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3bce2eda49fd018886220fb9c2c0bed6e5596a21.png)

5.开启抓包，点击保存
-----------

**正常发送，发现跳转了**

**那我们就把抓的包放掉**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-cccae3a998092d8df592c7e760ccc04661d850ee.png)

**发现保存成功，还重命名了，测试了这三个上传点发现都是会重命名文件，只是上传的目录不同而已**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-820e19f13cf0b96c6ef0929396f1f4999cf56246.png)

6.这里我思路有点断了。。。
--------------

**乱点乱点回到主页看了一下**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d865bb3be677a645ca87803bb11653ae66a2447d.png)

**看到附件处有一张证书，再看左下角有个敏感词** ***filename***

7.任意文件下载
========

**右键复制链接地址，粘贴到 HackBar 把 *filename*** **参数后面的值删掉**，**访问**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2067f53f6473786cce6e6e1546a518fd74d05d73.png)

**用../测试看看有没有 Web.config**

**8.经过一番测试，使用三个../可成功下载Web.config**
-----------------------------------

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a2958d39dae5ee2832c3532aa59e89393b62a4a2.png)

**其实经过图7可也发现 cet 对应的为 upload 后面的目录**

**(反正就是猜吗，猜一下又不要?，?)**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8c637755981c28cb191f1d03bb5399671635763f.png)

**经过测试呢，确实是，也可以更方便下载文件**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8351f095d5e02ea59255c16fa032e8902d633c50.png)

**一个中危到手，嘿嘿**

**查看 Web.config 发现有数据库ip账号密码，尝试连接，连不上，这里就不放图了**

9.尝试Getshell
============

**没头绪了乱点乱点**

**望着这个四六级证书的链接发了呆，想着，四六级四六级我TMD又考不过**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8ce425587cfde1082914734bead4db36d9a0578c.gif)

。。。。。。

**咦！猛地一看，嘶~这个不是把大学名称拼接到文件名里面了嘛**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-906be7b861f8be54a337a569cd022de50fda67b7.png)

**那我不是可以构造文件名来截断后缀！！！？？？**

**说干就干，先在本地测试一下先**

**10.上传测试**
-----------

**在本地测试可以发现%00截断是可以成功上传的**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a5fba695778c648440e79d7fa91f97d7bc34cb8a.png)

**先不截断，上传文件看看文件名是否为我所猜想的那样**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-214ec7a950d70aeea0dd55497c5020ba9c0906a0.png)

**芜湖！猜想正确，把大学名直接拼接到文件名里**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ca95c3e6ef1b8b984022813d498bcfbd7a376e0d.png)

11.想法很美好现实很骨感
-------------

**使用%00截断**，**就快要成功啦，好激动**！！

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-dd660d0f0cc7f7ed9d7326213c01427ded383e86.png)

**小手一点，上传！**

。。。。。。。。

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-8d0d53ba04e31d453fdf109b1e275e455771ea53.png)

**没事，那就换种截断**

**使用 *::*$*DATA*截断**

**em。。。提示保存成功，但是文件呢？？？**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c014b76bc28900de98b723ab39423fcf871fa81a.png)

**算了，那我自己找吧**

**通过上面任意文件下载爆出来的路径可知该文件在X:\\XXX\\Content\\upload\\cet\\目录下**

**文件名规则为：年-月-日\_姓名\_学校\_四六级证书.jpg**

**但是我们截断了后缀所以尝试访问：年-月-日\_姓名\_qwe.aspx**

**访问得：**。。。。。。。。。。。。**不可能吧**？

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-babb6594c87c542b6524aaf0c69779475e3940b9.png)

**那我访问正常上传的四六级png呢？**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-62a7d027e3462979c8e14059a3de06135ea4eacf.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-b447d84062e37bb7b5db9c31c4b6f9e4adf25144.gif)

**12.寄！**
---------

**这特码下载得到，访问不到**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a02f8a23f3bb6c9dd3aeacf6856d260ab492b497.png)

**太狠了，期间我还在想是不是以 \_ 替换了 / 来当作目录，最后测试无果**

**应该是做了目录限制，不允许直接访问这个cet目录**

。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。

划水划水划水划水划水划水划水

划水了好几天后

**13.尝试下载源码**
=============

**（可是。。没有玩过aspx啊，而且这还是个MVC框架的，我一无所知呀）**

**尝试使用任意文件下载 index.aspx(无果)**

**尝试使用任意文件下载 Default.aspx(无果)**

**尝试使用任意文件下载 Global.asax(成功！)**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d8dd1463ced0722dd4cadaf1c2caa32fb7ae170b.png)

**这。。我也看不懂啥意思啊**

**这目录结构是啥样我也不知道呀**

**14**.**于是，我决定去网上下个MVC源码下来看看目录结构**
-----------------------------------

**下载的这份源码叫Leavescn-v2.5**

**大概看了一下，好像还真像那么回事**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-3bcfd092126343718bb08080c1319b2f034c7b84.png)

**进到bin目录发现一个System.Web.Mvc.dll**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-962091d541290ae234c8a62ef986e676b1cc1b35.png)

15.尝试下载**System.Web.Mvc.dll**
-----------------------------

**嘿嘿，还真有**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9db60b0b91234e3db20fc602c097c55dd74ea592.png)

**下载dnSpy来反编译看了看**

**发现。。。看不懂，最后问了一下大哥，大哥说我下错文件了**

**。。。那我怎么知道代码在哪个文件呢(来自小白的疑问)**

**尝试下载其他文件无果**

。。。。。**继续日**

**16.对比目录**
-----------

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-031c0ad3036972fdea572a76f67a8035422afcdd.png)

**在该bin目录下有一个MyWeb.dll文件**

**那我这边也尝试下载**

**17.找到真正业务代码**
---------------

**成功下载该文件**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-788d519337dcd878667d16f611ef797319e09c59.png)

**丢进dnSpy找到下载功能的源代码**

**Download传了两个string参数**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ac3526a5e4a67705d5f9503927c65fb286d3675e.png)

**虽然看不太懂，但是也能看个大概**

**跟进Download函数**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-1286b83655c72a3865960bb1a08fc7bc51264865.png)

**上传过滤功能代码：**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-246754a94581267aeb97b33f8279a971bbf3868e.png)

**最后看了看有几个越权，可以遍历所有人的简历等**

**没啥能Getshell的漏洞(我看不懂代码呜呜)**

。。。。。。

**18.兜兜转转**，**峰回路转**
====================

**没希望了，去首页乱点乱点，打算告个别**

**突然！点到下载链接的时候，看到了很敏感的几个字母 ueditor**

**这还是个.net网站，难道说**？？？

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ed0025554174086414b6fe80eb9e72f614b2b174.png)

访问：http:127.0.0.1/ueditor/net/controller.ashx?action=catchimage

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ae56435db83387a8b223eb1325ee52dbee116114.gif)

**卧槽？**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-4cea4227c58d038c6064ce5b60a3a65ecf1db556.png)

**19.一波三折**
-----------

**构造html尝试上传：**

```php
<form action="http://xxx.com/ueditor/net/controller.ashx?action=catchimage" enctype="application/x-www-form-urlencoded"  method="POST">
<p>shell addr: <input type="text" name="source[]" /></p >
<input type="submit" value="Submit" />
</form>
```

**上传！！！**。。。

**这是不能抓取外部图片？**

**我jscjasjsapodisocasociacsacjaso**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-92a3b9a5392652acf3e59c81f383cd3fdddc376e.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-6aab68e278cef4cb5842dd177197c8294591068d.gif)

受不了啦

![此图片的alt属性为空；文件名为%E6%91%B8%E9%B1%BC.gif](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9421a77e049f1d175dc25df6e703fb1ecc1b75ed.gif)

摸鱼摸鱼摸鱼

摸鱼摸鱼摸鱼摸鱼摸鱼摸鱼摸鱼摸鱼摸鱼摸鱼

**20.抓取本地图片尝试上传**
-----------------

**不能抓取外部图片？那我能抓取它自己服务器的图片吗？**

**试试**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-2ed190162c63348c90d941369743a12a13299ee0.png)

**芜湖，jpg可以抓取**

**那么aspx可以抓取吗？**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-fbf51ef0d205929540b5d8e0d57f7d7389c078c0.png)

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-fccec56f7b2dafde71cda6011c6b2d7d93676f91.gif)

成？成功啦？

**访问一下aspx看看：**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9866f46e216ae492ef31ed44c4d7f90643a88358.png)

。。。。。。

**不慌，改为asmx看看，欸嘿有希望**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f12d009bc0aca2bcec37cff3d96c641854ced60e.png)

**下载一个Tas9er大哥写的asmx ?**

> <https://github.com/Tas9er/ByPassGodzilla>

**制作一个图片?**

```php
copy 1.jpg/b + 2.asmx 3.jpg
```

**1.去头像上传处上传图片?**

**2.利用ueditor抓取图片成功Getshell**

。。。。。。

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-87f82724573f5b8e5d39fd3ec818e06b1b6fef9d.png)

21.寄2
=====

**问了一下大哥应该是目录做了限制。。。**

**html等可以正常解析**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-39add7e1e532045e589945b38b6706f501c68d5d.png)

**下播**
------

**下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播下播**

![](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-773bf79759af8540135e3adb210981dd4c030f9c.gif)