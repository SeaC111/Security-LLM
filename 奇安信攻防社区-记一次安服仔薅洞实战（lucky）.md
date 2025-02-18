记一次安服仔薅洞实战
----------

在一个阳光明媚的工作日，一位安服仔突然接受到了上级的任务，任务竟然是对整个区收集漏洞，数量要求还不是一般多，这可难倒了安服仔，安服仔本想着安安心心过（摸）完这一周去过七夕（我猜这个时候评论区是醒醒你没有女朋友），怎么会收到这晴天霹雳不得安生。

好了，言归正传，先来一波信息收集，啥也不逼逼，上fofa。  
`title="区域" && body="平台" && country="CN" && region!="HK" && region!="MO"`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f71abc4a832906cb475e9015a80f8233633cfa2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5f71abc4a832906cb475e9015a80f8233633cfa2.png)

这样搜还能屏蔽掉一些菠菜，sq网站非常好用~，柿子当然挑好的捏，后台/管理/平台走起

好！接下来是很熟悉的登入界面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-896ba2010b7a9614a02ff05b2e3d136eb2ae64e8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-896ba2010b7a9614a02ff05b2e3d136eb2ae64e8.png)

这时候思路有什么，找接口/未授权/爆破/目录，这些可都是洞阿，不能放过一丝细节，不急着爆破进去，先来个F12大法（师从12少）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7cc42110890be603be349ae6d3fdf48f063a8fcf.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7cc42110890be603be349ae6d3fdf48f063a8fcf.png)

接口有了试着访问一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-74493181bedb6c11d8726b280c1cb54d9985986d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-74493181bedb6c11d8726b280c1cb54d9985986d.png)  
很好啥也没有，这时候看到aspx就想起修君大哥的教导，回到上级目录（tip:有的.net网站会有接口管理器，找到一个接口返回上级目录就可以看到所有接口，而且有的aspx接口是可以看到参数值的）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a9ca5f9ea722439388665855ab30ee15feae4c4c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a9ca5f9ea722439388665855ab30ee15feae4c4c.png)  
这洞不就来了吗？目录遍历稳了阿，翻阿还有啥好说的，看到最后倒数第二个uploader小心脏扑腾了一下。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a4db6663dde31ff91883cd79efdef6be01daefa8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a4db6663dde31ff91883cd79efdef6be01daefa8.png)  
很好白折腾，这时候猜想，有一个目录遍历就有千千万万个目录遍历，扫目录别愣着。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2853890098cee9c1beba4df0827f5d1bf5b6538e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2853890098cee9c1beba4df0827f5d1bf5b6538e.png)  
摸了一圈也没啥接口未授权，现在思路找页面未授权，刚刚在源码翻还看到这些东西，登入后的页面，马不停蹄去访问。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9f16afacde93a13e03bb4e49f683c92289970bde.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9f16afacde93a13e03bb4e49f683c92289970bde.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-de7b58c32ae8bebc3f98a4d6ff463ddb76dc2499.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-de7b58c32ae8bebc3f98a4d6ff463ddb76dc2499.png)  
很好，一个未授权，不过操作不了很鸡肋，顶多算个中低危看看东西罢了，前台测完了要深入了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-31a608757f71799702758042bf1266ad521b3b9b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-31a608757f71799702758042bf1266ad521b3b9b.jpg)
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

开始尝试登入框，老样子admin:123456尝试弱口令  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e70db00e84457e8dd4059549401663ab84dc385b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e70db00e84457e8dd4059549401663ab84dc385b.png)  
这不，又来2个洞来了，验证码和用户名枚举，这里还尝试登入窗口的SQL注入和万能密码无果只能放弃,上大炮上大炮爆破！  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2e38347b6dacabe4c4f8b8c7abfb2004f247e96f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2e38347b6dacabe4c4f8b8c7abfb2004f247e96f.png)  
不出意外的就进来了，弱口令漏洞+1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9dd8672dd777e897fb51a15dd6d622f974294be4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9dd8672dd777e897fb51a15dd6d622f974294be4.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-654f1a011888873974534eabfded031ad2bed6ba.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-654f1a011888873974534eabfded031ad2bed6ba.jpg)  
接下来开始翻功能点阿~其实这些.net的网站aspx接口很好搞sql注入的，通过点功能点抓包就直接丢到sqlmap一把梭。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b19f9fd39ebdb885012be2a2639f909b181a2654.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b19f9fd39ebdb885012be2a2639f909b181a2654.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5c55e171e28aa6ac76f1d7512019de4bbc351b88.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5c55e171e28aa6ac76f1d7512019de4bbc351b88.png)  
拿下拿下，不过这个太慢了，先放一边，继续翻功能点找到一个上传模板的上传点。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0703d52b3a2b29955b244dfd57f79430c1419c2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0703d52b3a2b29955b244dfd57f79430c1419c2a.png)  
上传一个正常的xlsx表格，修改掉filename值并且保留PK的文件头前缀躲避检测再将内容改成马子就可以愉快的上传了（这里在同事的帮助下搞定的这里感谢一下）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-09253d682e4285fdf0c955fbb908ca1ccb83ac01.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-09253d682e4285fdf0c955fbb908ca1ccb83ac01.png)  
这时候没有返回上传后的地址怎么办，不要急，再看看网站的功能，有个下载模板的按钮，这时候我们知道上传的是模板，下载的也是模板，那他们肯定在一个模子里面。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e13aa09788e813f3abd49d770d7bc147a9abfec6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e13aa09788e813f3abd49d770d7bc147a9abfec6.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d7ebead926e09b895e38b4d1a1cae7ca056a402.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d7ebead926e09b895e38b4d1a1cae7ca056a402.png)  
这里就能看到上传的地址了，这里有个小操作可以直接右键下载模板按钮点击复制链接，我这里是直接在闪过的一瞬间截图的。  
访问看看马子还在不在  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-515ed1f7d2e1f99a445e36fc9f3a5aec388a8590.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-515ed1f7d2e1f99a445e36fc9f3a5aec388a8590.png)  
上冰鞋完美收官~手工薅了7个洞，扫描器再搞一搞凑个10个距离完成任务不远了。

祝各位师傅都能遇到这么easy的系统天天好运气