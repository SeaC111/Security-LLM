0x00 前言
=======

之前一直在研究webpack的问题（有兴趣可以看我之前的两篇文章），最近感觉自己webapck已经大成，就看了看别的漏洞，在TOP10里我毫不犹豫的选择了主攻注入。我通常都是边学边挖的，这篇记录一下挖到的一个小通杀，这篇文章中的注入虽然很简单但也给了我很大的动力

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ee3c2c71430f0da01e6bbaaaf07f9fbaf0947d03.png)

0x01 过程
=======

通杀挖掘TIPS：EDU有个开发商排行榜，拿下一个就是通杀

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7af44aabd099b3edc636168896d3d3e140383bfd.png)

作为想上大分的人，快人一步开始打点，`鹰图语法：web.body="xxxx公司"`，经过一番打点，找到一个开发商不大也不算小，就是这个了

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dbe9d4801bd701714af151caeb048967d8868105.png)

进去一家，登录界面，功能点目前看来只有“登录”

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4c4814ec80437d6cf184afbd609000047511d4ff.png)

F12，想看一下会不会有前端的一些逻辑判断，可是第一眼就无了，都是第三方的库

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7caa5439b797c019a7a4630a6e0cebdc269c53f8.png)

想到在学注入，接下来就测了测注入（佛系测试）

第一步：账号`admin`，密码`admin`，显示账号不存在

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7625c3645d45d5ed4800c4ea7693f5a302edc3a9.png)

第二步：账号`admin'or'`，密码`admin'or'`，显示的不一样了，感觉存在注入

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-182cdd24438269603e02a0990a9d017ec2127a41.png)

第三步：账号`admin"or"`，密码`admin"or"`，看了看显示的页面和第一步一样，一定存在注入了，并且是单引号闭合

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7625c3645d45d5ed4800c4ea7693f5a302edc3a9.png)

抓包sqlmap一波试试水，发现参数被加密了

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-31b044e742912fe9123de28d3afc5626559a48a8.png)

之前学过一点JS逆向，Ctrl + Shift + F，搜索被加密的参数 - `user1`，找到了加密函数（呜呜这个逆向好简单，丝毫没有展示出我的逆向技术）

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fcbfead2b9094105d3c0e8b095c2b586fe0b0a67.png)

放到在线运行JS的平台看一下，确实和数据包里加密的一样

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-507658b516d196656a5c3b811e84b3f82c6d1653.png)

下面就是用python写sqlmap的插件，让sqlmap的payload也加密，然后看这个JS写的加密函数逻辑简单，就用python代码重写了一下（虽然不好看，能用就行 /摆烂）

JS与Python对比  
![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-836fa37baed3a81f0ffc5e330d4235e0928d017d.png)

加密的插件编写  
![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e791bac49b027dfae56d1b8f7564c278cb25d863.png)

sqlmap一把梭，成功！

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bdc5794449848a59a9094b75584b1848efc6af65.png)