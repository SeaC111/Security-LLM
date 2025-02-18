\*严正声明：本文仅限于技术讨论与分享，严禁用于非法途径。

一、开局
----

先拿到一个站点，这里假设是http://110.120.119.911/dashboard，大致浏览一下没啥，小手那么一动，<a href="">http://110.120.119.911，嗯，开局就是这么一个目录遍历。直接开始一个个访问的龟速运动</a>。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5b759be33942399adc65fb87dac27de3b1cf9fe1.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5b759be33942399adc65fb87dac27de3b1cf9fe1.png)

二、发现注入点
-------

十分钟后把这些文件全部扒拉了一遍，并没有出现想象中的用户信息泄露（tui，连小姐姐照片都没有）。无奈开始翻起了刚刚龟速运动过程中存下来的php站点，一顿跑马观花后把目标锁定在了这个具有搜索功能的页面，随手打了个1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3ac44f1323c24648633f624de1de8e4d3a57695d.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3ac44f1323c24648633f624de1de8e4d3a57695d.png)  
再来个1'  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c43aee37335b60a93fa8ebf851b31352e7bf00b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c43aee37335b60a93fa8ebf851b31352e7bf00b4.png)  
好家伙不多说，上神器！（因为是post传参所以直接抓包copy到txt文本中sqlmap -r跑）

嗯，没跑出来（跑出来也就不会有这篇文章了）

三、Bypass过程
----------

回到最初的起点，打一发1'--+  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3128fea45c8284fd3c5a3bda2eff99b75323a288.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3128fea45c8284fd3c5a3bda2eff99b75323a288.png)  
emm这咋就不顶用了呢，反手又打了一发1'%23不行，1%27%23不行，又试了一下1'#  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-da1f8b2906756d9d480f17741e77ec2524ac6771.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-da1f8b2906756d9d480f17741e77ec2524ac6771.png)  
好家伙合着我还给你整复杂了。接着考虑到这里是盲注，加之前面在浏览目标时发现这是一个用xampp搭建的站点（Apache+MySQL+PHP+PERL）先不order by，直接一个union select sleep（2）那不妥妥的~~~直接给转不出来了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6b29174bf18dbdd53f01a7cc15054bfb2e3ec729.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6b29174bf18dbdd53f01a7cc15054bfb2e3ec729.png)

阿这，居然有WAF？小小WAF，可笑可笑（你看我一点都不在怕的样子）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3f815df456c9cbfbc6870ca14dc53b389ff8c625.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3f815df456c9cbfbc6870ca14dc53b389ff8c625.jpg)  
这里充分发挥遇到waf我不慌，诶，就是绕的精神，挨着测，看到底是匹配到哪个字段触发了防护规则，1'union+没问题，1'union+select+被断掉了，紧接着union+selec，嗯没问题，看来就是匹配了select  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-37fe79b23f1fea160e3881d3ee8c0c8d03320acc.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-37fe79b23f1fea160e3881d3ee8c0c8d03320acc.png)  
那么这里大小写加&amp;amp;amp;lt;&amp;amp;amp;gt;，union+Sele&amp;amp;amp;lt;&amp;amp;amp;gt;cT打过去直接被断掉了，union+/*!Selec&amp;amp;amp;lt;&amp;amp;amp;gt;t*/又被断掉了， /*!50000UniON SeLeCt*/、/*!u%6eion*/ /*!se%6cect*/  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-02ce5f5230f868b3a61eaa172ccca36286d7ea9c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-02ce5f5230f868b3a61eaa172ccca36286d7ea9c.png)  
啪的一下很快啊，统统都被拦下了，emmmm  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b181304d83a0ee0c1780a183f74dab7d11ac5b3c.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b181304d83a0ee0c1780a183f74dab7d11ac5b3c.jpg)  
回过头来，单独试了一下select，union select，页面是正常的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-01b505e14114a81e8fddf099df763d9b726b0426.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-01b505e14114a81e8fddf099df763d9b726b0426.png)  
1'union select，页面是转不出来的，我陷入了沉思。。。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4d1741117f115e60e466b8bb68f767791a182e44.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4d1741117f115e60e466b8bb68f767791a182e44.jpg)

莫非是匹配整句1'+union+select？中间加空格是不顶用了，那我在中间加个字符串混淆一下呢？

要知道，MySQL数据库支持两种集合操作：UNION DISTINCT和UNION ALL，union其实是相当于 union distinct的。

那么在此基础上，我反手就打出一发1'union+distinct+select+sleep(2)#  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7537e65a286752cdcfef28dcf2c33249cc738f64.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7537e65a286752cdcfef28dcf2c33249cc738f64.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9b68a54d1096fe4948298e614cf7af4d93db23dd.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9b68a54d1096fe4948298e614cf7af4d93db23dd.jpg)  
emm难道是我猜错了。。。直接把sleep函数去掉，发现正常报错  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-57366d05d578a69143165a575ae1b07cd401c4b3.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-57366d05d578a69143165a575ae1b07cd401c4b3.png)  
看来是函数的锅了，这里直接一个sleep%23%oa(3)打出去

（其实在此之前尝试过/*!sleep(1)*/然后还试了一下参数污染多加了几个+尝试协议未覆盖bypass+尝试垃圾字符绕过后统统都不行。）然后  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-50921959e886731729d34aa71602f570e0cbe91a.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-50921959e886731729d34aa71602f570e0cbe91a.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-aec0ceb66d0789ef4d7ecf418970ae389cda83f5.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-aec0ceb66d0789ef4d7ecf418970ae389cda83f5.jpg)  
这个故事告诉我们，遇到waf不要慌，只要思想不滑坡，办法总比困难多（大概）

望师傅们看完能有一点小小的收获~