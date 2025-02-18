[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-38d42dcad8a5d10d8cc4ddf835a6f2c95fe4a586.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-38d42dcad8a5d10d8cc4ddf835a6f2c95fe4a586.jpg)  
看到登录页面，先试试弱口令，目录扫描试试未授权等  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0cdcb93f8641dc667c805dfbca9b58fe2f34ba90.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0cdcb93f8641dc667c805dfbca9b58fe2f34ba90.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-243bfa42cc56c7ea5653fe5e3abd5bb6dda58b57.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-243bfa42cc56c7ea5653fe5e3abd5bb6dda58b57.png)  
看到其中有个password.inc，看到password就直接点进去  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e70d036a2e55401ca3badeb0085fac8bd5197dbd.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e70d036a2e55401ca3badeb0085fac8bd5197dbd.png)  
可惜只有admin  
尝试admin admin  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8810c3ee7eeb6300eec3480bb1210fd73ec5d57e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8810c3ee7eeb6300eec3480bb1210fd73ec5d57e.jpg)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c3a960bc5dd12badf8619ea62b7de61887df1354.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c3a960bc5dd12badf8619ea62b7de61887df1354.png)

可惜，看来只是个账户名而已了，其他的文件也看了看，不能直接进后台，也就一点目录遍历而已

抓包看看  
正常发包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ccaf587a511658e54aefe1f52f6f334cfa5d2a98.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ccaf587a511658e54aefe1f52f6f334cfa5d2a98.png)  
这是name加了单引号发的包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dc15ed0bea540d59e88338622d08cc1547a84ead.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-dc15ed0bea540d59e88338622d08cc1547a84ead.png)  
可以发现，两次发包的回显并不一致，这里盲猜就觉得有sql，于是直接跑sqlmap（脚本小子可不会手注）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d3ab28427d9eb2f3283483a8f00059df048cfddc.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d3ab28427d9eb2f3283483a8f00059df048cfddc.png)  
成功，但是跑不出数据库信息，想想其他办法，跑tables，可以跑出数据  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3740486ac3248204d140757d5f4896e8fdbca332.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3740486ac3248204d140757d5f4896e8fdbca332.png)

经过长时间的搜索，终于搞到了这套源码(公开)  
大佬们都是通读代码，不用工具凭感觉挖，我这种脚本小子还是用工具先跑一遍吧  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-309f61f90d7317c57a4fb24907e35ec8f93e1798.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-309f61f90d7317c57a4fb24907e35ec8f93e1798.png)  
先去找登录页面的代码审一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-234fa903d3bff344eaa15f6d4842f08b690f792d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-234fa903d3bff344eaa15f6d4842f08b690f792d.png)  
发现只有一行，看的眼睛要瞎了，稍微排个版  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3baab6ba329ac1e50b92da1c5c28538d53ff4f65.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3baab6ba329ac1e50b92da1c5c28538d53ff4f65.png)

然后开始审计，23行，根据Name传参到webname，然后转到23行代入数据库查询，导致sql注入，不过除了这个注入洞，还意外发现了万能密码，看下图

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-23837130e6f90dea3e1a45623cb4ae2dda6e7b19.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-23837130e6f90dea3e1a45623cb4ae2dda6e7b19.png)  
第4行为post接收传过来的密码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fa5b59e2e6c405ead415b4419d8d3502fd858394.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-fa5b59e2e6c405ead415b4419d8d3502fd858394.png)

然后22,23行是从数据库中查询，是否有匹配webname（post传过来的参数Name）的密码，在29行进行逻辑判断  
如果数据库查询的密码和post传参的密码匹配，或者密码等于hassmedia，就可以直接进到home.php界面，那么我们直接令密码等于hassmedia，就可以无需知道密码进入后台了

可以看到，当密码等于hassmedia时，响应包直接302  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1b24957e72a942ebbe2c14f26ff6b7d38083f5df.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1b24957e72a942ebbe2c14f26ff6b7d38083f5df.png)

成功进入后台  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9292d94c56bf0adb44e9909865c41f1df8323cb3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-9292d94c56bf0adb44e9909865c41f1df8323cb3.png)

我们知道，这种管理界面一般都会有ping拼接rce的，找一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4b1fb6b84d6baee615f86e665d8eb1098317ea6e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4b1fb6b84d6baee615f86e665d8eb1098317ea6e.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ca316960b66b0a699e4b56bf0f96871f61f8ebd7.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ca316960b66b0a699e4b56bf0f96871f61f8ebd7.png)  
抓包查看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f5b71a5917d5ffd8fb48a35dbbd373f5387a267f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f5b71a5917d5ffd8fb48a35dbbd373f5387a267f.png)

尝试管道符拼接，拿下rce  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-88d61909f67dfc33c81d5f61f03fbf76b47b2d5e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-88d61909f67dfc33c81d5f61f03fbf76b47b2d5e.png)

然后看看源码，文件在manager/ipping.php

先效验一步登没登陆，没登录就直接退出  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-84db88ca3ecc48695d1e86bb80695b59d8f6756e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-84db88ca3ecc48695d1e86bb80695b59d8f6756e.png)  
可惜没有前台rce了，那就看下后台rce的代码吧  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-00f19ffbf08f4a32352916ec93adb1003a79487a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-00f19ffbf08f4a32352916ec93adb1003a79487a.png)

整段代码的逻辑语句  
1 post接收ipaddr参数，赋值到datip参数  
2 shell\_exec datip，并将这个语句赋值到output参数  
3 echo直接输出output  
可以看到，全程无任何过滤，所以可以直接rce

那么会不会有前台rce呢  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0402ccea580286d0db8e7d778af0f030fb290915.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0402ccea580286d0db8e7d778af0f030fb290915.png)  
还真有，看下图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8ec0bd47ea9193c7bf4fddef340723927c965625.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8ec0bd47ea9193c7bf4fddef340723927c965625.png)  
可以发现这段代码没有任何验证登录，逻辑如下  
1 get接收参数file赋值到file  
2 然后转到del\_file  
3 然后test直接调用del\_file  
4 exec直接输出exec  
也是全程无过滤，构造poc：

file=1.txt  
echo PD9waHAgQGV2YWwoJF9QT1NUWydjJ10pOw== | ba  
se64 -d &gt; xxx.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f86aedcb590317a57489428291e676e1e859cc26.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f86aedcb590317a57489428291e676e1e859cc26.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-04f98859096d7184c247eb69de03d8838f902095.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-04f98859096d7184c247eb69de03d8838f902095.png)

除此之外还发现了很多的rce，为了方便浏览，先说前台rce，然后再说后台rce

前台rce 1：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a70bfd3fc9d86e6a88e4b13ae48109feae75e2b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a70bfd3fc9d86e6a88e4b13ae48109feae75e2b0.png)  
逻辑线：  
1 没有检验登录  
2 post接收addflag bodaddr bondmask bondgw  
3 判断addflag是否等于1，如果是就执行下列语句  
4 拼接其他参数到$cmd中  
5 exec echo  
6 rce

前台rce 2：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-81227af1a45a3a6aa427b4b392dc38963a0b1cd7.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-81227af1a45a3a6aa427b4b392dc38963a0b1cd7.png)  
逻辑线

1 无效验登录  
2 赋值ip\_dev flag sipdev  
3 判断flag是否等于1，是的话执行下列语句  
4 拼接参数  
5 exec，echo  
6 rce

然后审着审着seay出问题了..所以下面就用phpstorm的界面了  
后台rce 1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-39a023ed9ad9e664a59a6e70d498995cdbefc037.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-39a023ed9ad9e664a59a6e70d498995cdbefc037.png)

逻辑线

1 前面判断了是否登录  
2 判断actiontype是否等于RestartChannel  
3 接收传参  
4 拼接cmdurl  
5 exec输出cmdurl  
6 rce

后台rce2  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2a680a0287cefa5aaae1929a1557804a4f5eebe0.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2a680a0287cefa5aaae1929a1557804a4f5eebe0.png)  
第一行先判断了登录  
往下翻，看到这段代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4d0d385fa6019825df943c2091f9c1fd4d23c468.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4d0d385fa6019825df943c2091f9c1fd4d23c468.png)  
逻辑线

1 判断用户是否登录  
2 赋值ip\_addr ip\_dev  
3 判断addflag是否为1  
4 判断ipaddr和ip mask是否为空  
5 拼接参数到cmd  
6 exec echo  
7 rce

后台rce 3  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3d00e325afbefe87b08c6b87e3817b3ca7ecc6f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3d00e325afbefe87b08c6b87e3817b3ca7ecc6f5.png)  
逻辑线

1 判断是否登录  
2 判断actiontype是否等于reboot  
3 获取一个dev参数赋值devname  
4 如果devname存在ppp执行下列语句，不过也可以直接通过else的system执行  
5 为了方便就直接跳到else语句，给devName直接管道符拼接就行了，例如|ls  
6 system执行  
7 rce

除了这些洞，还有很多，不过没啥时间了剩下的就暂时不写了，后面如果有时间的话再补点，技术含量不高，路由管理之类的一般都会有rce，算是一个小思路入门文吧，文章内容如有任何错误，打码不全可以定位目标或者对不上号的，可以加我微信说明，感谢各位大佬们的指点，微信号 zacaq999  
文章所有洞均已上交