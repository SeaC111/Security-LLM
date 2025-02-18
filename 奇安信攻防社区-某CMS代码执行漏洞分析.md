0x1 前言
======

对opensns的一次代码审计，涉及到一些tp框架的方法利用,以及对tp框架进行审计时经常忽略的点

0x2 漏洞分析
========

官网下载源码：<http://os.opensns.cn/product/index/download>  
解压 打开

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f7f3b5fdc2f8f55fa706fdd31f8df1e9853ea5ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f7f3b5fdc2f8f55fa706fdd31f8df1e9853ea5ce.png)

很典型的一个使用tp框架的cms，控制器都在application目录下  
然后粗略的看了一下所有能直接访问的控制器，没发现有明显漏洞的地方，但是发现了个比较可疑的方法。

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f3c5752b554af4636d875589fb2d63fb00a83c63.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f3c5752b554af4636d875589fb2d63fb00a83c63.png)

在Weibo/ShareController 控制器中有一个shareBox方法 其中获取了query参数 然后url解码 在parse\_str 将$query解析成数组，然后assign成模板变量 最后display模板。这里并没有对获取的参数进行操作，那就可能在模板里面对参数进行操作了，去看下模板内容

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fd548a69fcda4e494084ca73fb1d42767506d55b.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-fd548a69fcda4e494084ca73fb1d42767506d55b.png)

文件位于Weibo/View/default/Widget/share/sharebox.html  
看到用了{:W()}这种写法  
W方法位于Thinkphp/common/function.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f0f60c3d21026b749c55258ed16f0117e2810e9e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f0f60c3d21026b749c55258ed16f0117e2810e9e.png)

备注解释是渲染输出 调用了R方法 继续看一下

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d855c0de3243ee721d9e5da577666bb9a9155e37.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d855c0de3243ee721d9e5da577666bb9a9155e37.png)

远程调用控制器的方法  
{:W('Weibo/Share/fetchShare',array('param'=&gt;$parse\_array))}  
那这行代码就是调用fetchShare 方法，参数也就是之前获取的$query解析成得数组  
那去看一下fetchShare方法,位于/Weibo/Widget/ShareWidget.class.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4f89b96942834ed3a0a617ba56ecbdc632f6537d.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4f89b96942834ed3a0a617ba56ecbdc632f6537d.png)

接着调用了assginFetch方法，我们看下D方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2cc9ad4cba0d0089226f255970b0056b3ae434b4.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-2cc9ad4cba0d0089226f255970b0056b3ae434b4.png)

实例化模型类，那就是在Weibo/Model/ShareMode.class.php，然后又调用了getInfo方法

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-848315d378605529eb24ee019c3a3132d1d3107e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-848315d378605529eb24ee019c3a3132d1d3107e.png)

这里又调用了D方法，并且调用了有一个参数的方法。根据上面的了解，D方法可以实例化Model类，那可利用的范围就变大了，去找一下可以利用的方法，只要满足两个条件。  
1.为Model类  
2.方法只能有一个传入的参数

看下tp框架本身自带的Model类。/ThinkPHP/Library/Think/Model.class.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-dc4c90862f4e53ee0a5dbe89d2f09ca676d2bd9b.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-dc4c90862f4e53ee0a5dbe89d2f09ca676d2bd9b.png)

找到一个可以实现sql注入的一个方法。但是我们可以尝试去寻找能实现代码执行的方法。

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8efe6fed15b773a8df6304c42fd60e3a4e5efc9f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8efe6fed15b773a8df6304c42fd60e3a4e5efc9f.png)

同文件下有个\_validationFieldItem方法里面有call\_user\_func\_array方法，如果能调用这个方法 并且两个参数都可控 那么就能实现代码执行。根据现在已知的条件，还不能利用 可以先记录一下。

找到一个可以利用的类，这是cms自己写的类。/Application/Common/Model/ScheduleModel.class.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5ec791cfabf70e501391681472934930e99ff15c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5ec791cfabf70e501391681472934930e99ff15c.png)

一个参数，为Model,满足两个条件，然后看到又调用了D方法来实例化Model类，但是调用的方法为两个参数，结合上面找到的\_validationFieldItem方法。按照流程构造poc，就能实现代码执行。

梳理一下漏洞触发流程  
1.ShareController.shareBox-&gt;  
2.ShareWidget. fetchShare-&gt;  
3.ShareWidget.assginFetch-&gt;  
4.ShareModel.getInfo(这里控制D方法生成ScheduleModel类，并调用传入一个参数的方法)-&gt;  
5.ScheduleModel.runSchedule(这里控制D方法生成Model类，并调用传入两个参数的方法)-&gt;  
6.Model.\_validationFieldItem

0x3 漏洞验证
========

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5016276bc0d6e21289835b7795aaf4ba2cc83a1d.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5016276bc0d6e21289835b7795aaf4ba2cc83a1d.png)

0x4 总结
======

涉及到tp框架一些方法的调用 应该还有其他的调用链，或者还能使用魔术方法来实现利用 大家有兴趣可以找一找 顺便可以熟悉下tp框架