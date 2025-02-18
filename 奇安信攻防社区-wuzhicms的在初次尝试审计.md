前言
--

在网上漫游发现的一个cms cnvd也是有提交的  
也是初次审计这种  
官网：<https://www.wuzhicms.com/>  
现在也已经好像没更新了

也是先看了一会代码 才知道这是MVC的 之前由于也没有了解过MVC 就很懵  
开始啥都没看懂  
后来经过百度 和 求助了一波团队的时候 总算是有一点点明白了 能把代码走动  
 MVC全名是Model View Controller，是模型(model)－视图(view)－控制器(controller)的缩写，一种软件设计典范，用一种业务逻辑、数据、界面显示分离的方法组织代码，将业务逻辑聚集到一个部件里面，在改进和个性化定制界面及用户交互的同时，不需要重新编写业务逻辑。MVC被独特的发展起来用于映射传统的输入、处理和输出功能在一个逻辑的图形化用户界面的结构中。(百度的)

而在之后的路径中会看见m f v这几个参数  
m就是文件夹 f就是文件 v就是方法  
就先大概介绍这些  
下面开始审计  
sql注入肯定是容易找的 就先找sql注入了

### 工具：seay phpstorm phpstudy

### 第一处 sql注入(可惜是后台的)

先直接全局搜索select  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c17dc9b7660e2c2a3362e6df14dc6cc935e1255c.png)  
这个函数 展示没有发现有过滤  
然后找哪里调用了这个函数  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f087fe80a540de392c3cd8f28747b172e2571472.png)  
通过全局搜索 在这个地方 发现调用了这个函数  
然后查看传递的参数  
主要传递的是55行这个$where参数 传到了函数  
然后我们看$where参数的组成 里面有两个变量$siteid $keywords  
我们是可能可控的  
先看$keywords 因为这个没调用函数 但是调用了一个$GLOBALS来获取值  
这里就又要介绍下$GLOBALS 因为刚开始我也没懂这个是怎么用来获取值的 知道我百度一阵之后  
和代码翻翻之后 在一个文件中发现了

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-14f2692bc6c68dcd108968aec53d5fcd76c3dec4.png)

这个cms用$GLOBALS来获取全部的变量 直接把GET POST代替了  
具体怎么代替的就不跟进解释了 一句话 就是$GLOBALS可以取到get post的传的值  
那么这个keywords 前面又没有定义变量啥的 大概率是 传参的 (后面经过验证 也的确如此)  
那另一个参数就不用看了 就先控制这个参数才进行注入了  
有了可控参数 现在就需要找到整个payload了  
可能熟悉MVC的师傅 就知道该怎么构造payload了 但我没学过MVC 也不了解 就只能用其他方式来找了  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-17d47b74ada322a40e4e5cad50f39d2a8774987c.png)  
在这个文件看见了广告管理的注释  
那我就去后台找这个功能了  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-930cfc50b6400a4cad4f27804845a18285093f6b.png)  
又因为调用的函数是search嘛 那就是这个搜索框 八九不离十了  
直接输入1 然后搜索 但是这样看不出来  
就输入1然后抓包 看看包了  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-33098bded3c0ec09a4ba135dde08bf36647eafec.png)  
好了 这样路径参数什么的也出来了  
就全部复制到url  
然后构造payload ：SELECT COUNT(\*) AS num FROM `wz_promote_place` WHERE `siteid`='1' AND `name` LIKE '%1%' or extractvalue(1,concat(0x7e,(select database())))%23  
闭合%‘%23  
这里我尝试了下 盲注 和报错都是可以的  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3689720f2819966f359b105cce0e55efb10ca07b.png)

如果现在到过头来看 就一个简单的搜索框的注入没什么花里胡哨的 过滤也没 但审计来看 还是绕了一大圈子

### 第二处 前台sql注入

还是在搜索select的时候 发现在mysql.class文件下有一个函数里面有select 并且后面的拼接也没有任何的过滤  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3d41139a5ebc3144d3bb560877166c36f37763d5.png)

然后我们搜索哪里调用了这个函数  
首先是在api目录下的sms\_check文件中发现调用了get\_one函数 并且参数是通过前面的$code拼接  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ce18ab821ea6f6239e5861212f7ae514370e2210.png)  
我们可以看到code 先是通过$GLOBALS来获取参数param的值 从前面的介绍可以知道 $GLOBALS是可以获取post get的值 这个文件前面没有定义param变量 那么 这个param应该就是post 或者get 就是我们可控的 这也是导致注入的点

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-815e686f8f88d9941ac8807766adb6d320976323.png)  
code还通过strip\_tags() 函数 而这个函数的作用是剥去html标签 应该是过滤xss吧大概  
之后就直接传入了函数 继续更进函数 因为这个文件前面还引入了db类  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-803afde8a1a4b69c120770382e2737fe65d757d4.png)  
这个函数应该是调用的这个文件里面的  
来到这个文件

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b4f9220ee7c472500bcc5516c9f242095757204b.png)  
可以看到这个get-one函数里面 还调用了一个array2sql函数来处理$where  
那先来看看这个函数的作用  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-7b0f8ac87e586a53983dd37861ef4596d71503bc.png)

可以看到这个函数是用来过滤的  
如果是数组 这进入if 把括号 单引号这些过滤掉  
不是则走else 过滤 %20 %27  
然后返回参数  
但也就是这个过滤的地方 没有防护到位  
我们传的参数不是数组 所以就没有走if  
而else里面过滤的却是 %20 %27  
我们传参的时候尽管是经过url编码的 但是web服务器会自动解码一次 所以 我们传到后端代码处的时候是没有进行url编码 相当于  
但是二次编码的就不一样了 因为web服务器只解码一次  
如果是二次编码这里的else过滤就起效果

return 调用的get\_one 则是最开始看见的mysql.class文件里面了

下面就可以开始直接构造payload了 这里通过代码分析可以看到是单引号闭合

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-64bd676c09442bae0fa76fb18fa22cec44d40893.png)  
单引号报错  
闭合显示正常页面

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b8809c4a0ed48abb66590516856166e51f00ea85.png)  
就进行盲注  
我用的报错

payload：[http://192.168.1.7/wuzhicms/api/sms\_check.php?param=1%27+or%20extractvalue(1,concat(0x7e,(select%20database())))%23](http://192.168.1.7/wuzhicms/api/sms_check.php?param=1%27+or%20extractvalue(1,concat(0x7e,(select%20database())))%23)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d7479b568642fb25596c14cef08d60e8beb2fef0.png)

### 第三处 后台sql注入

从前面两个分析 我发现的注入的地方就存在两个函数中get\_list get\_one  
然后直接全局搜索这两个函数 看看什么地方调用

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-edfdbd26a79fab38853bdb8f2df91ff89569c1ef.png)  
可以看到 在copyfrom.php中listing函数下调用了这个函数  
然后我们网上分析 看看什么是可控的  
主要传进去的就一个$where 和 $page  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4f18d70c97062a4ab1a99224dca6597d831f522e.png)  
可以看到page会被intval()函数 转化为整数 所以我们不考虑它  
我们看看where 在if内部 想要进入if 就需要通过GLOBALS获取到keywords  
相当于就要传参嘛  
然后在看里面 就没有过滤这些 直接拼接  
这里也可以看出 闭合方式是百分号单引号 %'  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9f27f37d98d1f63c24b1dfa355fdb5629880e03c.png)

我们在来到mysql文件中定义的这个函数 也可以看到 是对where没有过滤处理的  
那么 有了前面的基础 直接来构造payload：[http://192.168.1.7/wuzhicms/index.php?m=core&amp;f=copyfrom&amp;v=listing&amp;\_su=wuzhicms&amp;keywords=%27](http://192.168.1.7/wuzhicms/index.php?m=core&f=copyfrom&v=listing&_su=wuzhicms&keywords=%27)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-34972277b4543fd515bf124a9bc4146b27d7ad9d.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e6d3c74eddf6167774c9e8fd148ca0d3843bd9d0.png)

报错了 直接插入报错注入的payload:[http://192.168.1.7/wuzhicms/index.php?m=core&amp;f=copyfrom&amp;v=listing&amp;\_su=wuzhicms&amp;keywords=1%%27%20or%20extractvalue(1,concat(0x7e,(select%20database())))%23](http://192.168.1.7/wuzhicms/index.php?m=core&f=copyfrom&v=listing&_su=wuzhicms&keywords=1%25%27%20or%20extractvalue(1,concat(0x7e,(select%20database())))%23)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1ef05237d2b537bb75d8012bfb24b94529eda936.png)

### 第四处 后台任意文件删除

通过全局搜索unlink函数 来找文件删除

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-43eb502bf6c53a4c9f646d968ea1589e96521ca6.png)

在这个文件下找到一个删除文件的函数 然后我们继续找哪里调用了这个函数

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-67f20399a45fb826ed2fc928719cade572379770.png)

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-81717c4757c0e24ee7773cd40262ce0beab0b5ef.png)  
还是在这个文件 找到了一个del函数 里面调用了删除文件的函数

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c0347e795a45e23c7501f92f1a12bcc1d502a016.png)  
然后来分析调用的过程 调用删除的时候通过把$path和ATTACHMENT\_ROOT 拼接  
而ATTACHMENT\_ROOT是前面定义的一个默认路径

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0692fd2e561a561bf42d3005bcff42f0c0b6aa9e.png)

path则是前面的$url 来的  
在看前面的if 如果path有值则进入到if里面 然后经过的数据库的get\_one查询操作 应该这里是要查出一个东西  
但是因为我数据库是空的 则进入的是第一个if里面 哪怕是查出1条 也是可以的  
这里也没有其他过滤  
然后网上看url的来源  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8e7bc73f02633f59e78cdb5333c9a7fe3178f7f6.png)  
GLOBALS 那就可以直接通过传参的 前面也介绍了 id为空的话 也就进入到了else里面

到这里也就可以构造payload了  
先在根目录下创建一个文件  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-89580f376889e8b76091175a47acb28df8c9e978.png)  
然后构造  
[http://192.168.1.7/wuzhicms/index.php?m=attachment&amp;f=index&amp;v=del&amp;\_su=wuzhicms&amp;url=../1.txt](http://192.168.1.7/wuzhicms/index.php?m=attachment&f=index&v=del&_su=wuzhicms&url=../1.txt)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-014a1de73fe567820e1ae334286c3e256d106fc5.png)

这里我把最终删除的路径 打印了出来

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8d539ab71dfe39b90c943c0d97173e530db702e0.png)

文件也是成功删除

### 第五处 后台任意文件上传

直接搜索file\_put\_contents函数  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-49b72967c9b4056ec979b3f7b6ac077776d8e6b0.png)  
在set\_cache函数下发现写入文件的函数 $data并且没有过滤是直接通过参数传过来的  
然后全局搜索 在哪里调用了这个函数  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2feae3e6fbafc9cd29ff353faad7cda70693b4f2.png)  
这个set函数下调用了这个函数  
并且写入文件的内容是可控的  
通过打印 知道了 写入的路径 文件名  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d1507f4c17f8cd5782992f2fd79b6be818f94bcf.png)  
并且这里也没有过滤  
直接构造payload

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-aadf2c605b6b342617518a1c3939dbc4c9ec967b.png)  
然后访问文件

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b54f580cf112042de9c7f684c24751773efd5aeb.png)

后面又发现一个函数调用的set\_cache  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-621783daf561db94673ab17f752fdf44ab87afe7.png)  
过程是一样的 基本上 就没有演示了

这里还要注意一点 这里是写入的缓存文件 不是一直存在的 我重启之后 写入的内容就还原了  
应该是还有的 就没有继续找这个了

### 第六处 信息泄露

最后在后台页面发现一出phpinfo  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-23a9cb2f9e6f0e8bfb87a0c974b15ddb2d921aba.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a9e8dc4e2aea0c1d31eacd3f190e1056796a0557.png)  
一个垃圾的信息泄露

### 最后

肯定还有审漏的  
经过这个cms的审计过后 对MVC这种框架的也有了基本的认识了 以后遇到也不至于这样的无厘头 不知道怎么搞路由 怎么调用的  
有了一个新的开始  
如果此文有什么不对点 师傅们指出 学习学习 这也是继前面几篇之后新的一次尝试把 但回过头来看这个cms 也就因为mvc 所以调用的时候不同 其他的点 漏洞的地方还是规规矩矩 大差不差的和以前的比较的话