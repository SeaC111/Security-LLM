### 前言

在看了社区https://forum.butian.net/share/460 师傅的文章后 找师傅要到源码 然后在次对zzcms发起了审计  
本文对应版本为2020 zzcms已于8月份更新为2021版 相关漏洞在新版本已修复 本文仅供学习思路  
最新版链接：<http://www.zzcms.net/about/6.htm>

### 审计开始

首先打开页面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-78ae0d7a04b90195809458ecdf7967fb751a6785.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-78ae0d7a04b90195809458ecdf7967fb751a6785.png)

### 第一处sql

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2a7e61554a6f0d2ed51242bbfa3da5f06206e32f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2a7e61554a6f0d2ed51242bbfa3da5f06206e32f.png)

来到ask/search.php 页面 这里定义了一个$fp 引入了一个模板 然后通过$f用fopen函数用只读的方式打开ask\_search.htm

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6fa30a5f2c4ea5e53a3a7048be9658cfabdd33f6.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6fa30a5f2c4ea5e53a3a7048be9658cfabdd33f6.png)

然后通过fread函数来读取  
fread() 函数读取文件（可安全用于二进制文件）。

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-acedeaec1714e8e9fbe6c1607f9098644dfd5a23.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-acedeaec1714e8e9fbe6c1607f9098644dfd5a23.png)

然后期间经过了一些str\_replace函数的过滤 在232行 调用的showlabel函数  
我们跟进这个函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9ea138b6ca69f3106d062222790d4794b88657cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9ea138b6ca69f3106d062222790d4794b88657cf.png)

通过foreach函数遍历channels数组 经过测试 最后都会进入到if里面

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-98b234b5fed7e4bf906d4bdcea81728c35de9ffc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-98b234b5fed7e4bf906d4bdcea81728c35de9ffc.png)

在if函数中又调用了fixed函数 我们继续跟进

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1123a533556060e514622e5a6c2c3e35a5307677.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1123a533556060e514622e5a6c2c3e35a5307677.png)

Fixed函数通过switch 根据传进来的channels值 分别调用函数 通过前面知道channels数组的第一个的ad 所以会进入ad 调用 showed函数 继续跟进showad

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e8b1f9e08c8b433f7e4f23349f7c7a34e79871b9.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e8b1f9e08c8b433f7e4f23349f7c7a34e79871b9.png)

Showad函数 会将传进去的内容先用explode函数进行分割 如果匹配不到分割的参数 则会返回整个$cs 是一个数组  
所以后面$b就有值了 $s就为空  
继续看后面

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-00dde496b6f554e7cad66099b52b4d27dbf043ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-00dde496b6f554e7cad66099b52b4d27dbf043ec.png)

这里发现sql语句 肯定想到的是sql注入 所以我们要想办法让代码进入这里面执行 sql语句在else里面 我们看看if

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0afccd5c9e5ef3978c4b5b212f5cd6202de0d356.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0afccd5c9e5ef3978c4b5b212f5cd6202de0d356.png)

If里面的条件都是通过&amp;&amp; 拼接 所以我们只需要让一个不为true 就进入else  
继续看 发现里面有一个filesize($fp)&gt;10的判断 然后我们往上看$fp  
$Fp是通过一系列的拼接 其中就有$b 最后拼接成htm  
这个$b从前面可知是我们可以控制的 所以最后拼接出来的htm只要不存在 if的条件就不成立 就进入了else 执行sql

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-72b43829ed0e76f2a4d33a1d8e7beaa3169f2d8c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-72b43829ed0e76f2a4d33a1d8e7beaa3169f2d8c.png)

后面调用了query函数 我们跟进query函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cc3c8bf0fe9df010311381ee60f8a2f4896d8f4f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cc3c8bf0fe9df010311381ee60f8a2f4896d8f4f.png)

是没有任何防护的（这里说错了 其实是有sql注入防护的 因为这里的数据是通过文件读取的 所以过滤函数没有起作用 后面会有介绍）  
Sql测试

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b27c128b4032b2f92de3128316aafcad3c779365.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b27c128b4032b2f92de3128316aafcad3c779365.png)

来到后台 添加一个模板ask\_search.htm  
内容 {#showad:' or sleep(5)#}  
然后保存 然后访问 ask/search.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-752dfa40f50f00d515717db4ac3bf91b73c9564b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-752dfa40f50f00d515717db4ac3bf91b73c9564b.png)

延时成功  
我在测试这里的时候当时遇到了一个小问题 开始一直不能延时 后来才发现是zzcms\_ad  
这个表的原因

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2947dc362820f1f3f695a60ab8035305dd948713.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2947dc362820f1f3f695a60ab8035305dd948713.png)

Zzcms\_ad 这个表不能为空 空的话 就无法延时

### 第二处代码执行：

在install/index.php的114行

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-aebe816139f9707c4987b43639c7ff17966855ef.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-aebe816139f9707c4987b43639c7ff17966855ef.png)

用fopen函数 写入的方式打开了文件  
用fputs函数写入文件  
fputs() 函数写入文件（可安全用于二进制文件）

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-148250b7b168fd02b1f2be7cd4316cec647a688a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-148250b7b168fd02b1f2be7cd4316cec647a688a.png)

然后在step\_2.php 以及 345文件中都没有发现判断是否又install.lock这个文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e56f659fde2a91e8f8f8ba87e8e967f910645baa.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e56f659fde2a91e8f8f8ba87e8e967f910645baa.png)

在install/index.php页面又是通过$step来包含这些页面的 然后我们看看这个$step是怎么传入的

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2ee711829054ccbdaf995973ab652935e2e9a2d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2ee711829054ccbdaf995973ab652935e2e9a2d0.png)

自己通过post的方式传入 也没有任何防护 所以我们可以直接通过post的方式构造step=2 直接来到安装步骤的第二步  
测试  
现进入install/index.php页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-bf5b5b7469be16d2bec771a5329253d79b7e6c5e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-bf5b5b7469be16d2bec771a5329253d79b7e6c5e.png)

然后打开hackbar

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8822ddf76739b106fa471a9b35dd78443b52e346.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8822ddf76739b106fa471a9b35dd78443b52e346.png)

这里有个疑惑 不知道为什么抓包改请求方式的办法 一直用不起 页面一直显示空白

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-498b7f02c30d2f2ad80821efb516de50940c8bd7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-498b7f02c30d2f2ad80821efb516de50940c8bd7.png)

一直下一步 来到这里

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ecc7d30ae02211c430a8bb07f3543599eacf2418.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ecc7d30ae02211c430a8bb07f3543599eacf2418.png)

通过这里可以知道 创建数据库这一步的这些数据 会写入到另一个文件config.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d445c36349001af902bbaaade93a8d4c07985e15.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d445c36349001af902bbaaade93a8d4c07985e15.png)

并且写入的时候 没有什么过滤 说明 写入的参数是可控的 在这里可以直接尝试写入一句话  
在端口的位置输入3306');eval($\_POST\['a'\]);('

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-40a0c8a89cc8944e15a68cf950a8e803ddeaaeef.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-40a0c8a89cc8944e15a68cf950a8e803ddeaaeef.png)

然后下一步

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8a42cc1bcfd8c52c91c6641f4223a26f75dd1857.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8a42cc1bcfd8c52c91c6641f4223a26f75dd1857.png)

然后查看config.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5667bbeec3c15887ebe6dcf382464fca99bf102e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5667bbeec3c15887ebe6dcf382464fca99bf102e.png)

成功写入

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d5003fa0f919e83e19de945a97c646d88f5ad25e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d5003fa0f919e83e19de945a97c646d88f5ad25e.png)

可getshell

### 第三处越权

来到tag.php页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c0bc81c38215753d5ddaaba635f3e4d71154318d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c0bc81c38215753d5ddaaba635f3e4d71154318d.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-472d19253f6f09503e465a4ad452d38e6cba755a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-472d19253f6f09503e465a4ad452d38e6cba755a.png)

现查出所有的表 然后和 cookie中的tablename的值进行比对  
str\_is\_inarr跟进这个函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-08270c0484218ba30d0aa715502e6a756399cb99.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-08270c0484218ba30d0aa715502e6a756399cb99.png)

然后通过in\_arr函数进行比对  
in\_array() 函数搜索数组中是否存在指定的值。  
通过前面可知$tablenames 后面拼接了# 所以能够进入到if被然后被explode函数拆分 然后进入if 返回yes

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-90ffcf6a689f9cb6f89925aabbae81973353f228.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-90ffcf6a689f9cb6f89925aabbae81973353f228.png)

返回yes之后 就会执行下面的代码 然后根据dowhat 的值执行switch  
前面两个看参数就知道 一个是增加 一个是修改 我们看第三个函数showtag()  
跟进函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c5b2b584f79f7d7d03a3a436cdc83ee98d94d07d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c5b2b584f79f7d7d03a3a436cdc83ee98d94d07d.png)

上面根据action参数 获取判断是px 或者是del  
通过代码分析px 没有没什么可利用的 下面的del 有可控制的点

我们可以控制tablename和id 来控制删除数据  
相当于这里就是通过cookie里面传的表 以及post传的id值 进行查询表的数据和id进行匹配 匹配到了 就直接删除 没有其他的限制  
测试

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a0360ca3e3ac66c6bcfe1dbb3cb018c46c272608.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-a0360ca3e3ac66c6bcfe1dbb3cb018c46c272608.png)

现在后台添加一个普通管理员ttt和一个超级管理员asd

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e615f961c2025995664ad93abbd597278a532fe7.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-e615f961c2025995664ad93abbd597278a532fe7.png)

然后登录普通管理员

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-18ed0ed2c9f2e0b493c1ab8f75096ebe2755a26d.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-18ed0ed2c9f2e0b493c1ab8f75096ebe2755a26d.png)

然后访问tag.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-864951d1c46451b7004ec05f118dad4334409e25.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-864951d1c46451b7004ec05f118dad4334409e25.png)

然后放包

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3fa9607f7c4f090972a01e9fe2e193ea0f8b2f84.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3fa9607f7c4f090972a01e9fe2e193ea0f8b2f84.png)

asd超级管理员成功被ttt普通管理员删除

同理 也可以删除其他表的数据 只要表明 和id能匹配上

### 第四处sql

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-43621215c6325b591c13ddb80b5d327647f0b80b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-43621215c6325b591c13ddb80b5d327647f0b80b.png)

来到bad.php页面  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d800e93727c426d4bba2696f5340a1da86d9e5fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d800e93727c426d4bba2696f5340a1da86d9e5fd.png)

下面有sql语句  
在in 后面的 $id 没有引号保护 可能被利用

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7b43e5b8bd41bf672b0b72cdc8ae3108de30586f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7b43e5b8bd41bf672b0b72cdc8ae3108de30586f.png)

先来到bad.php页面 在数据库随便添加的数据  
然后分析代码

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ef8ac418f73ab292f20e308ce48caf9cf873c1d4.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ef8ac418f73ab292f20e308ce48caf9cf873c1d4.png)

通过post传入id 然后action=del 进入到sql执行里面 如果id后面有逗号 则执行if  
有则else 看看下面

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-68e6b9932f60e36eb4c4bf8ce2819d2db92af5bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-68e6b9932f60e36eb4c4bf8ce2819d2db92af5bf.png)

执行sql的函数 我们跟进这个函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ed54e0a025f8774adfdc2a1ae9084bfcf705db1c.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ed54e0a025f8774adfdc2a1ae9084bfcf705db1c.png)

这个函数在conn.php里面 而conn.php还包含了其他文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d81294e5d76265e5b5caa7ca52189cdc5933dcd5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d81294e5d76265e5b5caa7ca52189cdc5933dcd5.png)

注意到stopsqlin.php 打开这个文件看看

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0b9b8dd8364e12c99b6200a4dc9b9d827eac4807.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0b9b8dd8364e12c99b6200a4dc9b9d827eac4807.png)

这个文件主要是过滤的  
addslashes() 函数返回在预定义字符之前添加反斜杠的字符串。  
htmlspecialchars() 函数把预定义的字符转换为 HTML 实体。  
相当于这里单引号双引号都过滤了  
但是 有个地方没有引号保护 直接尝试payload：

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b1b07e21a9de495625f95d79a60f138b368ffd11.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b1b07e21a9de495625f95d79a60f138b368ffd11.png)

点击删除 然后抓包

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b86039051a58b9d9690edf62857cab1b34ae53e2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b86039051a58b9d9690edf62857cab1b34ae53e2.png)

构造payload：id\[\]=1,1)+or sleep(5)#&amp;del=%E5%88%A0%E9%99%A4%E9%80%89%E4%B8%AD%E7%9A%84%E4%BF%A1%E6%81%AF&amp;pagename=showbad.php%3Fpage%3D&amp;tablename=zzcms\_bad

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7eb728e9bad4c039555836de4997c87dc88a1cfc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7eb728e9bad4c039555836de4997c87dc88a1cfc.png)

成功延时

但是这个sql也是要登录后台的

### 第五处sql

因为前面的sql需要登录后台 所以想找个不需要登录的  
前面找到没有引号保护的sql 这个cms肯定不止一个地方 全局搜索

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5ec56aa661deccc2c411dcf359f505358b81b7be.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-5ec56aa661deccc2c411dcf359f505358b81b7be.png)

在dl/dl\_print.php 文件下找到

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c8adce1fa46d98fa7e5c6c6492a24e4ab7af76fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-c8adce1fa46d98fa7e5c6c6492a24e4ab7af76fd.png)

这个文件在开始也没有检验是否登录 所以有戏 接着分析源码

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6b1d27c5ca7c815561b737bec8e153ffc87b0bdf.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6b1d27c5ca7c815561b737bec8e153ffc87b0bdf.png)

通过cookie是否有username 来判断是否执行OpenAndDataFunc这个函数 这个函数是弹出登录框的

往后看

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cd5714e628e3c0c8dd92dcd5b4e1bbb8c2602e97.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-cd5714e628e3c0c8dd92dcd5b4e1bbb8c2602e97.png)

id还是通过post传入

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-15f0dfa0632ed8797db4433b2097d5edd8ec6fec.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-15f0dfa0632ed8797db4433b2097d5edd8ec6fec.png)

这里有个权限的判断 我们跟进这个函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-25477100cc43a0db2f85ba4800af93e5af67477b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-25477100cc43a0db2f85ba4800af93e5af67477b.png)

这个函数是判断cookie中的uesname是否在zzcms\_user表中 有则返回yes  
这里这个username 是可以通过枚举来判断这个表里有哪一些

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-09dea2ed7e4e0cec7125a7bab3be31b80219aec3.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-09dea2ed7e4e0cec7125a7bab3be31b80219aec3.png)

然后就看到这里 和前面的差不多 但这里两个sql语句都没有引号保护 说明 都可以达到注入  
尝试测试

先打开dl/dl\_print.php 页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b8570d944b95f564e8d1bdaefc443daebf562dec.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b8570d944b95f564e8d1bdaefc443daebf562dec.png)

然后刷新抓包

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d1b591ceac0887aaaadecd7fb9a05a796a5009bb.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d1b591ceac0887aaaadecd7fb9a05a796a5009bb.png)

然后右键改包 构造payload：id\[\]=2+or sleep(5)#

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0fe1d7f9d4d6212026b295fce8c3f80b08825c8f.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0fe1d7f9d4d6212026b295fce8c3f80b08825c8f.png)

还有一种

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b241ddb99df08a8216cc98db97f110936e8941e0.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b241ddb99df08a8216cc98db97f110936e8941e0.png)

都可以延时

### 最后

感谢师傅提供的源码 求师傅们建议 轻点喷 小白第三次审计