前言
--

本次审计以学习思路及记录审计过程为主，因此看缘分选择了一个旧版本开源cms作为入门代码审计的学习。因为代码简单，对新人友好，但漏洞经典，故作本次分享，希望能启发一块学习代码审计的小伙伴。  
审计环境的搭建互联网上相关的文章比较多，就不详细记录了。在安装cms搭建环境前，可以先浏览一下源码压缩包中的使用说明：  
![image.png](https://shs3.b.qianxin.com/butian_public/f348788960c8fc61ae8f8c6e217e66ad53382a45c5145.jpg)  
按照上述的需求按照cms即可，为了方便，本次我在windows平台上跑Phpstudy\_pro，服务器环境配置为Nginx+PHP5.5+MySQL，审计过程主要涉及的软件有:  
Phpstorm  
Phpstudy\_pro  
Burpsuite  
Seay源代码审计系统

寻找切入点
-----

先使用Seay源代码审计系统跑一下，方便寻找切入点。可以看到出现比较多提示，但因为这只是简单的正则匹配的结果，存在的误报很多，还需要跟进确认漏洞。  
![image.png](https://shs3.b.qianxin.com/butian_public/f854645c26a0dc9ecc7a5807d83798a482c9ace440b26.jpg)  
但经过下文中几个注入点的测试，发现确实存在不少的误报?

注入点测试
-----

根据匹配的结果，先随意找个提示可能存在注入的位置进行测试。  
在/dl/show.php中  
![image.png](https://shs3.b.qianxin.com/butian_public/f119440efb06096971fc69994bd574c57207f617220a2.jpg)  
找到目标文件，并搜索关键字很快就能找到提示的注入点。  
![image.png](https://shs3.b.qianxin.com/butian_public/f312160b7aff14c1f280f987937173e2ce480bb97a3ab.jpg)  
根据代码，`$dlid`就是`$_REQUEST["id"]`，在burp中抓包并修改id进行测试  
![image.png](https://shs3.b.qianxin.com/butian_public/f55029670da6699e7dc63e94a2ca8b6be85cac9f6719a.jpg)  
结果发现提示非法字符，代码中果然存在关键字的过滤，此时需要找到该过滤函数的调用位置。

寻找过滤函数
------

### stopsqlin()函数

尝试搜索提示的关键字来寻找触发过滤的位置，从而找到了名为stopsqlin.php文件，并下断点调试。  
![image.png](https://shs3.b.qianxin.com/butian_public/f923542802dba525f9c8dc0854468a563da32af98ecd2.jpg)  
可以看到sql\_injdata就是我们要找的过滤字符串，并通过explode()打散为数组，方便后续对stopsqlin()函数传递进的字符串进行过滤时遍历使用。  
![image.png](https://shs3.b.qianxin.com/butian_public/f676667f0cd10d5b06642482ba49e7a3a3ba359b3b18a.jpg)  
部分过滤关键字如下：

```php
select|update|and|or|delete|insert|truncate|char|into|iframe|script|……
```

通过全局查找调用过滤函数stopsqlin()的调用位置，能看到基本已经对get、post、cookie中传递的数据进行了敏感关键词的过滤，只要传递上面显示的关键词，就会触发非法字符提示。  
![image.png](https://shs3.b.qianxin.com/butian_public/f452000dc0a91a59560546c92c472812d117c1ebe0caa.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f28559565e68c2c63a3e201328586b117f0baf674a695.jpg)  
此处的过滤并提示的代码使用了strpos()函数实现的，并在比较时使用了严格比较`!==`，导致一些绕过方式无法使用。（关于该函数的绕过方式会写在文章结尾的后记）  
![image.png](https://shs3.b.qianxin.com/butian_public/f422856fecde00cb3f51c317eabc5293595739d88f27b.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f808762555e8e3d9fc0ca293106ae5f789c71b06ff441.jpg)

### zc\_check()函数

继续对stopsqlin.php文件进行浏览，还发现存在一个zc\_check()函数，主要也是对字符串进行尖括号、单双引号斜杠等进行转译，防止xss和注入。因为使用的PHP版本为5.5，magic\_quotes\_gpc已被移除，所以会触发的是else下方的分支，通过addslashes()函数对引号、斜杠、NULL进行过滤。  
![image.png](https://shs3.b.qianxin.com/butian_public/f4993763476ab44ad4414c1439f3c79744dfbaf8a0407.jpg)  
紧接着zc\_check()函数函数下方就发现对它进行了调用，已然get、post、cookie传递的数据被过滤辽。因此在sql语句中的想要绕过单引号保护的变量时，输入的`'`是会被该函数处理，加上`\`无法正常生效。  
![image.png](https://shs3.b.qianxin.com/butian_public/f8609629eb21b5b1f8b5a0065bb8165aad5f226ab1060.jpg)  
经过对其他注入点的测试，这些过滤函数都能很好的完成工作，将用户输入的恶意payload进行拦截。?  
![image.png](https://shs3.b.qianxin.com/butian_public/f12613378196ce6d2df1c941acdb3e50f89e48b91c46b.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f439097d4241c780a6b6d197fb65d4590f05d8fb08577.jpg)

过滤函数stopsqlin()绕过
-----------------

其他的过滤函数未发现存在绕过的姿势。  
但在stopsqlin()函数的调用位置，发现在执行关键词过滤时存在一个前置的条件，这里存在一个逻辑判断bug。  
根据代码逻辑判断，在请求的url中不存在siteconfig.php、label等字符串时，才会执行关键词过滤。  
![image.png](https://shs3.b.qianxin.com/butian_public/f197172ae42348ae79d19615a956574e0e92527288859.jpg)  
合理推测一下，siteconfig.php、template.php在正常请求时会出现传递包含敏感关键词的情况，因此作者的本意应该是为了防止非法字符提示影响系统正常使用，专门给这两个文件留了后门。但因为这种写法实在不严谨，导致路径中只要包含这些的文件名就能绕过对敏感关键词的过滤行为。比如我们在url路径后面添加一个keyword=siteconfig.php就可以看到原本的非法字符提示就不再会被触发了。  
![image.png](https://shs3.b.qianxin.com/butian_public/f98091589d65e20c5a7211f870d61cef17e43b60c705b.jpg)  
但是这里出现了新的提示，参数有误。  
![image.png](https://shs3.b.qianxin.com/butian_public/f48435596b8b9be6de84fb6ce7828d679861bf4d69fd2.jpg)  
通过动态调试，发现是触发checkid()函数的数字型校验，指定的变量非数字或非数字字符串，就会触发参数有误弹窗，只能再去找其他注入点。  
![image.png](https://shs3.b.qianxin.com/butian_public/f72773270a79613cceff2af7fcb7d5fcf0c7181dcb90f.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f796807717dd397d8b02223cd435ad420cbde241d84a8.jpg)  
同样在/dl/show.php中，找到一处存在cookie传参的可控变量sql查询位置。  
![image.png](https://shs3.b.qianxin.com/butian_public/f25099990ff0eeca290061a005d65e429c4cb0613bb22.jpg)  
利用上面的逻辑bug绕过过滤函数stopsqlin()，使非法字符提示不在触发。  
![image.png](https://shs3.b.qianxin.com/butian_public/f311504045bbdb79350a5b6f8608875f4158f6f3606a2.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f915227e4bc1a9771f306b35c673419d690b7ee7e5035.jpg)  
但是因为该位置存在单引号保护，还未找到绕过方法，因此重新浏览扫描的结果，寻找可利用的注入点。  
![image.png](https://shs3.b.qianxin.com/butian_public/f291643f16bf39b8b53149b3a8b3ea5f687936493ce72.jpg)

注入漏洞挖掘
------

重新浏览扫描结果时，整理一下思路：  
1、在sql查询语句中，存在可控制变量  
2、可控制变量没有使用checkid()函数检查  
3、因为只能绕过非法字符检查，因此可控制变量没有单引号保护

此时，在zs/subzs.php中，存在一处符合上述条件的注入点。阅读源码并寻找触发条件。  
根据第14行中的判断条件，为了使变量cpid不会代入else分支中的sql语句被单引号保护起来，需要保证payload语句存在逗号。  
![image.png](https://shs3.b.qianxin.com/butian_public/f167087bdbe28958d07ac439d1bb31c636e11e9e907eb.jpg)  
为寻找触发条件，查找showcookiezs()函数的调用位置，找到fixed()函数，发现触发条件为满足$channel变量值为cookiezs。  
![image.png](https://shs3.b.qianxin.com/butian_public/f118034a351672a9dfb3881cfd745c5a3908a79455edb.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f471273151dd5c49d89290da6b410dcf81a29d36afb68.jpg)  
在showlabel()中发现fixed()函数的调用过程，发现需要满足条件$str中存在标签{#showcookiezs:时$channel的值才能等于cookiezs。  
![image.png](https://shs3.b.qianxin.com/butian_public/f994133ae0f09f4de292d51ad38816e43f54e83ded3df.jpg)  
而经过动态分析，$str的值为用户访问网站页面时的原始页面数据。只要找到原数据中存在{#showcookiezs:标签的页面即可。最终，是在/zs/search.php发现存在该标签的页面。  
![image.png](https://shs3.b.qianxin.com/butian_public/f6446347e21a6a51a57c8afbbaf1a5e817ac63905e319.jpg)  
触发流程如下：  
携带payload访问search.php -&gt; showlabel() -&gt; fixed() -&gt; showcookiezs() -&gt; sql查询造成注入

利用前面发现的绕过非法字符过滤方法，利用括号构造一个注入语句成功触发延时。  
![image.png](https://shs3.b.qianxin.com/butian_public/f1736065c9f1907d3a37d8e73bac5f9140c36b0abb284.jpg)  
经过测试，获得可以回显结果的注入payload，并通过注入漏洞获得管理员的密码MD5。  
![image.png](https://shs3.b.qianxin.com/butian_public/f91400202c1256f73a347b3b9279dd0b2e2baf2fd4ac5.jpg)  
因为权限校验部分只是使用如下代码进行，仅对比了cookie中的pass与数据库中存储的是否一致。  
![image.png](https://shs3.b.qianxin.com/butian_public/f721006ac334c5f9ef7e3f6e8a5cf2809acb4f4c4ba1e.jpg)  
则在cookie中添加`pass=21232f297a57a5a743894a0e4a801fc3;admin=admin`即可登录后台  
![image.png](https://shs3.b.qianxin.com/butian_public/f952961549549b674adbeee2fce6ba6bab877b893aaab.jpg)

总结
--

其实从前面的代码中能看出来这套系统还是有一定安全角度的考虑，编写stopsqlin()对post、get、cookie中传递的数据进行危险函数名的过滤，同样使用addslashes()、htmlspecialchars()对引号、斜杠、尖括号等进行过滤，引发注入问题的主要原因还是开发者为了方便，给siteconfig.php等文件开了后门，当路径中存在以上文件名时就不会触发stopsqlin()，导致可以使用没有引号的sql语句进行注入。

后记
--

### strpos()绕过

关于strpos()绕过可以利用php弱类型，比如在本次审计的cms中就存在一处文件写入点，因为开发者安全意识在线，使用了严格比较`!==`，导致无法进行绕过。但是这里因为使用了黑名单方式进行阻拦，因此在apache中间件情况下，是还有可能通过上传`.pht`和`.phtm`等后缀，来上传等效解析为php的恶意文件。  
![image.png](https://shs3.b.qianxin.com/butian_public/f521905e521823c020378d2bc2a5ec5d707ca8d60cf0a.jpg)

```php
if (strpos(strtolower($title), 'php') !== false) {
    showmsg('只能是htm或css这两种格式,模板名称：后面加上.htm或.css');
}
```

那么我们可以尝试对这个代码做个小改动，将`!==`修改为`!=`，来体现绕过的技巧。

```php
<?php
    $title = $_GET['name'];
    if(strpos(strtolower($title),'php')!=false){
        echo "上传失败，非法后缀";   
    }else{
        echo "上传成功，文件名为".$title;

    }
```

可以看到此时因为文件后缀包含php导致上传失败  
![image.png](https://shs3.b.qianxin.com/butian_public/f665456200afc7a5356f5a850a62c3a3d5c9a790b1cf4.jpg)  
但是当修改文件名为`php1.php`，上传成功了。可以看到虽然上传的文件依然为php后缀，但是已经成功绕过了strpos()的判断。  
![image.png](https://shs3.b.qianxin.com/butian_public/f964560985201ba7f90dc751802b87c80f4689593dfe9.jpg)  
因为在文件名起始位置添加了php，strpos()执行的结果为0。  
![image.png](https://shs3.b.qianxin.com/butian_public/f97754539d5a5601d868d1e389679dc34468785b048ff.jpg)  
我们能看出端倪，这里就是因为php的弱类型引起的问题，在对比strpos()结果时使用了松散的比较，导致在对比前先将strpos()的结果数字0转换为了false，令比较`==`成立。  
![image.png](https://shs3.b.qianxin.com/butian_public/f705021846b860399ba78a6b0b035ab53134d860f6bcb.jpg)