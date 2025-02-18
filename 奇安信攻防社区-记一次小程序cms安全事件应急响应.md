**记一次小程序cms安全事件应急响应**

1、安全事件发生

​ 2021年11月16日，上级发来不良检测记录，内容包含为某站点存在涉赌违规内容，该站点为基于ThinkPHP 5.0.10框架的小程序管理系统，下面以xcx.test.cn作为代替

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2570fdd08b5e8e56262edbc500d80e11c241f1f1.png)

​

​ 经过对比原始版本的源码，以及命令ls -alh确认，index.php于11月15日23:16分出现文件修改，确认该web服务器遭到非法攻击。

![image-20211119223349447](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1e229eafec8063506fd5704b095963333e893fc2.png)

后果：修改内容为在head内添加了meta标签和修改了title标签，标签内容为非法内容，搜索引擎的爬虫在爬取该站点时会爬取meta标签的内容，那么用户在百度搜索关键词时，会检索出不良内容。

![image-20211119223357499](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d66d0ddafa926eba9b91c0b0265ec07ed7a9c7fc.png)

2、安全事件溯源

2.1 暂停服务

首先进入宝塔关闭Apache与MySQL服务，其他途径告知用户系统正在维护

![image-20211119223414083](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6a33508307bb20887f97f601ad72b22cb8dcc652.png)

2.2 保存现场环境

​ 进入到宝塔的网站管理界面，点击被入侵站点，点击备份站点（数据库同理备份）。

因为备份文件过大，则把全部备份通过宝塔的“腾讯云COSFS 2.0”插件，转储到cos里，在通过访问cos下载备份文件。

![image-20211119223429399](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3870bc0a645ac197df1c85782d0f0d9ffa831863.png)

![image-20211119223433727](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9960807b62f723ebf4030647f963fae0ee3ce839.png)

2.3 提取WEB日志

ssh连接进入服务器，提取宝塔的web日志，路径/www/wwwlogs/xcx.test.cn/ ，提取xcx.test.cn-access\_log与xcx.test.cn-error\_log到本地

![image-20211119223438566](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-79cfcdebeecb0c3c7ee1fe781423a51d8c040b23.png)

2.4 find命令检索被文件修改

​ 使用find . -mtime -300 -name "\*.php"检索/www/wwwroot/xcx.test.cn/网站目录下被修改过的PHP文件，以快速确认webshell落地路径

![image-20211119223441983](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-926f8c4b65664fba7380095719ce6bfcdd2210dc.png)

从图中可以发现，在十一月份分别不同天数，有三个文件被添加或修改过，对比原始源码发现，除了index.php原本不存在图中另外两个文件。

2.5 分析webshell文件1

路径：/public/plugin/PHPExcel/PHPExcel/CalcEngine/index.php

![image-20211119223448891](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c8623760dc0556df08e2ff446e6712d80ae68f12.png)

分析该文件，总共分为两个部分

s函数：对$dapeng的字符串进行rot13解码

m函数与get1\_str函数：该函数作用是eval执行PHP代码，通过组合变量$dp和$dapeng1成新的系统函数，把rot13解码的字符串，从十六进制转换为字符串文本（既为PHP代码）。

PS：该图为十六进制转码后的PHP代码

![image-20211119223457267](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c0a739e06eef752a96dc73884ee651b9836e213a.png)

从图中可以得知，这里的变量file\_path是上一层的index.php的$file\_path，此处先备份网站首页index.php另存为index.bk.html，并把index.php的权限修改为0666，既所有用户可读可写权限，猜测此处目的防止因为权限原因无法修改首页。

2.6 分析webshell文件2

路径./public/webuploader/server/preview/dd887179e09b2326595305d8dd475763.php

![image-20211119223509423](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-85e9ef93d39e89ac5b5b62e14a71bc11ae325213.png)

分析该文件，可以得知是一个PHP远程文件包含+eval执行

Ps:该文件在后面日志分析得出，该文件为黑客第一个上传的木马。

从该路径/public/webuploader/server/preview/可猜测，黑客应该是使用webuploader下的fileupload.php或fileupload2.php或presiew.php里其中的一个php文件的上传漏洞，把webshell上传到服务器

![image-20211119223520486](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-19bd3ef256cecf35cbef8e9143d7d7ae99380fd2.png)

2.7 分析access日志之攻击手法

从access日志来看，该web站点一直由来自不同地区，不同国家的IP地址用web漏洞扫描器一直进行扫描

![image-20211119223526138](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2972d74795749439991a81406fe1f00a291cde8.png)

![image-20211119223531095](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-55738664de86ebfb1abe34d7440ce4484bb4d448.png)

由于刚刚提到webshell文件2的路径在webuploader/server下，而该文件夹下恰好有三个相关的上传文件，我们分别在access\_log中搜寻fileupload.php或fileupload2.php或presiew.php

结果均为无结果：

![image-20211119223550599](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-360765a71d931b622003750b0706570d1e7d3b6a.png)

![image-20211119223554727](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-842c23efc22921c9a4b220aa20d98a428b58b333.png)

![image-20211119223559202](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ef6c5778e0703c7647472fba3b0a2792173de816.png)

我们猜测，黑客在使用presiew.php的原文件名应该为preview.php，通过对比1月份的备份包与本月的备份包，其中得出1月份的preview.php与presiew.php的文件内容完全一致，可以确认是被黑客修改了名称，preview.php内是有关文件上传的PHP代码。

![image-20211119223625383](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ac5d48f144e9c1c8f35f95f3f73b5d92d9382c7.png)

那么回到vscode继续检索preview.php得到结果

![image-20211119223632042](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3ac7d24bd82ce7ea1028221f48ea7160e048fe20.png)

结果还是比较多，在精确搜索一下，只显示有200回响的

![image-20211119223636730](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9714b24b3c1d1b2d8e482725c0d3d79ed33d33d8.png)

成功筛选出4条记录，分别是

![image-20211119223642606](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-99150676ea1123e57293bfbe31580c61a97fcfeb.png)

![image-20211119223646742](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f3cc7f4fb03bb2cad7036bb219d2a0dc3ea467ca.png)

![image-20211119223650266](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a1b3a0f1fc7e0b5239ea19464089470cd7513513.png)

![image-20211119223653782](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3dc8ecf9836fa5f58ad51c658a51380be87f526c.png)

其中第1与第2条IP地址均为浙江省金华市婺城区 电信

![image-20211119223658434](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4270b4ad050194412d7e4966bc6a8b2af8a36266.png)

第3条与第4条IP地址均为深圳市腾讯云

![image-20211119223702562](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b1833aafee0f1a18276232cbf2bba62250b62a3.png)

然后对比user-agent，第1、2条为

![image-20211119223706506](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2557c37bc20ee464a1a47b34b2c3a8070a86cd71.png)

第3、4条为

![image-20211119223711222](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2882376cd686546faa2bf61bce6a4668ce5da60f.png)

请注意上述两条USER-AGENT都是非常旧的系统和浏览器版本，理应不符合该系统的对象用户，可初步判别均为异常流量。

通过相同UA头检索，发现UA为”Mac OS X 10\_15\_7”的主机，正在不断的从2021年6月21号到2021年11月16日，一直使用爬虫/web扫描工具进行扫描测试。

![image-20211119223717142](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8ba80fc801f64c905b1cfacbe915d7691c88a9a1.png)

可以看出图中的相关日志，该UA都在同一天访问有关sql数据库的管理页，通过检索可知，有关“Mac OS X 10”的UA有6838条，可以判断是爬虫工具。

继续检索UA头为"Mozilla/5.0 (Windows NT 6.1; rv:25.0) Gecko/20100101 Firefox/2X.0"的相关行日志共两条，请注意下面两条日志的时间与webshell木马的dd887179e09b2326595305d8dd475763.php时间。

![image-20211119223726402](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-23690c0ebfc687c77dd09fbfcd4f479e23305cb2.png)

![image-20211119223730110](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca6675e5dcb5b9252154f39a9a6816e27ed272bd.png)

![image-20211119223733858](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cc75276965bc06dd8a71330c24a6acb6d379a655.png)

从上图中可以看出，第二条日志的时间与webshell的修改时间完全重合，且同时说明在11月1日该站点已经被渗透，

跟随这个UA继续检索日志，又发现访问了另外一个木马CalcEngine/index.php

![image-20211119223739166](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-89440feb65c272aaaf73c826825bdfe4d2aa69cc.png)

故判断UA为“Mozilla/5.0 (Windows NT 6.1; rv:25.0) Gecko/20100101 Firefox/2X.0”就是黑客攻击我企站点的UA。

在这一些不同行的日志里，除了IP归属地为浙江省金华市婺城区 电信外，其他的IP归属地均为国外，所以金华市的这个IP很有可能是黑客的真实IP地址。

总结：黑客使用preview.php分时段上传了木马dd475763.php与CalcEngine/index.php，然后在11月15日23点16分通过dd475763.php修改了public/index.php

2.8 分析access日志之留种后门分析

根据来源地址为dd88719e.php，查找referer: <https://xcx.test.cn/webuploader/server/preview/dd887179e09b2326595305d8dd475763.php> 查找出以下几个后门

![image-20211119223749242](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-59fb2daf12ece39b42e96147b62dcf80636401a2.png)

（1）111.php

![image-20211119223753210](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9472d7c6ed40fd4be9c4aff637530513873cd0ec.png)

（2）banner3.php（经典大马）

![image-20211119223757364](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ac5710c40851212285b5be66f9e8aab1df5757b.png)

![image-20211119223807770](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f9c5ae695a8145f227d8230041d4430f44b14041.png)

（3）picture3\_6.php（此处与preview.php文件内容一致）

![image-20211119223817919](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-28076678776e3630c2954f36a747acc48684aaa1.png)

![image-20211119223823922](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ef8d9e2c346cd71a44cb7f07e471d5cea5724a84.png)

（4）config.php（WebShell）

![image-20211119223829781](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-744e095fad6366bf9585f9fe272859168a4480a4.png)

![image-20211119223838029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b895727b0f2cc570bf3eba8e4535ffe14f2b189f.png)

通过$\_REQUEST\[admin\]传参到eval函数，实现命令执行。

![image-20211119223846897](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aefb7fce14c23bb4737f700dd9c47bb95da7728c.png)

使用D\_SAFE补充验证

![image-20211119223853813](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ed68c3f95db5001b286639fe432fd2c2bc466433.png)

2.9 分析preview.php

![image-20211119223904521](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-88d381ac9619e2d68a5a58d9a334d80822a2dbb9.png)

1）首先该文件的首行应该是if判断session是否为管理员，但在该文件内并没有写校验，故存在越权漏洞。只要知道路径，任何人都可使用该php来上传文件。

2）存在上传文件后缀无限制

![image-20211119223912081](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ae2d9113ef015314aa04a9fd6aaced32ccd8e23e.png)

从图中可以看出，通过正则表达式，变量$base64是文件内容，变量$type是文件后缀，从红色框住的if语句里，完全没有任何的过滤，故payload为data:image/php;base64,PD9waHAgcGhwaW5mbygpOz8+

3）不校验上传文件内容

![image-20211119223917029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8741e12cb05ecbcd483a5f3d7c419b9d54f652e4.png)

从截图得知，上传后的文件名是文件内容的md5值，而代码中也不做文件内容检查，即可直接写&lt;?php phpinfo();?&gt;

2.10 preview.php攻击手法复现

![image-20211119223921389](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-290b98651255ce70958324850db44b3568c0f25e.png)

![image-20211119223928913](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-00b675054c323c10bf7f3c0055e41024a85f9963.png)

![image-20211119223934765](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92a766c830af817161670d224dc6dafabc1dc946.png)

复现完成

三、修复建议

1. 过滤presiew.php文件内上传的文件后缀名传参，并加入session校验。
2. 对webuploader/下所有文件进行审计后发现，fileupload.php和fileupload2.php都有文件上传漏洞，故建议对上传文件进行过滤
3. 对上传目录./preview/和./upload/禁止执行php。
4. 禁止非大陆地区的IP地址访问。