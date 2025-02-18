过程
==

这里在挖掘某项目的时候，通过信息收集发现了一个站点，这里为内部系统，访问的时候直接跳转进入到内部的http://x.x.x.x/home，但是却因为没有权限而提示非法操作：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e60f53c0677c6e716a2017d66d0e6a3c39d5e16a.png)

那么这里便通过F12对其中的js进行审计，其中发现了/login的一个接口，这里拼接后发现跳转到登录处，其中直接将管理员的用户名和密码写在了上面，这里F12将密码处的password属性删掉，发现还是弱口令：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a1469d9b3dd5067a3a831a23fe7edb32e696e1ac.png)  
这里点击登录后，如愿进入后台。这里在开心之余，便想着能不能在管理后台找到其它的漏洞，提升危害，于是这里便对内部的每个功能点进行点击抓包，其中在一个功能点发现了端倪。这是列出某门店排行榜的功能点，其中的busiModelList参数引起了我的兴趣。一开始它的参数值是空的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1b6de4999126cb1d9590f13e76ea2dd79a135ba3.png)

然后自己添加上参数值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2ef5922ec056c69a44c11689be2790faf2386b0e.png)  
在我加上单引号的时候，却开始报错：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1a4f2a56b72c5e2f302dc15b02585266cfd7e0e8.png)

然后再加上一个单引号又成功了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-47a915c910d8d93ea62407a045300a09ef0d7ad9.png)

我顿时虎躯一震，莫非，这里存在SQL注入？

那么这里开始fuzz数据库类型。其中带上注释符，--+不行而#却可以，这里数据库类型初步判断为MySQL

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-93e8092ea0f90e0b56ca27043f20b2d581a42d65.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-9f9577ef6e0e22a5cffe7891e55e5deb00d04dae.png)  
这里额外插入一下判断是否为MySQL数据库的小tips（这里采用别的站为例子来说明）：  
**第一种证明方法：**  
用内联注入来证明这里是MySQL，因为内联注入是MySQL特有的注入：  
这里先用’))来闭合，然后对后面的数字0进行注释，`/*0*/`，成功无数据：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ae25e9b8b76dbcb704ac05ff68c905d34875aa4a.png)  
可是这里进行内联注入，`/*!0*/`，成功执行后面那个数字0，成功导致交易进行错误的报错：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d8b6228c0b4ee8498a34466167bbe884aaf4ea2a.png)

成功证明这里可以内联注入，所以这里为MySQL

**第二种方法：**  
mysql在运行+号运算的时候，会将数字加起来不管是字符类型还是什么

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3b4e450a1d24303a9286e6d1dffbf957159bbc58.png)

像这里system参数在置空也就是我所认为的False的情况下也会返回数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-117651875e26052b1e4965c02937f8c92b8604d3.png)

因为都是字符串所以加起来等于0也就是False返回了数据,跟上面那种置空的效果一样

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f7add98dbafca9e477b465664477e81d2d2912f5.png)

那么这里后端的SQL语句大概如下,最后结果是0所以也返回了数据  
`SELECT xxx from xxx where xxx=xxx and dddd=dddd and system='jgxcl'+ database() +'a'`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0c8fc596760c3d3fb1cdf6f02dd8d1f0a1df6308.png)

但是把最后的`+'a`改成数字的话,这样的结果最后就是返回数字就不会正常的返回数据  
`SELECT xxx from xxx where xxx=xxx and dddd=dddd and system='jgxcl'+ database() +'1'`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-108216be36c0bf58bccf372288392d064c5ce719.png)  
跟填1同等效果

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7c6c86621e7e79108e04a2bcd918a1ba71f33b3e.png)

那么这里重新回到这个站，其中初步判断为MySQL后，这里我两眼放光，心中已经按捺不住的兴奋了。好久没在src碰到SQL注入了，今天在搞活动的时候却给我碰到了，真是好运来。然后这里只需要判断有无waf，如果没waf就可以直接一把梭了。正当我幻想着终于又能疯狂星期四的时候，这里却直接当头一棒打断了我的幻想。经过fuzz后，发现这里不仅用了阿里云waf，还有他们自己的代码层防御，真是雪上加霜。  
像这里0 and 1虽然没被阿里云waf拦截，但是却被代码层防御了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c6770f674e99f639afac73fb11c52dba3982e852.png)  
然后一波未平一波又起：这里带上`sleep()`函数直接被阿里云waf拦截：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-11259744abd9b674479aba64b01bd13a9ac65248.png)  
其中代码层防御的绕过还算简单，像`and`换成`&`就能绕过了（功能不同是这个符号是与）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f80fc1c2ee508d40be45688669883bda2beafef6.png)  
可是阿里云waf想绕过确实是要费点功夫。不过功夫不负有心人，这里最终用hpp传入多个同名参数+多行注释符/\*\*/成功绕过：  
注：HPP传入多个同名参数默认是.net环境可以，所以.net 环境下绕过一般可以采用hpp（即基本在windows服务器环境下可以使用绕过，linux一般不可以，但是也都可以试一试）

然后就是构造出true跟false两种状态，这里使用exp(1) 跟exp(710) 配合if ，注: exp(710) 在mysql会错误，这里1=1返回成功  
`'& if(1=1,exp(1),exp(710)) &'1`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7efe12812757b527b8d62801c9e972b5ff2b609e.png)

1=2页面错误  
`'& if(1=2,exp(1),exp(710)) &'1`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4ad49643e662ce74a98345dece1a53ef8581ba08.png)  
最后通过substr一位一位获取ascii值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2a6303c110a01bc754b794bb82295f736b53f82e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-51cf6f309985604b6431e536c9cfde3fc897b770.png)

脚本
==

这里写个脚本：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d02495acfe4cb3df40333782faa6a955dc714041.png)  
关于脚本，其中需要注意的是这里因为用的是hpp传入多个同名参数绕过，即有多个相同参数名，不同的值。那么这里不能像往常一样**"busiModelList": "……"，"busiModelList": "……"**这样列出，这样它最终传入的只会是最后一个参数值。这里的解决方法是提前用Tuple元组依次存储参数值，然后传递给参数即可。这里也不能用{ }，即dictionary，因为dictionary无法包含duplicate key，而且dictionary是无序的，所以无法满足要求。

然后这里写个proxy可以使用burpsuite对该python脚本的post请求抓包进行查看调试等等，其中如果遇到目标站点是https的，需要在requests.post处多写个**verify=False**。