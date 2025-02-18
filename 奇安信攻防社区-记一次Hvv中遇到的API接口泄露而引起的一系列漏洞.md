前言
==

Hvv中的一个很有趣的漏洞挖掘过程，从一个简单的API泄露到一系列漏洞。这次的经历更让我体会到了细心的重要性。  
这是第二次编辑文章了，刚编辑了一个小时的文章不小心X掉了，心态差点崩了。

挖掘起始
====

Hvv中拿到了一大堆的资产，有IP和URL的，我一般会先去手动挖掘已经给了的URL资产。面对众多的URL资产，怎么下手呢，我通常会选择去跑一下Title，然后根据Title来选择软柿子捏。  
比如下面某个业务应用系统，定位好了，就开始手动测试挖掘了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9883a7852effe80d624c68892e178ad42f2334a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9883a7852effe80d624c68892e178ad42f2334a1.png)

打开URL进入这个业务应用系统，首页就是登录页面，见到这样的无验证码登录页码，直接起Burpsuite固定用户名字典然后爆破弱口令尝试。尝试了5分钟的弱口令爆破无果后，选择转换攻击思路。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-15a49cb4f77473f892df02c595f2a1b8dc348934.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-15a49cb4f77473f892df02c595f2a1b8dc348934.jpg)

转换思路
====

转头去看下URL:`http://fxxx/wxxx/login.html`，感觉可以尝试下是否存在目录遍历的问题

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-10ec5bfb01905c9db02909d5d363f9feb1475a68.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-10ec5bfb01905c9db02909d5d363f9feb1475a68.jpg)

于是转到上层目录查看的时候`http://fxxx/wxxx`，发现页面有一个渲染的加载的过程，然后才跳转到login.html登录页面，而且`/wxxx`目录看上去又像一个未授权的页面。于是Burpsuite在`/wxxx`一个一个放包，观察转到`/wxxx/login.html`过程中加载了什么东西。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fdf8e716e2252aa0b2a37e8bdbcb283e7fc074c7.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fdf8e716e2252aa0b2a37e8bdbcb283e7fc074c7.jpg)

通过Burpsuite一个一个放包发现了一个特别的API调用接口

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fe66ffc18b238fc4879d28b5dfab3d1ac97d05ca.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fe66ffc18b238fc4879d28b5dfab3d1ac97d05ca.jpg)

在这个API接口之上再往前跨目录，直到回到根目录`/DFWebAPIServiceHT`下发现是一个接口数据库系统

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-71bf42819ebea0c377a750fed9ca09d75aa518ce.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-71bf42819ebea0c377a750fed9ca09d75aa518ce.jpg)

该系统存在非常多开放的接口，并且每个接口下面，还有详细的调用参数以及调用方法，过多的接口数据就不放了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1fbe5d7d244b9bc59a81fed78bd6f0b095fbc154.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1fbe5d7d244b9bc59a81fed78bd6f0b095fbc154.jpg)

因为进入该业务系统后是一个登录页面，于是我直接去寻找是否有用户信息的一些相关接口开放。找到了如下接口

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7da4fc2ab4830e59cfb27c08c4efb13ae077fbc0.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7da4fc2ab4830e59cfb27c08c4efb13ae077fbc0.jpg)

通过`/SXXXX_User/get`接口可以获取到用户名相关的Json数据，其中的user\_id键值就是用户名  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dcb233bededcfe5c2b8c4351d7273b0735469dcb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dcb233bededcfe5c2b8c4351d7273b0735469dcb.jpg)

通过该接口获取到了很多的用户名，这些用户名的设置确实刁钻，例如pte,dpsas等用户名，这是难以简单猜解到的。通过收集获取到的这些用户名，再次进行弱口令爆破。这里的登录页面对表单中的用户名密码进行了Base64的加密。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a4c21419378a42bbf11b0a8550c34a9900b79d23.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a4c21419378a42bbf11b0a8550c34a9900b79d23.jpg)

有一个很简单的方法，将收集到的用户名和简单的几个弱口令全部base64编码后放到txt里，然后导入Burpsuite的Simple list模式的payload中。这是比较简单的方法。  
我这里用的是[BurpCrypto](https://github.com/whwlsfb/BurpCrypto)插件来定义Execjs来将两个表单项在爆破过程中同时进行base64编码。需要我们定位到加密或者编码的js位置，由于用的是base64编码，图简单，用上面字典的方法即可。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7dcfd48c529cc4d2738f166417ba5c34b3723187.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7dcfd48c529cc4d2738f166417ba5c34b3723187.jpg)

柳暗花明
====

使用上述方法一顿爆破后，真的爆破出来了一个普通用户弱口令123456。拿着这个弱口令，我登入了系统，发现该系统只是一个外壳，里面还有很多的分系统。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1deee6403252febee066e1068e1355174790c541.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1deee6403252febee066e1068e1355174790c541.jpg)

这让我非常的欣喜，我猜想这些系统的账号密码可能是互通互联的。经过测试发现，这里面只有两到三个系统可以正常访问，且账号密码并不都是互联互通的。其中有一个决策系统，通过刚刚爆破出来的用户弱口令是可以进入该系统的，且用户认证为灌区管理员，权限还是非常的低。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-abd6103c702d0669674580668e3add95bf537531.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-abd6103c702d0669674580668e3add95bf537531.jpg)

由于权限还是太低，只有两个没什么用途的菜单，翻找了很久，都没有发现可利用的地方，或者可以上传shell的地方，索性放弃拿shell。但是打开右上角人员设置界面的抓包中发现了有意思的地方，在人员设置中有一个修改密码的表单设置，虽然是`********`，看不到具体明文，但是在返回的包中是直接显示出来的。而且Get请求里有一个很有趣的参数就是id=用户名的这个参数。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cba20157c79f010237d18387c91dcc4bcb00c894.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cba20157c79f010237d18387c91dcc4bcb00c894.jpg)

也许我可以遍历之前用户接口泄露出来的用户名来尝试获取用户密码？  
有了这个想法后，我直接起Bp的爆破模块，来遍历用户名尝试，果不其然。  
这里没有鉴权机制，可以直接通过遍历ID用户名参数，就可以获得对应的用户密码。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-11ac6ec1a283ee3f62e47ca6783e4bb5550c4bb6.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-11ac6ec1a283ee3f62e47ca6783e4bb5550c4bb6.jpg)

通过上面的越权漏洞获取到了高权限的用户密码，如root，admin,xxadmin等。利用高权限用户登录后，发现后台多了非常多的菜单，然后查找下敏感信息，发现泄露了很多敏感信息，并且高权限用户是可以直接看到所有的用户密码的。

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f4e99d10819e13f00c255ab01640cfd33a07671a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f4e99d10819e13f00c255ab01640cfd33a07671a.jpg)

通过上述组合式的漏洞发现和利用，提了不少分。通过这次测试感受到了手测的魅力，还是非常的有意思的。其中这个接口数据库还有非常多的敏感接口，比如权限变更，文件上传，而且在此次测试中，发现了两个类似的API数据库，但是另一个利用价值不大，所以这里没写。

结语
==

总结下上述的流程，从一个跨目录的尝试到大量API接口的泄露再到垂直越权获取管理系统的管理员账号，再到后台敏感数据泄露。总之，就是在手动挖掘漏洞的时候，要注重每一个细节，尝试多种可能性，富有创造力的去将一些可能的漏洞点结合，这样能大大的增加漏洞挖掘的命中率。