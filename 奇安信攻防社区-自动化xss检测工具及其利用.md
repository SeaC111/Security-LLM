**前言**  
XSS注入漏洞又称为"跨站脚本攻击(Cross Site S cripting)"，为了不和层叠样式表(Cascading Style Sheets,CSS)混淆，所以将跨站脚本攻击缩写为XSS。XSS注入攻击的原理其实和sql注入攻击的原理很相似，攻击者将恶意的S cript代码插入到网页中，当正常用户浏览该页面时，被嵌入的恶意S cript代码就会被执行，从而达到恶意攻击正常用户的目的。

**XSS分类**  
跨站脚本注入漏洞是由于WEB服务器读取了用户可控数据输出到HTML页面的过程中没有进行安全处理导致的，用户可控数据包括url、参数、HTTP头部字段（cookie、referer、HOST等）、HTTP请求正文等。

> （1）反射型XSS：攻击者输入可控数据到HTML页面中（通常是url），所以输入的数据没有被存储，只能在单次请求中生效。  
> （2）存储型XSS：攻击者输入可控数据到HTML页面（通常是POST表单：评论、留言板、登录框等），所以输入的数据会被存储到数据库中，由于数据经过存储，可以持续被读取出来，攻击的次数比反射型XSS多。  
> （3）DOM-XSS：攻击者可控数据通过J avaS cript和DOM技术输出到HTML中，其实是一种特殊类型的反射型XSS，基于DOM文档对象模型的一种漏洞。

**XSS危害**

> （1）流量劫持，利用木马修改浏览器不停的弹出新的窗口强制性的让用户访问指定的网站，为指定网站增加流量（也就是可以为其他网站引流）  
> （2）获取用户cookie信息，盗取账号（普通用户、管理员等账号）  
> （3）篡改、删除页面信息（钓鱼操作）  
> （4）配合CSRF攻击，实施进一步的攻击，控制被害人的电脑访问其他网站

下面介绍几款好用方便的XSS自动检测工具，仅用于学习和研究，不可用于违规途径。  
**一、XSS-LOADER TOOLS**  
**（1）工具连接---GitHub**  
`https://github.com/capture0x/XSS-LOADER/`  
**（2）简介**  
XSS-LOADER TOOLS：XSS 有效载荷生成器-XSS 扫描器-XSS DORK FINDER 的多合一工具

> 1.此工具创建用于xss注入的有效负载  
> 2.从参数中选择默认负载标签或写入负载  
> 3.它使xss注射，带Xss Scanner参数  
> 4.它使用Xss Dork Finder参数查找易受攻击的站点url

**（3）安装**  
克隆文件到kali上  
`git clone https://github.com/capture0x/XSS-LOADER/`  
注：我是先下载到windows上，然后再通过curl下载本地的压缩包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3ec404be6e46f95a01e357aba4375fffd89bfa2d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3ec404be6e46f95a01e357aba4375fffd89bfa2d.png)  
移动到 XSS-LOADER目录下  
`cd XSS-LOADER`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-64eeb4071188d3945953937221c35b9dc0cfce08.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-64eeb4071188d3945953937221c35b9dc0cfce08.png)  
安装依赖包  
`pip3 install -r requirements.txt`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e6a7cdb7d0476c08fbb15544f7d9266f9c88534d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e6a7cdb7d0476c08fbb15544f7d9266f9c88534d.png)  
**（4）运行使用**  
运行文件  
`python3 payloader.py`  
就会出现一个选项界面，有如下九个可以选择的模块

> Basic Payload默认参数设置为：&lt;S cript&gt;a lert(1)&lt;/S cript&gt;  
> Div Payload默认参数设置为：&lt;div onpointerover='a lert(1)'&gt;MOVE HERE&lt;/div  
> Img Payload默认参数设置为：&lt;img src=x o nerror=a lert('1');&gt;  
> Body Payload默认参数设置为：:&lt;body ontouchstart=a lert(1)&gt;  
> Svg Payload默认参数设置为：&lt;svg o nload=a lert('1')&gt;  
> Enter YOUR Payload默认参数设置为：对用户写入的有效负载进行编码  
> Xss SCANNER 选择该选项后会跳转让输入你要验证的url，然后再选择payload  
> Xss DORK FINDER 选择该选项后会跳转让你输入你要验证的url  
> Exit 退出程序

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e9a1276d628feb7f8792df1a87dcf8ad8376ce13.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e9a1276d628feb7f8792df1a87dcf8ad8376ce13.png)  
**（5）工具使用示范**  
构建一个靶机环境，只用于学习，不作任何违规操作  
构建一个小的环境用于验证是否存在XSS注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dd30bb2cd055d22d1bb3e03bf9829b6b46dd596e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-dd30bb2cd055d22d1bb3e03bf9829b6b46dd596e.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4972c5720058d6268a8299fc0d32d887db78abac.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4972c5720058d6268a8299fc0d32d887db78abac.png)  
运行工具，选择模块1（`Basic Payload`），跳转后再选择模块3（`url encode`）  
个人认为前6个模块是生成payload的，第一次选择的是payload的类型，第二次选择的是payload的变形，比如下面的url编码类型的payload，还有其他变形的方式（该模块默认是`<S cript>a lert(1)</S cript>`）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b042fad951b6d5bc055cebc7525eb70e663ff45.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2b042fad951b6d5bc055cebc7525eb70e663ff45.png)  
**原理分析**  
通过选择模块参数，然后将参数赋给函数`pylds(deger)`，从而执行对应参数的功能，并且返回新生成字符串  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-77c25043b1770c6519c31829652350fca7332de8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-77c25043b1770c6519c31829652350fca7332de8.png)  
**使用模块7（Xss Scanner）**  
输入需要验证的url后会跳转出来如下的7个payload模块列表  
前5个不作解释，第6个`MIXER PAYLOAD LIST`是混合payload列表，第7个是用户自定义的payload文件路径  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ca59e3bbbed52682d9060a6d6857c455066fdd3f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ca59e3bbbed52682d9060a6d6857c455066fdd3f.png)  
**原理分析**  
选择模块参数，然后将模块的对应payload文件赋给choose  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e8ddfd6ac6843247f3b74100b528ab088ea13b5d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e8ddfd6ac6843247f3b74100b528ab088ea13b5d.png)  
把payload跟url结合在一起，并且通过`get_user_agent()`获取浏览器信息，赋值给header和req参数（方便请求网页），如果payload出现在req.text的文本中，则输出成功的payload，并且记录到`vulnpayload.txt`中，如果没有出现在req.txt文本中则输出TRYING尝试中。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e5beb12fc80332bfb630d69973365d3e410b5628.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e5beb12fc80332bfb630d69973365d3e410b5628.png)  
这里我们选择第1个模块列表（`Basic Payload List`）  
红色的是显示比较可能存在的payload，直接复制到网页上验证是否存在即可（可能误报）  
蓝色的是显示正在尝试的payload  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-69ee97957bd12fac8da36fca3293be3f18296a87.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-69ee97957bd12fac8da36fca3293be3f18296a87.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-51e804d271a9d4ae3c8e137b25e4ff70e67308fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-51e804d271a9d4ae3c8e137b25e4ff70e67308fc.png)  
最后所有的扫描结果会保存在该目录下的vulnpayload.txt中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9d325e3d1f8427002c91872605ecc3f1fb28e958.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9d325e3d1f8427002c91872605ecc3f1fb28e958.png)  
**二、XSSMAP**  
**（1）参考链接：（工具连接---gitee）**  
`https://gitee.com/Luckyzmj/xssmap/tree/master`  
**（2）简介**  
XSSMAP：检测Web应用程序中的XSS漏洞  
（支持 POST 和 GET 请求方式，支持 Cookie、Referer、UserAgent 字段的参数注入检测。）  
功能

> 1.支持自动 urlencode 编码  
> 2.支持自动 unicode 编码  
> 3.支持自动 HTML 编码  
> 4.自动灵活替换 ()'"  
> 5.智能 Payload 组合

**（3）安装**  
其他安装方法的可以看上面的参考链接，我是直接下载到本机，然后curl从本机下载到kali上  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c652998a797ad511f354e2b4788a599d91560662.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c652998a797ad511f354e2b4788a599d91560662.png)  
**（4）运行使用**  
`Xssmap.py -h 可以查看可以运动的参数`

> -u url 目标网站的url  
> -p parameter 可测试的参数  
> \--version 显示程序的版本号并退出  
> \--cookie Cookie 设置http头部的cookie值  
> \--referer Referer 设置http头部的referer值  
> \--ua Useragent 设置http头部的useragent值  
> \--data Postdata 通过POST发送的数据字符串  
> \--timeout Timeout 设置连接超时时间  
> \--proxy Proxy 设置代理  
> \--random-agent 使用随机选择的HTTP用户代理头值  
> -v 设置详细模式

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8a9d1dee0ec2145a2d37d8190c53f5aa132a1e8b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8a9d1dee0ec2145a2d37d8190c53f5aa132a1e8b.png)  
**（5）工具使用示范**  
`./xssmap.py -u url 对url进行一个自动化的XSS检测`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0bf6cee7688f2367dcc589ae518fa6f33fad406.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0bf6cee7688f2367dcc589ae518fa6f33fad406.png)  
返回的payload在这两个位置，但是我这里显示不出来，我用windows的虚拟终端测试如下图所示  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0d2fde57caa327afaf98737db9c7e6c4d1570674.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-0d2fde57caa327afaf98737db9c7e6c4d1570674.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-76e9afe7a7294b5f3c21e7ee3da26a558e2de3de.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-76e9afe7a7294b5f3c21e7ee3da26a558e2de3de.png)  
复制payload到网页上测试  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-21e9a827530e837f8d00479147005ee2de416793.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-21e9a827530e837f8d00479147005ee2de416793.png)  
**总结**  
本次的实验以学习和研究的目的，所实验的环境为自己搭建的环境，不作任何违规的操作。作为OWASP TOP10中的漏洞之一，XSS注入漏洞在web安全中还是有很多案例存在，建站人员应该提前做好防护措施。可以在服务端对用户可控数据进行过滤和编码操作，如将所有on事件,S cript等关键字进行过滤，将所有&lt;,&gt;,”,’,=等特殊符号进行实体化编码或百分号编码便可以修复。