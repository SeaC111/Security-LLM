环境搭建：
=====

使用phpstudy进行环境搭建  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678286609981-9f91e41b-94ba-4608-9770-6cc28fbaab8d.png)  
接着进入下一步  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678286623545-1a1a21dd-e772-4c10-8cc8-1c3daa0b391b.png)  
然后输入数据库用户名和密码  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678286660693-f28ca2fa-1c2d-4b15-be25-6bb65606420f.png)  
安装成功。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678286681132-db3a9f35-40e2-4422-a1df-c53980146b71.png)

代码审计
====

1.任意文件写入漏洞
----------

通过全局搜索，发现 xml\_unserialize() 对 parse() 函数进行了调用

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678287497672-4494c930-bb91-41af-9d91-e1449030d035.png)  
接着去搜索xml\_serialize()函数的调用情况  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678287517794-a033b3d3-e06c-4b61-9932-d98829dbe976.png)

在该处发现xml\_serialize()函数调用并且参数可控。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678287611785-37047f22-5fd6-4830-a96c-5d3cf458e065.png)

parse\_str()函数可以把传递的字符串解析为变量，也就是说这里传递过去的字符串可以当做参数进行使用。  
我们去跟进下该函数。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678287855626-2ad44c4b-a298-41d3-98ad-f9387a49a450.png)

大致看下该函数是用于加解密字符串的， $string 参数传入我们需要加解密的字符串，这里也就是我们上述可控的 $code ； $operation 默认为DECODE也就是解密字符串，而 $key 则为加解密的秘钥。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678287894468-2d5d460a-2e24-42fe-b929-c24f6d153543.png)

在这里 $code 这里可控，所以下面的 $get\['time'\] 、 $get\['action'\] 可控

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678287972569-51c82e15-45d0-4c4d-8e5c-8effd3ebed99.png)

在代码中判断我们传入的$get\['action'\]方法是否为数组中的其中一个，如果是的话调用该方法，并将$get 、 $post 以参数形式传递。目前可知 $get 、 $post 我们可控。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678288009444-1b0a40b8-b103-4b2d-9fa3-1e3639dda3b4.png)

接着发现 updateapps() 方法中使用 preg\_replace() 将我们传入的内容进行正则匹配替换并通过 fwrite() 保存到配置文件。而这里的 $post\['UC\_API'\] 是可控的，所以这里我们可以替换任意内容到配置文件中。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678288080736-22cab63b-7be9-49a9-aa2a-c904537a531a.png)

### 漏洞复现：

由前面的代码分析可知, $code 参数我们需要构造的内容要满足两点：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678288450253-66ad8100-901b-47e9-9757-f9b457392d23.png)  
1、$timestamp - $get\['time'\]&gt; 3600

2、$get\['action'\]=updateapps; 且要通过 \_authcode() 解码，所以我们这里要将 $code 的内容先进行编码这里 $code 传入加密后的内容，而 $post 的内容按照XML格式构造才能解析。  
POC如下：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328196225-a9581726-e554-44b9-829b-f26dd30dd453.png)

配置文件中已经被我们成功写入一句话  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678288532437-c8a3deea-6641-412c-a3b6-0f085155e597.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328227023-75c5dc3b-a9f7-4799-8f69-37303de982a4.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328176384-a49513cf-a2c7-46c2-bb57-a2706496239a.png)

2.任意文件删除
--------

全局搜索 unlink() 函数。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328342332-db56223e-52b3-4c39-b7a1-0281b4de8c1a.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328372700-dc6c4d33-d55a-4e79-8b12-9bbe70278af5.png)  
我们跟进该文件并向上回溯 unlink() 下 $file 参数是否可控，最终在代码中发现了该文件两个可控参数。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328471968-95fe9507-9967-4e27-b336-633901103ed8.png)  
在代码中的 $action 是我们可控的， $mlname 也是我们可控的，这里通过 $mlname 传入文件夹名并遍历出该文件夹下的文件，最终将文件名赋值给 $file ，可以在上述的 unlink() 函数中实现遍历删除文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328552316-19beed6c-cb25-4afc-96dc-7550616a544d.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678328586549-7403a603-8248-441d-a9ac-027d713ef13f.png)

### 漏洞复现：

通过分析，构造路由进行文件删除测试，通过上面代码过滤了 ../ ，我们通过 ..\\ 绕过该处过滤

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678330317767-220ab621-a1a1-45c1-aaf9-ba5144c648f6.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678330077952-993921df-8c60-4313-836c-d1374edb3baf.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678330232594-4fc87c7a-2190-44bf-b2f0-2595946ff4de.png)

3.前台XSS漏洞
---------

由于该系统并没有严格的遵循MVC开发模式去开发，大部分的前后端代码都写在一个php文件中，如下面我们看到的这个php文件。在该PHP文件中本应该是有权限校验的，并且该权限还是后台admin权限，但是这里的 $\_COOKIE\["UserName"\] 是我们可以伪造的，以致于可以绕过这里的逻辑校验。

### ![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678331080985-85926680-72b7-42d8-b66a-e6e9028d4a3b.png)

一些MVC框架大多都使用了模板，并没有直接传入参数而是通过模板渲染进行输出的，如果在传输的过程中没有进行过滤或者转义的话也会造成XSS。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678331140266-fa3599eb-94cb-41cd-acce-a74849545e54.png)

### 漏洞复现：

我们在Cookie中加入UserName值  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678331428608-425ca236-c3aa-4d38-b531-8a2333370435.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344121010-52ee5a7c-2dbb-4ebc-a514-3fcd3640bd31.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344140050-9334c6ae-5a12-49bc-a250-1d2fcee4f744.png)

4.SQL注入漏洞
---------

在全局搜索关键字时发现一处SQL语句参数可控的地方，发现这里的 $classname 参数是可控的

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344267693-2ce7643b-8d5b-482e-9ece-69053b0c7cdc.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344382720-6a5c994b-fa8e-4f49-ab17-d9f97d354f1d.png)

在代码开始处可以看出这里的 dowhat 参数可控，我们可直接控制该参数进入 modifybigclass() 函数。  
跟进 modifybigclass() 函数

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344493257-400a683d-548f-4e56-9e91-63c3ad4bbb8c.png)

在该函数中我们可以控制 action 参数走到存在漏洞的if条件中，而由我们上述说提到的这里的classname直接通过POST传入并拼接到SQL语句中，最后通过代码query()执行SQL语句。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344651462-565e2405-b9eb-48f4-a484-3643fd2cf442.png)

query() 中封装了 mysqli\_query() 去执行SQL语句。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678344715991-998361aa-e208-4bb2-8eb2-04c8bf30cd27.png)

### 漏洞复现：

从上面的分析可以看出这里的是存在盲注的，接下来我们用payload测试下

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678345436842-9685cc04-57f4-451b-8d7c-ffb8763e8377.png)

5.逻辑漏洞
------

在登录测试时发现该处登录页面有验证码和登录次数的校验

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678346065495-8a9c7b99-fcf5-41bf-a90f-dffdfb5b2f40.png)

首先通过 getip() 获取我们登录的ip地址，大概率这个函数是有问题的。将获取到的IP地址直接拼接在SQL语句中并且在15分钟内登录次数不能尝试超过10次，最后通过 checkyzm() 来进行验证码校验。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678346108661-721c1218-da2e-4a31-b98d-9e06f2ab998b.png)

getip ()函数中，可以通过XFF的形式获来获取IP地址，所以存在伪造的情况，而下面的 check\_isip()则会检测ip地址的合法性，这里防止了SQL注入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678346222280-98ec2d01-6e44-43a6-961f-654669fc509c.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678346263399-39be144c-d363-4e7e-a3d1-f6501fffb1d9.png)  
该函数通过判断传入的验证码与SESSION中的验证码是否相同而忽略了验证码可重用的问题。应该对每次提交的验证码进行删除并重新生成SESSION中的验证码，所以这里在设计时是存在逻辑缺陷的。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678346312766-4d8dd4f8-ff24-48fe-b99f-0ed071232f22.png)

### 漏洞复现：

我们根据IP的正则形式通过burp构造请求包来绕过登录次数的检测，抓取登录包

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678346364837-ab65e037-cffb-46c3-937d-edc18563f3ef.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678347336850-5459e078-53cf-4dd8-9301-0323a563052b.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678347434163-ac0fe185-d264-4db7-b4a9-71820577cf63.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678347476645-cdb11fb0-3c8d-4d22-9370-aebd9f04ebc8.png)

6.SQL注入
-------

全局搜索email from，发现一处sql语句。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368827574-2840638e-2bdd-4b93-a5f0-707f6d86dbb4.png)

发现这里的 $username 参数是可控的

### ![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368733597-3220b47a-5876-4de1-9880-b65e69e387de.png)

然后直接写入用户的登录次数和登录时间。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368811146-c851d350-2635-4e5a-ae2c-d06a34a671f8.png)

在获取 $\_COOKIE\['dlid'\] 的值，然后从表中读取passed 值、然后包含“，”字符。表示群发模式。这串代码主要用于邮件群发功能。没有对执行的语句进行过滤。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368773705-becf6a89-6e2b-4f9e-b701-8f0197239924.png)

### 漏洞复现：

SQL语句select中的条件变量不受单引号保护，可能导致SQL注入漏洞

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678348321287-9377c79f-f7e4-45a8-884f-dc2f7c44afc2.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678348307029-43b6d221-7b69-4d8e-a804-5bf4551ac80e.png)

抓包查看SQL注入点

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678348402549-1add96bb-4fa4-491a-9aeb-4dbccdce7ba0.png)

使用sqlmap进行注入,成功跑出注入点。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678348547280-38aabeac-9ab1-4560-902e-2689c0045f1a.png)

7.sql注入3
--------

通过“/admin/baojia\_list.php”参数“keyword”进行SQL注入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368939399-5bc50b6b-7974-4e92-98aa-767a69f88976.png)

发现这里的 $ckeyword参数是可控的

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368958420-402f99c7-91b1-42cc-a023-4247cbe1b547.png)

跟进这个fetch\_array函数，发现未对输入的参数进行过滤，导致可以产生sql注入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678368983122-8d0aabf4-b7fa-4731-8273-803a225254a5.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678349063104-38a8ee20-ff39-4974-bcab-476c1efea0a0.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678348913817-d0c072f9-e33d-4119-9df2-72a41650c476.png)

keyword=1' AND (SELECT 3526 FROM (SELECT(SLEEP(5)))qvLz)-- Iojq&amp;Submit=%E6%9F%A5%E6%89%BE

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678348892374-8f9092c9-3814-4ffb-8f66-bb6951f0b0ab.png)

8.敏感信息泄露
--------

### 漏洞复现：

漏洞地址1：  
[http://119.28.176.129/index.php?\_SERVER](http://119.28.176.129/index.php?_SERVER)  
poc：/index.php?\_SERVER  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678350207656-1afbab16-b60b-4525-8671-5b7cf6a80e5a.png)  
漏洞地址2：  
[http://demo.zzcms.net/index.php?\\\_SERVER](http://demo.zzcms.net/index.php?%5C_SERVER)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678350314700-bf818f43-0f0d-4157-9787-4f610dd1f835.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678350293807-b3927966-4de1-4c23-80fa-b90e2a827612.png)  
127.0.0.1/admin/index php?\_ Server  
poc：/admin/index php?\_ Server  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678350483750-d90bce1c-550a-4722-b2fc-0876040ef676.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1678350679817-fcab184e-376d-4aa8-ba63-506a660fa7ba.png)

REF：  
<https://xz.aliyun.com/t/10090>  
<https://wx.zsxq.com/dweb2/index/footprint/88455551854122>  
[https://blog.csdn.net/qq\_53123067/article/details/126805823](https://blog.csdn.net/qq_53123067/article/details/126805823)