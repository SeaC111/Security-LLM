一、 环境搭建：
========

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675949714418-5abfbfa5-34d7-411d-ac39-63ff32b7b5a8.png)

框架介绍：
-----

此项目为dede自研系统，其中所有功能点都由dede自开发，访问对应PHP文件即可找到对应功能点。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675949890846-d0fc76ab-d062-481a-8249-d53267c1ad2b.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675949983352-ce468ce6-d26d-495f-a6f6-90e980a82b54.png)

二、代码审计
======

1.任意文件写入
--------

通过搜索 fwrite() 函数，发现这里存在可疑写入点，而我们知道得知dede的路由可以通过直接访问。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950095485-9a99ff3d-e6cf-41d2-99c7-0ee43dcba3db.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950119013-72406398-a848-486d-873b-9ba8ccd6d333.png)  
这个数组是怎么传入的。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950256216-83fde758-8718-4b68-8340-625693050b5e.png)  
直接访问该文件发现如下功能点，而这里的验证码设置功能处正是传入参数的地方![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950401809-3d4b1fb9-5acd-41ee-89f8-265728e944c9.png)  
这里抓包看到此处参数可控的地方![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950671427-6b326bbb-3a03-4e54-8fa6-97e670b9fcd0.png)在代码的中是存在过滤的，但是我们发现可以进行绕过。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950739188-633adad0-57ab-4343-85cb-18080fd0b227.png)

我们在看一下要写入的文件内容  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950805840-30f500a3-3f4c-4c47-b8c6-e8a5928b2c91.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950920362-a34ce3b3-35e1-42ed-b238-02b5bcb01008.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675950962731-69a00355-829f-4429-b84f-91ac596b3ba7.png)

2.目录遍历
------

全局搜索 read() 函数，发现存在参数可控的地方，接着我们进入 select\_images.php 文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951139722-608d0621-f9dc-498b-8177-a41453d7d0e0.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951186968-5ed82615-bc5c-446c-94ce-2b1e72bbdf44.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951220301-9d450a8c-178e-46e8-9706-26b52dfc601b.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951607824-320700ed-a3f4-4e3c-978a-980e96dbe3e5.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951733671-13600662-2dfc-4295-98ae-2631e3746b75.png)

3.数据库操作getshell
---------------

在测试功能点模块管理时，发现一处可以操作数据库的地方，我们点击修改。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951812705-a43cf52f-a24d-4b3f-a428-5cb546c14511.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675951911334-f3ef0cae-7108-43a9-ba73-deec516128ff.png)  
其实我们可以直接在删除程序处输入我们想要执行的SQL语句进行测试  
这里传入了两个参数 action 以及 hash。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952214178-038de41a-0266-48db-a810-e812e5922a19.png)

这里通过uninstall执行该处分支，然后通过上面传入的hash参数值来定位文件， GetFileLists() 获取

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952306732-e1e1ef0b-110e-40c9-bb8f-fa3ae6341915.png)

跟进 GetFileLists() 函数。'

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952324747-29a367a4-2582-4a76-bf80-2b8b308ebfc7.png)  
在该函数中首先包含了 modulescache.php 文件，并通过 $hash 返回xml文件内容。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952366237-8ead972b-dd0b-4540-9c64-fb752b77b255.png)

查看一下modulescache.php,![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952429686-3d8ba2b5-15ae-4bba-b575-0fa1aeb7e251.png)

查看该xml内容，该文件内容中就是相应模块的配置信息。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952505307-087ebe47-335d-450b-90ce-0664dc30a316.png)  
发现执行了 uninstallok 分支。该分支就是卸载模块的分支，这里最重要的是通过 GetSystemFile() 获取文件内容，这里传入了另一个参数 delsql ，跟进该函数。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675952778294-eb0e08c5-0457-4715-8d71-bf702605df91.png)  
通过 GetHashFile() 函数获取文件内容。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675953033220-65901474-939d-481a-b5d6-b80c276c929c.png)

delsql内容中正是删除程序处的文件的base64内容

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675953193641-601b25eb-0306-4e61-b4e1-329a5f68ea29.png)

最后在代码518行执行SQL语句，所以我们可以通过Mysql日志文件来getshell，而这里需要网站的绝对路径，通过之前的目录遍历，可以获取到绝对路径。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675953564506-77416d65-9b89-4320-bda8-422f463d1f4d.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954011022-0c2514ce-6e2c-469b-9671-ad92e8cf9e97.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954037053-7803cfaa-022d-4c91-8d7c-9d6d742ac926.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954074266-f72a0f71-0510-45e3-ba1a-6428bf515119.png)  
最后访问cyw.php，获取敏感信息。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954166790-c969ff3f-e2f7-4684-a8d2-a8e3452b1649.png)

4.任意文件写入2
---------

全局搜索危险函数 fwrite() 时发现在 article\_string\_mix.php 中存在可以控制写入内容。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954302684-6fe0baa7-f6f1-4436-8ce9-0f82406628d7.png)  
在 article\_string\_mix.php 中 $allsource 写入的内容是可控的，但在代码中存在危险函数过滤，但在过滤函数中过滤不严格导致绕过，实现代码执行。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954405413-d3eabf0d-f711-4ad9-9457-675f1b0672ec.png)

### 漏洞复现：

通过 preg\_replace() 绕过危险函数过滤，造成代码执行。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954709466-3b59880e-1442-410a-8bf6-44f5137c3381.png)

写入downmix.data.php

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955297172-a6f2b324-b3df-4043-acf2-02dc3f4669ef.png)

访问dede/article\_template\_rand.php文件，执行phpinfo()。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955316547-32f8401c-f22b-409c-8d48-b5bdb054835b.png)

5.任意文件写入漏洞3
-----------

在dedecms中使用 fwrite() 函数写入配置文件的操作是很多的，在该系统中我们只需要观察两点即可，一写入的位置为可解析的php文件，二写入的内容我们是可控的即可。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955429612-13bdc9cd-30e0-49fc-b7af-d193dd0886c2.png)

在函数 ReWriteConfig() 中，我们可以发现代码的第38行和第42行都是用了 fwrite() 函数，向上回溯发现该处的值是从代码3的 sysconfig 表中拿到的，我们去看看该表中的内容。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955582125-314d35c4-87ab-45d3-a742-8fc0b9aef1db.png)  
该处存储了网站的配置信息，上面的代码中可以看到type为 number 时会将 varname 字段的值以及value字段的值写入配置文件，如果类型不为type时，这里会存在一个小小的过滤，这里的单引号会被替换为空。  
**绕过思路:**  
1.我们可以直接在type=number类型的字段中直接插入我们要执行的代码

2.通过\\反斜杠来转义原本的单引号，然后使我们的代码逃逸出来

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955626068-994ca693-9dad-4df8-bf58-2a19382023d3.png)

在 dopost 参数为 save 时，发现这里接收了post传入的参数，并且将传入的内容写入到sysconfig 表中。在代码中执行了上面分析的 ReWriteConfig() 函数。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955661493-d1e4d892-8f84-44c5-8d31-525435a1869e.png)

### 漏洞复现：

访问/dede/sys\_info.php文件，发现该处功能点确实是配置系统参数处，所以我们直接在type=number参数处插入我们的代码。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955823595-261e31e6-17b8-4e1d-b3b3-ad0f276b381b.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955962912-3050c6f1-c7af-4af6-ba5d-a82b876b299f.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675955844807-ffa8a3a3-1da5-4c35-a356-80e1abc743e2.png)、

第二种方法可以通过\\反斜杠转义原有的单引号，使我们的代码逃逸出来。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675956034416-83bc3f86-4dfb-4d3e-976d-01a4e965a377.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675956048227-e3201bfc-df06-4a9c-8011-c8fc4366f4ea.png)

6.数据库操作getshell(2)
------------------

在测试系统功能点的时候，发现一处可以操作数据库的地方，下面的功能可以执行SQL语句。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675956202922-ced3ace3-5526-4974-bb6b-86a0ffaf3fa6.png)

### 漏洞分析：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675956403431-117e10c5-e369-4409-86c9-14f6c4a1f430.png)

这里执行到query分支，代码中存在过滤，这里过滤了drop关键字，然后执行SQL语句。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675956457710-e164d540-5dbf-4985-9011-7bd38f44d1bf.png)

### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676009**735455-5027f793-b02f-4c7a-aa49-bbf7bd800b47.png)  
**利用条件:\*\***  
set global general\_log = on;  
set global general\_log\_file = 'D:/phpstudy\_pro/WWW/www.dedecms12.com/uploads/shell.php'; ![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676009962651-5cb815cc-8071-4819-8523-8a51a51f708f.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676010066961-ded64939-e2e7-4724-a17b-276f4808f2fc.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1675954166790-c969ff3f-e2f7-4684-a8d2-a8e3452b1649.png)

7.文件上传漏洞
--------

此处首先具有前端限制，上传 .jpg 后缀文件，结合brup抓包，发现处理上传功能的文件为dede/archives\_do.php

然后结合抓包，来看看具体代码

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676016081085-2ab417c2-42b0-4589-ae26-375babc697c2.png)

入口文件通过 config.php 会实现权限认证和一些外部参数过滤注册，这里上传文件会带有$\_FILES参数，通过全局分析得知会触发uploadsafe.inc.php的过滤，过滤后，通过AdminUpload()实现最终文件上传。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676016179970-f57901d8-7d79-4418-bc62-629b8e2a0856.png)

进入include/helpers/upload.helper.php

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676016246014-6165eaa6-5087-47c5-b8d6-5b242c7f3a1d.png)

最终实现文件上传的AdminUpload()来自upload.helper.php，传入AdminUpload()的$ftype固定为imagelit，则一定会进入对应的检测判断。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676016261092-d33935b8-d6b9-4667-ab06-f11d4206a14e.png)

### 漏洞复现：

进入添加文档，该功能可以发布文章，而且具有文件上传的功能。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676015524828-5ba9590a-3321-4940-b61c-c0d380e222bf.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676015577647-79386d5b-82b1-4800-8b90-8a1122e1c5c7.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676015781020-97301ac8-773e-43c7-8337-0e002dc0a159.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676015881068-1d23fca3-ad76-450f-9e5a-57d786de4c23.png)

8.xss漏洞
-------

在qrcode.php及加载的文件都没有做xss过滤，通过common.inc.php会注册全局变量。进入qrcode.php，qrcode.php及加载的文件都没有做xss过滤，通过common.inc.php会注册全局变量。

$id只能为整数类型，$type类型可控，加载模板qrcode.htm，利用视图类格式化输出$id,$type的值，$type可控，这里就存在xss漏洞。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018226599-d59335f4-7f69-47f0-8a8e-a67c536ee14a.png)  
可以看到这里的触发点$dtp-&gt;SetVar('type',$type);  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018520764-ecf5aa46-619a-4897-87cd-05147d9b6b8b.png)

9.url 重定向漏洞
-----------

进入plus/download.php，发现对$link做了base64解码

发现有一个很奇怪的限制，in\_array($linkinfo\['host'\], $allowed)，然而download.php中却没有$linkinfo这个参数![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018633070-75a1b1e1-ebdc-4aaa-be39-d043f9fc9b58.png)

10.会员中心任意用户密码修改
---------------

在用户密码重置功能处，php存在弱类型比较，导致如果用户没有设置密保问题的情况下可以绕过验证密保问题，直接修改密码(管理员账户默认不设置密保问题)。值得注意的是修改的密码是member表中的密码，即使修改了管理员密码也是member表中的管理员密码，仍是无法进入管理。

### 代码分析

php弱类型比较问题很常见，在不同类型比较时，如果使用的是\\==，php会将其中一个数据进行强制转换为另一个。

'' == 0 == false '123' == 123 //'123'强制转换为123  
'abc' == 0 //intval('abc')==0  
'123a' == 123 //intval('123a')==123  
'0x01' == 1 //被识别为十六进制  
'0e123456789' == '0e987654321' //被识别为科学计数法  
\[false\] == \[0\] == \[NULL\] == \[''\]  
NULL == false == 0  
true == 1

dedecms的/member/resetpassword.php就是用来处理用户密码重置的问题。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018773051-093a5d32-32e3-4eaa-a11e-9c5fa28da8d9.png)  
先从数据库取出相关用户的密保问题及密保答案，在对用户输入做了一些处理后，进行了关键性的判断if($row\['safequestion'\] == $safequestion &amp;&amp; $row\['safeanswer'\] == $safeanswer) ，就在这里用了弱类型判断\\==。  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018887551-bb2b02da-5ef3-49db-a587-cefca7c3db7d.png)  
跟踪newmail。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018915297-b4b8f088-3007-4a09-8df5-a5b7538e2317.png)  
在sn函数中将send参数设置了'N'，其实就是生成了暂时密码并插入了数据库中，并进行跳转：  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676018964051-a0e022a4-a45c-47c2-8da0-ba6f5e122cc7.png)

### 漏洞复现：

在找回密码处，点击通过安全问题取回。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676019783258-4e9651f4-5767-437f-a4f2-42c4dd284241.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676021402785-4a92a636-de1a-4b2a-a747-18b0e13a7046.png)![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676021412126-444df7e3-349f-4809-9564-5090fc3298b2.png)

11.任意用户登陆漏洞
-----------

dedecms的会员模块的身份认证使用的是客户端session，在Cookie中写入用户ID并且附上ID\_\_ckMd5，用做签名。主页存在逻辑漏洞，导致可以返回指定uid的ID的Md5散列值。

### 代码分析

在/member/index.php中会接收uid和action参数。uid为用户名，进入index.php后会验证Cookie中的用户ID与uid(用户名)并确定用户权限。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676021557995-d4c05261-46b4-4823-bfb0-e7ba4d4517ff.png)

看到当uid存在值时就会进入我们现在的代码中，当cookie中的last\_vid中不存在值为空时，就会将uid值赋予过去，$last\_vid = $uid;，然后PutCookie。

进入/include/memberlogin.class.php

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676021604502-97eda5a8-9f30-4ebe-81ac-a660e964387a.png)  
$this-&gt;M\_ID等于Cookie中的DedUserID，我们继续看看GetCookie函数![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676021706450-31436fda-1293-48cb-b692-8bf10395cd6a.png)它不但读了cookie还验证了md5值。这样，由于index.php中我们可以控制返回一个输入值和这个输入值经过服务器处理后的md5值。那么如果我们伪造DedUserID和它对应的MD5就行了。

### 漏洞复现：

主要思路就是:  
访问member/index.php?uid=0000001并抓包(注意cookie中last\_vid值应该为空)。  
**1. 先从member/index.php中获取伪造的DedeUserID和它对于的md5** 2. 使用它登录\*\*\*\*  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676023247396-2978fdff-8ff3-4a22-b928-c45c21eb8d0b.png)  
![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676023773833-1941a3fe-8f5b-4d7a-a392-deed89912d8f.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1676024214821-65d9dede-6c58-4252-8c0c-875560f74ecb.png)

**REF:**  
<https://www.freebuf.com/articles/web/281747.html>  
<https://blog.szfszf.top/article/25/>