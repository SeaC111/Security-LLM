一.项目搭建：
=======

使用phpstduy+mysql进行环境搭建。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684559312589-2e894cc1-5927-4a84-8f36-b2db41b10309.png)

输入数据库名和登录用户名、密码之后，进入下一步。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684559326747-514818c7-7e6f-4d9f-b06a-8834713c69b7.png)

成功登录后台地址。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684559300108-f3f9a122-7400-4a49-9c87-bea06a50c88a.png)

二、代码审计：
=======

全局分析：
-----

分析网站根目录下/index.php包含的头文件/init.php，发现，其中对GET,POST等进行处理的只有第二十一行的函数doStripslashes()。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684560503258-3bd90474-28eb-474a-9ca8-607b1be07a81.png)

跟踪该函数，发现该函数作用居然还是去除转义字符，所以可以说，全局对GET,POST数据实际上是毫无过滤的。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684560516689-6ec5e3a0-a70e-4ee4-9b2a-2dacf1890f42.png)

漏洞分析：
-----

1.SQL注入漏洞1
----------

进入/admin/comment.php第46行语句

$ip = isset($\_GET\['ip'\]) ? $\_GET\['ip'\] : '';发现未对参数的输入进行过滤。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684560619018-41a89956-682c-48b0-8c34-94c43d8cb121.png)

跟踪该函数delCommentByIp()

在/include/model/comment\_model.php中第152行中将该参数拼接到SQL语句，由单引号来进行包裹。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684560641580-039d6c25-7f44-47b6-af48-1f7394470a1d.png)

经过分析之后，发现是未对用户的输入是进行过滤的。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684570828417-a166c9e4-ac03-4811-bbbf-6d4fdd09421c.png)

### 漏洞复现：

进入插件功能模块处，然后进行上传文件，f12查看网页源代码，获取token。

### ![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684570849208-d732a7d1-76a5-4da9-bfad-13e1e655b632.png)

然后使用burptuiste进行测试，发现出现报错注入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684570828417-a166c9e4-ac03-4811-bbbf-6d4fdd09421c.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684570806309-4792c568-9c54-4232-833e-c995b53e8c8e.png)

2.任意文件删除漏洞（1）
-------------

进入/admin/data.php

在第143-144行存在未过滤变量$\_POST\['bak'\]并直接拼接到unlink中。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572180006-d16ccb59-7c78-4371-90f3-71b9fd901fe9.png)

接着进入/admin/blogger.php代码中存在危险函数unlink，跟踪变量$icon\_1，该变量来自80行中的sql查询字段photo返回结果，跟踪语句31行中变量$photo通过POST传入，有一些过滤操作，但是我们可以进行绕过。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572276400-1e35dc2c-9946-48f0-be41-a5a01b388e88.png)然后向上 查找， 去找它的调用方式。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572315934-4ee85bcf-0fde-4a6d-a9a8-9cf17f228f16.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572335481-16704f34-c99d-47bb-8719-4f44d37b997c.png)

### 漏洞复现：

先通过POST将构造的任意路径变量$photo更新到数据库中（$action=update），再通过$action=delicon触发unlink($icon\_1)，进行任意文件删除

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572459790-6a9fe940-df88-48db-bba5-ad2d8ef3de74.png)

使用burpsuite进行抓包，成功删除x.php文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572704619-f89d9f69-8470-4817-a74d-34cd3fece2dc.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572691906-eb3af5c2-eb47-4666-b695-a873aa53c43a.png)

3.数据库备份上传getshell
-----------------

进入/emlog/init.php 中

发现变量 $action，通过GET方式传入$action\[\]数组的形式，会出现SQL注入漏洞。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684750019255-b895dfa9-2e16-4d95-b48f-29f6a1dab2e1.png)

### 漏洞复现：

进入数据功能处，然后进行备份文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684572886899-12896299-a7e6-4c03-8352-0974da1db95f.png)

在文件中写入phpinfo

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684573083838-3dff1650-08fc-4f4c-a7c2-676739b15a17.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684573191251-aa7deb71-98b7-4b6d-99f8-62c326b3f0e6.png)

接着提示访问报错，我们换一种方式写入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684573215984-6570cf1f-a540-4934-9a7d-3dedfcaedd78.png)

进入本地文件进行查看，发现文件已经成功写入。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684575430668-3590f61b-ddb6-49f1-9580-807503f6ab5d.png)

成功访问到phpifo。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684575411678-3953636c-1dad-4517-b46b-27db2fc3c51b.png)

4.文件上传漏洞
--------

进入/admin/plugin.php页面可以上传一个zip压缩包，并在后台将压缩包解压成文件![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684652089212-05f58c5c-0413-4e0a-8512-0a0776f4eb55.png)

跟踪emUnZip()函数。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684652140690-04f717eb-2951-4a4e-a55d-ce732e7fffab.png)

### 漏洞复现

然后使用.zip文件进行测试。成功上传文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684652196776-80374374-ab1a-4bb0-b75e-c6dfdc4f961e.png)

5.存储型XSS漏洞
----------

/admin/write\_log.php添加文章存在html代码形式，尝试直接添加&lt;script&gt;alert('xss')&lt;/script&gt;

跟踪到/admin/save\_log.php文件

$content变量未对用户的输入进行过滤。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653443996-331cc25d-cec3-4cc0-9a52-fb234def7759.png)

### 漏洞复现：

进入评论页面。输入xss的payload

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653279281-df520b34-0bf2-4708-a7bd-d30dead60da2.png)

然后点击查看。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653383086-765ac763-0448-4c64-87b5-058b2e93acc6.png)

成功实现弹框。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653362477-f1f23914-06a5-46d6-bdf9-16b8f1bb6060.png)

6.SQL注入漏洞2：
-----------

进入admin/navbar.php，发现这里接受POST传入的pages参数，遍历调用addNavi

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653788909-77daadcf-89ba-40f6-8e83-ebec2f663f42.png)

跟进addNavi函数

发现未对用户的输入进行过滤，导致sql注入漏洞产生。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653820218-780a6c38-0146-46a4-b798-761cc81b34f6.png)

### 漏洞利用

进入自定义导航处。![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653869891-9c54ae06-35a5-4c78-80de-b9337400b876.png)

然后进行报错注入尝试。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684653944231-3ffdb9aa-3716-4785-9b32-711b81971643.png)

使用sqlmap进行验证。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684654335595-d031a953-162f-48c9-821f-35e54622b77b.png)

7.SQL注入漏洞3
----------

进入data.php，发现bakstart 未对用户的输入进行过滤。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684750412029-00fd5451-34ad-415d-b617-8c153239a297.png)

### 漏洞复现：

POST /www.emlog6.com/src/admin/data.php?action=bakstart HTTP/1.1  
Host: 127.0.0.1  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,\*/\*;q=0.8  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
Accept-Encoding: gzip, deflate  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 96  
Origin: <http://127.0.0.1>  
Connection: close  
Referer: <http://127.0.0.1/www.emlog6.com/src/admin/data.php?action>\[\]  
Cookie: em\_plugin\_new=block; commentposter=1; postermail=178499%40qq.com; posterurl=http%3A%2F%2F1; XXL\_JOB\_LOGIN\_IDENTITY=7b226964223a312c22757365726e616d65223a2261646d696e222c2270617373776f7264223a223864646366663361383066343138396361316339643464393032633363393039222c22726f6c65223a312c227065726d697373696f6e223a6e756c6c7d; PHPSESSID=4ia7lpsune36918ksppu61a8dq; EM\_TOKENCOOKIE\_caff76b1035523472f95e14586cabce5=cdfe196eb124564199f08c42e5970d1f; EM\_AUTHCOOKIE\_M7UXVI3lOecv3OwT3uWOBeOai1TmLrM1=admin%7C%7C6cf405b484dd316c6f2e1ecc5edfbcf9  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: same-origin  
Sec-Fetch-User: ?1

table\_box%5B%5D=emlog\_attachment'&amp;bakplace=local&amp;zipbak=y&amp;token=cdfe196eb124564199f08c42e5970d1f

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684654780752-340e2f46-89d7-4423-8526-aea7fad3f50d.png)

8.任意文件删除漏洞2：
------------

进入删除插件功能处。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655306490-37c6ac48-9c23-4aab-89a6-8ea1914d761f.png)

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655330739-628b3d30-5f6a-443a-a2c4-5aeb842a04e1.png)

跟进preg\_replace这个函数。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655425946-ed165db0-c5e7-4d22-b683-f1dfa575fa79.png)

发现对其中部分字符进行过滤，我们可以进行绕过。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655456622-1633c39e-b636-4cf3-881a-b7f50969627a.png)

### 漏洞复现：

进入插件功能处，然后点击删除。然后进行抓包。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655031130-c7686b3a-e141-474e-b732-a61dbade4d41.png)

在文件目录添加一个测试文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655115556-27c518b4-df41-4274-b602-fab0a48a405b.png)

然后成功删除测试文件。

![](https://cdn.nlark.com/yuque/0/2023/png/1353500/1684655241486-0f09e98e-7bfb-481b-a9ee-bee0c888959f.png)

**REF：**  
[https://blog.51cto.com/u\\\_15847702/5808324](https://blog.51cto.com/u%5C_15847702/5808324)

<https://www.cnblogs.com/cHr1s/p/14262968.html>

<https://www.geekmeta.com/article/1118334.html>