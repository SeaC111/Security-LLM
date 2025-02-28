### 前言

seacms是php开发的视频内容管理系统，目前更新的版本已经算是比较高了，在过去版本中修复了很多漏洞，比较适合入门学习。前段时间看到一位师傅分享的一个老版本的源码，于是下载进行学习。本文分析的漏洞都是老版本漏洞，最新版已修复

### 审计环境

```markdown
phpstudy(php5.6.27+Apache+mysql)
PHPStorm
seay代码审计工具
```

将源码放到WWW目录，访问/install安装即可，安装完成后，访问首页如下  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6937573bff852e86e7ab3f03f44580c710415e7c.png)

### 代码审计

开始审计前，先浏览网站的目录结构，通过文件名大概判断对应功能  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba21aff2f3e6f81d8a48605c60f5e8428db4d01f.png)

```markdown
admin //后台管理目录
article //文章内容页
articlelist //文章列表页
comment //评论
data //配置数据及缓存文件
detail //视频内容页
include //核心文件
install //安装模块
js //js文件
list //视频列表页
news //文章首页
pic //静态文件
top //静态文件
templets //模板目录
topic //专题内容页
topiclist //专题列表页
uploads //上传文件目录
video //视频播放页
index.php //首页文件
```

大概了解了网站的目录结构之后，可以使用seay代码审计工具的自动审计功能进行审计，然后配合自动审计结果进行手工审计  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5512f0bb2b99bbf512925534bc77d6427c94ba43.png)

审计前可以看看网站全局文件，一般这些文件里面会有cms自带的安全防护函数，而这些全局文件一般会在文件开头包含  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c971a53d5a5ce6e4dcbe6a3c448340bc4e2c7f64.png)

进入`/include/common.php`  
可以看到通过GET、POST、COOKIE方式传进来的参数都会调用`_RunMagicQuotes`方法进行处理，并且将过滤之后的值存入以键值对的键为变量名的变量中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-873734eb2fc31065d6cf20172e708f0e87e5d4b7.png)

`_RunMagicQuotes`方法中，当gpc功能没有开启时，会使用`addslashes函数`对所有参数进行过滤  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-992cbb72684ce3901473f772b4c0d8bad3330384.png)

如果上传文件，会包含`uploadsafe.inc.php`文件  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c19cb95a2cb4ec0e5ee3220f1a4e2dffab023e3d.png)

跟进查看，使用了黑名单的方式限制了一些特定的文件后缀  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4beb730bcb15ebc5f931ea3aec5a13e3c64e8756.png)

看了cms的防护措施，可以发现对sql注入的防护只是调用了`addslashes`对传入的参数进行处理，所以只要没有被引号包裹，直接带入sql语句的参数，都可能存在sql注入

### 后台SQL注入

从seay工具的审计结果中可以看到很多可能存在SQL注入的地方，  
`/admin/admin_ajax.php`  
`admin_ajax.php`文件包含了`config.php`，而config.php中又包含了`/include/common.php`，所以会调用`addslashes函数`对参数进行过滤  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2a1d2d11369e20fccfc7410ee3722c1287213393.png)

当`$action=checkrepeat`时，对传入的`参数v_name`进行编码处理，在下一行对参数进行拼接  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c290c98e4e114f8bea1da8a3ab32fedef498db6a.png)

当GET传入`v_name`参数时，会调用之前说的过滤函数，使用`addslashes`函数过滤`v_name`的值，并存入`$v_name`，也就是说被过滤的是`$v_name`变量。但是这里直接对GET传入的`v_name`的值进行编码后存入`$v_name`变量，相当于对`$v_name`变量重新赋值，重新赋值的`$v_name`变量就没有经过任何过滤，然后在第二行直接带入sql语句  
跟进GetOne函数  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-017462ad0d1cc1439f12e5f033c05aa004c77c67.png)

只是执行sql语句并返回，并没有过滤措施

##### 漏洞验证

payload：

```markdown
/admin/admin_ajax.php?action=checkrepeat&v_name=11' and (select 1 from(select count(*),concat(0x7e,user(),0x7e,floor(rand(0)*2))x from information_schema.plugins group by x)a)-- &timestamp=1
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b1f2875bb22a94193e999cb825d92668fe9f3ee.png)  
后台还有很多SQL注入，大多都是由于参数未使用引号包裹，直接带入sql语句执行，后台sql注入也是比较鸡肋的，这里就不过多分析了。

### 任意文件读取

`/admin/templets/admin_collect_ruleadd2.htm`  
该htm文件中使用了`file_get_contents`函数，且参数可控,如果`showcode`不为空，就执行`file_get_contents`函数，读取`$siteurl`的内容  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-74b6267ba7490344e2250cbee5ffd8e58b73ba50.png)

由于是htm文件，需要找到包含该文件的地方，全局搜索包含`admin_collect_ruleadd2.htm`的文件，发现`admin_collect_news.php`和`admin_collect.php`都包含了该文件  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c0a6781db6209aaa9dda3a0f1bf14eda920edfef.png)

`admin_collect.php`  
只要满足`action=addrule`，`step=2`，`itemname不为空`，即可调用  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-925baf1a77aab7c5401b4eebbc9f73ab59a76f3f.png)

##### 漏洞验证

payload

```markdown
/admin/admin_collect.php?action=addrule&step=2&itemname=1&showcode=1&siteurl=C:\windows\win.ini
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0adacc1a54c3175a644e5168b5603a8d86cb98a8.png)

`/admin/admin_collect_news.php`  
逻辑和`admin_collect.php`中基本一致  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0c5ce086352f297278a4247cc7e6e3b1ea419da3.png)

##### 漏洞验证

构造payload

```markdown
/admin/admin_collect_news.php?action=addrule&step=2&itemname=1&showcode=1&siteurl=C:\windows\win.ini
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bc641b1a0f5ce7185b34c0a829d82d7e195c40f2.png)

### 代码执行

`include/main.class.php`  
`parseIf`方法中，3118行，`eval`执行的语句中存在变量`$strIf`，正常情况下，如果`$strIf`是用户可控的话，就有可能造成代码执行。  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6d2b3f6f46fddbb3fb7cd8794993128fb3a21cca.png)

往上查看`$strIf`的来源，3108-3109行，取`$iar数组`中的值赋值给`$strIf`，并经过`parseStrIf方法`处理，现在只分析`$strIf`的来源是否可控，细节暂时不管。  
3105行，`$iar`数组又是来自于`$content`，接下来追踪一下`parseIf()`，寻找调用这个方法的文件，找到`search.php`中。  
`search.php`  
在212行，在函数`echoSearchPage()`中，调用了`parseIf()`方法  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9b5fee66971ff9a3f03a17b9ee6cc9fde3db3e55.png)

继续往上追踪`$content`，在一个if语句中，`$cfg_iscache`是全局变量，在`data/config.cache.inc.php`文件中定义值为1，所以会使用`getFileCache`函数获取缓存文件的值赋给$concent  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4e8f9ed65818ef4c79b96361dd83895f3a687ac5.png)

随后通过`$page、$searchword、$TotalResult、$order`等参数对`$concent`进行内容的替换  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5c52317ffc02915f63996e2f4bfe890aa9bde6ef.png)

第1行包含了`include/common.php`文件，那么就可以通过传入`$page、$searchword、$TotalResult、$order`等参数控制`$content`的部分内容，其中只有`$order`完全可控

```php
$page = (isset($page) && is_numeric($page)) ? $page : 1;
$searchtype = (isset($searchtype) && is_numeric($searchtype)) ? $searchtype : -1;
if(is_array($row)){
    $TotalResult = $row['dd'];}
else{
    $TotalResult = 0;}
$order = !empty($order)?$order:time;
```

在`echoSearchPage()`函数中，在`searchtype==5`的时候，content信息来自于`cascade.html`  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cebd0b32c54f448e8d8e2698efe3987e257117c1.png)

`cascade.html`  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-421458b88c6afd701d4ee1c6b378ae5e70efa134.png)

$content中的`{searchpage:ordername}`会替换为`$order`参数  
关键在于要怎么构造$order的内容，匹配的正则表达式为`{if:(.*?)}(.*?){end if}`，匹配到的值会传入$iar数组中  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a000ae45c0cd66c5bb6af24e23f71b0510c1c710.png)

$iar数组会有3个子数组，$order在第二个子组里面  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-00d761298f124c05a73d7d3bcbfc6ed7683c3186.png)

eval()执行的恰好是第二个子组  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-894a5ecd70efb21bc4687ca2bf34b1c8c6ad8ddb.png)

于是构造$order参数}{end if}{if:1)phpinfo();if(1}{end if}  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-08ca58631fb1ce585418141f6d51c68768046c1a.png)

将第二个子组带入eval函数就造成代码执行：

```php
eval("if(1)phpinfo();if(1){\$ifFlag=true;}else{\$ifFlag=false;}")
```

##### 漏洞验证

payload

```markdown
/search.php?searchtype=5&order=}{end if}{if:1)phpinfo();if(1}{end if}
```

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-32215ac7eb4b693534e1f3a2d93ab4df7f03a93f.png)

### 总结

这虽然是一个入门的cms，但是也从中学到了知识，而且有些漏洞还是比较麻烦，需要细心和耐心，有些不太好分析的地方，也可以配合phpstorm的degub功能进行调试。