前言
==

最近在社区看文章的时候,发现了这一篇文章:<https://forum.butian.net/share/291> 感觉应该还有洞,所以通读了下代码,所以有了这篇文章。

sql注入1
======

在/Include/web\_inc.php中我们可以发现这一串代码:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d3729ad17b26ba16c2840d2533b840f953bb654a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d3729ad17b26ba16c2840d2533b840f953bb654a.png)  
我们可以看到先让`$web_urls`接收`$_SERVER["REQUEST_URI"]`的值,然后分割后,传进`web_language_ml`函数中,所以继续跟进该函数:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cb3a717950ed93a132e5012107cb464e4a3a6eb0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cb3a717950ed93a132e5012107cb464e4a3a6eb0.png)  
很明显的sql注入,而且是用`$_SERVER["REQUEST_URI"]`接收值,而代码只过滤了传入的参数,对这个是没有对其过滤,所以直接注入就ok了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-33dcec87919320ed09bb7a13e76fa42d6099e04e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-33dcec87919320ed09bb7a13e76fa42d6099e04e.png)  
这里用的是时间盲注,但是`$_SERVER["REQUEST_URI"]`接收值不会解码,所以空格要简单的绕过一下,不然传入的就是%20,后面的注释直接`or'`就好了！

sql注入2
======

如果想要访问后台的文件,其所有文件都存在这段代码:

```php
<?php include_once 'SEMCMS_Top_include.php'; ?>
```

所以跟进查看,发现内容是:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f43efefd8357c218116fc5ae5b6762299ff421c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f43efefd8357c218116fc5ae5b6762299ff421c1.png)  
发现会使用`checkuser()`函数来进行判断,所以继续跟进:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-35d088a06988a9829a8fdcfebe5e33c9621d1ec9.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-35d088a06988a9829a8fdcfebe5e33c9621d1ec9.png)  
发现它是通过使用cookie中的值,方入sql中进行执行,这里先把`verify_str`,`test_input`两个函数的过滤内容奉上:  
test\_input:

```php
function test_input($data) { 
      $data = str_replace("%", "percent", $data);
      $data = trim($data);
      $data = stripslashes($data);
      $data = htmlspecialchars($data,ENT_QUOTES);
      return $data;

   }
```

verify\_str:

```php
function verify_str($str) { 

   if(inject_check_sql($str)) {

       exit('Sorry,You do this is wrong! (.-.)');
    } 

    return $str; 
} 
```

inject\_check\_sql:

```php
function inject_check_sql($sql_str) {

     return preg_match('/select|insert|=|%|<|between|update|\'|\*|union|into|load_file|outfile/i',$sql_str); 
} 
```

可以看到,过滤了很多东西,正常的sql注入似乎没办法搞,但是,这里是想要登录后台,所以我们完全可以不用注入得到密码,可以直接想办法构造使该sql语句正确就好了,所以这里的想法是构造出`'xxx' or 1=1`这种形式,所以直接上payload:

```php
scuseradmin:fthgb\\
scuserpass:or 1#
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d8390ab05e3d555050f6be0a89ba7a90e89f8837.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d8390ab05e3d555050f6be0a89ba7a90e89f8837.png)

总结
==

这个cms感觉漏洞挺多的,最近有些事,没看完,有兴趣的小伙伴可以全篇通读一下,不出意外还能找到一些洞...