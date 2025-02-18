前言
==

网上有许多关于XSS漏洞的文章，但是这些文章大部分都是直接给出了攻击载荷却并没有对他们的编码方式进行分析与讲解，这对与刚接触到XSS想深入学习的人并不是十分的友好，当我看到这个攻击载荷的时候，我不明白为什么要这样写，为什么这样写了就可以绕过一些防护，所以这篇文章我准备分享一下，我对XSS编码的理解与大佬们一起学习进步。

XSS常见编码分类
=========

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9745b3254327ca6a301b71061f4563ed8fb04f25.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9745b3254327ca6a301b71061f4563ed8fb04f25.png)

#### 输出点处做编码最主要的目的是什么，为什么要去做编码？

最主要的目的就是绕WAF、过滤函数，通常在没有WAF和过滤函数的情况下，我们只需要使用原始字符，XSS攻击的一大精髓就是简短，利用少量代码达到攻击效果，编码往往会使exp的长度增加

##### 输出在HTML中

**Entity（实体）编码**  
**概念：**在编写HTML页面时，需要用到"&lt;"、"&gt;"、"空格" 等符号，直接输入这些符号时，会错误的把它们与标记混在一起，非常不利于编码。那么就需要把这些字符进行转义，以另一种方式书写，以相同的形式展现。在HTML中，这些字符可称为HTML Entity,即HTML字符实体。

**编码范围：**包括但不限于以下字符: ASCll Characters(可见部分).ISO 8859-1 Characters、lSO 8859-1 Symbols、Math Symbols、Greek Letters、 Miscellaneous HTML entities。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-61c579d778e11fc456123690adde3a68bef35687.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-61c579d778e11fc456123690adde3a68bef35687.png)

##### Entity（实体）编码 ————两种格式

**格式一：**&amp;entityName  
说明："**&amp;**"开头，";"结尾，以语义的形式描述字符。如字符"**&lt;**"，英文名称为"less than"，EntityName为"**&amp;lt**;"，取自"less than"2个单词的首字母。  
**格式二：**&amp;#entityNumber  
**说明：**"**&amp;#**"开头，"**;**"结尾，以编号的形式描述字符。此编号可以为十进制或十六进制(以"**&amp;#x**"开头)等数字格式。  
**注：**entityName的数量要小于entityNumber的数量

##### Entity（实体）编码 ————实例

这里我们主要研究的是编码方式，所以我直接使用菜鸟工具里的在线编辑功能进行演示  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9b5267a699a70b24f8c7faf0a86c7df8280eba1f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9b5267a699a70b24f8c7faf0a86c7df8280eba1f.png)

```php
<h1>Entity编码</h1>
<p>entityName:</p>
&lt;<br>
&gt;<br>
&excl;<br>
&quot;<br>
&num;<br>
8amp ;<br>
<p>entityNumber:</p>
&#60;<br>
&#62;<br>
&#33;<br>
&#34;<br>
&#35;<br>
&#38;<br>
```

##### 浏览器的解析行为

**行为1:** HTML解析器在建立文档树的时候会针对节点内的Entity编码解码后传输。  
等效语句:

```php
<img src="1" onerror="alert(1)">
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-409a8a72e4d3e34eea93524243b6a48ccd0218a3.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-409a8a72e4d3e34eea93524243b6a48ccd0218a3.png)  
通过entityNumber编码

```php
<img src="1" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3673205e1468bd5b7827ead305107bd62bf4cb0c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3673205e1468bd5b7827ead305107bd62bf4cb0c.png)  
**注意:属于标签本身结构的部分不会被解析**

```php
<img src=1 onerror&#61;alert(1)>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ddd388562cda2300295b29832036d6defd2bc807.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ddd388562cda2300295b29832036d6defd2bc807.png)

```php
<a href="javascript:alert(1)">click me</a>
<a href="j&#x61;vascript:alert(1)">click me</a>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cda6820b44bdda4d3c793de836d9dcbf08032d1c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cda6820b44bdda4d3c793de836d9dcbf08032d1c.png)  
**行为2：**允许在如之后插入任意多个0。  
等效语句:

```php
<img src="1" onerror="alert(1)">
<img src="1"
onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-60495efbf71d5b3271b4fe1fb549d92dbd216100.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-60495efbf71d5b3271b4fe1fb549d92dbd216100.png)

```php
<img src="1"
onerror="&#00000000000000097;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-85dc58162b094ea8011b6ebc7015c9ba659032cb.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-85dc58162b094ea8011b6ebc7015c9ba659032cb.png)  
**行为3:**针对URL类型的属性，允许进行一次URL编码。  
注：URL类型的属性，通俗理解就是链接的属性  
等效语句:

```php
<a href="javascript:alert(1)">click me</a>
<a href="j&#x61;vascript:alert(1)">click me</a>
<a href="j&#x61;vascript:%61%6c%65%72%74%28%31%29">click me</a>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cdba148282908ab78d7ce810c7b2a441e989ae50.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-cdba148282908ab78d7ce810c7b2a441e989ae50.png)  
**行为4：**URL编码的部分可以进行第二次Entity编码。  
注：不能无限套娃，只能在URL编码部分进行一次Entity编码，若是经过Entity编码之后，又进行了一次URL编码，这是不会被解析的  
等效语句:

```php
<a href="javascriptalert(1)">click me</a>
<a href="j&#x61;vascript:alert(1)">click me</a>
<a href="j&#x61;vascript:%61%6c%65%72%74%28%31%29">click me</a>
<a href="j&#x61;vascript:&#37;&#54;&#49;&#37;&#54;&#99;&#37;&#54;&#53;&#37;&#55;&#50;&#37;&#55;&#52;&#37;&#50;&#56;&#37;&#51;&#49;&#37;&#50;&#57;">click me</a>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7a586c02f14e69ff8fb6ee4735c26381d5773683.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-7a586c02f14e69ff8fb6ee4735c26381d5773683.png)  
**行为5：**URI类型的属性忽略Tab和回车符。  
等效语句:  
&lt;a href="javascript:alert(1)"&gt; click me&lt;/a&gt;  
&lt;a href="javascript:%61%6c%65%72%74%28%31%29"&gt;click me&lt;/a&gt;  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4ed696a9108d70d7695cc9bc1875b0c6239b4201.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4ed696a9108d70d7695cc9bc1875b0c6239b4201.png)  
注：Tab符和回车符也可以再进行一次Entity编码

**行为6:** Entity编码的;可以去除。  
等效语句:  
&lt;a href="javascriptalert(1)"&gt;click me&lt;/a&gt;  
&lt;a href="j&amp;#x61vascript:&amp;#37&amp;#54&amp;#49&amp;#37&amp;#54&amp;#99&amp;#37&amp;#54&amp;#53&amp;#37&amp;#55&amp;#50&amp;#37&amp;#55&amp;#52&amp;#37&amp;#50&amp;#56&amp;#37&amp;#51&amp;#49&amp;#37&amp;#50&amp;#57"&gt;click me&lt;/a&gt;  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f67dfc8ec67190452aeeffbdb7177070ec7278a3.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f67dfc8ec67190452aeeffbdb7177070ec7278a3.png)  
注：不同格式的Entity编码可以混用

##### 四种编码策略

**C语言编码：**对于一些控制字符，使用特殊的C类型的转义风格（例如\\n和\\r)，公认的ECMAScript编码。  
**八进制编码:**三个八进制数字，例如"e"编码为"\\145"，该语法不属于ECMAScript,但是基本所有的浏览器都支持。  
**十六进制编码：**两个十六进制数字，例如"e"编码为"\\x65”，同样不属于ECMAScript，但是在解析底层，c语言中有很好的支持。  
**Unicode编码：**如\\u0065可表示字符e，属于ECMAScript编码。  
注：ECMAScrip是Javascript的一个标准

```php
<script>
document.getElementByld("a").\u0069\u006e\uO06e\u0065\u0072\u0048\u0054\u004d\u004c="\x3c\151\155\147\40\163\162\143\75\61\40\157\156\145\162\162\157\162\75\141\154\145\162\164\50\61\51\u003e";
</script>
```

**注：**前三种只能用于给字符串编码。第四种还可以用来给方法名编码  
不可以代替括号，引号，点号等特殊字符

```php
<script>
\u0061lert("test");
</script>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bb7ace8d17363a667f4343391e9dda14f304840e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-bb7ace8d17363a667f4343391e9dda14f304840e.png)

##### 常见误区

误区1: XSS，不是专门去"绕过"限制。  
误区2: XSS，不仅仅存在于你所看得见的位置。  
误区3: XSS，绕过限制不是乱用字符去绕过，切忌盲目。

总结
==

在刚接触XSS的时候，需要做的是了解其中的原理与编码方式，自己构造的语句中哪里可以在此基础上进行编码的构造，掌握了XSS编码的基础，在之后的学习中可以更好的理解别人构造的攻击载荷，而不是盲目的瞎改，导致语句无法解析不能绕过防护。