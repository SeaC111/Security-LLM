0x00 前言
=======

来蹭一波刚打完的CISCN 2022热度。对于逆向手来说确实有点措手不及，三道题竟然只有一道能用ida打开的（乐）

不过还是很开心的，hack just for fun。未知意味着能够有机会学到新的知识点。

再一次致敬ciscn2022 逆向手的阅读理解大赛

（开场swift ast阅读题 中午mruby bytecode阅读题 下午rabbit xtime 爆破题，1k+行的main函数......）

0x01 swift ast产生原理
==================

![image-20220530045703338](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3a8f2230ea4689fb0e22a548dd67379303e7a71e.png)

可以看到，AST文件是swift源程序到可执行文件.o编译过程中的一个中间性文件。

某国外大佬对 swift生成ast过程的介绍

First, the compiler parses the source code and build the [Abstract syntax tree (AST)](https://en.wikipedia.org/wiki/Abstract_syntax_tree). We could see the AST by the option `-dump-ast`:

```fallback
xcrun swiftc -dump-ast main.swift
```

Semantic analysis could be performed when the AST is constructed.

**解析**。首先，编译器解析源代码并构建[抽象语法树（AST）](https://en.wikipedia.org/wiki/Abstract_syntax_tree)。我们可以通过选项看到 AST `-dump-ast`：

```fallback
xcrun swiftc -dump-ast main.swift
```

可以在构建 AST 时执行语义分析。

0x02 从swift AST 到源码
===================

暂时还未找到从swift AST编译回Swift的方法，那么最好的办法就变成了手撕，不过手撕不能生拉硬撕，我们应该寻找规律。接下来我们借国赛的这道题目来看看swift AST有什么样的规律（如何优雅的手撕）。

函数初始化
-----

```php
 (func_decl range=[re.swift:1:1 - line:14:1] "check(_:_:)" interface type='(String, String) -> Bool' access=internal//函数声明
    (parameter_list range=[re.swift:1:11 - line:1:49]
      (parameter "encoded" type='String' interface type='String')//定义局部变量
      (parameter "keyValue" type='String' interface type='String'))
    (result
      (type_ident
        (component id='Bool' bind=Swift.(file).Bool)))//返值回类型
```

swift AST的结构看似复杂，实际上还是比较妙的，毕竟这种文件其中一个作用就是用来检查代码的正确与否，所以细节和严谨是必须的，加上注释，可以说是一目了然

0x03 变量赋值
=========

```php
  (argument
        (integer_literal_expr type='Int' location=re.swift:6:55 range=[re.swift:6:55 - line:6:55] value=3 builtin_initializer=Swift.(file).Int.init(_builtinIntegerLiteral:) initializer=**NULL**))
                        )))
```

按上述格式，swift变量赋值大概有如下四个关键参数

type：变量类型

range：范围（没弄明白什么意思）

value：变量值（这个好理解）

initializer：初始值设定项 一般为null

list转换为字符数组
-----------

```php
(argument_list
            (argument
              (member_ref_expr type='String.UTF8View' location=re.swift:2:29 range=[re.swift:2:21 - line:2:29] decl=Swift.(file).String extension.utf8
                (declref_expr type='String' location=re.swift:2:21 range=[re.swift:2:21 - line:2:21] decl=re.(file).check(_:_:).encoded@re.swift:1:14 function_ref=unapplied)))//@的方式给函数传参
          ))
```

上述代码可以翻译成

```php
encoded.encode('utf8')
```

encode函数在这种奇奇怪怪的表达形式中是如何被调用的呢，仔细观察了一波发现好像是因为encoded@re.swift

循环结构
----

如下代码声明了一个for循环，定义了循环变量

```php
 (for_each_stmt range=[re.swift:5:5 - line:12:5]
        (pattern_named type='Int' 'i')
        (pattern_named type='Int' 'i')
        (binary_expr type='ClosedRange<Int>' location=re.swift:5:15 range=[re.swift:5:14 - line:5:26] nothrow
          (dot_syntax_call_expr implicit type='(Int, Int) -> ClosedRange<Int>' location=re.swift:5:15 range=[re.swift:5:15 - line:5:15] nothrow
            (declref_expr type='(Int.Type) -> (Int, Int) -> ClosedRange<Int>' location=re.swift:5:15 range=[re.swift:5:15 - line:5:15] decl=Swift.(file).Comparable extension.... [with (substitution_map generic_signature=<Self where Self : Comparable> (substitution Self -> Int))] function_ref=double)
            (argument_list implicit
              (argument
                (type_expr implicit type='Int.Type' location=re.swift:5:15 range=[re.swift:5:15 - line:5:15] typerepr='Int'))
            ))
```

计算
--

swift ast中，计算是怎么进行的呢。了解如下几个概念，方能拨云见日

### .extersion

我们要注意程序中的.extersion后缀 后面存储的是运算符号，比如此处，存储了我们的加号

![image-20220530062154140](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-917076dfd04f2739afea428ceb9325a0b953296a.png)

本题目中出现的.extersion

```php
.extersion +
.extersion -
.extersion &
.extersion >>
.extersion ^
.extersion count # 计算数组长度。相当于len()
.extersion subscript # subscript b = b[] 原谅笔者语文水平不佳，不知道如何形容了
extension. ... # 不知道是啥，和循环有关
```

运算顺序：先符号后数据
-----------

什么意思呢，我们看如下一段实例(去除了非关键代码)

```php
  (subscript_expr type='@lvalue UInt8' location=re.swift:6:44 range=[re.swift:6:43 - line:6:48] decl=Swift.(file).Array ##extension.subscript(_:)## [with (substitution_map generic_signature=<Element> (substitution Element -> UInt8))]
  (declref_expr type='@lvalue [UInt8]' location=re.swift:6:43 range=[re.swift:6:43 - line:6:43] decl=re.(file).check(_:_:).##b@re.swift##:2:9 function_ref=unapplied))
  // 加## 的地方是标出要关注的重点 
  //
```

subscript 英文意思：下标的；写在下方的；脚注的。这里作为一种运算，subscript b = b\[\](初始化了一个数组 b)

```php
(declref_expr type='(Int.Type) -> (Int, Int) -> Int' location=re.swift:6:46 range=[re.swift:6:46 - line:6:46] decl=Swift.(file).Int## extension.+ ##function_ref=double)
    (declref_expr type='Int' location=re.swift:6:45 range=[re.swift:6:45 - line:6:45] decl=re.(file).check(_:_:).##i##@re.swift:5:9 function_ref=unapplied))
       (integer_literal_expr type='Int' location=re.swift:6:47 range=[re.swift:6:47 - line:6:47] ##value=2 ##builtin_initializer=Swift.(file).Int.init(_builtinIntegerLiteral:) initializer=**NULL**))
```

第一句是说把两个int变量做加法运算。第二三句分别给加法运算所需的变量赋值 及i+2；

以上结合起来则翻译成：

```php
b[i+2]
```

未解决的问题：range是什么？
----------------

例：

```php
range=[re.swift:5:15 - line:5:15]
```

re.swift:-line:这个代表什么，没搞明白，希望有明白的大佬能给弟弟传授一二（猜测和地址有关）。

0x04 题目回顾：baby\_tree
====================

题目给出了一个 swift ast文件。

p.s:原来从来没见过这种类型的逆向。

非常有趣，一开始蒙蔽了

思路类似于python 给出opcode字节码。鄙人不才采用手撕的办法得到源码

![image-20220529134135336](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fd0a5997f4339f153d62064ba6faae4afaa192c2.png)

这里定义了check函数。定义了两个变量 encode keyvalue

函数内定义了两个字符数组，b k 分别为 encode，keyvalue的值

![image-20220529134521297](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-143f53a025d5fcb6dd16989b29ced99dc396358a.png)

![image-20220529134531104](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ab7356008d78c894efdba8e1587783a483b23e56.png)

数据来源在下方代码中有定义，这样就能推出如下部分源码

```python
def check(encoded,keyValue):
    b= bytearray(encoded.encode('utf8'))
    k= bytearray(encoded.encode('utf8'))
```

![image-20220529141356512](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-34501c2f1a99e3acf097b0a1c7ef86f6ebd72b8b.png)

![image-20220529141501662](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b894f5eca4a2348028bbba3e020e96768c009a2e.png)

结合着两处可以推出

```php
 b[i + 1] = r3 ^ ((k[1] + (r0 >> 2)) & 0xff)
```

同理，我们恢复到

```python
 for i in range(len(b)-4+1):
        r0,r1,r2,r3=b[i],b[i+1],b[i+2],b[i+3]
        b[i+0]=r2^((k[0]+(r0>>4))&0xff)
        b[i + 1] = r3 ^ ((k[1] + (r0 >> 2)) & 0xff)
        b[i + 2] = r0 ^ k[2]
        b[i + 3] = r1 ^ k[3]
```

根据下述两张图片，反写出

```php
 k[0],k[1],k[2],k[3]=k[1],k[2],k[3],k[0]
```

![image-20220529141724265](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e542b3722287fed73feeba3f596787903f4554f0.png)

![image-20220529141733405](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-84feef3cf7dde8350bec51b5aadc67f0f30a54cc.png)

encode数据

![image-20220529134826403](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8fcf0d2b7ec14770b3f4fa2e3bf313b7be68b534.png)

keyvalue

![image-20220529134855986](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-75522d941769d259ca24b72d4777d88fe0c02b58.png)

最终得到大致加密源码如下

```python
def check(encoded, keyValue):
    b = bytearray(encoded.encode('utf8'))
    k = bytearray(keyValue.encode('utf8'))
    for i in range(len(b)-4+1):
        r0,r1,r2,r3=b[i],b[i+1],b[i+2],b[i+3]
        b[i+0]=r2^((k[0]+(r0>>4))&0xff)
        b[i + 1] = r3 ^ ((k[1] + (r0 >> 2)) & 0xff)
        b[i + 2] = r0 ^ k[2]
        b[i + 3] = r1 ^ k[3]
        k[0],k[1],k[2],k[3]=k[1],k[2],k[3],k[0]
    return b ==bytes[flag加密后数据]
check(flag,'345y')
```

根据加密源码写脚本解密即可得到flag

0x05 参考文章
=========

<https://cloud.tencent.com/developer/article/1858023>