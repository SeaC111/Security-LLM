近期的CTF比赛中，python类题目在re题目占比快速上升，为了跟上时代，我们不得不系统学习一下python逆向，目前出现的python类题目，按照给出附件种类主要分为四种：pyc文件/给出pyc字节码txt/加花pyc/打包成exe的py文件

0x00 前言
=======

这篇文章开始之前要特别鸣谢ppppz师傅，做出了这么好的一期python逆向入门总结视频。俗话说的好，前人栽树，后人乘凉，让我们站在大佬的肩膀上继续学习总结。

觉得文章比较难以理解的可以去看看大佬的视频，人帅声甜吾辈楷模：

[https://www.bilibili.com/video/BV1JL4y1p7Tt?spm\_id\_from=333.999.0.0](https://www.bilibili.com/video/BV1JL4y1p7Tt?spm_id_from=333.999.0.0)

0x01 pyc文件类
===========

前置知识：pyc文件及pyc文件结构
------------------

pyc文件是python在编译过程中出现的**主要中间过程**文件,是一种**二进制**文件，是由py文件经过编译后，生成的文件，是一种**byte code**。pyc文件是可以由python虚拟机直接执行的程序。因此分析**pyc文件的文件结构**对于实现python编译与反编译就显得十分重要。pyc py文件变成pyc文件后，**加载的速度有所提高**，而且pyc是一种跨 平台的字节码，这个是类似于JAVA或者.NET的虚拟机的概念。**pyc的内容，是跟python的版本相关的**，不同 版本编译后的pyc文件是不同的，2.5编译的pyc文件，**2.4版本的python是无法执行的。**

Python代码的编译结果就是PyCodeObject对象。PyCodeObject对象可以由虚拟机加载后直接运行，而pyc文件就是PyCodeObject对象在硬盘上的保存形式。因此我们先分析PyCodeObject对象的结构，随后再涉及pyc文件的二进制结构。

下图展示了pyc文件的完整格式

![86d1ebfa6c7c3a5cdc6ed45768acb9cc.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b32d6bacf2db1b83694c1363cf46b2ffc497633d.png)

这里不再赘述，一个简单的实例分析可以看如下这篇大佬文章

[https://blog.csdn.net/weixin\_35967330/article/details/114390031?spm=1001.2014.3001.5501](https://blog.csdn.net/weixin_35967330/article/details/114390031?spm=1001.2014.3001.5501)

pyc类题目处理
--------

uncompyle6直接反编译即可。不过现在裸的pyc越来越少了，一般需要加花

的安装，直接上pip

```php
pip install uncompyle6
```

uncompyle6反编译实例：

![image-20220525024108641](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-207d406a74ab9337bf1f899bfa959f558b2bef55.png)

0x02 给出pyc字节码类
==============

前置知识：pyc字节码是什么
--------------

Python实际上将源代码编译为一组虚拟机指令，Python的解释器就是该虚拟机的一个具体实现。这种跑在虚拟机内部的中间格式被称为“字节码”。

python字节码个人感觉有一点类似于汇编代码，但是比汇编代码易读，所以大家不必太过担心。

pyc字节码类题目处理
-----------

使用库对pyc文件逆向，代码如下

```python
import dis
import marshal
f=open("printname.pyc","rb")
b_data=f.read()
f.close()
PyCodeObjectData=b_data[8:]
Pyobj=marshal.loads(PyCodeObjectData)
dis.dis(Pyobj)
```

运行以上代码可以将pyc转换为字节码

```php
1.读py字节码

2.根据opcode文件查询意思
```

pyc类题目让我想起了vm虚拟机题目，都是需要将类汇编语言转化为高级语言~如果感觉pyc字节码类题目难理解的话可以联想理解一下。

### 例题1：浙江省赛某题目（感谢pz师傅）

```php
 0 LOAD_CONST               0 ()
              2 LOAD_CONST               1 ('keyinit')
              4 MAKE_FUNCTION            0
              6 STORE_NAME               0 (keyinit)

  8           8 LOAD_NAME                1 (__name__)
             10 LOAD_CONST               2 ('__main__')
             12 COMPARE_OP               2 (==)
             14 POP_JUMP_IF_FALSE      250

  9          16 LOAD_NAME                2 (print)
             18 LOAD_CONST               3 ('Can you crack pyc?')
             20 CALL_FUNCTION            1
             22 POP_TOP

 10          24 LOAD_NAME                3 (input)
             26 LOAD_CONST               4 ('Plz give me your flag:')
             28 CALL_FUNCTION            1
             30 STORE_NAME               4 (str)

 11          32 LOAD_CONST               5 (108)
             34 LOAD_CONST               6 (17)
             36 LOAD_CONST               7 (42)
             38 LOAD_CONST               8 (226)
             40 LOAD_CONST               9 (158)
             42 LOAD_CONST              10 (180)
             44 LOAD_CONST              11 (96)
             46 LOAD_CONST              12 (115)
             48 LOAD_CONST              13 (64)
             50 LOAD_CONST              14 (24)
             52 LOAD_CONST              15 (38)
             54 LOAD_CONST              16 (236)
             56 LOAD_CONST              17 (179)
             58 LOAD_CONST              18 (173)
             60 LOAD_CONST              19 (34)
             62 LOAD_CONST              20 (22)
             64 LOAD_CONST              21 (81)
             66 LOAD_CONST              22 (113)
             68 LOAD_CONST              15 (38)
             70 LOAD_CONST              23 (215)
             72 LOAD_CONST              24 (165)
             74 LOAD_CONST              25 (135)
             76 LOAD_CONST              26 (68)
             78 LOAD_CONST              27 (7)

 12          80 LOAD_CONST              28 (119)
             82 LOAD_CONST              29 (97)
             84 LOAD_CONST              30 (45)
             86 LOAD_CONST              31 (254)
             88 LOAD_CONST              32 (250)
             90 LOAD_CONST              33 (172)
             92 LOAD_CONST              34 (43)
             94 LOAD_CONST              35 (62)
             96 BUILD_LIST              32
             98 STORE_NAME               5 (text)

 13         100 LOAD_NAME                6 (len)
            102 LOAD_NAME                4 (str)
            104 CALL_FUNCTION            1
            106 LOAD_CONST              36 (32)
            108 COMPARE_OP               3 (!=)
            110 POP_JUMP_IF_TRUE       140
            112 LOAD_NAME                4 (str)
            114 LOAD_CONST              37 (0)
            116 LOAD_CONST              27 (7)
            118 BUILD_SLICE              2
            120 BINARY_SUBSCR
            122 LOAD_CONST              38 ('DASCTF{')
            124 COMPARE_OP               3 (!=)
            126 POP_JUMP_IF_TRUE       140
            128 LOAD_NAME                4 (str)
            130 LOAD_CONST              39 (31)
            132 BINARY_SUBSCR
            134 LOAD_CONST              40 ('}')
            136 COMPARE_OP               3 (!=)
            138 POP_JUMP_IF_FALSE      154

 14     >>  140 LOAD_NAME                2 (print)
            142 LOAD_CONST              41 ('Bye bye~~')
            144 CALL_FUNCTION            1
            146 POP_TOP

 15         148 LOAD_NAME                7 (exit)
            150 CALL_FUNCTION            0
            152 POP_TOP

 16     >>  154 LOAD_NAME                8 (list)
            156 LOAD_NAME                4 (str)
            158 CALL_FUNCTION            1
            160 STORE_NAME               9 (st)

 17         162 BUILD_LIST               0
            164 STORE_NAME              10 (key)

 18         166 LOAD_NAME                0 (keyinit)
            168 LOAD_NAME               10 (key)
            170 CALL_FUNCTION            1
            172 POP_TOP

 19         174 SETUP_LOOP              48 (to 224)
            176 LOAD_NAME               11 (range)
            178 LOAD_CONST              36 (32)
            180 CALL_FUNCTION            1
            182 GET_ITER
        >>  184 FOR_ITER                36 (to 222)
            186 STORE_NAME              12 (i)

 20         188 LOAD_NAME               13 (ord)
            190 LOAD_NAME                4 (str)
            192 LOAD_NAME               12 (i)
            194 BINARY_SUBSCR
            196 CALL_FUNCTION            1
            198 LOAD_NAME               10 (key)
            200 LOAD_NAME               12 (i)
            202 LOAD_NAME                6 (len)
            204 LOAD_NAME               10 (key)
            206 CALL_FUNCTION            1
            208 BINARY_MODULO
            210 BINARY_SUBSCR
            212 BINARY_XOR
            214 LOAD_NAME                9 (st)
            216 LOAD_NAME               12 (i)
            218 STORE_SUBSCR
            220 JUMP_ABSOLUTE          184
        >>  222 POP_BLOCK

 21     >>  224 LOAD_NAME                9 (st)
            226 LOAD_NAME                5 (text)
            228 COMPARE_OP               2 (==)
            230 POP_JUMP_IF_FALSE      242

 22         232 LOAD_NAME                2 (print)
            234 LOAD_CONST              42 ('Congratulations and you are good at PYC!')
            236 CALL_FUNCTION            1
            238 POP_TOP
            240 JUMP_FORWARD             8 (to 250)

 24     >>  242 LOAD_NAME                2 (print)
            244 LOAD_CONST              43 ('Sorry,plz learn more about pyc.')
            246 CALL_FUNCTION            1
            248 POP_TOP
        >>  250 LOAD_CONST              44 (None)
            252 RETURN_VALUE

Disassembly of :
  2           0 LOAD_CONST               1 (0)
              2 STORE_FAST               1 (num)

  3           4 SETUP_LOOP              42 (to 48)
              6 LOAD_GLOBAL              0 (range)
              8 LOAD_CONST               2 (8)
             10 CALL_FUNCTION            1
             12 GET_ITER
        >>   14 FOR_ITER                30 (to 46)
             16 STORE_FAST               2 (i)

  4          18 LOAD_FAST                1 (num)
             20 LOAD_CONST               3 (7508399208111569251)
             22 BINARY_SUBTRACT
             24 LOAD_CONST               4 (4294967295)
             26 BINARY_MODULO
             28 STORE_FAST               1 (num)

  5          30 LOAD_FAST                0 (key)
             32 LOAD_METHOD              1 (append)
             34 LOAD_FAST                1 (num)
             36 LOAD_CONST               5 (24)
             38 BINARY_RSHIFT
             40 CALL_METHOD              1
             42 POP_TOP
             44 JUMP_ABSOLUTE           14
        >>   46 POP_BLOCK
        >>   48 LOAD_CONST               0 (None)
             50 RETURN_VALUE
```

获取到字节码之后，其实没什么好说的，和虚拟机逆向有opcode并且有对应汇编表一个道理，纯纯苦力活。 题目逻辑很简单，将给出加密flag 和特定密码表每8位一异或得到flag。下面详细讲解一下获取密钥部分的翻译。

密钥函数字节码

```php
Disassembly of :
  2           0 LOAD_CONST               1 (0)
              2 STORE_FAST               1 (num)

  3           4 SETUP_LOOP              42 (to 48)
              6 LOAD_GLOBAL              0 (range)
              8 LOAD_CONST               2 (8)
             10 CALL_FUNCTION            1
             12 GET_ITER
        >>   14 FOR_ITER                30 (to 46)
             16 STORE_FAST               2 (i)

  4          18 LOAD_FAST                1 (num)
             20 LOAD_CONST               3 (7508399208111569251)
             22 BINARY_SUBTRACT
             24 LOAD_CONST               4 (4294967295)
             26 BINARY_MODULO
             28 STORE_FAST               1 (num)

  5          30 LOAD_FAST                0 (key)
             32 LOAD_METHOD              1 (append)
             34 LOAD_FAST                1 (num)
             36 LOAD_CONST               5 (24)
             38 BINARY_RSHIFT
             40 CALL_METHOD              1
             42 POP_TOP
             44 JUMP_ABSOLUTE           14
        >>   46 POP_BLOCK
        >>   48 LOAD_CONST               0 (None)
             50 RETURN_VALUE
```

首先是一个循环体

```php
 4 SETUP_LOOP              42 (to 48)
              6 LOAD_GLOBAL              0 (range)
              8 LOAD_CONST               2 (8)
             10 CALL_FUNCTION            1
             12 GET_ITER
        >>   14 FOR_ITER                30 (to 46)
             16 STORE_FAST               2 (i)
```

翻译一下就是

```php
for i in range(8):
```

接下来将num 以及7508399208111569251入栈

```php
  18 LOAD_FAST                1 (num)
  20 LOAD_CONST              3(7508399208111569251)
  22 BINARY_SUBTRACT
```

查表了解到BINARY\_SUBTRACT是指减法操作

![](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ebba2f5695ec7ba3e993cf731d3473696ce3253c.png)

接着与4294967295取模

```php
 24 LOAD_CONST               4 (4294967295)
             26 BINARY_MODULO
             28 STORE_FAST               1 (num)

  5          30 LOAD_FAST                0 (key)
             32 LOAD_METHOD              1 (append)
             34 LOAD_FAST                1 (num)
```

组合一下就是

```php
 num=(num-7508399208111569251)%4294967295
```

```php
30 LOAD_FAST                0 (key)
             32 LOAD_METHOD              1 (append)
             34 LOAD_FAST                1 (num)
             36 LOAD_CONST               5 (24)
             38 BINARY_RSHIFT
             40 CALL_METHOD              1
             42 POP_TOP
             44 JUMP_ABSOLUTE           14
        >>   46 POP_BLOCK
        >>   48 LOAD_CONST               0 (None)
             50 RETURN_VALUE
```

BINARY\_RSHIFT查表是位移右运算，整体组合下来就是

```python
num=0
for i in range(8):
    num=(num-7508399208111569251)%4294967295
    print(num>>24)
```

运行得到密钥

![image-20220525100925716](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a9cf2f9407d44644cf2a3d2c56513977127bb80b.png)

就如这般分析上文代码,得到是一个循环key异或

```php
 188 LOAD_NAME               13 (ord)
            190 LOAD_NAME                4 (str)
            192 LOAD_NAME               12 (i)
            194 BINARY_SUBSCR
            196 CALL_FUNCTION            1
            198 LOAD_NAME               10 (key)
            200 LOAD_NAME               12 (i)
            202 LOAD_NAME                6 (len)
            204 LOAD_NAME               10 (key)
            206 CALL_FUNCTION            1
            208 BINARY_MODULO
            210 BINARY_SUBSCR
            212 BINARY_XOR
            214 LOAD_NAME                9 (st)
            216 LOAD_NAME               12 (i)
            218 STORE_SUBSCR
            220 JUMP_ABSOLUTE          184
        >>  222 POP_BLOCK
```

翻译出来

```python
for i in range(32):
flag+=chr(ord(str[i])^key(i%len(key)))
```

这样组合得到最终脚本。

```python
a=[108,17,42,226,158,180,96,115,64,24,38,236,179,173,34,22,81,113,38,215,165,135,68,7,119,97,45,254,250,172,43,62]
b=[40,80,121,161,202,242,27,67]
for i in range(32):
    print(chr(a[i]^b[i%8]),end="")
flag:DASCTF{0hH_My_9Uy!_vou_D_1T_0^0}
```

### 例题2：不知出处

趁热打铁，再做一道。

```php
Disassembly of a:
  3           0 LOAD_CONST               1 (0)
              2 BUILD_LIST               1
              4 LOAD_GLOBAL              0 (len)
              6 LOAD_FAST                0 (s)
              8 CALL_FUNCTION            1
             10 BINARY_MULTIPLY
             12 STORE_FAST               1 (o)

  4          14 LOAD_GLOBAL              1 (enumerate)
             16 LOAD_FAST                0 (s)
             18 CALL_FUNCTION            1
             20 GET_ITER
        >>   22 FOR_ITER                24 (to 48)
             24 UNPACK_SEQUENCE          2
             26 STORE_FAST               2 (i)
             28 STORE_FAST               3 (c)

  5          30 LOAD_FAST                3 (c)
             32 LOAD_CONST               2 (2)
             34 BINARY_MULTIPLY
             36 LOAD_CONST               3 (60)
             38 BINARY_SUBTRACT
             40 LOAD_FAST                1 (o)
             42 LOAD_FAST                2 (i)
             44 STORE_SUBSCR
             46 JUMP_ABSOLUTE           22

  6     >>   48 LOAD_FAST                1 (o)
             50 RETURN_VALUE

Disassembly of b:
  9           0 LOAD_GLOBAL              0 (zip)
              2 LOAD_FAST                0 (s)
              4 LOAD_FAST                1 (t)
              6 CALL_FUNCTION            2
              8 GET_ITER
        >>   10 FOR_ITER                22 (to 34)
             12 UNPACK_SEQUENCE          2
             14 STORE_FAST               2 (x)
             16 STORE_FAST               3 (y)

 10          18 LOAD_FAST                2 (x)
             20 LOAD_FAST                3 (y)
             22 BINARY_ADD
             24 LOAD_CONST               1 (50)
             26 BINARY_SUBTRACT
             28 YIELD_VALUE
             30 POP_TOP
             32 JUMP_ABSOLUTE           10
        >>   34 LOAD_CONST               0 (None)
             36 RETURN_VALUE

Disassembly of c:
 13           0 LOAD_CONST               1 ( at 0x7ff31a16f0e0, file "vuln.py", line 13>)
              2 LOAD_CONST               2 ('c.<locals>.<listcomp>')
              4 MAKE_FUNCTION            0
              6 LOAD_FAST                0 (s)
              8 GET_ITER
             10 CALL_FUNCTION            1
             12 RETURN_VALUE

Disassembly of  at 0x7ff31a16f0e0, file "vuln.py", line 13>:
 13           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                12 (to 18)
              6 STORE_FAST               1 (c)
              8 LOAD_FAST                1 (c)
             10 LOAD_CONST               0 (5)
             12 BINARY_ADD
             14 LIST_APPEND              2
             16 JUMP_ABSOLUTE            4
        >>   18 RETURN_VALUE

Disassembly of e:
 16           0 LOAD_CONST               1 ( at 0x7ff31a16f240, file "vuln.py", line 16>)
              2 LOAD_CONST               2 ('e.<locals>.<listcomp>')
              4 MAKE_FUNCTION            0
              6 LOAD_FAST                0 (s)
              8 GET_ITER
             10 CALL_FUNCTION            1
             12 STORE_FAST               0 (s)

 17          14 LOAD_CONST               3 ( at 0x7ff31a16f2f0, file "vuln.py", line 17>)
             16 LOAD_CONST               2 ('e.<locals>.<listcomp>')
             18 MAKE_FUNCTION            0
             20 LOAD_GLOBAL              0 (b)
             22 LOAD_GLOBAL              1 (a)
             24 LOAD_FAST                0 (s)
             26 CALL_FUNCTION            1
             28 LOAD_GLOBAL              2 (c)
             30 LOAD_FAST                0 (s)
             32 CALL_FUNCTION            1
             34 CALL_FUNCTION            2
             36 GET_ITER
             38 CALL_FUNCTION            1
             40 STORE_FAST               1 (o)

 18          42 LOAD_GLOBAL              3 (bytes)
             44 LOAD_FAST                1 (o)
             46 CALL_FUNCTION            1
             48 RETURN_VALUE

Disassembly of  at 0x7ff31a16f240, file "vuln.py", line 16>:
 16           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                12 (to 18)
              6 STORE_FAST               1 (c)
              8 LOAD_GLOBAL              0 (ord)
             10 LOAD_FAST                1 (c)
             12 CALL_FUNCTION            1
             14 LIST_APPEND              2
             16 JUMP_ABSOLUTE            4
        >>   18 RETURN_VALUE

Disassembly of  at 0x7ff31a16f2f0, file "vuln.py", line 17>:
 17           0 BUILD_LIST               0
              2 LOAD_FAST                0 (.0)
        >>    4 FOR_ITER                16 (to 22)
              6 STORE_FAST               1 (c)
              8 LOAD_FAST                1 (c)
             10 LOAD_CONST               0 (5)
             12 BINARY_XOR
             14 LOAD_CONST               1 (30)
             16 BINARY_SUBTRACT
             18 LIST_APPEND              2
             20 JUMP_ABSOLUTE            4
        >>   22 RETURN_VALUE

Disassembly of main:
 21           0 LOAD_GLOBAL              0 (input)
              2 LOAD_CONST               1 ('Guess?')
              4 CALL_FUNCTION            1
              6 STORE_FAST               0 (s)

 22           8 LOAD_CONST               2 (b'\xae\xc0\xa1\xab\xef\x15\xd8\xca\x18\xc6\xab\x17\x93\xa8\x11\xd7\x18\x15\xd7\x17\xbd\x9a\xc0\xe9\x93\x11\xa7\x04\xa1\x1c\x1c\xed')
             10 STORE_FAST               1 (o)

 23          12 LOAD_GLOBAL              1 (e)
             14 LOAD_FAST                0 (s)
             16 CALL_FUNCTION            1
             18 LOAD_FAST                1 (o)
             20 COMPARE_OP               2 (==)
             22 POP_JUMP_IF_FALSE       34

 24          24 LOAD_GLOBAL              2 (print)
             26 LOAD_CONST               3 ('Correct!')
             28 CALL_FUNCTION            1
             30 POP_TOP
             32 JUMP_FORWARD             8 (to 42)

 26     >>   34 LOAD_GLOBAL              2 (print)
             36 LOAD_CONST               4 ('Wrong...')
             38 CALL_FUNCTION            1
             40 POP_TOP
        >>   42 LOAD_CONST               0 (None)
             44 RETURN_VALUE
```

本题的结构为main函数+多函数组合。这样的话，我们采取先看main函数，再逐个分析函数的策略。

main函数,可说的就if函数这一部分，最后一行的 POP\_JUMP\_IF\_FALSE 表明这是个if判断语句

```php
        12 LOAD_GLOBAL              1 (e)
             14 LOAD_FAST                0 (s)
             16 CALL_FUNCTION            1
             18 LOAD_FAST                1 (o)
             20 COMPARE_OP               2 (==)
             22 POP_JUMP_IF_FALSE       34
```

翻译一下就是

```php
if(e[s]==o):
```

这样我们就可以毫不费力地翻译出main函数

```php
s=input("Guess!")
o=b'\xae\xc0\xa1\xab\xef\x15\xd8\xca\x18\xc6\xab\x17\x93\xa8\x11\xd7\x18\x15\xd7\x17\xbd\x9a\xc0\xe9\x93\x11\xa7\x04\xa1\x1c\x1c\xed'

if e(s)==o:
    print('Correct!')
else:
    print('Wrong...')
```

其他abcde几个函数 的翻译难点，主要在于 对字节码 函数来回之间调用涉及的语句不明白。我们来看一下最复杂的e函数

```php
             20 LOAD_GLOBAL              0 (b)
             #22~26行 调用了a(s),28~32 调用了b（s）
             22 LOAD_GLOBAL              1 (a)
             24 LOAD_FAST                0 (s)
             26 CALL_FUNCTION            1
             28 LOAD_GLOBAL              2 (c)
             30 LOAD_FAST                0 (s)
             32 CALL_FUNCTION            1
             34 CALL_FUNCTION            2
             #第20行+34行 call function后面的参数为2 包裹了整体调用 a(s),c(s)成了 a()，c()中的s
```

这几行的翻译非常有意思，看我的注释:  
翻译出来很简单

```php
b(a(s),c(s))
```

接着倒上去看函数e的第16行，首先我们发现结果存在s中，然后将一个函数带着参数s返回。

```php
 4 FOR_ITER                12 (to 18)
              6 STORE_FAST               1 (c)
              8 LOAD_GLOBAL              0 (ord)
             10 LOAD_FAST                1 (c)
             12 CALL_FUNCTION            1
             14 LIST_APPEND              2
             16 JUMP_ABSOLUTE            4
        >>   18 RETURN_VALUE
```

结合看函数，发现这是做一个循环，将每一个元素c转换为ord(c)返回。所以我们猜测这里应该是s=\[ord(c) for c in s\]。

```php
              4 FOR_ITER                16 (to 22)
              6 STORE_FAST               1 (c)
              8 LOAD_FAST                1 (c)
             10 LOAD_CONST               0 (5)
             12 BINARY_XOR
             14 LOAD_CONST               1 (30)
             16 BINARY_SUBTRACT
             18 LIST_APPEND              2
             20 JUMP_ABSOLUTE            4
        >>   22 RETURN_VALUE
```

第17行类似于上一行，不同的是函数里的参数，首先第一个函数b有两个参数，每个参数又在调用一个有一个参数s的函数a,c。所以这里应该是

```php
o=[(c^5)-30 for c in b(a(s),c(s))]。
```

按照这样的逻辑再去翻译其他函数即可

完整代码

```python
def a(s):
    o=[0]*len(s)
    for i,c in enumerate(s):
        o[i]=c*2-60
    return o

def b(s,t):
    for (x,y) in zip(s,t):
        yield x+y-50
def c(s):
    return [(c+5) for c in s]

def e(s):
    s=[ord(c) for c in s]
    o=[(c^5)-30 for c in b(a(s),c(s))]
    return bytes(o)

s=input("Guess!")
o=b'\xae\xc0\xa1\xab\xef\x15\xd8\xca\x18\xc6\xab\x17\x93\xa8\x11\xd7\x18\x15\xd7\x17\xbd\x9a\xc0\xe9\x93\x11\xa7\x04\xa1\x1c\x1c\xed'

if e(s)==o:
    print('Correct!')
else:
    print('Wrong...')
```

逆向解题：

```python
o=b'\xae\xc0\xa1\xab\xef\x15\xd8\xca\x18\xc6\xab\x17\x93\xa8\x11\xd7\x18\x15\xd7\x17\xbd\x9a\xc0\xe9\x93\x11\xa7\x04\xa1\x1c\x1c\xed'
ll=[]
for i in o:
ll.append((((int(i.encode("hex"),16)+30)^5)+50+55)//3)
m=""
for ii in ll:
        m=m+chr(ii)
print(m)
```

### 例题3：\[羊城杯 2020\]Bytecode

没什么要多说的，这种题就是硬翻译

注意这种load+store形式的翻译

```php
    125 LOAD_NAME                3 (flag)
    128 STORE_NAME               4 (str)
    翻译：str=flag
```

得到源码

```python
en = [3, 37, 72, 9, 6, 132]
output = [101, 96, 23, 68, 112, 42, 107, 62, 96, 53, 176, 179,
          98, 53, 67, 29, 41, 120, 60, 106, 51, 101, 178, 189, 101, 48]

print('welcome to GWHT2020')

flag = input('please input your flag:')
str = flag

a = len(str)
if a < 38:
    print('lenth wrong!')
    exit(0)

if ord(str[0]) + 2020 * ord(str[1]) + 2020 * ord(str[3]) + 2020 * ord(str[4]) == 1182843538814603:
    print('good!continue\xe2\x80\xa6\xe2\x80\xa6')
else:
    print('bye~')
    exit(0)

x = []
k = 5
for i in range(13):
    b = ord(str[k])
    c = ord(str[k + 1])
    a11 = c ^ en[i % 6]
    a22 = b ^ en[i % 6]
    x.append(a11)
    x.append(a22)
    k += 2
if x == output:
    print('good!continue\xe2\x80\xa6\xe2\x80\xa6')
else:
    print('oh,you are wrong!')
    exit(0)

l = len(str)
a1 = ord(str[l - 7])
a2 = ord(str[l - 6])
a3 = ord(str[l - 5])
a4 = ord(str[l - 4])
a5 = ord(str[l - 3])
a6 = ord(str[l - 2])
if a1 * 3 + a2 * 2 + a3 * 5 == 1003:
    if a1 * 4 + a2 * 7 + a3 * 9 == 2013:
        if a1 + a2 * 8 + a3 * 2 == 1109:
            if a1 * 3 + a5 * 2 + a6 * 5 == 671:
                if a4 * 4 + a5 * 7 + a6 * 9 == 1252:
                    if a4 + a5 * 8 + a6 * 2 == 644:
                        print('congraduation!you get the right flag!')

```

构造相应exp：

```python
# EXP

from z3 import *

en = [3, 37, 72, 9, 6, 132]
output = [101, 96, 23, 68, 112, 42, 107, 62, 96, 53, 176, 179, 98, 53, 67, 29, 41, 120, 60, 106, 51, 101, 178, 189, 101,
          48]
flag = ''
k = 0
x = []

for i in range(13):
    c = chr(output[k] ^ en[i % 6])
    b = chr(output[k + 1] ^ en[i % 6])
    x.append(b)
    x.append(c)
    k += 2

flag = ''.join(x)
# print(flag)

a1 = Int('a1')
a2 = Int('a2')
a3 = Int('a3')
a4 = Int('a4')
a5 = Int('a5')
a6 = Int('a6')
s = Solver()
s.add(a1 * 3 + a2 * 2 + a3 * 5 == 1003)
s.add(a1 * 4 + a2 * 7 + a3 * 9 == 2013)
s.add(a1 + a2 * 8 + a3 * 2 == 1109)
s.add(a4 * 3 + a5 * 2 + a6 * 5 == 671)
s.add(a4 * 4 + a5 * 7 + a6 * 9 == 1252)
s.add(a4 + a5 * 8 + a6 * 2 == 644)

if s.check() == sat:
    result = s.model()
print(result)

s = [97, 101, 102, 102, 55, 51]
for i in range(6):
    flag += chr(s[i])
print(flag)
```

0x03 加花的pyc类
============

根据uncompyle6和字节码判断花
-------------------

可以看到在第七行停住了，说明此处存在阻碍反编译的花指令

![image-20220525233810707](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f2eae8207baa19e593c2b5c8ca43420d12cf209d.png)

读取co\_code长度
------------

**何谓co\_code?**

co\_code ：字节码指令序列，字节码都由操作码 opcode 和参数 opatg 组成的序列。记录着指令数量，指令的增加和减少都会影响该值。

获取该值的方式很简单，键入len（code.co\_code）即可获取

![image-20220525234746110](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-22948f9e03cd7ce187f36fa885ef64a1201e6a71.png)

去花并修改co\_code 长度
----------------

接下来我们就要尝试去花了，使用010editor打开pyc文件，然鹅我们面临一个新的问题，怎么在二进制格式中定位花指令的位置呢

![image-20220525235137780](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0af4820862a39b3e5649c5de0dac172d9d34236e.png)

首先找到python2 文件目录下的opcode.h文件，其中存储着所有opcode以及其对应的值。

![image-20220526000501276](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-758d96879170edd123322567ebc523f694ec2097.png)

![image-20220526000009834](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-74e58f0f58611b97799b0c99b5876449d0371782.png)

记得转换16进制113 转换16进制为71，100转换为64.

在010editor中搜索71和64，发现只存在一个71，且我们知道python2 中一条指令占3位，就能确定该六位是我们需要的花指令，选中后直接按退格键删掉。

![image-20220526000548792](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2b5af3f49c7d0ad24dacfed76250f8ba2dcfb813.png)

然而光删除花指令并不能完成去花，我们保存文件后再次获取co\_code的值 仍为27 。说明我们的去花工作还没结束，接下来还需要修改co\_code的值为21。

![image-20220526000729139](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b125ed7259c6c95e595180706505d80437f72e89.png)

仍然是在010editor中搜索27的十六进制（1B），找到后修改为hex（21）=15 之后保存文件，这样去花工作就完成了。

![image-20220526001025213](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b3449ccddd39e99f4a2b4abc33874bea33152271.png)

保存 uncompyle6反编译
----------------

保存好去花的文件就可以愉快的进行反编译了

![image-20220526001324255](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f34055c9eecec9ecb0f9e27669e81764622591c3.png)

0x04 打包成exe的py文件类
=================

### 例题：\[SangFor2020\]login

通过脚本变成结构体+一个文件

![image-20220525184814342](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-58b16c877e970ad932ece724432ab4d78525109a.png)

![image-20220525184830598](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-515dfa4c1deadcd273b43474f7a0e1f9589ca4ac.png)

把时间属性和版本的魔术字放回去保存  
具体到这个题将struct.pyc中的前12位复制粘贴到login.pyc中

![image-20220526211407468](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ffe4fc00a2d75e05de0650a487266b66efc9d148.png)  
uncompyle6即可

![image-20220525185840719](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2c94a93f84e18fff9b9052b445f569f92b7570e5.png)

不同版本的修复方法：

> 在Python3.7及以上版本的编译后二进制文件中，头部除了四字节Magic Number，还有四个字节的空位和八个字节的时间戳+大小信息，后者对文件反编译没有影响，全部填充0即可；  
> Python3.3 - Python3.7（包含3.3）版本中，只需要Magic Number和八位时间戳+大小信息  
> Python3.3 以下的版本中，只有Magic Number和四位时间戳  
> 用Winhex修复文件，在头部写入（非覆盖）上述格式的内容，就可以进行反编译了

继续回到解题：

看这个源码很明显的z3约束

```python
from z3 import *
def main():
    s=Solver()
    a1=Int('a1')
    a2=Int('a2')
    a3=Int('a3')
    a4=Int('a4')
    a5=Int('a5')
    a6=Int('a6')
    a7=Int('a7')
    a8=Int('a8')
    a9=Int('a9')
    a10=Int('a10')
    a11=Int('a11')
    a12=Int('a12')
    a13=Int('a13')
    a14=Int('a14')
    s.add(a1 * 88 + a2 * 67 + a3 * 65 - a4 * 5 + a5 * 43 + a6 * 89 + a7 * 25 + a8 * 13 - a9 * 36 + a10 * 15 + a11 * 11 + a12 * 47 - a13 * 60 + a14 * 29 == 22748)
    s.add(a1 * 89 + a2 * 7 + a3 * 12 - a4 * 25 + a5 * 41 + a6 * 23 + a7 * 20 - a8 * 66 + a9 * 31 + a10 * 8 + a11 * 2 - a12 * 41 - a13 * 39 + a14 * 17 == 7258)
    s.add(a1 * 28 + a2 * 35 + a3 * 16 - a4 * 65 + a5 * 53 + a6 * 39 + a7 * 27 + a8 * 15 - a9 * 33 + a10 * 13 + a11 * 101 + a12 * 90 - a13 * 34 + a14 * 23 == 26190)
    s.add(a1 * 23 + a2 * 34 + a3 * 35 - a4 * 59 + a5 * 49 + a6 * 81 + a7 * 25 + a8*128  - a9 * 32 + a10 * 75 + a11 * 81 + a12 * 47 - a13 * 60 + a14 * 29 == 37136)
    s.add(a1 * 38 + a2 * 97 + a3 * 35 - a4 * 52 + a5 * 42 + a6 * 79 + a7 * 90 + a8 * 23 - a9 * 36 + a10 * 57 + a11 * 81 + a12 * 42 - a13 * 62 - a14 * 11 == 27915)
    s.add(a1 * 22 + a2 * 27 + a3 * 35 - a4 * 45 + a5 * 47 + a6 * 49 + a7 * 29 + a8 * 18 - a9 * 26 + a10 * 35 + a11 * 41 + a12 * 40 - a13 * 61 + a14 * 28 == 17298)
    s.add(a1 * 12 + a2 * 45 + a3 * 35 - a4 * 9 - a5 * 42 + a6 * 86 + a7 * 23 + a8 * 85 - a9 * 47 + a10 * 34 + a11 * 76 + a12 * 43 - a13 * 44 + a14 * 65 == 19875)
    s.add(a1 * 79 + a2 * 62 + a3 * 35 - a4 * 85 + a5 * 33 + a6 * 79 + a7 * 86 + a8 * 14 - a9 * 30 + a10 * 25 + a11 * 11 + a12 * 57 - a13 * 50 - a14 * 9 == 22784)
    s.add(a1 * 8 + a2 * 6 + a3 * 64 - a4 * 85 + a5 * 73 + a6 * 29 + a7 * 2 + a8 * 23 - a9 * 36 + a10 * 5 + a11 * 2 + a12 * 47 - a13 * 64 + a14 * 27 == 9710)
    s.add(a1 * 67 - a2 * 68 + a3 * 68 - a4 * 51 - a5 * 43 + a6 * 81 + a7 * 22 - a8 * 12 - a9 * 38 + a10 * 75 + a11 * 41 + a12 * 27 - a13 * 52 + a14 * 31 == 13376)
    s.add(a1 * 85 + a2 * 63 + a3 * 5 - a4 * 51 + a5 * 44 + a6 * 36 + a7 * 28 + a8 * 15 - a9 * 6 + a10 * 45 + a11 * 31 + a12 * 7 - a13 * 67 + a14 * 78 == 24065)
    s.add(a1 * 47 + a2 * 64 + a3 * 66 - a4 * 5 + a5 * 43 + a6 * 112 + a7 * 25 + a8 * 13 - a9 * 35 + a10 * 95 + a11 * 21 + a12 * 43 - a13 * 61 + a14 * 20 == 27687)
    s.add(a1 * 89 + a2 * 67 + a3 * 85 - a4 * 25 + a5 * 49 + a6 * 89 + a7 * 23 + a8 * 56 - a9 * 92 + a10 * 14 + a11 * 89 + a12 * 47 - a13 * 61 - a14 * 29 == 29250)
    s.add(a1 * 95 + a2 * 34 + a3 * 62 - a4 * 9 - a5 * 43 + a6 * 83 + a7 * 25 + a8 * 12 - a9 * 36 + a10 * 16 + a11 * 51 + a12 * 47 - a13 * 60 - a14 * 24 == 15317)
    if s.check()==sat:
        print(s.model())
```

先利用脚本求出code数组

![image-20220525192035060](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b6c34a35a830960fbb29ee5336c099567536f0d0.png)

注意顺序不是一 一对应的,code数组赋值正确后倒序异或求解即可即可。

```php
 code=[None]*14
    code[0]=10
    code[1]=24
    code[2]=119
    code[3]=7
    code[4]=104
    code[5]=43
    code[6]=28
    code[7]=91
    code[8]=108
    code[9]=52
    code[10]=88
    code[11]=74
    code[12]=88
    code[13]=33
    inputs=[None]*14
    inputs[13]=code[13]
    flag=""
    for i in range(12,-1,-1):
        inputs[i]=(code[i]^inputs[i+1])
    for i in range(14):
        flag+=chr(inputs[i])
    print(flag)

if __name__=='__main__':
    main()
```

0x05 后记
=======

花了两天将ctf中目前常见的py逆向题型梳理了一遍，感觉收获还是蛮大的。未来在比赛中遇到python类题目，就不会像之前那样如此慌张，可以按照类型准确定位，条理分析。怒拿flag。

![image-20220526011644902](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7156e5349bc80b5303f401685367ef8925e324ba.png)

0x06 参考文章
=========

[https://blog.csdn.net/Zheng\_\_Huang/article/details/112380221](https://blog.csdn.net/Zheng__Huang/article/details/112380221)

[https://blog.csdn.net/qq\_27825451/article/details/80283737](https://blog.csdn.net/qq_27825451/article/details/80283737)

<https://www.cnblogs.com/serendipity-my/p/13735229.html>

<https://www.bilibili.com/video/av849399494/>

[https://blog.csdn.net/m0\_37157335/article/details/124121928](https://blog.csdn.net/m0_37157335/article/details/124121928)

<https://developer.51cto.com/article/664357.html>

<https://blog.csdn.net/ChiWu98/article/details/118674302>

<https://0xd13a.github.io/ctfs/0ctf2017/py/>