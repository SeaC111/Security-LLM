0x01 RE
=======

easyxor
-------

简单的xor

![image-20220502104255229](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-05f4e6a01d385dd89113873b04726fa137bdb8cb.png)

异或后的字符串

![image-20220502104324772](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-121fdb3b478869e5c14ed26dcd9629f22c638ef1.png)

```python
f2 = [0x44,0x4E,0x43,0x45,0x59,0x5A,0X6D,0X50,0x7D,0x13,0x51,0x7D,0x54,0x11,0X50,0X5B,0X5B,0X5B,0X5B,0X5B,0X5B,0X5B,0X5B,0X5B,0X5B,0x7D,0x47,0x16,0x51,0x5B,0x5F]
flag=''
for i in range(31):
    flag +=chr(f2[i]^0x22)
    print(flag)
```

oh\_my\_python
--------------

pyc反编译一下

![image-20220502104417566](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5e9064e69bcc8f51a917df489c51ef56cf2344a3.png)

吧answer当flag输出即可

```python
def chall():
    flag = ''
    l = 'CKNOPWY_acfghkloruwy{}'
    index = [
        10,
        14,
        8,
        11,
        20,
        0,
        8,
        2,
        7,
        6,
        3,
        17,
        7,
        1,
        3,
        5,
        2,
        7,
        12,
        3,
        5,
        7,
        4,
        19,
        9,
        7,
        18,
        15,
        16,
        13,
        21]
    answer = ''
    for i in index:
        answer += l[i]
    print(answer)

if __name__ == '__main__':
    chall()
```

xpu
---

把xpu脱壳

`https://upx.github.io/`

然后解base64就行

![image-20220501110644696](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6da8214c59302359a3c3b310af6be0db89dd50a6.png)

asm\_master
-----------

汇编：

![image-20220502104700343](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-bb30ecc41a30f33981d12220a6281035ca804341.png)

然后拿出gcc编译一下：

gcc编译成.o，扔IDA里，就能看到printf

![image-20220501110736281](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d48b3615612254f4423f7ee5bf8ac65f3c1ddd95.png)

0x02 Misc
=========

Checkin
-------

仿照的pwnhub的签到，二维码链接#后面就是flag

simplepcap
----------

![image-20220502104954164](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-50673938946d90c3f7b4e4b71578d97852565525.png)

流量里有个macos的程序，提出来

![image-20220501144003244](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-305d88fa74c358a965ff5d794eaabe6d981d7cc5.png)

![image-20220501145109980](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-50e665700e13d1d68c26506071d51d270efaf444.png)

```python
v7 = [0x25,0x2F,0x22,0x24,0x38,0x21,0x22,0x21,0x3A,0x1C,0x33,0x20,0x22,0x33,0x1C,0x2A,0x30,0x1C,0x35,0x26,0x31,0x3A,0x1C,0x26,0x22,0x30,0x3a,0x3E]
flag = ''
for i in range(len(v7)):
    flag+= chr(v7[i]^0x43)
print(flag)
```

warmatap
--------

照着视频的节拍敲键盘就行

`flag{wozuixihuanwarmale}`

0x03 Web
========

你比香农都牛逼
-------

Ctrl+S保存下来，在js最后jsfuck

![image-20220501111112043](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9983e8e7046ad360019ac0f0655307a13a76fadc.png)

old php game
------------

```php
<?php
    error_reporting(0);
    require __DIR__.'/flag.php';

    $exam = 'return\''.sha1(time()).'\';';

    if (!isset($_GET['flag'])) {
        echo '<a href="./?flag='.$exam.'">Click here</a>';
    }
    else if (strlen($_GET['flag']) != strlen($exam)) {
        echo 'Not allowed length';
    }
    else if (preg_match('/`|"|\.|\\\\|\(|\)|\[|\]|_|flag|echo|print|require|include|die|exit/is', $_GET['flag'])) {
        echo 'Not allowed keyword';
    }
    else if (eval($_GET['flag']) === sha1($flag)) {
        echo $flag;
    }
    else {
        echo 'What\'s going on?';
    }

    echo '<hr>';

    highlight_file(__FILE__);
```

$exam的长度为49，然后过滤了一堆：

``|"|\.|\\\\|\(|\)|\[|\]|_|flag|echo|print|require|include|die|exit`

所以如下构造：用短标签闭合

![image-20220501111302529](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b4ba9de0bceb7b5b23e2a63bf25bbff3d0f363e3.png)

very old php game
-----------------

eval(string $code)把里面的字符串当做PHP代码来执行，所以会执行var\_dump($$a)，$a = hello; 所以$$a = $hello ，所以可以用超全局数组 $GLOBALS 开输出flag

![image-20220501111446624](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f49a7d41d3a7154240dc894e20df8b08cbf1c908.png)

Baby Unserialize
----------------

考点应该是PHP垃圾回收机制+wakeup绕过+变量重定向，没用上那个垃圾回收

```php
<?php

require_once "flag.php";

class Foo
{
    private $i_am_flag;
    public $i_am_not_flag;

    public function __construct() {
        $this->i_am_not_flag =&$this->i_am_flag;
    }

    public function __wakeup()
    {
        $this->i_am_not_flag = 'I am not flag!';
    }
}

$O = new Foo();
echo base64_encode(serialize($O));
```

![image-20220501204600680](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-29e3679b464ae033eb28d39515d18e39da46b1a0.png)

0x04 PWN
========

flag\_in\_stack
---------------

简单的格式化字符串，读入了flag，所以泄露一下就行

![image-20220502105729544](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5acf3a37eecdc4eddaa3b64503ec161ec11f2555.png)

`%10$p%11$p%12$p%13$p`

![image-20220501205030555](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-87737421847a8e195fc8f429b43352ef4fa858d9.png)

![image-20220501204802921](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c3ceac7cef31cd6fdbd6fb37cdeda7e408218150.png)