这是\[**信安成长计划**\]的第 6 篇文章

CobaltStrike 提供了一个内存混淆功能，它会在 Sleep 的时候将自身混淆从而避免一定的检测

0x01 C2Profile 分析
=================

因为 sleep\_mask 是从 C2Profile 中设置的，所以就需要先搞清楚 TeamServer 是如何解析的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-11d6975b28e6576d2b394b0ce27ed8b300157f52.png)

很明显它还跟其他的设置项有关，这里我们重点关注一下 rwx 的设置

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b58b1e54fc6012c1fad3d8e22f73223833f1535b.png)

首先会将 text 段的结尾地址存储到 index=41 的位置

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ef781143ad10041cf9cf3cc493f01bd9024c4622.png)

接着判断了 text 段与 rdata 段中间的空白位置够不够 256 个字节，推测会将加解密函数放在这里

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5c46ef368116febd2777a3e3576da068dc8389fa.png)

obfuscate 就让它默认为 false，它不是我们这次关注的重点，接下来就会将 0 和 4096 添加到其中

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8d03445cc550f0e25e049f9e1e8ee2740df46f9a.png)

再看一眼 text 段的 Virtual Address，这块很明显就是 PE 头的那段内容

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-38cc1fd1dc4716241db46489118967719cc5b08a.png)

接下来就是循环添加内容了，可以很明显的看到 do while 的循环条件是 text 段且不允许使用 rwx，这也就意味着，当我们不允许使用 rwx 的时候，text 段并不会被添加到 index=42 的项中，应该也就不会被混淆了，在最后还添加了零，用于标示结尾

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6bc4cec1f5de37807a3c6ddc8f9a04f2165a8efe.png)

0x02 set userwx "true"
======================

为了快速定位到加解密函数所在，可以设置断点来完成，因为按照之前的分析，使用 rwx 的时候，text 段也会被混淆的，所以跟入函数以后，直接滑倒开头下写入断点即可

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bd60e96e7681f2868813cf42a3638cfd6a35a779.png)

接着直接放过也就到达了位置

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3436fd2a1c1831955414fa8bfc22f79b36e496bf.png)

接着根据这个位置到 IDA 中进行查找，然后通过回溯也很容易能够找到整个的调用链

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0a49b1f713e45560457050e837bf3a9e117c26bf.png)

在主循环的最后有一个用于处理 Sleep 的函数

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cb668f381c59e61dbb5636f1be066c3ab7f301b2.png)

它通过判断 0x29 来决定是否直接调用 Sleep，如果使用了 sleep\_mask，0x29 中存储的就是 text 段的结尾地址

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7db2b9504ac6de9a051dae8578d86a80e8c38428.png)

首先它会将自己当前函数与加解密函数一起传入

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-aa9c7b5161922d8e97d56e3a3680f803b68a5880.png)

在函数中先计算了两个函数地址的差值，通过对比很明显能够看出这个就是加解密函数的长度

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-508cd9d58bbe458cc769bbd8079e59c658cd4baf.png)

接着从 0x29 中取出 text 段的结尾地址，并从全局变量中取出 PE 头的位置，相加也就得到了在内存中的 text 的结尾地址，也就是后面要存放加解密函数的地址，接着传统的拷贝也就不提了，重点是后面的赋值操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bcbd34e5629456ddcd37cc29e70bbf3cb57a76fe.png)

申请了 0x20 的空间，也就是 32 个字节，8 个字节存储 PE 头地址，8 个字节存储 0x2A 的地址

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d74e3df116508010a96ad347318138ee197539f0.png)

这个 0x2A 也就是之前构造的那一串结构

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-9d8b32ad30666832206535ae9f0d059f5aaee2dc.png)

然后将加 16 的位置传入

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c21808032fee1252955e27696f4b358bde29af18.png)

第一个使用 CryptoAPI 生成密钥

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-fee921c3cac84d971b809e262395b1d1b44bb3ec.png)

如果失败的话，用第二个自己实现的算法生成密钥

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7c81ad26e2d53bcc5c6d4d8009ba5b3968e43e0e.png)

最后就来调用加解密函数了，第一个是构造的结构，第二个是 Sleep 函数，第三个是时间

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-49de1fdf7d63e14e606bc5a00f560551fe8125d8.png)

接着就来分析加解密函数，根据中间 Sleep 调用可以推断出，上面是加密函数，下面是解密函数

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-3df3cf03eabab6131284c6e0e6421aef0fb7739d.png)

参数是指针类型，取数组，下标 1，也就是 0x2A 所取到的值了

然后 v6 就是第一个值 sectionAddress，v7 就是第二个值 sectionEnd，然后将 v3 再后移

用来判断跳出规则的就是最后添加的两个零

do while 的混淆条件就是 sectionAddress&lt;sectionEnd，也就是将所有的代码都进行混淆

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c503ae13bb4c93e7b725ae873d0e0013d095df43.png)

之后的解密也是一样的逻辑就不提了

接下来就是验证的时候了

Sleep 时候的状态

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-db0e2718670fb38aa35e23ec2b11f6b6f80f2eac.png)

此时的代码段

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-15e3587ea1771313d1da7c03933a01d5a209d878.png)

接收命令时候的状态

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a4a76768ce3b68a07337f7415d78dcf78fcad14e.png)

此时的代码段

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-267ec3fd3c71cb100e09e13a162c5b6e6764f8ff.png)

在允许 RWX 权限的时候，代码段是混淆的

0x03 set userwx "false"
=======================

理论在之前也都讲完了，这里就是验证一下最终的效果

Sleep 时候的状态

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-63f2c8f3023a30870727ab6ee84f249d876a712e.png)

此时的代码段

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8a07ceca1f7da7fae01a3a52242eaf29d7b383f0.png)

接收命令时的状态

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ed73073911032ca1e5799ed91081ab4ad8a3f4a2.png)

此时的代码段

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a67b48635449b901495f19bfdb793e7c557243df.png)

在禁止 RWX 权限的时候，代码段是不混淆的

[文章首发公众号平台](https://mp.weixin.qq.com/s/56qpeeEOoayGakx0pWbtRg)