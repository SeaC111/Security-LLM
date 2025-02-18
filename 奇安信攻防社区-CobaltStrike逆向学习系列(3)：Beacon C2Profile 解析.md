这是\[**信安成长计划**\]的第 3 篇文章

0x00 目录

0x01 Controller 端分析

0x02 Beacon 端分析

0x03 展示图

在上一篇文章中完成了 Stageless Beacon 生成的分析，接下来就是对 Beacon 的分析了，在分析上线之前先将 C2Profile 的解析理清楚，因为 Beacon 中大量的内容都是由 C2Profile 决定的。

而且，目前 C2Profile 也是被作为检测 CobaltStrike 的一种手段，只有在理解了它的实现原理，才能真正明白检测原理和绕过方法。

0x01 Controller 端分析

直接跟到 beacon/BeaconPayload.java，看 exportBeaconStage 方法

对于前面值的获取暂时不管，直接看重点，是如何添加的，因为最后是直接把 settings 转 byte 数组，然后混淆后 Patch 的，所以就重点看一下 settings 都干了什么事

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8de88cbbffa38f8d4097b5c6bbd20e0ac08aba3a.png)

看一眼 settings 的设置，可以很明显的发现四个方法 addShort、addInt、addString、addData

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5508cb00efafb3699795965800cf7768ae73df3b.png)

但是可以发现 addString 根本上调用的就是 addData，所以重点就是 addShort、addInt、addData 三个方法

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a7e8d25637a58ff78da92a27e41429f76a9def2f.png)

再回头看一下前面在调用时候的情况，后面的参数是需要添加进去的内容、长度，但在第一个参数位置还有一些不明白含义的数字，这个序号是在 Beacon 端解析 C2Profile 的时候需要用到的，在后面来进行解释。

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2ed4cc9b0d4ad46a1b6a94a0ea515db746d88e57.png)

在分析这三个关键方法的时候，还有三个 final 类型的值需要注意一下，到这里也就可以猜个八九不离十了，C2Profile 一定是用某个字节的值来表示数据类型，然后将对应的数据存储在后面

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-304828623feab280b521b0e6a6ebfaa0a9b80d00.png)

所以来整体看一下这三个方法，首先将序号添加进来；接着 addShort 添加了 1，addInt 添加了 2，addData 添加了 3，这刚好就是上面所定义的几个值；然后 addShort 添加了 2，addInt 添加了 4，addData 添加了 长度值，所以推测，这个位置应该是后面数据的长度；最后他们都将数据添加在了后面

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-430c461ae68b27db734a27862e03e008da58b89e.png)

所以整体的结构应该是

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-97de12aa02c0a0b3112d59d45c6f97fdb85af141.png)

0x02 Beacon 端分析

在理 C2Profile 的时候，顺便把解析前的一些内容一起分析一下，在之前分析 Beacon 生成的时候，已经分析过了，实际执行的 Beacon 是由一个 Loader 加载执行的，所以在实际运行的时候，运行的是 Loader，我们在 CreateThread 下断，然后在线程函数中下断也就跟到了熟悉的 PE 头，这里也就是之前说的引导头

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5a81dd27f90b32f1b1fb742fe9ee218f443a550d.png)

首先，它通过计算偏移的方式调用了 ReflectiveLoad

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-76a0638c919d1e9f1aecdf11e330467fbd83ad02.png)

跟进去后，可以发现 ReflectiveLoad 最后调用 DLLMain 的时候传递的 fdwReason 为 1，同时在 return 的时候，也将 DLLMain 的地址 return 回来了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b50c999063a23348393bd2cc095267613c9760b1.png)

继续往下跟，可以发现它再次调用了 DLLMain，并且传递的 fdwReason 为 4

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-446bd6c984b77881fddfe58ff09b1e5f4a64faaf.png)

接下来就该分析真正核心的 beacon.dll 在 DLLMain 中干了什么事，经过分析发现，当 fdwReason 为 1 时，实际执行的是解析 C2Profile 的操作，当 fdwReason 为 4 时，才是真正的功能执行，很明显，这里我们更关心的是解析 C2Profile 的操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-63f3586d11b9e44124564d7c13e7cb04623c8efe.png)

跟进分析，先申请了一片 0x800 的内存用于存储，接着有一个很明显的操作，将一片内存异或，这些都与之前分析生成时候的逻辑一致

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-57f975b29eb4a3788808d4a9aeb1986ad1b0dc2e.png)

AAAABBBBCCCCDDDD 的内存特征

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2ab236de150689688cc79db2e74b8f975a2cce6f.png)

4096 的内存大小

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6eea6616f5d7fe009597f3424f6438d93f0c0d49.png)

0x2E 的异或操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2cde6e47e4956808dce966941d90a41bebef282b.png)

接着设置了一个结构体，将 C2Profile 的地址存两份，将其大小也存两份，这个结构体在后面解析的时候会用到

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e9751bf0ad0477f1f76599a4ea7a5cea1842adbc.png)

之后就是循环解析，并在最后的时候将这片区域抹零

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3533eb2c53a2d3f56e6d4fe731f2fdc9ea0e1feb.png)

首先在最开始的时候取了 Short 类型，并且这个函数也是结束解析的关键，首先判断一下结构当中的 Size，如果小于 2，直接 return 0，也就是说所有的都解析完了，这个 0 也就刚好在外层结束了整个解析的流程

转换字节序，取两个字节，这个值也就是之前所说的 index，然后将位置偏移加二，总大小减二，返回 index

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-70e31a371846069b23be38784863ed1631c9d054.png)

然后按照刚才的逻辑可以取出 type 和 size

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-baf366093c602b9704ecfea5c53d40a47779d453.png)

接着将 index\*16，并将 type 存储到对应的位置，到这里 index 的作用也就明确了，是用来指定存储的偏移位置的，这样做就相当于内存对齐一样，在查找的时候是非常方便的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a131abe9686c2f8067616397dca58bed0d8968b5.png)

接着便是根据 type 类型来决定执行操作了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c3d96ee83729837d0d1deaca882f2eeec2c84998.png)

获取 Short 与 Int 的都是一样的，就不细说了，重点说一下 Ptr 类型的

先根据 size 申请了一片内存空间，并将地址存储在了对应的位置上，然后去解析

如果剩余大小小于 Ptr 要取的大小，说明有问题，直接 return；然后与之前一样，将所存储的这个结构体的位置偏移后移，将大小进行对应的减小，最后将数据的地址 return 回来

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-df403b60a362a3449ae7fc0e9502697aa5bb4ce5.png)

最后使用内存拷贝的方式将数据拷到所申请的内存当中

所以最终在 Beacon 中所使用的样子是这样的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-449188446ed56f7017a28ed680039e5fc01ca07d.png)

0x03 展示图

所以 Controller Patch 到 Beacon 中的 C2Profile 与 Beacon 在运行时所使用的 C2Profile 长的并不是一样的

Controller

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-97de12aa02c0a0b3112d59d45c6f97fdb85af141.png)

Beacon

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-449188446ed56f7017a28ed680039e5fc01ca07d.png)

[文章首发公众号平台](https://mp.weixin.qq.com/s/KLAG_8jafwEurVzk7Qz26A)