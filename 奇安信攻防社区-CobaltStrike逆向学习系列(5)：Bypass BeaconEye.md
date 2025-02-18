这是\[**信安成长计划**\]的第 5 篇文章

0x00 目录

0x01 BeaconEye 检测原理

0x02 Bypass 1

0x03 Bypass 2

0x04 效果图

在之前的三篇文章《[Stageless Beacon 生成流程分析](http://mp.weixin.qq.com/s?__biz=MzkxMTMxMjI2OQ==&mid=2247483983&idx=1&sn=3bd71f46b49963ec976686f9c98e5aee&chksm=c11f56adf668dfbb86c4baeada6c702c06d7fd02852b6b95fad68b2b7cdd2f8504593ae75024&scene=21#wechat_redirect)》《[Beacon C2Profile 解析](http://mp.weixin.qq.com/s?__biz=MzkxMTMxMjI2OQ==&mid=2247483984&idx=1&sn=2b6a4ca48751889262a7be6c05c28a9d&chksm=c11f56b2f668dfa48f28660547fb1d0836e2280ecc937c9c29978fda65a122f4e0ac5b860279&scene=21#wechat_redirect)》《[Beacon 上线协议分析](http://mp.weixin.qq.com/s?__biz=MzkxMTMxMjI2OQ==&mid=2247484014&idx=1&sn=39ff274f2f61b87a1c13ad4e0a2060ef&chksm=c11f568cf668df9a36e53e58123444218225c70ff2f67e9309b11e03858e50b14be92fe656c8&scene=21#wechat_redirect)》中，已经穿插着将 C2Profile 的全部内容介绍完了，也把 Bypass 所需要的一些内容也都穿插着提到过了，接下来就该说如何对其进行 Bypass

0x01 BeaconEye 检测原理

BeaconEye 是通过 yara 规则来对 Beacon 进行检测的，规则所匹配的就是 C2Profile，在 Beacon 解析完以后，每一项都是占 16 个字节，前 8 个字节是 type，后 8 个字节是 data

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0392b027b00ca97aa4151bea0bfdfbc145c5a3cb.png)

为了明确对比一下，先看一下 Java 端的操作，关键需要对比的就是这五条

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-20ac4c21ef60ef9a31501cc6e5c1f40c1f36f672.png)

yara 规则的第一条全为零，是因为 Beacon 在解析的时候直接偏移了 index 个位置

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ed5a506675b3c2104def6d09277e56cedf8dd15d.png)

接下来也就都对得上了，类型依次是 short、short、int、int、short，对应过去就是 1、1、2、2、1，后面的值也就都是一样对应了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-72f7f193a896c9fc4ea1948f3ae032b17460fce1.png)

所以只要能够打破这个规则结构也就可以完成 Bypass 的工作了

0x02 Bypass 1

如果单纯做打破结构的话，将中间的值进行替换就可以了，整个十六个字节，实际需要使用的也就是第一位和后面的数据，中间的一片零都是没有意义的，所以在申请这片内存的时候，直接将其设置成其他值就可以了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0ea0d6beb3731de565c5ee14a7b3b5952adf83e0.png)

直接去改字节兴许还有点困难，再或者就是使用寄存器的赋值操作，将其他寄存器的值，替换到 edx 当中

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c66761a668d12eba7b1fe4c99b136769a76cee09.png)

再者就是 inline Hook，这样所有的问题也都很容易解决了

0x03 Bypass 2

这个方案会比较复杂，但是做完这个以后，之后要做其他的操作就会比较方便了，不管是进行特征修改，还是后续继续做 Beacon 的二次开发也都是非常方便的。

这个方案就是 HOOK，而且需要对两边都需要进行修改才可以，工作量也是比较大的。

整个 C2Profile 的流程是这样的，先在 Controller 按照指定格式组成数组，将其 Patch 到 beacon.dll 当中，再将 beacon.dll Patch 到 Loader 当中，Beacon 在执行的时候再将其解析成后续需要使用的格式。

为了能更方便处理 beacon.dll，最好的方式是重写 Loader，这样对于修改特征等也都会很方便。

接下来需要讨论的就是如何修改，关键函数就是解析 C2Profile 和取值两块，总共四个函数

对于解析是很容易处理的，之前提到过了，当 fdwReason 传入 1 的时候，所执行的是解析 C2Profile 的操作，直接将这个函数 HOOK 掉就好了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2bcdfddfda5ff94d36bdf711130ee43cb18f86fa.png)

对于取值的话，也都是单个独立的函数，所以整体操作的逻辑都是一致的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-acaae3fe161afdd0aa65281d2ba769dafdee6d23.png)

对于 HOOK 的库自行选择一个自己感觉舒服的就好，重要的还是地址的偏移，下面是 X64 的偏移量

```php
ULONG_PTR ulParseProfile = ImageBase + 0x18694;
ULONG_PTR ulGetShortValue = ImageBase + 0x18664;
ULONG_PTR ulGetIntValue = ImageBase + 0x185DC;
ULONG_PTR ulGetPtrValue = ImageBase + 0x18630;

```

后续的代码重写也就非常简单了，申请内存赋值、取 Short、取 Int、取Ptr，这些都按照个人的设计思路来写就可以了

可以很简单的把数据进行罗列，这样在取值的时候会比较麻烦，毕竟不好定位，当然也可以用定长的方式来做

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d912f3af987e5746e2f289159cf54b631c27baea.png)

也可以做的很复杂，在中间插入大量的垃圾字符，用一种只有自己才明白的格式来写

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-67aa66903d991ec67310187bdc46048ad52dff22.png)

有一点需要注意，在 X86 上写三个取值函数的时候，并不能直接去取值，beacon.dll 并不是堆栈传参的，而是通过 edx 来传参的，因为 X86 是支持内嵌汇编的，所以在修改上也是很容易的

```php
__asm mov index, edx

```

0x04 效果图

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-566ac5c69ff07af1136bede43a0d247fafbc98b0.png)

[文章首发公众号平台](https://mp.weixin.qq.com/s/eQ_OYbhuDEEJFBvNKI9duA)