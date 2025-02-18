这是\[**信安成长计划**\]的第 4 篇文章

0x00 目录

0x01 Beacon 发送

0x02 TeamServer 处理

0x03 流程图

0x04 参考文章

在上一篇讲解 C2Profile 解析的时候，已经提到过如何断入到真正的 beacon.dll 当中，并且也清楚了它执行时的调用顺序，Beacon 上线的所有流程也都是在第二次主动调用 DLLMain 时执行的。

因为主要说明的是上线流程，功能性的暂且不提，但是中间会穿插 C2Profile 的读取操作。

0x01 Beacon 发送

通过导入表能够很明显的看到通信相关的函数，所以就直接在关键函数上下断

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-609c2032db550dd5314dfb30a943686d556813d6.png)

首先调用 InternetOpenA 传入了 agent

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-06022002a40ee1365de68a03e2d9b092a23f5dcf.png)

接着是 InternetConnectA 传入 IP 与端口

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-51790b6ea9642292d821d8dd5618445f04e0cd8c.png)

之后便是 HttpOpenRequestA 传入了请求类型和 URI

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-cb13c6680c8e2541efa7d2e97fc4c8339edbc6ef.png)

最后便是 HttpSendRequestA 发送请求了，很明显能看到 COOKIE 已经被加密了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ece16700aef22779637fb125e972069d4e627571.png)

接下来就需要往回跟，看它是从哪里进行加密的，最终发现，在进入功能性的 while 循环之前，就已经完成了信息收集和加密操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-30b9211c5f1f2161b2d54cbfa41f5dfff0e552f3.png)

这里也就顺带理一下 C2Profile 的解析，在加密之前，会先从 C2Profile 中取出一个值

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ecf4e854021f2c07cdb12e64c795a3443b43eb02.png)

回到 BeaconPayload 查一下 index 为 7 的就是 publickey，这也就说明了，在取值的时候是通过 index 来取对应内容的

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-48e1b5fddc0a93e10f86f0151dd11b183074eb1d.png)

然后分析一下 GetPtrValue，这里用 F5 就很不友好了，还是看汇编更容易理解一些

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-06f74c74f99f1c82bf4553ce1aea9a7a481b02cf.png)

中间的 GetValue 也就是根据 index，取出来其中的值，并返回

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-99bcb06d6846a6be93ae551fac1ab28ce2f65b9f.png)

整体下来的逻辑就是，根据 index 跳到对应的偏移，前八个字节用来判断类型，后八个字节是取出真正的值或地址，其他几个类型的取值也是一样的。

到这里为止，对于 C2Profile 的全部逻辑也就理清楚了，之后就可以对 BeaconEye 进行分析了。

0x02 TeamServer 处理

在 TeamServer 中使用了 NanoHTTPD 库来处理 HTTP 请求，并且写了一个 WebServer 类，继承了 NanoHTTPD，并在里面写了处理函数，我们就直接在这个位置下断即可

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1e051b072c383fc175ddf29d58421aa98b2790fb.png)

在接到流程以后，继续往下跟，会跟入 MalleableHook.serve()，它实际上调用的是 BeaconHTTP.serve()，在这里进行了解析操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9f4ae5b48dff359da04a927943d7b4c3b3c13b7a.png)

到这里也就到了真正处理的地方了，它判断了长度是否是 128 位

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4ef4b8d29b544a9a9732bf9c4bdf6f1b15ab706a.png)

跟进以后，直接就进行了解密操作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c488140f019c00c56d7286c1c03f6c6a4e1367c1.png)

直接初始化私钥，然后进行解密

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-261c32e9bdd30a3d0b62e97771f463895302b4a5.png)

随后判断了标志位 48879，然后读取长度，看是否小于 117，接着把剩余的字符返回

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4ae4cc40fa0b3c827ac55ab8fca162f2e5e78d30.png)

接着会保留前 16 个字节，然后 16-20 判断字符集

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-fca0b74ba33d2791d4d9e840faa6c0cd38ef6cfd.png)

之后在获取了 Listener 的名字以后，就来初始化 BeaconEntry 了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ccecb49e96511bfddd47cbbd490cfafe6acabc87.png)

就是不断从中间取值，所以 metadata 主要的作用就是填写 Beacon 所需要的信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-60d24f855907d19fdcaf20bca668ffa9e47e8f3e.png)

接着调用 this.getSymmetricCrypto().registerKey 方法来注册加密 Key，这里传入的 var8 就是刚开始保留的前十六个字节

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-63115a382075de58a09e674d856422907c25febe.png)

会先判断当前 BeaconId 是否存在，存在的话会直接 return，如果是第一次上线的话，肯定是不存在的，然后将传进来的十六字节 sha265，前一半作为 AESKey，后一半作为 HmacSHA256Key，接着将他们与 BeaconId 做成 Map

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-63db330d29a92def13108ade3a39ecf6e3f7a89d.png)

最后就调用 sendResponse 返回信息了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-217e3c4f15045fb9edd9c459550a30e9e2dde32c.png)

0x03 流程图

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4f15a8fb0f2615df990fed0618bb002b1b09441e.png)

0x04 参考文章

快乐鸡哥：<https://bbs.pediy.com/thread-267208.htm>

[文章首发公众号平台](https://mp.weixin.qq.com/s/ZfzbtehT5dVAaRR0mQMYrw)