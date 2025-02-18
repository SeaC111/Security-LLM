这是\[**信安成长计划**\]的第 1 篇文章

**0x00 目录**

**0x01 密码校验**

**0x02 aggressor.authenticate**

**0x03 aggressor.metadata**

**0x04 数据同步**

**0x05 流程图**

**0x06 参考文章**

先统一一下后续文章所提到的一些名词，以确保大家都在聊同一个东西，文中将 CobaltStrike分为 Controller、TeamServer、Beacon 三端，本文所描述的是 TeamServer 启动之后，从 Controller 登陆 TeamServer 的流程分析。

由于水平有限，对于数据同步并没有理解的足够清楚，望各位斧正。

0x01 密码校验
=========

启动 TeamServer 后，会创建 SecureServerSocket 对象并且循环调用 acceptAndAuthenticate 方法等待 Controller 连接

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8b74f10d4b67e3333d147817a86ebade67d20f0f.png)

在接收到信息并验证成功以后，才会去调用 clientAuthenticated 方法来线程执行 ManageUser 以处理与 Controller 的信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d501dbbcf351b3a5c734d1454e00b193df877a06.png)

当 Controller 在点击 Connect 按钮时，会调用 Connect 中的 dialogAction 方法，会先创建 SecureSocket 对象，并调用 authenticate 方法进行验证

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-212e8f06b794e57f84cc7247d564ba2088e762c7.png)

在创建 SecureSocket 对象时，会与 TeamServer 进行握手等操作，TeamServer 会进入 SecureServerSocket.this.authenticate 方法进行验证，此时会一直在 var4.readInt() 阻塞，直到 Controller 将信息发完

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-9d778a25b9eceac92c29acde6d978846a50b448a.png)

接着来看 Controller 的处理，在 authenticate 中，进行了数据包的构造，先写入一个标志 48879（int），接着是密码的长度（byte），然后是密码，之后用 65 来进行填充

密码长度加填充长度，不超过 256，再加上标识位和密码长度，256+5=261

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8a25f11ada5c5e5f1567d17bbf070e092d87c912.png)

接着在 flush 之后，TeamServer 就开始验证了，判断标志位是否正确，读取密码，读填充字符

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-17ce658cd6028eb76b4d450f530c7af34d344c8e.png)

对比密码，如果正确，写回标志位 51966

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-6b5700950b4c8a94d0645bd95027a53da703f4ee.png)

在 Controller 这边同样也会进行验证

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-69d0dddbb72f209f9be7f98176376b5d5470f718.png)

密码校验到此也就结束了

0x02 aggressor.authenticate
===========================

接着，TeamServer 创建 Socket，并创建 ManageUser 来处理 Controller 发送的信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-faae7d3fee60b68786a82297a718ff163b2f0553.png)

Controller 创建 TeamQueue 来进行后续操作，TeamQueue 是用来处理与 TeamServer 的通讯的

在 TeamQueue 的构造函数中，创建了两个线程分别来跑 TeamQueue 的内部类 TeamReader 和 TeamWriter，用来与 TeamServer 进行通信

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-0bdb0dde5d222dfa389f8ca1d60db33741b90d99.png)

接着，当前线程调用 call 向 TeamServer 发送 aggressor.authenticate，并将 user、pass、版本号组成对象传递过去

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f3f483b1c1cb5d8a582b79b2deca17a9a0b6b1e2.png)

在调用 call 中，最关键的就是 addRequest，它将构造好的 Request 对象存放到 LinkedList 当中

因为此时专门有一个线程 TeamWriter 一直在从 LinkedList 中取值发送，所以在添加完之后，这个信息就会被发送到 TeamServer 中

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e58c31724c6c1175da642348f12e45f09cd99295.png)

在 TeamServer 中，是由 ManageUser 一直循环等待 Controller 发送到请求的，在上面发送完成后，TeamServer 也就接收到请求了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-505a7e48cc32d8afa0be4ddcb39035d624db1b4e.png)

进入 process 来处理请求，通过对比任务类型，来决定实际执行的内容

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-59e3538a21f926df302e55a58c0fd023b5dada26.png)

接着对 版本、密码进行校验

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-904ed921594af04c5704b8727eff0cfa9af62e6d.png)

全部验证成功后，返回 SUCESS

接着会起一个线程，ManageUser 的内部类 BroadcastWriter

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5030995191d4699faa3134559446ef4761f0b320.png)

此时 Controller 由 TeamReader 接收到信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f635e137b03682f9c41a72a46d7b36a951a314e4.png)

这里接受的是 Reply，发送的时候是 Request，这两个类基本是一样的，可能是用来区分数据包的

在请求的时候填入的 callback，也是在这个时候使用的，在之前 call 的时候，将一个 callback 值与这个对象做 Map，在这个时候取出来用于去调用对应类中的 result 方法

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b6f4ea3a5821d14e40ee3d7e7e209ea588ee1e41.png)

在判断返回值是 SUCCESS 之后，接着又发送了 aggressor.metadata

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-c956e32339fbf1dbbf890d528a844636bf20a0be.png)

0x03 aggressor.metadata
=======================

调用 call 与之前一样，此时传入的参数是当前的时间戳

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-eca9ca817b3723b313d4920fc01424d2bc04be64.png)

TeamServer 中的 ManageUser 接到消息后，继续走 process 处理

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f930e7e5ad85d7885615066d35965e50be3c173d.png)

做了一堆 Map，然后将信息传回给 Controller

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-92854f483328bf0942b7251dda52c1ec71f291f0.png)

Controller 的 TeamReader 接收到回传信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8dec40d6563e051a9557acfb880f0d35c2257a82.png)

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-7ba763d282c339387f42af0a9f5e32e2ea0e1968.png)

到 Connect 处理 aggressor.metadata

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3c22c6a5ef4f217ec13badcfaad0c8013225fe77.png)

在进入 AggressorClient 以后，调用 setup 方法，处理与界面相关内容，最后向 TeamServer 发送了 aggressor.ready 表示完成

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3785d67623ac0270720c28eb19a465ae363e15ef.png)

TeamServer 在 ManageUser 中接到数据以后，process 进行处理，接下来的任务就是处理数据同步

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-064389dbb2d2ea40d27f989caf38cfc4cc6eeb2c.png)

0x04 数据同步
=========

在 register 中，会先将 user 与对应的 manageUser 存储到 Map 当中，接着调用 playback 来处理同步的工作

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-f37c88268098fe782816dc6c32f1f3f9486d8a7d.png)

在 playback 会计算 this.transcripts 与 this.replayme 的总大小，然后进行发送

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8ef35a25ef51555a3c82c877cea3e6ff7b44bad1.png)

send 的时候，就用到了前面所创建的 Map，通过名字取出相应的 ManageUser

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d887da3dee0e5c08ed99bfc9732af2317bed167d.png)

之后也就是发送的常用流程，将信息打包成 Reply 或 Request 然后发送

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-00ae6cc54f9fccbb363e6b1484a4db4a67d0d12e.png)

Controller 会在 TeamReader 中接到消息，因为 callback 是 0，所以会走走 else 当中处理，调用 DataManager 的 result 方法来进行处理

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-db6602b7eccb1221b40a7ab9b16fafc82f2c5cf7.png)

用于判断 sent 与 total 是否相等，来明确是否已经完成

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-e27c33ec8ce7252baa56122c5c7679ec457d435c.png)

接着遍历并调用对应的 result 方法

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4e34d7c5e7bbe9e8973791f1d981b81c027090ec.png)

继续回到 TeamServer ，接下来当前线程会来遍历 this.transcripts 和 this.replayme，并将信息 send 到 Controller，由于这里 this.transcripts 为空，就直接看 this.replayme

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-4d75d917d5570c6a209e426aebb3635ec63093c6.png)

先把其中所对应的值都取出来，修改了当前的 message 信息以后，先将 playback.status 包发回，然后再将取出来的 Key、Value 发回，最后将 send 加一，用于 Controller 中对比 send 与 total 值

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3e17d68d7d096f42e7c7c9a32a296022d2cfc02c.png)

当回信息时，Controller 判断是 Data，所以进入了另外的分支，由于不是 ChangeLog 类型的内容，存储到 Map 后就直接结束了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-09b92a0f852b4b0658acaef4183dabcfdbf1b146.png)

之后再调用 将当前用户信息提供给 Controller

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-152054e3e201c6b983e4cbc53a284e65ad86e079.png)

在 TeamServer 继续执行调用的时候，也是调用的 broadcast 来同步 eventlog

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-416b2edc1d51510010b343d381ea4d45b7750537.png)

之后也就进入到了常态化的，接 Controller 的 aggressor.ping，和 BroadcastWriter 回写 Beacons 信息

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-625a2e5706a75b5a96b98b889c6a3566f928b5af.png)

0x05 流程图
========

![图片](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-96dc4b61e1f669fd024cabeedcc8c5f56771f9c9.png)

0x06 参考文章
=========

快乐鸡哥：<https://bbs.pediy.com/thread-267208.htm>

WBGlIl：<https://wbglil.gitbook.io/cobalt-strike/cobalt-strike-yuan-li-jie-shao/untitled-2>