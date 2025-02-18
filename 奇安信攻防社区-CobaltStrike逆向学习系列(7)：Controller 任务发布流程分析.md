这是\[**信安成长计划**\]的第 7 篇文章

0x00 目录

0x01 Controller-&gt;TeamServer

0x02 TeamServer-&gt;Beacon

0x03 流程图

所有的任务在 Controller 处理以后，都会直接发送到 TeamServer，接着等待 Beacon 回连的时候将任务取走，文章以 shell whoami 为例

0x01 Controller-&gt;TeamServer

当在 Console 中输入命令回车后，会进入 BeaconConsole 进行处理

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-cdbd67d8aec995cf38f12eb6323f3728a5cf4ca8.png)

专门来处理 shell 命令，命令解析 popString 所返回的就是要执行的命令 whoami

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d8172c2868390513c565696acccd2bd95bf56069.png)

接着会在 TaskBeacon 中处理执行逻辑，因为只有一个 Beacon 就直接跟入了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a4df0ce1e6373f75354273ec827f533ce46fc374.png)

然后就是构造任务了，将信息处理后用于 Beacon 去解析执行

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1ec298774c4cbd906cabd4ca615136210b4b71ae.png)

之后会先打印执行日志，然后才是真正的传递了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8b2b6e483c591c96703c81614012155cdfc26136.png)

日志记录也是一样通过 TeamQueue 传给 TeamServer

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-823b8b01cbb3999e0e4dce5c28dc039fa2d9c3dd.png)

TeamServer 在 ManageUser 中接到日志

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-adc60afb7c1291e927187ece1e5957bc8d962cd6.png)

在处理以后直接添加广播将信息发送出去

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b04f69fb6b3b391b327509becb8428f5816770a1.png)

然后通过 BroadcastWriter 写回给 Controller

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5b73309b987b23f5b341c86972b8665f39f9733f.png)

接着 Controller 将任务发送给 TeamServer

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-833fcacdec5d0322fed7c6b765781eee353a5fe1.png)

TeamServer 在接到以后同样走对应的处理逻辑

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8d7fd54155fcad5e85b0e104407be55f776389b5.png)

从两个参数中取出 BeaconId 和任务，然后进入 BeaconData 处理逻辑

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c80342d2241193301284f5789f911f7e49710801.png)

这里的有用代码也就是 else 中的 add 了，上面的判断是 CS 的一个暗桩，运行三十分钟后再执行命令就会直接发布退出任务

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-86b65612ed6e359568acc2053793e585454d7d88.png)

在将任务添加到 List 以后，也会将 BeaconId 记录下来

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-b798fa03f1357e9d4914435fbac264ce73437186.png)

到这里任务的发布就完成了

0x02 TeamServer-&gt;Beacon

在 Beacon 回心跳包的时候，会来请求任务

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a5609e672de3198a29f43f241f11424ae161b2c0.png)

直接从任务队列中取出数据

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-74319b81ba0cdf45f2dafc26ae5ecb094cf34fbe.png)

然后循环添加，并将添加过的移除，如果任务大于指定大小的话就会跳出循环

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8a803f76afa50c5b0f5cf366d28698fa709e310e.png)

最后将任务队列返回

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-41258e8dba7c2411552c08599709f1f2a8861745.png)

之后再相应的将其他的内容取出

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d3f9fabea46d6699861e15c367f9a80c7d346c97.png)

最后构造并返回，这里会进行打印日志的操作，输出发送了的命令的长度

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-7563e7e63bfe7014e53d7b33bafe006d4303da58.png)

在返回之后会对数据进行加密

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-73bc80d67bf41b9453187f6f6178917d22ff54b7.png)

首先会根据 BeaconId 取出对应的 AESKey 和 HmacSHA256Key

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-8455bc89c0896bba64fa096b38278534061c42f7.png)

之后写入系统时间/1000，任务长度，任务数据，并对其进行补齐，添加 A，补够 16 的整数倍

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ada0c64dbb501fb326c4a011b2793450135e3ea7.png)

然后进行 AES 加密

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-e1d66b23c813604f223b62ff124a4f2c1df66f4a.png)

接着对数据进行 Hmac

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5189eddb82d5e5d36f70bed2cfea131d476d23c3.png)

之后将 AES 加密后的任务写入，并将 Hmac 的前 16 位拼接到后面

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-27aaccdafecf9f7b9823f68a4527d7aee44df4d2.png)

之后便返回给 Beacon 了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5bf6c101d8f915770bf7d1c22d197a20669e6da3.png)

0x03 流程图

![图片](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-61107496d4d6b72ae608ee4fd517bca890e703ea.png)