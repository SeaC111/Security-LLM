0x00 概述
=======

 AZORult是一种信息窃取的恶意软件，随着时间的推移已经发展成为一种多层功能的软件。Azorult是通过垃圾邮件活动传播的恶意宏文档中使用的木马家族，同时也是RIG利用套件中的备用payload。

 本次获取的样本通过携带恶意shellcode 代码的诱饵文件，利用CVE-2017-11882 漏洞执行shellcode 代码从黑客服务器请求下载恶意文件并执行实现对受害者计算机的入侵，具体分析如下。

0x01 样本信息
=========

 诱饵文件基本信息如下：

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-51b2f2b4e3e634caa8ec70e9ad884e040bb0f779.png)

诱饵文件伪装为调查统计表诱导受害者打开。

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ba3dbb89956dc798d3a8f1235c24ef17e164a989.png)

利用office 组件漏洞执行shellcode，从[http\[:\]//maontakt.az/chief.exe](http://maontakt.az/chief.exe) 请求下载，将下载所得的文件存放至%APPDATA% 路径下，并重命名为name.exe。

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8b34f4718b5345bac64f76c7260b565644408063.png)

 在下载完成后，使用ShellExecuteW() API 函数执行文件。

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e0c4ff8264070d6585a27eb4920f2f02bd9f0d56.png)

 下载所得name.exe 基本信息如下：

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9f295026bb84176f574632476836ebb51b7ba8ed.png)

 对name.exe 进行分析发现，该文件为C# 编写，并且进行了混淆。

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6e613569a2ad9492a8eb36504967b2730cc0c63e.png)

对样本行为观察发现，该文件在运行过程中会产生两个自身的子进程。

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-479ec297430a5c910ef39bf8350b2860ce71c434.png)

 使用工具对name.exe 进行调试。Name.exe 在执行时，首先会创建一个互斥，实现单例运行。

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-162314d347f79bd500f5f0da4d0346241d3c95e7.png)

 当然，如果创建失败，会弹出提示窗口并结束执行。

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ad0fba664d429c5e0b2e11fefac5ee5cc72e0cda.png)

 Name.exe 文件本身不会直接执行恶意操纵，而是通过加载本身携带的被加密过的PE 结构数据并进行解密，待该数据加载到内存后调用其中函数实现对系统数据的窃取。

![10.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8fa1eba0de0da588fc46e672d5ad81cceafd7014.png)

 这里使用zip 加密方式对PE 数据进行加密，通过对数据解密，dump 真实的PE 结构并保存为test.bin。

![11.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2dd27b4031c43294bf2538ecfa1ebcf878838d30.png)

 Test.bin 本身为使用C# 编写的dll 文件，基本信息如下：

![12.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4876b9d387991bb5137fb77f6dbdeef6e367c76e.png)

 通过对该文件调试发现，该dll 文件于name.exe 类似，都是解密一段PE 数据并加载到内存中执行。

![13.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7dee35ff32477123557efa94f2f677e79cd18373.png)

 将解密的PE 数据dump 并保存为dump.bin，基本信息如下：

![14.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cef8a18932f64a29156df980c48617bd82d6b613.png)

 在虚拟环境下执行dump.bin并抓取程序行为。可以发现该程序在运行过程中会产生多个相同的子进程，并且这些进程都在执行一小段的时间后结束。

![15.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-131b394d7180ec7b6665feec5b12b30473f72304.png)

 使用工具对该程序进行调试。在调试过程中，发现该程序导入了多个系统API 函数用于某些恶意操作。

![16.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e6e26f9585db846af2643a2b0e67b8c6c3984588.png)  
并且在调试过程中，发现该会获取一些计算机信息，如硬件主板信息：

![17.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ab6cad21e12c33388572c00862d8e0603ae44223.png)

 除此之外，程序还会对当前运行环境进行判断，检测是否为虚拟机环境或沙箱环境。其中对虚拟机环境的检测包括检测Virtual Box 平台、VMWare 平台以及QEMU 平台。

![18.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a6410fee1294fd59a54f95e6c6ac1a66ffe136fb.png)

![19.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7720c0d4604fc78c4b5de13ef4a3d887088a0684.png)

 以及对沙箱的检测：

![20.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ef2a2cb44b418159526a732149e9ed0fe62012a2.png)  
 到此也解释了为何样本行为中所产生的多个子进程都执行很短时间就退出的原因。

 此外，该程序还会对服务器发起请求，执行文件下载操作并保存到%TEMP% 路径下。

![21.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a5cee659dcbe113730d49c625bbc5ef85c2540e5.png)

以及通过在%APPDATA% 路径下创建自身文件实现程序的自我复制。

![22.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8c364971c6fa34acecf51209f95da1d7f5cbb836.png)  
通过创建计划实现程序的持久化操作。

![23.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3c7662710f09ff95b7c3a1d23bf09e0499077977.png)

 除上述操作之外，程序还会创建自身子进程并将其挂起。

![24.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-accd3820292fb473e958e43242735fccd187fe89.png)

 使用WriteProcessMemory 函数向该进程写入一段恶意数据。而该数据同样也是一段PE 结构数据。

![25.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-95c6e20a53dc6cc58898c7ad50f454387e8db5d3.png)

 与上述类似的操作，dump 下该数据并保存为dump1.bin,基本信息如下：

![26.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-04cd6b9f431e477fcbee1912b60f71ac26acb957.png)

 通过使用PEiD查看可知该文件为Delphi 编写。

![27.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-27c22cefaf1d2af53b629a7d7116b142e9530ed1.png)

 对dump1.bin 进行调试。

 在恶意功能开始前，程序会先对所需要使用到的函数地址进行获取，具体函数包括：

![28.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3a3150d562f5bae49ca4bcd9783a81feb7aec5f9.png)

 接着，程序会利用之前获取的部分函数实现对计算机信息的获取，如：

 获取计算机机器码

![29.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-70314fd4958be562cd65c1cbcbec0f7708ae8e7e.png)

 获取当前系统版本

![30.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-98a0216624afa3e12a2ed74ee1013b41c5596a2e.png)

 获取计算机用户名

![31.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b13b07d6910022c07a4c6d872ad2f0f3535043a0.png)

 在获取到这些信息后，对这些信息进行拼接，并且暂存到内存空间中，用于后续使用。

![32.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7718e6c7414a069ef1a3f21284f287f6295d092f.png)

 之后程序根据之前获取的信息生成独立的互斥体名称，并依据该名称创建互斥体。

![33.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-20b28331ffe3463745fde1b5b7992aefeaf4b0a2.png)

 在互斥体创建成功后，会执行一段对网络发起请求的操作，这里主要是向 地址发起POST 请求并保存回传的数据到系统中。不过目前该地址已经无效。

![34.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7a44769482114e43e6b8e4e30cbf776e064ae2eb.png)

 尝试与服务器主机地址70.35.203.53 建立连接。

![35.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2c4c5dd21d0c64dc44f3ce2037974679e765844b.png)

 该程序最重要的功能是窃密，这里所被窃取的数据包括浏览器Cookie数据、浏览器历史记录、比特币钱包数据、Skype 聊天数据、Steam 凭证、屏幕操作截图等。

![36.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1a4441a648ec9b839d8abb534088b1af950f11ca.png)

 除此之外，程序还可以通过调用系统函数执行系统内的文件，实现对受害者计算机的远程操作。

![37.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-157f3fa2605fbb208e8310670455228307838614.png)

 程序还会对计算机基本信息进行获取并存放为system.txt，这些基本信息大致包括计算机机器码、计算机名、用户名、系统版本、屏幕分辨率、进程列表、用户权限等。

![38.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9d4ebf5ebbaba2a425b6838660da5693e182393a.png)

 当对程序对受害者计算机内所需数据获取完成后，程序会删除自身在系统中存在过的痕迹。

![39.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-36d6f76f0183561d0af6952244ad046f29ffcdf5.png)

0x02 总结
=======

 本次获取的样本利用携带恶意shellcode 的诱饵文件触发漏洞下载恶意文件并执行，恶意文件通过逐层解密，最终在内存中执行真正的恶意代码。通过分析该样本，总结出其大致执行流程如下：

![40.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3116edf83dd98b57387d94845b74a617670933d0.png)