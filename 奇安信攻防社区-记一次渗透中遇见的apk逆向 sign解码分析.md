### 前言

在对某次渗透测试任务中，目标为一个apk，对其进行渗透测试，在使用抓包测试中发现存在sign的数据包防篡改，通过分析获取加密方法。

### 初步渗透

配置好https证书，使用Burpsuite配置代理，抓取目标apk注册数据包

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4f694bd78fe221418bd1488e533339e31adbbef8.png)  
发现存在用户遍历的问题，不存在的用户会显示未注册，存在的用户显示已发送短信。  
放到intruder模块进行手机号爆破，看下有没有测试的手机号信息  
姜姜，修改mobile参数发现会显示认证失败，请求的数据包中存在sign参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f0708ee74bc371652e582be861ba0e2ea87fb077.png)

##### 这里解释下什么是sign

sign签名校验法本质上是对客户端传输数据合法性的一种校验手段其常用手法为，在用户客户端传输的数据中额外加上时间戳以及特殊字符，随后一起得出整体数据的加密值(常用MD5,SHA1等加密算法)这就导致了用户在不知晓程序的原始数据生成sign值的方法情况下，若对传输到服务端的数据进行篡改，在后端都会鉴权失败，导致用户篡改后的数据无效。

### 解决sign签名问题

目前想到的有三种方法：

1. 测试下sign是否为弱加密方法
2. 测试下sign是否可以置空绕过
3. 对apk进行逆向，分析其加密算法

首先看来下加密字符，长度不太像md5的，可能是其他的加密算法，丢到cmd5上也没解开，G下一个  
置空发送也是失败了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b7821e5d17a1570e0de0992988a938bec3988483.png)

只能尝试最不擅长的apk分析源码了  
首先使用几个查壳工具查看下存不存在加壳

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-82759c8a92a5bf116e4b7d25130e46eb0b49cfa2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e3a45e3f9565983ac6fdca0e252fdd4f7760ff7a.png)

还行，用了几个工具都没显示加壳了，省了不少事情  
使用AndroidKiller工具分析一下这个apk

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e1e799904fcc03ab6126ae736696f8ce16379a11.png)  
我干，试了好几个工具不知道为啥都会爆这个错误，有没有大佬讲解下的。  
既然这样不行的话只能使用frida-dexdump脱源码了，这里就不讲怎么操作了，网上应该都有操作流程。  
脱下来了两个dex文件，通过dex2还原成jar格式查看源码。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8c8d7b436452451de3702d2852136910e7393e00.png)  
通过搜索sign关键字，分析了半天，并未发现存在相关的加密代码。

#### 神奇的思路二

想着既然java代码里没有，它又是存在加密的想到可能是通过js实现的，所以想着怎么把apk中的其他源码搞出来。  
在网上搜寻找到了一个方法，在没有壳的情况下，把apk后缀名改成zip方法，在解压缩，获取到了更多的信息了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8d5ba9bf69c6acc7002ee6b5e49ad457c4efbdbf.png)  
使用idea再次进行搜索，终于在漫长的查询中发现了其加密的算法，果然是在js当中的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2a8a11015fe5e04a9a28eb114f695c9bd3b450cc.png)  
存在一个为secretKey的加密密钥，通过跳转也获取到了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7fbd0e90e7a59c000d92f8589ef395cf526e4082.png)

懒得写python的脚本，直接丢给chatgpt，帮我写一下。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f83ba4cddd1288ac26192eddfff2c978cfd53465.png)  
gpt牛皮，面向gpt渗透  
不过目前还是有个问题，不知道是传什么样的值来做加密，主要因为菜看不懂js，调的层级太多了。

想到了两种方法：

1. 通过hook查看能不能获取到加密之前的信息
2. 通过分析猜一下，会加密那些数据包信息

测试方法一：  
因为我安装了现成的环境，使用xp框架配合Inspeckage来进行hook

首先打开Inspeckage，选择你要抓取的apk，然后打开目标的apk程序

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b1435908c126807c6f07189b253a36e6497342fa.png)  
然后使用adb工具执行下面的命令  
adb forward tcp:8008 tcp:8008

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e81584a2984e01d149291058a0002a4e6dfb4bf7.png)

打开你本机的127.0.0.1:8008

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-925411e9720a94d3431a69c5d9c9925df69f13b7.png)  
要保证App is running: true Module enable: true都为true  
然后打开burp进行抓包，获取当前加密的sign值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b4c7899add3579a2d26dfaac831d8434d19cbc8c.png)

获取到的为d3开头的，打开网页点击成on状态，然后查看hash

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-06862703f92f3c3095bef9c88ab91ec05adbd6ea.png)  
又陷入的坑里，发现并没有存在我想要的值，只能把最后的希望放到方法二了

方法二：  
首先需要判断下这个sign有没有把head包也做了加密，还是只是data的数据一些数据。  
通过测试发现，更改cookie的信息和token都不会影响sign的认证，只有在改data里面的值会显示认证失败。  
那就好办了直接把data要发送的数据，放到py脚本中，进行加密，看看加密后的结果一不一致

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f4a03443642e590171e6fd51d4ac2925a1fc5a5a.png)

奈斯

### 后言

这是本小白的第一次进行sign的逆向，中间遇到了很多挫折，绕过很多弯路，搞了好几天才成功，总体过程中也学到了很多知识点，只能说坚持就是胜利，成功就在眼前。