0x01 前言
=======

简单说就是演习活动中发现cs里面有很多不懂的点，这篇文章的话主要是记录对Cobaltstrike4.0 http分阶段stagebeacon上线流量的分析结果以及自己对一些东西的一些思考和想法

0x02 CS流量
=========

CS的流量通道有很多，如http、https、dns、TCP、SMB等，**此文里面具体来讲beacon通过http通道的CS上线过程**，所以我们创建监听器的时候payload选择Beacon HTTP。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7ac2c66638338770d69b39a82f8659d82d8cf676.png)

在研究之前，我们要实验抓取相关流量，这里笔者实验的时候使用的上线方式是使用的分阶段的stager，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a5f1aa67c3d410cb3e434f80ae68c01d391d1fa8.png)

抓取的流量的过程就是起虚拟机，然后运行对应exe，利用baecon运行了个whoami命令，整个过程起wireshark抓流量。

拿到流量文件，如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-753dc89db1bde7fa4327ca60379263db0f0bf2dd.png)

下面我们就上述过程产生的流量进行详细分析下：

0x03 CS上线过程（理论学习）
=================

这里我们通过一个图来描述下http 分阶段beacon上线的过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6696f8f752b6a397b8c5b5cfa1d71e58d6758f54.png)

接下来我们按照顺序对其中的几个点展开分析：

1、其中第三步中的特定算法是什么？为什么要使用特定算法来生成URI，为什么要在第四步中对这个URI进行校验：

2、第七步中的怎么使用公钥对哪些受害端的信息进行加密传输到服务端了？

3、第九步中的要执行的命令是什么，我们能否通过流量还原出对应待执行的命令？第十一步中受害端通过post回传的命令执行结果的内容是什么，我们能否通过流量还原对应待执行的命令？

我们一个一个来看：

1、其中第三步中的特定算法是什么？为什么要使用特定算法来生成URI，为什么要在第四步中对这个URI进行校验：
------------------------------------------------------

之前大家可能多多少少都听说过一些安全公司可以识别互联网上的使用CS的C2服务器，并且识别出对应使用的心跳回连uri和任务执行回传使用的uri以及相关心跳间隔和使用的是那种beacon通道：

如下是QAX的ti引擎对某IP的查询结果

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e034e8cf59fc0c61029919c2ad1d618c6cc3000e.png)

我们来看下主机信息：

发现这里80端口直接访问是404：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5f768162c554d76024737bf09b90db5490bb2e29.png)

但是下面确实标记了是CS的Beacon：

可以看到这里的80端口上是绑定了两个完整stager，X86和X64的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-eae8493b5d969dafc4a9e21240e3e43a10d65737.png)

如下图是X86 beacon的详情：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-275cc8ed2e84e9259a9b888892222a4caab34f19.png)

X64如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a38388ac6e95a67d2ef77fa03818b80af0b2a989.png)

我们需要重点关注的，上面两个图都用红框标出来了。

回到这个问题的起初，为什么网络安全相关公司能给对应端口下这种标签呢，就是因为我们这里讲的这个特殊算法：

如下是笔者在分析CS源码里面找的的对应的特殊算法（工具类里面CommonUtils）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-75659ca9ece22c923f0cd6ce8759b6f2ab290421.png)

核心的话就是checksum8这个方法：如下图，其实就是转ascii对应十进制，然后求和对256取余，最后余数和92、93来对比，92是x86，93是x64

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6a96d880f95463db220406297f69a1bad5b138c0.png)

所以对应网络安全空间扫描，扫的是上面这个算法生成的uri，请求对应的uri就会获取到CS对应C2上的beacon.

在我们上述测试的流量里面URI就是这个`CeKi`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dc0f7b365aa503685eeb6c5c05dd5d4ab5d72803.png)

这里我们将响应体里面的beacon文件的内容导出来：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-178309905734c12513540d72031b20c7f79ec508.png)

导出`CeKi`文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e7b7ff8a50d7a013e2db275d6a9945c024009c84.png)

生成如下文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-07df38ccb98990f6f176b51200cb46ac84a01edb.png)

如下图，在流程中的第六步中，受害端会去解密这个beacon文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5cbde719779fec2b32788f031cade4a89f6d7746.png)

这里我们通过如下脚本对beacon文件解密：

脚本获取：<https://github.com/minhangxiaohui/CSthing>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cd2bd7bccdf2ae6d3e47d45edd7abfe27d934826.png)

如下图，对该beacon文件解密后我们就可以得到上文网络空间安全扫描引擎，扫出来的结果：其中每个字段都是有意义的，这里我们如果不做更深入的研究工作的话，看标记的相关即可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-51859b905497909565c43be2d07164ba77abd26a.png)

2、第七步中的怎么使用公钥对哪些受害端的信息进行加密传输到服务端了？
----------------------------------

如下图是第七步：这里使用的是之前从beacon文件里面得到的publickey来实现对相关信息（注意这里的信息里面是存在一个自己随机生成对称加密使用的密钥的）的加密的（使用的是非对称加密算法）：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5effda80cc3dbce82c9b6dab2bc892a8bb58cf1a.png)

我们先来看下对应的流量包，其实这里这个过程的直观体现就是心跳连接，如下图就是这个第七步的流量，里面的cookie承载的就是对应的加密内容：（CS里面我们一般将这个加密的内容称为元数据 metadata）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c0298789203e7d2b779f620241b3bd266ee7b552.png)

如果我们想对其流量进行还原的话，我们来分析下，这里使用的是非对称密钥加密的，所以想到还原流量其实就是拿到私钥，使用私钥对其进行解密就行。

那么私钥从哪来呢？

如何获取这个私钥是一个非常关键的一个点，这里面可以展开讲很多。我们先不对其进行考究。

上述我们分析的流量其实是笔者自己搭建的环节的测试，其中的CSserver也是自己的，所以我们获取私钥的最直接的方法就是跟下cs的源码，看起beacon文件生成的时候从哪拿的这个publickey，这个publickey附近说不定有privatekey的线索，或者直接跟源码里面的上述过程中第八步的实现，看看从哪里取出来的privatekey，这里我们用后者的思路来找一下：

如下图：CS对httpbeacon回连流量的处理在BeaconHTTP类里面：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9f3728b74e721b7377a5bbad40b098ff3823203b.png)

跟进BeaconC2类的process\_beacon\_metadata方法，如下图，第一句就是在进行一个解密操作

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ba55f7d14d49e6c793fcd34c5e12b618553e132f.png)

跟进AsymmetricCrypto类的decrypt方法：如下图就是对传入的变量使用RSA/ECB/PKCS1Padding解密，提取到了私钥，我们来看下私钥从哪来的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-031e34b5d210dfc7bbef734c22ea5baed1471b26.png)

确认这里的确出现使用私钥之后我们回到process\_beacon\_metadata这个方法，看下前面对调用decrypt方法的对象怎么初始化的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5e838a2fd1d029936567d58e79dbe18855970661.png)

如下图，this.getAsymmetricCrypto的实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4e7c31dd6756ee1758ebed52b43eea1ad42a41e2.png)

可以看到获取到的对象就是BeaconC2这个类里面的asecurity对象，所以接下来我们来找下，什么地方对该类赋值了：

整个类里面就一个方法里面对其进行赋值了：如下图，setCrypto这个方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-58884cc20edd55d771de0c80c7093aed18297048.png)  
接下来我们来看下这个方法在哪被调用了：如下图，在BeaconSetup类里面的initCrypt这个方法里面被调用了，传入的参数是从beacon\_asymmetric这个方法得来的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d0bf71f9e3bfff6e4aaff2bbd40ede9735793623.png)

我们跟进beacon\_asymmetric方法：如下图，这个参数的来源是.cobaltstrike.beaconkeys文件来的，并且是对其进行反序列化得来！

这里对照着下图我们多说一句，大家注意，这个方法里面是先检测是否有这个`.cobaltstrike.beacon_keys`文件，如果没有，这里是会调工具类创建一个。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8747991a84fe9fa96892b5955cca07291b0a29a4.png)  
然后我们来到我们起的CS server服务器看一下：如下图，果然存在这个文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c51e653cede8424db00c1ed84bcf5594d0713fb1.png)  
拿到该文件，我们使用如下代码直接反序列化得到对应的公私钥：

public class Getkey {  
 public static void main(String\[\] args) throws Exception{  
​  
 ObjectInputStream var2 \\= new ObjectInputStream(new FileInputStream("keys"));  
 Scalar var3 \\= (Scalar)var2.readObject();  
 var2.close();  
 KeyPair keyPair1 \\= (KeyPair) var3.objectValue();  
 System.out.println("privatekey :"+new String(Base64.getEncoder().encode(keyPair1.getPrivate().getEncoded())));  
 System.out.println("publickey : "+new String(Base64.getEncoder().encode(keyPair1.getPublic().getEncoded())));  
​  
 }  
}

如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-640bb51f5e236ffa5af5ac110dab201724e005d0.png)

首先不着急拿私钥对刚刚的流量进行解密，我们先来核对下这里的公钥是否和之前beacon里面取得的公钥是一致的，从而来证实我们的确没有找错：

之前从beacon里面拿到的公钥如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2cf94035e58ae4a690fd002c27d952356ac015e0.png)

我们拿到的公钥，对其进行base64解密并传成hex之后是：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5aad67bc731939184e56cff522afa9082ab35878.png)

对比上面两图中的公钥，确认无误！

接下来我们就可以放心的使用私钥对Cookie里面的内容（元数据）进行解密了：

这里我们使用一个叫`cs-decrypt-metadata.py`的脚本对其进行解密：

这个py的作用：使用RSA私钥对传入的内容解密，然后根据CS里面元数据的结构体，将解密后的内容进行整理，

脚本获取：<https://github.com/minhangxiaohui/CSthing>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-95091394b661f4722c70a05fbbb866ac7dfed851.png)

先把私钥转出来：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5f6b2e97e276c7dee456aa7af6a4f57388b0cb6b.png)

待解密的cookie内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-79428347ce58da1917bbd134f753f4d3ad2f1b19.png)

使用将私钥、待解密内容传入脚本：如下图，得到解密内容：

使用的命令是：

python cs-decrypt-metadata.py -p 私钥 待解密内容

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b31be96530706a9610ca94cb246b596d1c7b18a6.png)

如上图就是CSbeacon传输的常见元数据的形式，这里在此篇文章中不对上面的内容做详细讲解，知道里面存在对应标记的内容即可。

其中最关键的就是Raw key，在上文中我们提到，这个元数据里面存在一个由受害端生成的AES的对称密钥，就是由这个Raw key生成的。（注意这里的表达，是“生成的”）

到这请求的心跳包我们就分析明白了。

3、第九步中的要执行的命令是什么，我们能否通过流量还原出对应待执行的命令？第十一步中受害端通过post回传的命令执行结果的内容是什么，我们能否通过流量还原对应待执行的命令？
--------------------------------------------------------------------------------------

当有相关任务的时候，心跳包的响应包时存在响应体的，这段流量其实就是下图中的第九步。受害端执行相关任务后需要将执行结构响应个CS server，这一过程在httpbeacon里面时通过post请求中的请求体来将数据传回去的。当然这两部份的内容都是加密的，接下来我们来分析下这两个内容：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2a97859df1c72e7b4810e8d0d9ed82cad15dffae.png)

我们先回到流量包看下这两部分的流量：

如下图是，一个心跳包的来回，发现响应流量中，响应体存在一些看不懂的流量，这里便是C2在发送任务给受害：这里是第33个流

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bf03d1fca52b4d236335edf2cd5425261282a295.png)  
往下跟踪：第34个流

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7924ecaec51b07863f45c26b0bd9e92635edabae.png)

上文中我们有提到这两部分流量都是由对应的对称密钥加密的，所以我们解密的时候只要有对应的对称密钥即可。

同时在上文中我们解密元数据已经拿到Rawkey：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6665896bedf9d4ad0ef9f9645b3f3ddf1a6e4117.png)

所以这里直接解密就行了：

使用脚本：cs-parse-http-traffic.py

脚本获取：<https://github.com/minhangxiaohui/CSthing>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d91a31c4b704383e8d967e8e11aca57a598f0301.png)

这里这个工具是支持直接从wireshark筛选操作的，所以我们要给python装个pyshark：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d0de24554417ea51dd05f903af15d3cba2645ac0.png)  
然后使用如下命令运行即可：

python cs-parse-http-traffic.py -r Rawkey -Y ”wireshark过滤表达式“ 待解密pcap

如下图，完成解密之后，我们可以看到c2和受害端直接通信的明文流量：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f639279d99aa1d91f8d1b7d362623a3a95600fd3.png)  
这里我们简单看下这个py的源码，主要是讲下对应的rawkey和对称密钥的关系：

如下图，在cs-parse-http-traffic中，通过传入的rawkey，计算其sha256的值，前16位为hmac的key，后16位为aes的key。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e0cd73191c793187fe5254139ad0f0d0d75a5357.png)

接下来我们来看下解密：

如下图，这里其实就是和cs的验证机制里面的，对dll的验证方式一样，计算出加密数据内容除后16位之外的hmac的值，和后16位的值做校验，校验通过之后对加密数据除后16位之外的内容使用aes解密，其实使用的模式是cbc，初始IV为：`abcdefghijklmnop`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-03d2746bbf7f07572b3504ad66145a8352af1109.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-968947072045cf02473cab36af2925be8fb25db8.png)

到这就分析得到解密的内容了，原理就是如此。

延申一个点
-----

**这里我们稍微延申的讲一个点：**

上面传输内容实验的AES\\CBC模式的来加密的，其实对于对称加密算法AES来说，其常见的使用形式有ECB\\CBC\\CFB\\OFB\\CTR 这五种形式，其中除了ECB之外都使用了IV这个初始向量来参与到加密过程中来，那么为什么有的有IV有的没有IV呢？这里简单从密码学的角度阐述下IV存在的意义：

ECB模式没有使用IV，其加密实现是：

- 1、对待加密内容进行分组，一组是128或者192或者256，看我们用的是多少位的AES了。
- 2、对分组后的加密内容逐组的加密（AES的加密过程简单说就是四个过程：字节替换、行移位、列混合、子密钥相加，然后看我们选择的AES的位数（其实就是密钥的长度）将上述的四个过程循环重复对应的轮数从而得到最终的结果）
    
    如下图是密钥长度与轮数对应的关系：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ed6952fc38faf22ec06fc8e51f653a2c1d747943.png)

- 3、按照顺序将每组的加密之后的内容拼接起来。

那么问题就出现了，如果我是一个攻击者，我即使不知道你怎么加密的，我拿到密文之后其实也是可以控制明文的，为什么这么说呢?

举个简单例子：

某条银行转账的信息是：A给B转1千万

如果使用的是AES的ECB模式来进行加密，使用的位数是128位的，我们都知道银行转账的时候的肯定不是直接用的A和B来代表客户，而是类似有一个ID来代表一个客户，这也是这个客户的唯一值，其实就是数据库里面说的“主键“。如果这个主键正好就是128位。那么我作为一个攻击者C，我只需要将你加密之后的结果的内容里面第一个数据包和第三个数据包调换一下，就可以构建一个新的数据包，这个新的数据包就变成了”B给A转1千万“。

其实上面这个例子体现出来最ECB最致命的问题是

- 1、数据直接没有关联性，每个孤零零的单着，即使第三方不知道怎么解密，但是可以通过操作密文的顺序来改变对应的明文内容，从而使攻击者C有了可乘之机。
- 2、还有一个致命的问题就是相同明文相同密钥会被加密成相同密文，（插一句题外话：如果有人看过《模仿游戏》的话，里面最后图灵能够破解德军的恩格玛加密，就有这个原因，因为德军发的电报的开头总是会加一句”伟大的希特勒万岁“这样意思的内容，具体是什么我记不太清了，大概就是这个意思）这样会导致什么危害，我再举个例子，我发现Alice和Bob之间在通信，每次Alice给Bob发送一段”fjaskljfklsajfkljasklfjas“的密文之后，Bob就会去打Bob儿子一顿，那么我们下次我们看到这段密文的时候我们就能得出结论，Bob儿子要被打了。所以就相当于间接的知道了这段密文表达的内容。我甚至可以对这个稍加利用：
- - 第一种情况：比如，我告诉Bob儿子，如果他给我1000$的话，下次他爸要打他的时候我就提前告诉他，让他赶紧跑，这样就可以免遭一顿打；
    - 第二种情况：比如，我儿子正好和Bob儿子是一个幼儿园的，Bob儿子平时总是欺负我儿子，于是我将那段密文发送给Bob，Bob看到之后就会去把他儿子打一顿；

那么IV的引入之后呢是怎么来解决这个问题的呢？

我们来看下引入了IV的CBC的加密是怎么实现的：如下图，其中Pn代表分组后端明文。Cn代表加密后的明文。Ek代表AES加密算法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9dae8a8c64ee694c2a2634ea0f136fedff35a930.png)

首先第一组的明文不再是直接被加密，而是和初始向量IV异或之后在进行加密。后续明文也不是直接加密，而是和前一组的密文异或之后再加密。

1、这样就解决了上述密文直接没有关联的问题，只要有人改了一个密文分组的内容，后面的就全部会产生变化。

2、通过改变IV的值，即使使相同的明文和相同密钥，我们也可以通过设置不同的IV来避免，其生成的密文相同的情况。并且IV的正常使用就应该使随机生成的，每次都不一样，并且每次IV都会随着密文一起发送出去。因为解密的时候要用。这里需要注意的点是IV不需要保密，是可以被每一个人所知道的。

因为每个现代密码算法要遵守柯克霍夫原则，数据的安全基于密钥而不是算法的保密。 换句话说， 系统的安全性取决于密钥， 对密钥保密， 对算法公开。

了解了上面IV的作用之后我们回过头来看上面我们还原对称加密的cs的流量的时候，CS怎么做的：

CS这里使用的是AES的CBC模式，并且传入了初始向量IV，但是传入的IV竟然是固定，固定为下图中的内容！

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-548810042d295d3f933cb789f9891a7d2d5fcf3c.png)

并且其对称密钥也是固定的，这也就意味着相同的明文会被加密成相同的密文。所以这里笔者如果是一个第三方的攻击者，如果我监听了受害端和c2的通信流量，来看看我们能做什么，

- 第一种情况：我们根本不用对这个流量分析破解，直接重放一个心跳请求流量，那么c2的CS server就会以为是新的一个受害上线了！！！！！这个想法其实就是一种反制CS的思路，我们通过流量重放，从而使攻击者的cs服务器出现大批量的上线操作，来迷惑干扰攻击者。
- 第二种情况：当我下次看到这个流量的时候我就知道，受害者又再发送上线的心跳包了，然后我就可以以此盈利，如果受害者给我钱，我就告诉他，他的机器在什么时间段向c2发送了上线包

上面的第一种情况就是CS的反制的一种场景；第二种情况其实就是，有点像告警的意味了，你给了我钱（你买了我的设备），你就可以知道你的哪些机器在上线，可能这里稍微有点不那么合适，但是能让大家明白这个道理就可以。

**我们会发现无论是上面的哪种情况，最后的”受损者“都会是使用CS server的人，原因就是CS使用的是固定密钥固定IV的AES的CBC加密模式来加密通信内容。**

这里其实就是因为CS这个的开发者，对密码学的理解不够深入导致的，如果要使用CBC模式那么请每次生成随机的IV，而不是使用固定的。（还有一种原因可能是作者这里图省事，方便之后的功能流量啥的，也没想那么多之后可能会被人反制的场景；这里我带入进去完全想不到作者不用随机IV的合理原因）

**在笔者看来，实际上这种”失误“出现在很多的安全工具上：**

比如大家耳熟能详的webshell管理工具，冰蝎和Godzilla他们都是用了AES加密，而其使用的加密模式还停留在**ECB模式**，并且其密钥也是通过直接写死，或者协商之后，一直使用的。

再比如，Shiro这个安全框架，早些版本使用的CBC模式的AES加密，对登录认证的身份信息进行加密，从而实现持续登录的功能。攻击者可以通过结合其返回信息对其AES\\CBC的加密体系构造特殊的填充使用字节反转攻击，爆破出加密之后的payload，从而攻击利用，其实就是大家说的shiro721。（不过这个严格意义上来说没有并没有用错加密算法导致的，而是使用的算法存在脆弱性，攻击者结合算法的脆弱性和组件的脆弱性，从而成功发起攻击利用）

好了接下来我们回到流量分析中

0x04 回到pcap分析
=============

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a553e9f92918247c5459bfbdc95454b1466bc20.png)

对照下图分析对应pcap流量

1、第三步和第五步
---------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b05a0c44eb42a2dd0e3fcf0dbb31a4b922670c72.png)

对应pcap里面的流量

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-17154593c7dfa98692444fd2e70aa572b57e2864.png)

请求的uri，其实就是使用特定算法生成uri，这里我们来计算下CeKi 转10进制之后模256之后的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3013153c298ae16eec59be3be608008fba7aee13.png)

（67+101+75+105）mod256=92

如下图是判定标准，这里是92所以是一个x86的beacon：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e28864b2cf3341c27b38c8076f3b22ec2099f0a9.png)

而响应体里面的内容其实就是对应的stageBeacon的内容，所以这么长。

这里我们简单分析下这个流量的特征特征：

1、对应uri生成使用的是特定算法。

2、响应头里面的CL字段，这个CL是一个非常大的值，因为要传stagebeacon文件。

2、第七步和第九步
---------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-625b00bbaa7f75ac4086abad36d38a34061dd214.png)

对应pcap里面流量：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e6dfe82e31a0ed8429236a8b1aa1fc1d2048701b.png)

这里我们简单分析下这个流量的特征特征：

1、请求的uri是cs的默认心跳uri

2、Cookies是一个base64编码的内容

3、响应头里面的CL字段为0

4、响应头的CT字段是一个可执行type (application/octet-stream)

上面的单挑每一条可能都是弱特征，但是如果组合在一起，那就是一个非常强的特征了！！！！！！！

其对应的阶段，如下图：图中的第七和第九步：第九步中的没有任务情况。

3、第十一步
------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b7767752cebb41ac4862d6fb1bf2322f7d9ad75e.png)

对应pcap流量：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3e99fd0fc2b2acb09d8ce5e503686b05a44e5b06.png)

两种分析方式：

1、这里post的uri：submit.php,其实就是cs默认的回传命令执行结果的uri，并且参数还是默认的id。那么我们直接就得出结论了

2、严谨一些，这里我们找到并导出对应beacon文件，然后导出对应的CeKi stagebaecon文件，对该文件进行上文中的方法解密，然后就可以看到其回连心跳的uri以及回传命令执行结果的uri。

这里同样我们来看看这个流量的特征点：

1、post的uri是CS默认回传命令执行结果的uri，和参数id

2、post请求头里面的CT字段为(application/octet-stream)

3、 post请求头里面的UA字段，这个UA在cs的ua库里面，如下图，cs4.0内置168个ua，

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-411cdbffd44dadec0c93db1abe50be508e868d6e.png)

4、响应头中的CL字段为0

5、响应头里面的CT字段为test/html

6、（待实践证明，aes可检测）请求体里面的流量是一个aes加密后的流量，具体的话怎么检测aes流量，大家也可以了解下。

0x05 几个需要去思考的点
==============

1、上文我们去解密cookies里面的metadata数据的时候，是直接从自己的cs server里面拿到私钥的。那么如果是攻击者的服务器我们这里怎么拿到私钥呢？
---------------------------------------------------------------------------------

这里我们有两种方式来获取攻击者server上面的私钥：

- 1、上文我们曾提到过，公私钥对（.cobaltstrike.beacon\_keys）这个文件的由来，如果没有才会重新生成。
    
    这里其实就是有问题的，大家想一下，我们自己或者是攻击者手上的cobaltstrike是从哪里来的，是正版买的吗？肯定不是吧，其实都是破解版的，也就是相关研究人员逆向改变源码之后“绕过对应cs的自验证机制”生成的破解版，笔者在奇安信攻防社区曾发过一篇文章[《Cobaltstrike4.0 学习——验证机制(破解)学习》](https://forum.butian.net/share/1836)，感兴趣的话可以去看下，里面详细的讲述了cs的自验证的原理，并提供了破解思路，看完之后就可以直接破解cs4.0了。所以这样就导致了，很多对cs的了解不够深入的人在使用破解版的cs的时候，使用的密钥文件（.cobaltstrike.beacon\_keys）都是破解版里面自带的。
    
    那么机会就来了，对于互联网上几个通用的破解cs的版本，都可以通过vt收集到，对应的.cobaltstrike.beacon\_keys文件就泄露出来了，大概有10来个，我们可以通过这些密钥对去尝试加解密对应的元数据metadata。然后通过metadata里面获取到的rawkey来解密对称流量，从而还原对应的执行命令和命令响应流量成明文。
- 2、第二种方式的话，严格意义上不叫获取私钥，但是其最终的目的也可以拿到rawkey，从而来解码流量。
    
    这种方法是通过dump下beacon的内存，从中将元数据metadata给dump下来，然后拿到metadata里面的rawkey对交互流量解密。
    
    使用Sysinternals 的 procdump来dump内存数据：
    
    <https://docs.microsoft.com/zh-cn/sysinternals/downloads/procdump>
    
    但是这里有一个问题，cobaltstrike4.x之后在beacon内存里面其metadata数据不是直接存储的，而是被“编码”了的（这里我们要对beacon进行调试分析可可以去验证这个），只有在使用的时候才会还原，所以我们这里就有点不好找了，但是可以瞎猫碰死耗子嘛多dump几次，说不定，碰见这个被解码之后的元数据了呢，还有一些其他的碰撞的方法，可以自行了解下。

2、上文中的metadata是在cookies里面传输的，为什么，是都这样吗？我们来看看CS的c2.profile文件分析。
--------------------------------------------------------------

其实这里的元数据是通过cookies来传输这个行为，就是由我们的c2.profile来控制的，此文我们不去详细将CS里面的c2.profile的修改方法，和分析一些C2.profile的配置，只是简单看下默认的配置c2.profile。

常见的profile文件：<https://github.com/rsmudge/Malleable-C2-Profiles>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4b6e4bd617c0340fb74b5fb198b6cbde4aa7d38d.png)

这里我们来看看默认配置的c2.profile：

如下图是，运行server的时候我们没有加c2.profile参数，这里就会使用LoadDefaultProfile（）来加载自带的c2.profile：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dbe2c561d13e43fc791041659e40e251cd95c8af.png)

跟进该方法：如下图，使用的是resource/default.profile文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-af3593f8bec5ec6fd7291c2ce849d275cb838e93.png)

该文件如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ca88dbf51193608ea47ef36092a53760b622e86c.png)

这里我们来看下几个关键点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c5a09b7f1d1588fd92b5336a3f272c4f38243bb4.png)

下面是配置的心跳回连的一些参数：如果有任务，直接在响应体里面传过来

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f85d19ff64d0175caac79014c4e0b39374e46c20.png)

命令执行响应：执行结果在请求体里面传出去

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4617b43a9d36f584e35f94667f06600230078fdf.png)

感兴趣可以去了解学习下，哪些apt的样本使用的c2.profile，还有前两年比较火的云函数cs上线的c2.profile，等等。

其实这就是核心，我们ids的规则流量检测点都是从这个文件里面分析出来的。同时这也是为什么基本上我们的ids设备上基本告cs通信流量都是由情报触发的，因为流量侧非常不好写规则，只能说对一些默认配置做规则，如上面我们这个例子，但是中高级的攻击者对流量形式做修改之后，流量监测规则基本就失效了。由于cs的这一开放性，所以从攻防的角度来说，防总是跟不上攻的。

3、CS的反制手段，上文我们简单提到了一个通过重放流量，来实现批量上线cs，来干扰攻击者，但是这是非常局限的，我们就批量上线详细看看。
-------------------------------------------------------------------

其实cs的反制手段有很多，此文不过多深入，但是上文有提到一个利用重放流量批量上线的点来做cs的反制的思想，这里我们就这一点展开讲讲：

首先我们的确可以通过重发心跳流量来重复上线，但是这很容易被攻击者所发现并处理，因为这里上线的内容是重复的，我们使用脚本批量重发之后的效果只是同一台机器，在cs上上线了n次，因为使用的metadata数据都是一样的，攻击者只要不傻就知道怎么回事了。

那么我们怎么进一步升入呢？

如果我们知道公私钥对的话（上面有讲到获取私钥的姿势），那岂不美哉，知道私钥之后我们就可以，通过模仿受害端使用公钥来伪造很多不同客户端上线的metadata元数据，那么我们的目的就达到了，攻击者cs server直接炸裂，全是上线，通过这样我们就可以干扰并反制攻击者，从而在特殊场景下为我们的排查争取时间。

4、简单看看cs里面的证书文件
---------------

CS里面的证书一共有三个cobaltstrike.store，proxy.store，ssl.store，三个证书的作用如下：

- 1、cobaltstrike.store证书用于服务端和客户端加密通讯
- 2、proxy.store证书用于浏览器代理也就是browserpivot功能
- 3、ssl.store证书，如果你没有配置https-certificate选项，并且使用的是https监听器那么Cs默认就会使用这个证书

我们通常所提到的更换cs的证书，指的是第一个证书，第一个证书里面默认的用户单位啥的名称都是cs server运行使用Java 里面的keytool生成的默认的：

keytool -keystore ./cobaltstrike.store -storepass 123456 -keypass 123456 -genkey -keyalg RSA -alias cobaltstrike -dname "CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike, L=Somewhere, S=Cyberspace, C=Earth"

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1533ac9924fafe803449d747cbefe85e4ec26459.png)

5、（分阶段）stager和（无阶段）stagerless的区别：
---------------------------------

如下图，我们在生成可执行文件样本的时候，一个带s，一个不带s：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-eb3fa818cb64a533375f17720ecab773bb26d374.png)

其实这个直接的影响就是，生成文件的大小，我们使用上面没有s的生成的exe会小一些，使用下面带s的生成的exe会大一些，同时对应的上线流量也会有些区别。

在笔者看来，一般来说我们不用花里胡哨，直接使用下面那个带s的就行。上面这个不带s的一般的使用常见是结合一些漏洞使用的，如相关溢出漏洞，对空间的要求比较严格，所以我们就是放一个比较小的“恶意代码进去”，此时才需要使用不带s的。除此之外，为什么建议我们直接使用带s的无阶段的原因还有就是防溯源，因为使用分阶段的stager，我们的beacon是会被扫出来的，上文也提到过。当然这里可以将cs的源码改了，对其验证算法进行魔改，但是其beacon文件传输的特征还可能会被相关ids设备检测到。

0x06 总结
=======

很多东西知其然不知其所以然，这样稀里糊涂的学习的是不可取的，我们应时刻保持好奇和求知。

**路漫漫其修远兮，吾将上下而求索**

笔者才疏学浅，若文中存在错误观点，欢迎斧正。