0x01 前言
=======

简单说就是演习活动中发现cs里面有很多不懂的点，这篇文章的话主要是记录自己对cs4.0的认证模块进行学习的"心路历程"。

0x02 cs中的认证
===========

拿到jar（这里我使用的是之前发布的4.0的破解版），通过idea反编译下：

![image-20220816175731043.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d0efd5dd1986b3261f11ddd0efbe49e11fe39ad0.png)

![image-20220816175641815.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-46b536ca5de30f45586033980bfa2dd35db5391f.png)

这里我习惯先静态分析下：

首先我们找主类：

![image-20220816175916830.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b12cfba3cb68c96ac27842ab0904f7402112f4c2.png)

其实现如下：

![image-20220816175958809.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8e48771a6c41bf9f79073d3fc15ea5262c202f76.png)

如上图，很明显这里进入main方法之后，最先要开始的就是我们这里的认证了，因为cs是一个收费的软件，买了之后可能会有类似的注册码啥的（我也不清楚，没买过，估计是），所以笔者写这篇文章的主要目的也正是研究下这个认证的过程。

![image-20220816180626278.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e7af5c5769b28ea04fcdc0b39d1f54d48c2d4e2c.png)

如上图，上面的都是初始化和环境兼容的东西，这里我们直接过，

来到`License.checkLicenseGUI(new Authorization());`

看着是再检查个什么license，就是我们要找的，这里直接先去看下Authortization类的无参构造方法的实现：

该类的位置如下：

![image-20220816180905866.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4edaea4c4490ec1e6ea4030674ea6e8e5cb2b3b1.png)

其构造方法实现如下图：

![image-20220816181002300.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9d06b779bb90018ee7e2de767ca341e289d5c6db.png)

代码：

 public Authorization() {  
 String var1 \\= CommonUtils.canonicalize("cobaltstrike.auth");  
 if (!(new File(var1)).exists()) {  
 try {  
 File var2 \\= new File(this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI());  
 if (var2.getName().toLowerCase().endsWith(".jar")) {  
 var2 \\= var2.getParentFile();  
 }  
​  
 var1 \\= (new File(var2, "cobaltstrike.auth")).getAbsolutePath();  
 } catch (Exception var11) {  
 MudgeSanity.logException("trouble locating auth file", var11, false);  
 }  
 }  
​  
 byte\[\] var12 \\= CommonUtils.readFile(var1);  
 if (var12.length \\== 0) {  
 this.error \\= "Could not read " + var1;  
 } else {  
 AuthCrypto var3 \\= new AuthCrypto();  
 byte\[\] var4 \\= new byte\[\]{1, -55, -61, 127, 18, 52, 86, 120, 40, 16, 27, -27, -66, 82, -58, 37, 92, 51, 85, -114, -118, 28, -74, 103, -53, 6};  
 if (var4.length \\== 0) {  
 this.error \\= var3.error();  
 } else {  
 try {  
 DataParser var5 \\= new DataParser(var4);  
 var5.big();  
 int var6 \\= var5.readInt();  
 this.watermark \\= var5.readInt();  
 byte var7 \\= var5.readByte();  
 byte var8 \\= var5.readByte();  
 byte\[\] var9 \\= var5.readBytes(var8);  
 if (var7 &lt; 40) {  
 this.error \\= "Authorization file is not for Cobalt Strike 4.0+";  
 return;  
 }  
​  
 if (29999999 \\== var6) {  
 this.validto \\= "forever";  
 MudgeSanity.systemDetail("valid to", "perpetual");  
 } else {  
 this.validto \\= "20" + var6;  
 CommonUtils.print\_stat("Valid to is: '" + this.validto + "'");  
 MudgeSanity.systemDetail("valid to", CommonUtils.formatDateAny("MMMMM d, YYYY", this.getExpirationDate()));  
 }  
​  
 this.valid \\= true;  
 MudgeSanity.systemDetail("id", this.watermark + "");  
 SleevedResource.Setup(var9);  
 } catch (Exception var10) {  
 MudgeSanity.logException("auth file parsing", var10, false);  
 }  
 }  
 }  
​  
 }

接下来就是分析这个构造方法的内容了，

其中17-31行如下图，就是在获取cobaltstrike.auth这个文件的内容，当然其中还做了一些兼容，比如说这个文件和jar不在同目录之类的，这里我们不做过多研究

![image-20220816182541029.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0308247c388a3926e3ca89d4596d28ea72377b4a.png)

其中CommonUtils这个类是 cs里面的一个工具类，里面集成了大量方法以及函数的实现：

其中在上图中出现的两个`CommonUtils.canonicalize`、`CommonUtils.readFile`分别是获取绝对路径和读取文件内容到byte数组

![image-20220816183236539.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d57690a1914415424e385b687d044039dc3ccb50.png)

继续接着Authorization的构造方法往下分析，如下图，从36行开始其实就是一直对var4这个写死的变量，通过DataParser转换成var5之后，对其进行读相关字节进行一堆判断操作了，这里应该就是再做认证了：

![image-20220816184024410.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ffb85799e1657ef0c5736ac4f99f3e6a1a17ef88.png)

那问题来了，var4这个变量又是哪来的呢，奇奇怪怪的，自己给出了一个变量，然后自己又对这个变量一顿解析，感觉怪怪的，难道不是由使用者提高这个变量吗？

擦回头一看，我反编译的是破解版，丢，这里应该是在做破解操作，这个var4应该是通过某种验证手段生成来的，这里破解的时候直接就把4.0正确的值写到这里面了，看来还是要反编译原版的更能讲的清楚些，但是其实这里我们漏了一句，如下图35行中的内容：

![image-20220816184712004.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f24140cd7f57ae82d5674e526d2a02e1147a3d57.png)

这里面的var3，最后一直都没用到了：

![image-20220816184811966.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-345131816d42dce771dda6ded544b4533d9f8cf4.png)

所以这里不难可以得出，var4原本可能是从var3通过某种方式得来的：

如下图，我们跟进下AuthCrypto这个构造方法：不难看出构造方法里面在准备一个rsa的cipher对象，使用的模式是ECB/PKCS1Padding，应该是之后要用

![image-20220816184941199.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bd26471268a45f3944b6f9d9cc30337105014217.png)

同时在该构造方法中也调用了其load方法，如下图，load方法里面，首先拿到了resources/authkey.pub的值，然后计算其md5的值，用来和写死的一个数值作比较，如果相等的话就会利用这个resources/authkey.pub中读出来的文件内容的值作为参数来初始化一个X509EncodedKeySpec对象，进而通过KeyFactory对象的generatePublic方法传入该X509EncodedKeySpec参数对象生成一个公钥。

![image-20220816185418574.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-474d1cbcceca5760196b6733241f2d5cd05ee00e.png)

这里我们思考下两个问题

1、上面这个authkey.pub文件是干啥的,为啥要将其hash值和固定的值作比较?

其实很明显了，这个文件的命名可以看出和公钥有关，所以这里其实就是在验证公钥的“合法性”，用合法性这个词有点怪怪的，嗯简单来说就是，代码在这里就是为了确认这里的公钥是cs自己的公钥，大概就是这个意思。

2、这个公钥是用来干啥的呢？

在密码学里面，公钥就两种用途

- 第一种用途就是，当非对称加密算法被用于加密时，其中的公钥被用于加密，私钥用于解密
- 第二种用途就是，当非对称加密算法被用于签名的时候，其中的私钥被用于签名，公钥被用于签名验证也叫解签名

这里的话是第二个用途，上文也有提到，当我们获取到cobaltstrike.auth文件内容之后，就没有操作了，莫名其妙冒出来一个var4，这个var4就是破解者自己插入进去的，实际情况，这个var4应该是cobaltstrike.auth文件内容和刚刚生成的公钥一起获取到的，所以这里就很明显了，cobaltstrike.auth这个文件是被cs的私钥签名某个特殊字符后生成的内容，而公钥就是来解该签名的，从而获取之后的特殊内容，该特殊内容就是var4，所以也就是为什么后续一堆操作都是围绕var4来展开的。

搞清楚这两个问题之后这里我们来详细看看对这个利用公钥解签名之后的var4的值做了哪些处理：

首先将其转成DataParser之后就连着读出来里面的5个值：

![image-20220816191433618.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-12ef1f5d9393ccc3e83ebb4be8c57d24fbad3e7e.png)

对其中的第第一个值进行判断，如果等于“29999999”那么这个是一个永久的授权，不然好像就是20天的体验期，

![image-20220816191535854.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d5720c8116b107fa9c4884d3e014b93f18a0d913.png)

对其中的第三个值进行判断是否小于40，小于40就不是4.x的授权

![image-20220816191651892.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-16618466531af04503662d281f9dcc6eb316192c.png)

其中的第二个值是一个id数字

![image-20220816191745560.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c9ece2b027eb0b5c52a0f3170bfed7a9bb2a83ff.png)

其中的第四和第五个值，是存在关联的，第四个值应该是第五个值的长度，因为在读第五个值的时候readBytes传入了第四个值，

![image-20220816191913030.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8b26a57551c7f347aa2a499be171a975d8eea1ca.png)

最后第五个值也就是var9，被带入了SleevedResource.Setup方法里面：

![image-20220816192019473.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-22337695f72fd9a618eab59887cd0dbc4cb671d6.png)

接下来我们跟进该方法的实现：该方法最终实现是由this.data.registerKey来实现的：

![image-20220816211846863.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-217c54d62b70a80e56a59ade5a898afd99aa1902.png)

而this.data的数据类型是SleeveSecurity ：

![image-20220816212038324.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6bdca40aa349f468a37b54070b462de153d1fd29.png)  
所以接下来我们跟进分析下SleeveResource的registerKey的实现：

如下图，该方法里面先上了个同步锁，34，35行直接计算出上面我们从cobaltstrike.auth里面解签名拿出来的第五个变量的sha-256的哈希值

![image-20220816212605293.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b7143cf17be4dcbf32f812816d347df21f31d53f.png)

然后在后面的四行，也就是36-39行，则是，将计算出来的32位hash值分为两半，前16位是用来初始化一个AES的SecretKeySpec对象，

后16位，用来初始化一个Hmac的SecretKeySpec对象，然后就结束了。

分析到这，我们会回头来看aggressor的主方法：

![image-20220816212925920.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5d94ef49bdefd206cdb6c41f425155a969908560.png)

跟进License.checkLicenseGUI这个方法：

其实就是更具Authorization的返回值用isValid和isPerpetual和isAlmostExpired来做判断

![image-20220816213035818.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fb4762ceec213e34695506511a5828c373e838ac.png)

其实就是在Authorization()种对对应的解签名后的cobaltstrike.auth逐个读做出的判断，如下图，判断好之后就是对error、validto的值做调整，从而使启动失败，在License.checkLicenseGUI中就会执行system.exit(0)退出

![image-20220816213603870.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ad625ec0c77bfa5d3772bc7a8276c006f9a23481.png)

到这就直接分析明白了，只要我们将cobaltstrike.auth的解签名之后的值控制成符合要求的，我们就可以破解这个

`License.checkLicenseGUI(new Authorization());`带来的验证效果：

思路的话有以下几点：

1、暴力点，和上面这个破解版的一样，这个破解版的应该是作者不知道从哪搞到的一个正确的”var4“，直接写死到里面。直接over

2、智取，自己生成一对rsa，公私钥，用私钥对上面的正确的var4签名，并且替换掉cobaltstrike.jar里面的resources/authkey.pub里面的公钥，并修改AuthCrypto里面的load函数里面校验公钥的时候的写死的md5的值，如下图：

![image-20220816214427380.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1b5c92cf6d801dee96c2975fc75a1a64b30f4e1b.png)

这样我们就也可以完成这个验证，但是要修改源码

3、智取，和2的思路一样，但是修改源码我们不通过反编译来修改，而是借助javaagent来修改，和javaagent型的内存马一样，通过javaagent注入技术结合java assistant技术来实现 premain方式的注入，在打开之前篡改“内存”里面的对应类的字节码（其实这里说内存好像不太对，笔者拿不准，可能说jvm会准确些）

简单总结下并抛出疑问：
-----------

不管通过那种方式，其实还是要构造一个合格的正确的var4才行，这里破解版里面给出来了我们一个，是只能是这个，还是可以我们自己构造呢？因为看校验其实也就两三个字段，一个是等于29999999，一个好像是小于40这些不到随便构造吗？按道理符合这个而条件都行的，同时包括后面的那个长的变量最后生成的两个（一个AES一个Hmac）SecretKeySpec在后续的验证中也没有用到？怎么感觉怪怪的

为了解决上面的疑问，这里我们要继续分析研究

0x03 另一个验证的点
============

其实到这，正常思路是使用原版的cobaltstrike.jar，进行动态调试进行分析了，但是这里我们用的是破解版的，这里我们继续静态分析下这个破解的版本的cs。

上文最后的疑问的核心点，其实是围绕最后那两个key的，意识到那两个key是关键，那么解下来我们去找找，后续过程中在哪里使用了那两个key，或许能发现上面蛛丝马迹：

这两个key是在SleeveSecurity类里面的registerKey（）方法里面提到的，所以这里我们继续回去看下这个类的：

该类的结构如下：

![image-20220817191713742.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-522fa43d927868794c13d0f6a1a724194484706a.png)

如上图，我们可以看到这个类里面的还存在一些加密解密以及填充的方法。

简单来看下几个用到key和hash.key的方法：encrypt方法和decrypt方法

![image-20220817193143961.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5c3b6ff5015f213f37ff2a7e2e2f2cc6d9351c1e.png)

如下图是encrypt方法的实现：

![image-20220817193219541.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-17d2e300cfc87af2ae77171ea29a686e69de1f9e.png)

分析代码内容的话：

首先对传入的字节数组拓宽了1024的位置，并做了下reset，和pad方法：

![image-20220817194021681.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6ae9b471880544886bf19ed3df8348d037f1bcac.png)

这里我们来看下pad方法：如下图，这个方法就是在做填充：填满128位，换成ascii的话就是16个，填充使用的是65（“A”）

![image-20220817194105883.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a99c9c98113dee3f1af4b6261cba7e31a3033955.png)

这里我们接着往下看，注意先不要关注var3，因为我发现这个方法里面没有对var3进行使用，感觉这里应该是被修改过的，所以我们直接往下看对var2的处理，如下图：上了个锁，然后调用do\_encrypt方法并传入之前的AES的key和var的内容

![image-20220817194435565.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-643f7d969889eeb1dddfe1737632d6abd8e9be86.png)  
所以我们要先来看下do\_encrypt方法，如下图，该方法

![image-20220817194557218.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2e454dc5ddb6a10d497b166c96baee190554e6a0.png)

这里面调用了this.in，我们去看下this.in是什么：

如下图在SleeveSecurity函数的构造方法里面我们可以看到：in是一个加解密使用的Cipher对象，并且初始化的时候是准备用来做`AES\CBC\NOPadding`模式的加解密的，其实使用的iv则是由“abcdefghijklmnop”初始化得来的IvParameterSpec对象（这里多加一句话在密码学里面，CBC模式需要IV，除ECB模式之外的CBC、CFB、OFB、CTR等相关模式都是要使用IV的，是为了防止，相同的明文内容被加密成相同的密文，从而被敌人得以利用）

![image-20220817194826009.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-07955e55806c4c524b54397addfce5071e995840.png)

回到do\_encrypt，如下图，这个方法就很明显了，就是使用之前我们第一阶段获取到的aes的key来对var2做了一次aes的加密然后返回：

![image-20220817200206706.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-802e0d6d75fff0ce6cdde1ed864c802b27d5c10c.png)

![image-20220817200145918.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b7819ea97e023817b85b02fd99a445439cedf474.png)

并且最后赋值个var12：

![image-20220817200318552.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ddd0f11284989ab8f2f4ca1e1fbde302226c972b.png)

解析来我们看下对var12又进行了哪些操作，如下图，对var12进行hmac生成var13

![image-20220817200433616.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-81fab25ea89a6f1a8f6b72cd9e91bd38b1cea9f3.png)

接着往下，最后返回的内容是var7，而这个var7是由两部分构成，前面是var12（aes加密生成）的内容，最后的16位是var13（计算加密生成的var12的内容的hmac）的前16位：

![image-20220817200746624.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5b8dd7a722fce43b0ef8e003d62a8777978598ec.png)

到这里其实就很明显了，因为笔者之前有过对密码学的学习，可以看出这里其实就是使用aes和hmac的配合，从而来保证数据的机密性和完整性，其中aes用来保障机密性，hmac则是保障消息认证时候的完整性，没有被未授权篡改。

基本是同样的原理，我们分析SleeveSecurity里面的decrypt方法，如下图，这其实就是在验证传入的数据是否为之前我们通过encrypt的方式得来的。

![image-20220817201421159.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-82c5126db5070802f5c0b03bea1cff6d354ad21c.png)

分析清楚这些之后，接下来我们需要找到在哪调用了这里的两个方法，所以这里我们需要拿到破解版的源码，遗憾的是之前破解版的源码被公开的时候，我当时没fork，也没download下来，所以这里只能尝试反编译还原下源码了：

借助idea里面的java-decompoler.jar来实现反编译拿到源码：

java -cp java-decompiler.jar org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler -dgs=true lib/\*.jar decomp/

上命令中 lib/\*.jar 是我们想要反编译的jar，后面是反编译之后的结果：

等个3、5分钟执行完后：

![image-20220817211745282.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c002cdb5715be5e0b561eb9ab66aa702e898c0a2.png)

![image-20220817211915638.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a6cc5781adafa2fa9b3e6b3d5d34dd6d8fe0e500.png)

如下图是解压后的文件：

![image-20220817211953339.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-260eff9c50da74c1cda9167d445898f6f228ff63.png)

随便打开一个之后发现里面都变成了源文件：

![image-20220817212026759.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7924721d09e81fa7dbe9633416f478427ce6ec31.png)

接下来我们看下源码里面哪里调用了上述encrypt和decrypt方法：

我这样找了一遍，调用地方太多了，并且调用其的地方也是一个方法，再被其他地方调用，所以这样反着推好像不太好推出来了，这里再往下就两个方法了：

1、将上面找到调用的地方打上断点，动态调试cobaltstrike.jar，这种方法比较难搞，工作量有点大。

2、找到4.0的原版，在原版的基础上二次开发，绕过前面的认证，然后看下后面哪里会出问题，那么就从哪里找（ps：其实一开始就应该这么干，不过没关系，咱们前面的工作也不是白费）

这里我们使用第二种方法：

我去”知识的海洋“里面找到了一个4.x的版本原版：

![image-20220818201927292.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d892ea837e372428fe9ca838957da3b8e322fbbf.png)

打开4.0，然后和官方的核验校对了下，确认没有问题，接下来我们就可以放开手干了

![image-20220818202403682.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5d1a77cee6aeb5857196284cfe1e483eb3f57718.png)

将原版的考到项目lib文件夹下面并区别命名：

![image-20220818203456706.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3cc35866befe74a4eb720f955c3e09c7786c9824.png)

然后同样调用java-decomplier.jar来反编译：

java -cp java-decompiler.jar org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler -dgs\\=true lib/cobaltstrike\_origin.jar decomp/

将得到的jar解压：

![image-20220818203701372.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8d23811a7fafc10fd4b113ff0c01fd7d101afdff.png)

然后就是回到项目里面，为项目添加jar依赖：

![image-20220818203939388.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d5aa608e3010727d2d6b62fb6c7839e31157f4ec.png)

添加一个artifacts：主类用之前的一样的主类，aggressor.Aggressor

![image-20220818205120525.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-69eea616b5e61d3617bd61865c253a097d2ae39c.png)

到这二开的环境就准备的差不多了，一会有大用处。

接下来我们先来对比下，原版和破解版的区别：

如下图，果然如我们在上文推测的，这里对这个var4进行的篡改，直接填入4.0对应正确的值。

![image-20220818210158883.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0ab0e0c54347f0600780dc09fdaf8ad6f0da5f2e.png)

其他的两个存在差异的点对认证好像没什么影响，所以这里我开始怀疑是否真的需要后半段的认证。

![image-20220818210421496.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0bfd8cc6686384794c3c8672797c3a01919c18bb.png)

接下来我们二次开发下这个原版的cs，仅仅是干掉aggressor里面的认证环节。简单暴力点，如下图，把下面的var4替换成破解版里面的var4，但是我们这里修改下后面的内容，因为前文我们分析过，这里的var4的前部分是用来做gui的验证的，后面的才是key：

![image-20220820200919098.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d07b9809149504f58018a95e50144cfeab86f8ff.png)

![image-20220820201025764.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1ed433fe45de4f348df787773e6c599a14edfabc.png)

然后用用生成的jar，去测试下server端：

![image-20220820201129857.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b95867489c2818a885957c50b1c43291ff8221ca.png)

丢到kali的cs里面，并改名cobaltstrike.jar:

![image-20220820201215630.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0ddbc89f8940744fb047e14f49191f4f39b86c6c.png)

运行：

![image-20220820201241593.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-098523fb63d4c3d3ddca49c7c22000fc80e4ed0c.png)

这里出来了个错误提示：`Bad HMAC on 208928 byte message form resource`

我们去源码里面找下：

![image-20220820201715197.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-124b346572f18a059da6ba63cd65a82eab93375d.png)

有两个点，存在这个错误信息：

![image-20220820201823173.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ed7e9afaf4e24f6cd2b83c05fd0ba4bb30e03de9.png)

我们先来看看这个SleeveSecurity这个类，因为上面我们静态分析的时候就是分析是这个类在弄后续的校验：

找到125行：

![image-20220820202059058.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9b955241db4f82110f049e0c446e85536bd57ee6.png)

如上图，这里其实就是我们静态分析的时候的decrypt方法，这个方法是在做aes hmac的一个校验：

接下来我们来看下这个decrypt方法是在哪里被调用的：

![image-20220820202400493.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e56fd76bcd2b3ef63ffd23186a6058d2a101cc72.png)

来到SleevedResource这个类的\_readResource()方法：如下图

![image-20220820202532777.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f6d9693bcdee347c01755fa12985f37a68b8aea8.png)

先不着急分析内容，我们看看哪里调用了这个：如下图，其实就是自己的readResouece这个静态方法里面调用了：

![image-20220820202729246.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0a7f37621cb23ced56d0d26afc1a8bd7cc2a0316.png)

继续找找哪里调用这个静态方法readResource方法：如下图，这些都是调用点，发现这里似乎都dll的相关操作有关系，如下面的，exportSMBDLL里面调用了，exportTCPDLL里面调用了等等，

![image-20220820202819493.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a8769ac6e25925e6ad9ce9336e62f3c4cb0a12ba.png)

因为点太多了，这里我们选择回来看下SleeveResource类里面的readResource整个方法到底在干什么

如下图，readResource里面其实就是调用了\_readResource方法，

![image-20220820203327353.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-871d7a2c1958fc36a51e16e3970b8a074c71663a.png)

上图中调用了工具类的strrep方法，就是将var1里面的`resources/`替换成`sleeve/`，得到var2

然后调用工具类的readResource方法，将var2文件内容以byte形式读出来，得到字节数组var3，所以其实var3就是这个var2文件的内容的字节数组

![image-20220820203738666.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c4970340c4e17cb74ca6339db5934e89fc94c52a.png)

如下图，然后，如果var3有内容的话，这里就直接调用data的decrypt方法对var3进行处理（其实就是解密验证）：

![image-20220820204023206.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2801cd1efe7fd05729dda0e54c9a72d8852ca21b.png)

如下图，这里的data是：SleeveSecurity类的一个实例

![image-20220820204140192.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-22cb4fd424c1daae5a47872dd123a73424b25f93.png)

所以接下来就是调用SleeveSecurity()的decrypt方法：如下图我们来分析这个，先将传入的分成两部分

![image-20220820212032453.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dae43c4cf8d88f7cd112bf7e71e972586777bbb5.png)

然后来了个锁，对var2也就是文件内容前面到倒数16位的内容做了个hmac操作，赋值给var14,这里做hmac前面我们分析过，用的就是得到的hkey来做的：

![image-20220820212308848.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8c1500e7ff42975cb5ff3e02480b58f3747d753e.png)

然后将得到的hmac的值也就是var14的前16位赋值给var5，并校验var5是否和var3（文件byte的后16位）相等：如果校验失败，就直接报我们刚刚运行服务端的时候的错误了：

![image-20220820212514561.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2ad74c6e5bea278e66c57fbb38f9d10b7e3fe647.png)

如果校验通过的话，我们来看下接下来的else，如下图：使用之前的aes Cipher对象对文件字节的前面内容（var2）解密，赋值var15

![image-20220820212939441.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-42c5d5de60ca591dda353f6ec0c61c399807860c.png)

最后将解密的内容var15做了个流转化，读前面两个int，以第二个int为长度，来获取最终的解密内容并return：

![image-20220820213443492.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a2b49d5989e6edd507b4161fcffcf28367d1025d.png)

到这，就分析的差不多，其实\_readResource这个方法，就是做个字符替换，然后找到对应文件，对文件进行hmac验证，并解密。那这个些要验证解密的文件是什么呢？

如下图，做替换的是将`resources\`替换成`sleeve`

![image-20220820213729656.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9d00234bec654ad85f92f36c318207abc8ac5fd0.png)

也就是最终是要读sleeve里面的内容，这里我们去找了下，cobaltstrike.jar里面的sleeve里面的内容，如下图：所以很明显了，就是后续要用到dll的时候就会做验证，而这些dll的内容其实都是加密的，前部分内容是aes加密的，最后16位是使用hmac对aes加密后的内容的产生的特征值。我们后续要使用dll的时候都要先解密才行。

![image-20220820213914722.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ea9f26fcd29e5fa498a66ec1adcad2da0321b5d7.png)

0x04 总结
=======

其实分析一通之后，得到的结论，就是cs4.0存在两个验证的点，一个gui的验证，一个是server端调用dll的时候的验证。所以想要破解cs4.0并使用，就必须绕过两个验证的点。其中第一个gui验证比较好弄，破解的方法上文也有提到过，可以简单粗暴也可以更具原理我们构造rsa公私钥对去绕过验证。但是第二个dll验证就不好搞了，因为核心是cs.jar里面我们要使用的dll是被加密了，而加密使用的密钥是由cobaltstrike.auth文件经过解签名之后的一部分内容得来的，我们可以自己构造auth文件，但是这样只能绕过gui的验证，但是后面用于校验和解密的hmac的key以及aes的key都是没有的。所以第二个dll，其实从原理上是“破解”不了的！！！！！！！！

擦，分析一堆，最后徒劳？

其实也不是，那“市面上”的破解版都是从哪来的呢？

上面用于解密的hmac的key和aes的key，是有“好心人”提供出来的。简单来说就是，当我们有一个“好心人”买了一个正版的cs之后，那么他就可以直接或者间接的拿到一个cobaltstrike.auth文件，然后他将这个文件被使用cs的公钥解签名之后得到的内容公开提供出来了，我们在“破解”的时候，就可以直接将key写死在里面（这也是现在市面上的cs的破解的方法）

下面是收集的那个var4byte\[\]:

cs4.0：

byte\[\] var4 \\= { 1, -55, -61, 127, 0, 0, 34, -112, 127, 16, 27, -27, -66, 82, -58, 37, 92, 51, 85, -114, -118, 28, -73, 103, -53, 6 };

这个key好像在4.1里面也能用。