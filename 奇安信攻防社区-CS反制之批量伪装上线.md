CS反制之批量伪装上线

先来张效果图  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9cc032a2015ccbb56859acf0e8b0ca4a846ae118.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-9cc032a2015ccbb56859acf0e8b0ca4a846ae118.png)

分析原理：  
我们利用Wireshark抓包工具分析一下Cobalt strike的上线过程是怎么样的  
CS生成马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-246afe731d897bfc1621c0d69d59833df0047123.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-246afe731d897bfc1621c0d69d59833df0047123.png)  
受控机上线并抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0b3a164a9118a2e99f8115fea3eba12f76838d91.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0b3a164a9118a2e99f8115fea3eba12f76838d91.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-39870421d67a686b9b052a41743b29ffa85e19d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-39870421d67a686b9b052a41743b29ffa85e19d1.png)  
可以看到CS的上线过程中，有一串很明显的加密Cookie，  
查找资料得知，是**非对称RSA加密类型**，需要一个**私钥Private Key**才能对其进行解密  
我们对Cookie解密看看，网上找到了相关的代码提取Private Key与Public Key  
（注意，实战中我们肯定拿不到Private Key的，这里只是弄出来分析一下加密的Cookie里有啥）  
代码（放在文末）：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0dff7ad99f878913dae34882e8460cbb46e296cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0dff7ad99f878913dae34882e8460cbb46e296cc.png)  
代码来自：  
<https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/>  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-32c4d5ee465888243886ce99a7816fb8ea4f4bd1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-32c4d5ee465888243886ce99a7816fb8ea4f4bd1.png)  
**有一个坑点：**  
**代码注意要在JDK11版本下运行。还要把这个java文件放置在CS服务器的CS文件夹下，与“cobaltstrike.jar“同一个目录下。  
java -cp “cobaltstrike.jar” Dumpkeys.java**  
解密完可以看到HTTP类型Beacon上线包里的Cookie是RSA加密过的主机元数据。  
解密网站：  
<https://the-x.cn/cryptography/Rsa.aspx>

[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2788ea81de085aaa1de3dfee07dad7681117aacf.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2788ea81de085aaa1de3dfee07dad7681117aacf.png)  
既然知道了上线的流量过程，我们模拟Cobalt Strike模拟重放一下上线的过程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c70664013d9e3c889661748bd35d82616c72a850.gif%23pic_center)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c70664013d9e3c889661748bd35d82616c72a850.gif%23pic_center)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ebb162976493840aed4c2edceee83997bec3f65.gif%23pic_center)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ebb162976493840aed4c2edceee83997bec3f65.gif%23pic_center)

可以看到通过重放数据包，**last被重制为1s**，这就说明我们成功了。  
实战环境下可以写循环语句，不停模拟上线操作，让攻击者即使能够上线也无法执行命令  
当然，如果只是这样那就不会这篇文章了。

继续沿着思路展开，既然数据包中的核心是加密后的Cookie，我们能否进行伪造，达到假的主机上线效果?  
答案是**可以**的

只要知道加密的过程，我们就可以达到伪造的目的  
于是，现在的目标很明确，研究加密过程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-033370d3ebab65c7a3a16e3d3b61f9c7751b0f63.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-033370d3ebab65c7a3a16e3d3b61f9c7751b0f63.png)  
以上来自：  
<https://www.secpulse.com/archives/165561.html>  
**核心：**  
**Stager Url校验算法  
Beacon配置的解密算法**  
其实Stager就是小马拉大马的操作  
上线的时候先投递一个小巧的Stager Payload，然后通过Stager 去Beacon Staging Server的某个URL下载完整的Stage（也就是体积更大功能更复杂的Payload），并将其注入内存。  
**（这个URL作为特征也可以用来识别CS服务器，做网络测绘，某Quake就是这么做的）**  
如何得到那个URL？  
CS中Stager URL校验算法，就是生成4位的随机校验码，将校验码拼接到URL后面即可请求到Stage的代码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-218a9ade76a55cc213d9d194fcde4f19ba2b3561.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-218a9ade76a55cc213d9d194fcde4f19ba2b3561.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-234b6971b471a9613dc7074d053e5b526b360cdd.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-234b6971b471a9613dc7074d053e5b526b360cdd.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-519912b376f66b0b75fae54d3f69178e6af9cea5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-519912b376f66b0b75fae54d3f69178e6af9cea5.png)  
拿到Stage

**Beacon配置解密**  
这里有两个项目地址都可以进行解密操作：  
<https://github.com/Sentinel-One/CobaltStrikeParser>  
<https://blog.didierstevens.com/2021/06/15/update-1768-py-version-0-0-7/>  
第一个项目效果：可以看到我们从stage中得到了Public Key 这意味着我们可以自己对数据进行加密了  
**Python parse\_beacon\_config.py stage文件 --json**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ccf0f6302e9d525cc40c0af265db17ed000252d5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-ccf0f6302e9d525cc40c0af265db17ed000252d5.png)  
第二个项目效果：不知道为什么这个项目解出来的是串十六进制字符串？我尝试还原了一下。。。没能还原出第一个项目中的Public Key(有了解的大佬麻烦解答一下 感激不尽)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-78439c5fdf5ed81f3cb96e38b682a6ceb9652f3a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-78439c5fdf5ed81f3cb96e38b682a6ceb9652f3a.png)  
解密后可以看到：**公钥PublicKey**以及**CS服务器地址**  
**坑点：**  
**Public key别忘了要删点后面的无效Padding  
正确的格式是MIGfXXXXXXXXXXXXXXXX==  
也就是说我图中的Public Key 后面那一堆AAAAA要删掉**  
接下来思路：  
加密伪造，向C2服务发送欺骗包  
伪造服务器上线。  
虽然网上已经有类似项目了，但我还是决定造个轮子试试。

先分析一下各十六进制位都代表了啥  
我们只要对着改就行了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-eca1e188abf0b64eb0d3dbe1805b8f291e2c0145.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-eca1e188abf0b64eb0d3dbe1805b8f291e2c0145.png)

脚本效果如下：  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1c061ced3c74fd2d17e4177528e3dcaa580ff83.gif%23pic_center)

项目地址：  
[https://github.com/LiAoRJ/CS\_fakesubmit](https://github.com/LiAoRJ/CS_fakesubmit)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2c6d22a60616119b4dcd3282f75cd142e0379335.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-2c6d22a60616119b4dcd3282f75cd142e0379335.png)  
使用方法：  
先从这个项目中解密Publickey  
<https://github.com/Sentinel-One/CobaltStrikeParser>  
在Process\_name.txt 中加入上线进程的字典  
在Computer\_name.txt 中加入受控机名称的字典  
在User\_name.txt 中加入受控机用户名的字典  
在Public\_key.txt中放入通过Beacon解密获得的Publickey  
脚本供大家研究之用  
实战建议还是用以下这个项目：  
<https://github.com/hariomenkel/CobaltSpam>  
但是此项目的缺点就是主机信息都是随机的，特征太明显了，大家可以试试改一下，改成和我那样用字典的。

后记：  
写这篇文章的灵感是来自知微攻防实验室发布的文章  
但写这篇文章踩了很多坑。。  
很多细节的东西  
本来想请教一下知微攻防实验室的大佬们。。结果身边好友没有一个人认识  
楞是疯狂查资料才解决了问题。。。过程有点痛苦

参考与引用：  
<https://www.secpulse.com/archives/165561.html>  
<https://wbglil.gitbook.io/cobalt-strike/cobalt-strike-yuan-li-jie-shao/cs-mu-biao-shang-xian-guo-cheng>  
<https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/>  
<https://www.cnblogs.com/donot/p/14226788.html>

所有的代码我都打包到了百度网盘，有兴趣的朋友可以研究看看：  
链接: <https://pan.baidu.com/s/1togwfbj2F1O-854whGFYBQ> 提取码: yfaq