0x01 前言
=======

兄弟们，火眼系列来了，想做很久了。我打算从火眼的第一篇文章【2016-3-21】开始，从头到尾逐字逐句解读，研判一波国外的安全人员是怎么分析恶意样本、甚至溯源的，此系列长期更新，点个关注不要掉队哦。

0x02 解读
=======

Dridex是银行木马，用来盗取用户银行凭证的，虽然这是2016年爆出来的，但是2022年的变种仍然活跃，以下是火眼捕获到的邮件。

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d1cd265ffd11cd3744bf21e88e17164b701b5bf1.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

SPAM是垃圾邮件的意思，说明被识别为垃圾邮件了。

邮件标题伪装成了发票报销信息。

可以看到还带了一个rtf的附件，是word的标志，这是由WordprocessingML伪装成的rtf文件。

**科普一下：WordprocessingML是Microsoft Word支持的一种XML格式，用于描述Word文档，在国内很少见，我的理解是通过XML的形式生成一个docm文件。**

我们要怎么拿到恶意样本？

其实火眼已经把IOC（陷落标识，你可以理解为恶意样本的特征）给出来了

```php
MD5
33b2a2d98aca34b66de9a11b7ec2d951
```

直接在微步情报中心搜索上面的MD5就可以拿到恶意样本，如下图

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3e4f356de1fa796dcf787dbbf32a1cd749eb191f.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

下载样本可能需要注册个账号。

然后放虚拟机，改个后缀，我们重命名为test.rtf，然后打开。

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-89bae1b1528f83281def33a6713dfa742abd535d.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

打开可以看到经典宏病毒画面，近几年已经被玩烂了，

我们进一步看看他的VB代码。

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cdb3221e9f6b367e8e7eabadf2f174ec9905ddfa.640%3Fwx_fmt%3Dgif%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1)

哦豁，被加密了，看不到。

我尝试用了010editor、EvilClippy和oledump-py等常用工具，发现无法进行解析，因为正常的rtf文件是不会带宏的。

**本人水平有限，有其他办法的兄弟，可以评论区留个言。**

不过火眼的人是能解出来的，如下图

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-56296d7d16e97b1d0a24eacaa1110ea42117b2ea.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-11fb7a8b4cb97403fb5de6a0ce788cb10ab92086.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

将关键的恶意代码，储存在创建的文本框中，让VB代码保持正常，以此来逃逸静态检测。

0x03 行为分析
=========

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-669731b238f7f1386f37c163173e4b957aef3c3e.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

[通过Process Monitor抓到了文件创建的行为，打开rtf文件释放宏后，会在temp目录创建一个名为rdFVJHkdsff.vbe的文件](http://mp.weixin.qq.com/s?__biz=MzkzOTE5MTQ5Ng==&mid=2247483845&idx=1&sn=1839874dd8a72a67cbb52bcf51820521&chksm=c2f5fc62f582757452a5aeaf17897255682d556339be3d5c3b7b8d69a5b557418f55d3e7e296&scene=21#wechat_redirect)

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a8df6379675dc8cfe4a1e4c092742746f82ec708.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

[从Process Explorer可以看到，打开了VB脚本解释器的进程，来执行上面vbe文件。](http://mp.weixin.qq.com/s?__biz=MzkzOTE5MTQ5Ng==&mid=2247483845&idx=1&sn=1839874dd8a72a67cbb52bcf51820521&chksm=c2f5fc62f582757452a5aeaf17897255682d556339be3d5c3b7b8d69a5b557418f55d3e7e296&scene=21#wechat_redirect)

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-66fd4f4c7959abc7ab31a821d9f5b5c92fad8bd6.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

编辑vbe文件，发现是被加密过的。

这个好办，可以用下面的工具解密。

```php
https://github.com/JohnHammond/vbe-decoder
```

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fd1757883325d26dbce6f8a330528e867ccb9bd2.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

可以从解密后的代码看到，这是一个VBE下载器，访问指定网址下载exe文件并执行。

通过wireshark分析流量，看到确实是请求了

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7a4f89f2758bed2ead573e26b95a8d3720622f7e.640%3Fwx_fmt%3Dpng%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1%26amp%3Bwx_co%3D1)

0x04 总结
=======

- Dridex喜欢利用Office文档，并且VBA会被加密。
- 可以通过文件MD5，在微步情报社区获取到恶意样本。
- 利用vbe-decoder工具，对加密后的VBE文件进行解密。
- 通过[Process Monitor和Process Explorer](http://mp.weixin.qq.com/s?__biz=MzkzOTE5MTQ5Ng==&mid=2247483845&idx=1&sn=1839874dd8a72a67cbb52bcf51820521&chksm=c2f5fc62f582757452a5aeaf17897255682d556339be3d5c3b7b8d69a5b557418f55d3e7e296&scene=21#wechat_redirect)结合，对恶意样本行为进行分析。

**XDM，你们的点赞和关注**

**是我更新的最大动力！！！**

![图片](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2b249c0d44e2ab3f33fb92771d7521a0985e8ace.640%3Fwx_fmt%3Dgif%26amp%3Bwxfrom%3D5%26amp%3Bwx_lazy%3D1)