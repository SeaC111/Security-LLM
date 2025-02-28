0x00 前言
-------

前几天一直准备别的事情，然后用了2/3天时间去挖了补天某厂的SRC，还是太菜了，最后提交了一个低危（还没出结果，还有点敏感信息泄露，感觉略鸡肋也没交），不过偶然发现之前提的一个公益SRC被收了（当时快半个月都没人处理）不过没money，等过几天有时间再看吧，还是得虚心学技术，慢慢的进步。

0x01 HOST头的作用
=============

1.1 文字原理讲解
----------

首先我们需要了解一个概念叫`虚拟主机`，也就是一台服务器上存在多个网站。你会想这还不简单，每个站点分一个端口即可，但是我说的是一个端口。

既然如此，那么我们不管它是怎么实现的，我们要关注的是为什么如此，为什么我们访问这些网站均是正常的呢？这就是HOST头的作用了，当我们去访问一个url的时候，这个域名只会被DNS解析为IP，但是因为这些虚拟主机的IP是同一个，所以会看我们的HOST头，它的值是谁，那么服务器就去交给那个站去响应。（如下图）

![image-20220608134349633](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cbdb3ac1e95ae2f316961eede0b2904e4b7bc41a.png)

1.2 实际演示
--------

我这里用`小皮面板`再来演示一下它的奇妙之处，首先我先创建两个站点，分别是pikachu和dvwa，配置如下图。

![image-20220608135012232](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f3ed4a1308b7e8fe6a31b9b3c83cf2f227edab55.png)

![image-20220608135031215](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-88970e20e1d50ee9651cf3e22c5b42a301fecc37.png)

可以看到，这时候我给它们不同的域名，而且端口均为本机的80，好，接下来我去访问。

![image-20220608135147488](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0ac49b324cfba2c394ee8a40043a50dd36d57efc.png)

![image-20220608135153094](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ee9e5561d728e57d4e475bc2106a67cf049c702e.png)

两个站点没有任何问题，紧接着我重新访问dvwa并抓包

![image-20220608144116741](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e26c53eb9e6e9194a44a66457928da9ac1ad3586.png)

再来看一下页面

![image-20220608144151455](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a1d6250854e5eb6df053294fc9e20fcc6ab490a2.png)

OK相信到这里就了解了，HOST头的作用了，接下来，围绕着Burp Suite官方实验室，演示下会发生的安全问题

- - - - - -

0x02 漏洞利用
=========

2.1 基本密码重置中毒
------------

**要求如下：**

![image-20220608145041353](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fcb7c4cce18bf7b6b845685d79237b84af699511.png)

我们需要登录到Carlos才可以完成，登录时点击忘记密码

![image-20220608145206659](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c850a9989561c8542d395fff1d73e8116800dec3.png)

可以看到是根据我们的账户名或邮箱地址，发一封重置密码的邮件给我们

![image-20220608145241705](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7abeab2368ba649098190e2dc48dede493180a6f.png)

我们先用自己的账户，也就是wiener来试试，ok，点击后去漏洞利用服务器试试

![image-20220608145617649](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-211b8d67f6e525d9112a1cc341901ed294e0c2d6.png)

往下翻有个Email client，点进去查看刚刚的邮件内容

![image-20220608145609138](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4ea6402b78d5863361ab49edf990f0a7fcb76c0a.png)

看到有个修改密码连接，ok，我们打开它，并随便修改成123

![image-20220619163246817](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9c55bb655655eebaee9350dcb281f8303556a362.png)

![image-20220608145900506](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2184a99c4bdfd2b85a21cece75d341d88c6f29d5.png)

接下来我们去Burp看下刚刚的数据包，如下，可以看到里面存在一个`temp-forgot-password-token`值，所以我们现在需要搞到它。

POST /forgot-password?temp-forgot-password-token=F7vqHnRQVDFVZwEfG8CjqPOx4gwgMGr2 HTTP/1.1  
Host: ac3d1fxxxxxx060.web-security-academy.net  
Cookie: \_lab=46%7cMasdCwCFAiRGPkiVdxxxNhS8mYDOMvkk3CWJakAhR0wUzpasdGqNbbKzMESDTwqnN4%2bmfnDv415Yp1OeYCQWOHaYTqDhOeWLYsbDczuZvkT8kfY2yqQxeqN9CdAsyGMC7FUxTGUuUMjnXEJlyJaZ1ArCyi5xbmznovOWg2psOzMjkzQnGNekasdzgthyY%3d; session=jcqZVUOp3gtGaRpFeBD7r577ERV38AkV7  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,\*/\*;q=0.8  
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2  
Accept-Encoding: gzip, deflate  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 135  
Upgrade-Insecure-Requests: 1  
Sec-Fetch-Dest: document  
Sec-Fetch-Mode: navigate  
Sec-Fetch-Site: same-origin  
Sec-Fetch-User: ?1  
Te: trailers  
Connection: close  
​  
csrf=KmpFXtDQMQuzxEkE0t8LRYxfT698ibN1&amp;temp-forgot-password-token=F7vqHnRQVDFVZwEfG8CjqPOx4gwgMGr2&amp;new-password-1=123&amp;new-password-2=123

接下来我的猜想就来了，既然我们知道漏洞肯定跟HOST头注入有关，那么我猜我们刚刚点击忘记密码，发包的时候肯定是抓不到这个token的，而是网站后端服务器发送到我们的邮箱，但是这个时候如果我们将HOST头改成我们自己利用服务器，那么流量会不会就会到我们这里，然后根据这个token值构造重置密码链接，ok，说干就干。

![image-20220619163138663](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-686ae8a7aa02695e6cc3426f92fb0464b492ecd7.png)

紧接着去我们漏洞利用服务器查一下token

![image-20220608151427869](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-192e581c2507bcad59f613ba363bb247b6b79e4f.png)

构造重置密码链接，直接将我们重置密码的包里面的`csrf` （值在上上个图中）和`temp-forgot-password-token`值改成对应的，然后成功了

![image-20220608152531500](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c1acee65055a40cf1322d34cb86ae64d2765f655.png)

- - - - - -

2.2 主机标头身份验证绕过
--------------

**要求如下：**

![image-20220608161747546](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0f51af763db021f3d71d9331b35197336bef3b0f.png)

既然要进入管理面板，那么首先我们应该找到路径，随手加一个admin，演示仅对本地用户可用

![image-20220619163056154](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6cfeb5b92ab31e4a464a149a093006c0ee909210.png)

一般我们搭建靶场用的最多的就是localhost，同理这里将HOST头改为localhost

![image-20220608162732093](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-70861fee58f1a37206ea5a04e7263cd2d8f99b0a.png)

直接删除，同样还得抓包改HOST

![image-20220608162912147](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5a636901cbcdbbca9ebdcb21ee94ee719d350ebc.png)

- - - - - -

2.3 通过模糊请求导致 Web 缓存中毒
---------------------

**要求如下：**

![image-20220619163031177](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd7c704b15081c00f54cd87a71d308f11a122376.png)

**利用过程：**

这个我盲猜可能就就是web缓存投毒并且非缓存建是HOST，相信看到我之前那篇文章的兄弟一下就懂了，就是web缓存投毒，投到HOST键上

首先刷新一下观察历史包，发现加载了两个js

![image-20220619163858150](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-459e3b8ab27221f880930dd0736a9af6e7589118.png)

存在缓存机制

![image-20220619163938866](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a0472af256f592f2069de62f536db926fb1cbd6b.png)

那我现在漏洞利用服务器构造一下js文件

![image-20220619164331866](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-551f9ab2306c353efd956a5bcbc198e98724d807.png)

ok，改一下HOST，投毒吧

![image-20220619165421749](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-af3999c9d224c69270dba37aa55662c38916010d.png)

改了发现不可以，那么也就不能在原来基础上修改，那就尝试在原来基础上增加，双写HOST

![image-20220619165540252](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4f1214e989e9e20a7bca92489f96c9f1462892be.png)

可以看到加载我们利用服务器的js了，这个时候正常如何访问就会中毒了

![image-20220619173820386](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4cd4c1ff00a9b72ae21c7602b9467edc27f765e0.png)

- - - - - -

2.4 基于路由的 SSRF
--------------

**要求如下：**

![image-20220619173951042](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0468244798b389117edc510e799cf8aef9fa0d6c.png)

**利用过程：**

首先这里提示了，必须使用`Burp Collaborator`来进行测试，如果不知道它是什么，可以百度，我暂时没找到好文章，后续打算就其使用写个帖子，这里先简单理解成dnslog就好了，数据由Burp-&gt;靶机，靶机响应到`Burp Collaborator`再到Burp，也就是说它的内网靶机不会出网，除非是Burp自带`Burp Collaborator`地址，所以我们需要配置一下

点击`Burp`-&gt;`Burp Collaborator client`出现下图界面，点击`Copy to clipboard`来获取一个随机地址

![image-20220619215636812](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b755d0174a37fd3fdd47f46fcb5917ed2ea37c1b.png)

然后可以在`Project options`里面查看一下，我们这里使用默认的Collaborator的server就好

![image-20220619221018445](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-827b88220e34915f295535f6630567f347d87bc8.png)

尝试SSRF漏洞，将访问实验室主页的包的HOST头改成我们的`Collaborator server`地址，然后发包，然后就可以看到`Collaborator server`存在流量，然后就可以关掉Collaborator了

![image-20220619221233374](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-155bf2d3c9bd22352013a7912242369529577ab5.png)

证明存在SSRF漏洞，可通过HOST值访问内部敏感系统，但是不知道IP，所以直接爆破，如下图设置

![image-20220619174730976](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-64f03fe5410e0fa5c255daf737cc54befe150c15.png)

别忘了关掉自动更新Header功能

![image-20220619221528007](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-52d61119b333bc68752f9df41e82c67b95cd5258.png)

Payload设置如下

![image-20220619174835235](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d4794ec42a71390cca6c277ad480a0ca63511771.png)

这里因为没特殊字符，所以paylaod Encoding勾不勾没关系，直接爆破，130被爆破成功

![image-20220619221621267](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4793ad2ac29eeb593a97f0b53ac86f42b185a238.png)

然后我们访问主页并抓包将HOST改成192.168.0.130然后放出去，同样的删除用户的这个POST包也需要将HOST改为192.168.0.130

![image-20220619221949746](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4c934dddf4ec97e4c4c83322024b5a18b622b43e.png)

成功了

![image-20220619222022811](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a66066398397d2be60cc8b81583eceed37b8dba3.png)

- - - - - -

2.5 SSRF 通过有缺陷的请求解析
-------------------

**要求：**

![image-20220619222536993](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9e1cfee06db831ff8573d028a7a5029d02cb7bbf.png)

**利用过程：**

这题拿到手很懵圈，感觉跟上一个一样，于是按照上一个的做法将HOST先改成`Collaborator Server`的地址，发现返回403，并且`Collaborator Server`无解析

![image-20220619222925187](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5dd5f821d59061d88cb24f94dbad120bfed57c7a.png)

既然如此，再看一下要求，`基于路由的`这几个大字出现在眼前的时候，就应该意识到是路由地址的问题，于是尝试将GET / 改成绝对的

![image-20220619223244507](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fe86a6d427970fde18b3b61d93327751fb7e78ae.png)

非常nice，然后就跟上边一样了，爆破，251

![image-20220619223436312](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd8c5254b3d66bddfa04c73c2bdeecf072fd5aa7.png)

删除用户，像下边这样改包（请求admin目录的和删除用户的都类似）

![image-20220619224113256](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-04686806eeed290360caf60b5ea3d9ab4f32632e.png)

成功