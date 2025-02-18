0x01 前言
=======

微信平台是目前公众使用频率极高的一款即时通信软件，为公众带来极大的便利，但同时也给不法分子带来新的机会，许多违法犯罪行为在微信平台上发生。由于微信本身是一个信息传递平台，并且拥有数量庞大的非实名制用户群体， 在鱼龙混杂的用户环境下，利用微信进行的犯罪活动 日益猖獗，而许多微信犯罪案件的侦破工作都需要相应的取证分析技术，所以对微信信息的分析技术的研究就有了重大意义。且微信在即时通讯工具中所占的份额越来越大，取证实践中已经逐渐取代QQ成为最重要的取证项，目前主流的取证方法有内存镜像和数据库解密等

WeChat PC在安装后，默认会在“我的文档”目录下创建“WeChat Files”文件夹，后续每登陆一个微信账号，便在该文件夹下创建一个以微信号命名的子文件夹，用来放置配置信息、聊天记录以及附件数据

文中我以一台 Windows10系统搭配最新版微信为例,登陆了我的微信“JaneXXX ”,我们先跳到微信文件的主路径

```php
C:\Users\username\Documents\WeChat Files\
```

以下的所有操作都是围绕这个主路径进行的

0x02 信息解密
=========

### 账户信息

一般Windows下，微信默认的使用数据放在以下路径

```php
C:\Users\%UserName%\Documents\WeChat Files\
```

在下述文件夹查找文件可以发现

```php
C:\Users\%UserName%\Documents\WeChatFiles\All Users\config\config.data
```

中指向了含有微信账户相关数据的data文件（这里的路径也暴露了wxid）我这里是指向

```php
C:\Users\Administrator\Documents\WeChat Files\wxid_xxx\config
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0cd07a87bfae7bb44a330fae70f9a3d4e5b450ea.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0cd07a87bfae7bb44a330fae70f9a3d4e5b450ea.png)

我们跟着文件指向跳到AccInfo.dat文件打开发现含有(用户原始ID+昵称+头像Logo+区域信息+手机号+邮箱)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0225927df637c873be34da6025d6ab754e3f7a3e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0225927df637c873be34da6025d6ab754e3f7a3e.png)

以上文件路径中的用户名是变量获取 在特殊情况下可以尝试去C:\\Windows\\PFRO.log中读取，大概率可以发现报错日志输出的用户名。

### 聊天图片

通过上面的我们知道了数据存放的主路径，PC版的微信会加密用户接收到的所有图片信息。默认图片类的存储路径为：

```php
C:\Users\%UserName%\Documents\WeChat Files\wxid_xxx\FileStorage\Image\year-month
```

存储的图片文件均为dat格式加密。无法直接打开，用户删除聊天记录后，如果能找到其加密方式就能对这类文件解密还原成jpg/png/gif等常见的文件格式

一般来说这种对文件加密的方式大多是“异或法加密”，即每个文件逐个字节与加密码进行"异或计算"得出加密文件。我们可参考以下加密码算出源文件

```php
#  JPG 16进制 FF D8 FF
#  PNG 16进制 89 50 4e
#  weixin.bat 16进制 e1 c6 e1
#  key 值 1e1e 0x1e  weixin.bat-jpg
```

我们使用Notepad的插件来浏览文件的十六进制，由于我们知道了bat的开头值为：7d a4 png的开头值为：89 50 。此时可以通过程序员计算器，计算异或值计算公式：7D Xor 89 = F4；A4 Xor 50 = F4 由此可知16进制异或值为：0xF4

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b83b28d4359359b54debe83408f2e9c8628c741f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b83b28d4359359b54debe83408f2e9c8628c741f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d9cdc0af5b95fab3da7759b85a330d2527036c10.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d9cdc0af5b95fab3da7759b85a330d2527036c10.png)

我在这里用python写了一个自动化脚本可以批量解密源文件

**获取工具公众号回复：JaneNB**

### 实际运行图

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-38fb1310f5b80affa2347b15d93c367026ffce4c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-38fb1310f5b80affa2347b15d93c367026ffce4c.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bce8fe205695b58121297a92f4cdcc5ae3ee9d1c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bce8fe205695b58121297a92f4cdcc5ae3ee9d1c.png)

0x03结语
======

这期就到这里了，回来我们再讲一下PC端通讯工具的多种电子证据提取以及解密方式