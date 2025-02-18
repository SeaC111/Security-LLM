0x01 简述
=======

流量分析作用通常是溯源攻击流量的。

通常在比赛中提供一个流量数据包的PCAP文件，有时候也会需要选手们先进行修复或重构传输文件后，再进行分析的。

PCAP文件这一块作为重点考察方向，复杂的地方在于数据包里充满着大量无关的流量信息，因此如何分类和过滤数据是我们需要完成的目的！！！

0x02 流量包结构与Wireshark的使用
=======================

2.1 界面介绍
--------

分组列表、分组详情、分组字节流：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-310486123e861d21ac6f8f62355a505ecd36dbc5.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-fae89e9b026cc2d7274af678ecaccb9090add9a3.png)

2.2 过滤器
-------

显示过滤器如上图；捕捉过滤器在我们打开wireshark的时候可以进行不同网卡的选择捕捉过滤。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9af18aef20d245b96ce575b91b9250fca0f68c4d.png)

- 过滤符号

| 比较运算 | 含义 |
|---|---|
| eq | 等于 == |
| nc | 不等于 != |
| gt | 大于 &gt; |
| lt | 小于 &lt; |
| ge | 大于等于 &gt;= |
| le | 小于等于 &lt;= |
| 逻辑运算 | 含义 |
| and | 逻辑与 &amp;&amp; |
| or | 逻辑或 \| |
| xor | 逻辑异或 ^^ |
| not | 逻辑非 ! |

- ip的过滤 ```php
    ip.addr==192.168.1.1   //只显示源/目的ip为192.。。的数据包    
    not ip.src==1.1.1.1   //不显示源ip为1.1.1.1的数据包  
    ip.src==1.1.1.1 or ip.dst==1.1.1.2  //只显示源ip为1.1.1.1或目的ip为1.1.1.2的数据包
    ```
- 端口的过滤 ```php
    tcp.port eq 80    //不管端口是来源的还是目标的都显示  
    tcp.port == 80  
    tcp.port eq 80 or udp.port eq 80  
    tcp.dstport == 80   //只显示tcp协议的目标端口80  
    tcp.srcport == 80   //只显示tcp协议的来源端口80  
    udp.port eq 15000  
    tcp.port >= 1 and tcp.port <= 80   //过滤端口范围
    ```
- MAC地址过滤 ```php
    eth.dst == A0:00:00:04:C5:84   //过滤目标mac  
    etc.src eq A0:00:00:04:C5:84   //过滤来源mac  
    eth.addr eq A0:00:00:04:C5:84   //过滤来源MAC和目标都等于A0:00:00:04:C5:84的
    ```
- HTTP请求方法的过滤 ```php
    http.request.method == "GET"  
    http.request.method == "POST"  
    http.host matches "www.baidu.com|baidu.cn"  //matches可以写多个域名  
    http.host contains "www.baidu.com"  //contains 只能写一个  
    http contains "GET"
    ```
- 数据包长度的过滤 ```php
    udp.length == 26 这个长度是指 udp 本身固定长度 8 加上 udp 下面那块数据包之和 。  
    tcp.len >= 7 指的是 ip 数据包(tcp 下面那块数据),不包括 tcp 本身  
    ip.len == 94 除了以太网头固定长度 14,其它都算是 ip.len,即从 ip 本身到最后  
    frame.len == 119 整个数据包长度,从 eth 开始到最后
    ```
    
    也可以在分组详情中选择想要选择的字段，单机右键--作为过滤器应用--选中或者非选中！！！

2.3 分组分析
--------

追踪流：我们不但要知道每一个包我们怎么去看，也要清楚连续的流之间的关系。

我们知道的http的包，协议是tcp协议。当一个http数据包非常大的时候，在传输过程中分层传输。追踪流看一下http中传输的数据流量

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-94a725dd8bb9af891bdbfc3e70803f3c1ef0f3dd.png)

2.4 导出对象
--------

那么，如果我们想看攻击者上传了什么木马或者文件，也是可以在他的流量包中看出来，那么导出的话就可以在文件--&gt;导出对象--&gt;选择对应得协议。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-af4dd34d0109e64647fbeb8be973ad9e73208c33.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-f220a19151758007b434316c4b1818f88bc4b2d1.png)

另一种方法，悬着要导出得字段，在分组详情的data处单机右键导出分组字节流。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1fc1cb7ba2614c7525cd1223c2fbebc315d6d0f5.png)

2.5 其他
------

- 统计

统计--&gt;协议分级统计（流量包有多种多样）

统计--&gt;http--分组计数（占比，状态包的多少）

- 搜索
    
    ctrl+f
- 颜色
    
    视图--着色规则

0x03. tshark使用
==============

是在安装wireshark自带的tshark工具。

```php
tshark -r \*\*\*.pcap -Y \*\* -T fields -e \*\*\*\*\* > data  
tshark -r %s -T fields -e usb.capdata -Y 'usb.data.len == 8' -Y 'usb.src == "3.9.1"' > data
```

- -r 指定数据包
- -Y 指定过滤器（跟wireshark中是一样的）
- -T fields -e 配合指定显示的数据端（可以选中右击作为过滤器查看名字）

Eg：tshark -r easy.pcapng -T fields -e ip.src &gt; 1.txt (**流量包**)

如果要去掉1.txt，那么就要grep进行过滤

```php
tshark -r easy.pcapng -T fields -e ip.src | grep "\[^\\s\]"
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1855b9bffddf2155172565b2fe1fb38b264f2c7e.png)

0x04. 各种协议
==========

http协议分析
--------

基于http的应用流量，明文传输容易分析。

通常是分析攻击者攻击时的流量包，用于溯源发现攻击者信息和被利用的漏洞，难点是需要配出大量无关流。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-268666548edda206e5e81e17015de4653f88e875.png)

举例分析一下：

- 菜刀流量
    
    首次打开流量数据包，在统计中协议分析可以看到只存在http包，没有其他，然后追踪流

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-da240b4a59877d638d818530a9fc3588cdfd444f.png)  
发现攻击POST请求访问了一个3.php的文件数据，响应包则是列出了一个目录情况，那么说明攻击者拿到了一个webshell，在用客户端连接后，执行了第一个命令就是列出目录的命令。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5baafee674bad5d92de5bd5f60ade2ca1f3fd8ee.png)  
并且在列出的目录下，存在一个flag.tar.gz文件。  
接着分析第二个tcp流：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0ff4ab9bada4cf6677e4ecfaa0cb0580afa30e28.png)  
这个返回来一个POST响应是一个webshell 不重要。  
接着分析第三个tcp流：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5336b244fce65bcb7702db9cdefe19fa701c939d.png)  
看得到在执行了一些命令之后，响应包是一个二进制后的内容，大概可以猜到是跟前面flag.tar.gz有关。首先，将请求中的命令解码看到底是执行什么命令

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-14952cf047d4d38aa3dde1eb0a55d6f0b3a8f0f4.png)  
看到echo出X@Y，fopen访问文件，并且readfile文件，那么提取出响应返回的文件，在分组详情中选择data块 然后导出分组字节流保存为tar.gz后缀文件。  
使用010打开，在刚才的命令中又看到前后都有无用的输出，那么就要把前后去掉。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4a3696a34bfc5130e65c0b0aff17b9379aaf7f0e.png)  
那么，通过解压得到flag.txt中的key。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-70ac6b77dd8b6a10a1e50d8ae1c6338c8d1052b9.png)

https协议分析
---------

TLS加密流量，通常是需要**密钥解密**。

HTTPs= http+SSL/TLS 服务端和客户端的信息传输都会通过TLS进行加密，所以传输的数据都是加密后的数据

那么解密，就是拿到密钥后导入wireshark可以看到明文的http内容。例题见后

USB协议
-----

usb接口是目前最为通用的外设接口之一，通过监听该接口的流量，可以得到很多有意思的东西。例如键盘击键，鼠标移动与点击，存储设备的明文传输通信，usb无线网卡网络传输内容。

USB协议的文档，可以找到这个值与具体键位的对应关系

[http://www.usb.org/developers/hidpage/Hut1\_12v2.pdf](http://www.usb.org/developers/hidpage/Hut1_12v2.pdf)

### 鼠标

数据一般在Leftover Capture Data中，每一个数据包的数据区有4个字节（可能回有8个字节），第一个字节代表按键，当取0x00时，代表没有按键、当0x01时，代表按左键，当为0x02时，代表按右键。第二个字节可以看成是一个signed byte 类型，其最高位为符号位，当这个值为正时，代表鼠标水平右移多少个像素。为负时，代表水平左移多少个像素。第三个字节与第二个字节类型，代表垂直上下移动的偏移像素。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4c61807031ee0925c384911879e09a0a64825ee8.png)

用tshark 将鼠标数据提取出来：

```php
tshark - r mice.pacpng -T fields -e usb.capdata > micedata
```

然后在脚本将鼠标数据转换成坐标图分析鼠标点击和移动轨迹分析。

### 键盘

它的与鼠标类似，数据也在Leftover Capture Data中，键盘数据包的数据长度为8个字节，击键信息集中在第三个字节，每次key storke都会产生一个keyboard event usb packet

用tshark 将键盘数据提取出：

```php
tshark -r mice.pcapng -T fields -e usb.capdata > micedata
```

下载地址<https://github.com/WangYihang/UsbKeyboardDataHacker>

WIFI协议
------

IEEE 802.11是现今无线局域网通用的标准,常见认证方式有:不启用安全、WEP、WPA/WPA2-PSK、PA/WPA2 802.1X

> BSSID :路由器、AP的MAC地址 PWR:信号强度，- -看就是越小越强了 Data :传输的数据大小，大的可能在下载或看视频什么的 CH:无线信道，要看准 ENC :加密协议 ESSID:这个就不用多说了，wiff名称，有中文可能会出现乱码哈

对流量包爆破密码 aircrack-ng XXX.pcap -w /usr/share/wordlists/rockyou.txt 用密码解密流量包 airdecap-ng \[capfile\] -e \[ESSID\] -p \[password\]

0x05. CTF中相关的题目
===============

http流量分析
--------

http1.1中，可允许一个tcp中发送多个http流

打开流量数据包分析，追踪tcp流，前面的几个数据流是列目录和linux

安装包，一直到第7个tcp包，发现

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2778c6cee00de0c16977814f2b6915afc7c27549.png)

它是将post中action进行了base64编码让后执行了eval，那么@action是要执行的命令，将action的值解码后分析：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-45dff4b5350fdd0e485efd728e3c822daeee13af.png)

首先，它echo三个字符进行混淆填充，然后是通过fwirte向f写了buf内容，而f是post的z1的内容，buf则是已输入的内容以2个为分组进行了切分，再加上%再进行urldecode，相当于hex编码的解码。

再查看z1的内容:

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-87db81596ecfa45e6e7c51be725ea1e4f16bb78b.png)

那么验证刚才想法会在这里目录中写一个文件，文件内容就是z2：

那么我们将z2的内容以二进制的形式保存下来。并且可以看到这个列目录别之前多了一个666.jpg文件

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-72d1f3760285a4073f1a50860bd9d1406f296197.png)

在010中以16进制文本粘贴后，看到是我们熟悉的jpg文件，当然不是最终得flag文件。

然后再往下查看tcp流，再第9个中发现post数据中存在一个flag.txt文件(在搜索中也是可以直接搜到的)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5661fb5d2257e92c65a12c53734a9b05e9190153.png)

并且看到数据开头是pk开头，并且后面提示需要密码，那他就是一个压缩包文件。

那么在分组详情中保存data的分组字节流，并保存为zip后缀文件。并且在010中删除头尾混淆字符

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-be73d84bd72b9806db037d4151f2323681b72e14.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-591cf003e1bf6ed921c7d719fea69969f2975cf6.png)  
解压之后得到flag。

https流量分析
---------

打开数据包，看到的里面数据是非常多的，我们统计中分级统计查看一下看到的是存在udp tcp smtp ftp等协议，对每一个协议进行比较费时间，这里直接看SMTP邮件协议的数据包。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2d4fe7f065597ac6b4bfab108bf7915dd507b51d.png)

那么，导出该数据包中所有的smtp协议的数据包，通过文件--&gt;导出对象--&gt;IMF

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6bee6d70d31394a757b59fe2f3a3b8cc7b9e0065.png)

save保存全部，

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-1b3a14caa55a3165acb2196855fdd4a42706c09a.png)

打开邮件1234是广告，而第5给是一个邮件密钥，然后更具提示，将密钥格式补全：

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-8a891db4f35dd999cec583dc052a787dc7259e4e.png)

那么接下来就要导入https的私钥后就可以看到明文传输信息。

首先我们筛选出所有的https的协议数据包 （tls）

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-974fc4a94e6909fa865487f358202a540389c29e.png)

然后在编辑--&gt;首选项--&gt;protocols--&gt;TLS 将进行导入

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9152dbfe654318f4d73c470fd9a8830fe163c4cb.png)

然后编辑-添加一个密钥，

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-831d87b6d31c3536a7877d964e06c01e81524902.png)

保存确当后，TLS数据包中就有可以看明文的http数据包了，追踪http流就发现了flag。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5106a82c0b066c4ff00041e1a3042131b7a1c0c0.png)

USB流量分析
-------

鼠标：usb2

拿到数据包，里面不知有鼠标，也有其他的数据包，那么使用tshark将数据导出：

tshark - r usb2.pcap -T fields -e usb.capdata &gt; micedata

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c77646c193c30ac9197858a9cab995538de5725e.png)

那么，也可以用工具提取出左右键的轨迹：

下载地址：<https://github.com/WangYihang/UsbMiceDataHacker>

安装完成后，运行语句

```php
python UsbMiceDataHacker.py usb2.pcap RIGHT  
python UsbMiceDataHacker.py usb2.pcap LEFT  
python UsbMiceDataHacker.py usb2.pcap ALL
```

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4f3c0977cf2ed9c4f05c3354a368e5bb7576e5ba.png)

键盘：usb1

打开流量数据包，看到和鼠标的类似，我们直接用脚本工具跑

python UsbKeyboardDataHacker.py usb1.pcap

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ec6dc1aa62287c28f29e8e6a4fab03faa3dae47d.png)

可以简单看到一些i am ...但是存在一些内容混淆的，我们看到流量包存在来源有2个3.10.1和3.9.1 。

那么解决办法就是在脚本中修改一下抓取来源：

```php
tshark -r %s -T fields -e usb.capdata 'usb.data\_len == 8' > %s  
tshark -r %s -T fields -e usb.capdata -Y 'usb.data\_len == 8' -Y 'usb.src == \\"3.10.1\\"' > %s
```

修改为3.9.1时，我们抓取键盘真正敲击内容。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-0212a0b7a7416e5839687e997cc3f7da90d71e86.png)

```php
hello<SPACE>,<SPACE>i<SPACE>am<SPACE>writing<SPACE>something<SPACE>important<SPACE>.<RET>but<SPACE>i<SPACE>do<SPACE>not<SPACE>use<SPACE>pinyin<RET>i<SPACE>am<SPACE>old<SPACE>.<RET><RET>ddpeiyuj,q<SPACE>s<SPACE>gavclwbmpyg<SPACE>rug<SPACE>stk<SPACE>b<SPACE>.<RET>i<SPACE>fpi<SPACE>j<SPACE>et<SPACE>kkyy<DEL><DEL><DEL><DEL>k<SPACE>yygy<SPACE>r<SPACE>gaaa<SPACE>lwbmr<SPACE>.<RET>wwq<SPACE>sk<SPACE>c<SPACE>rcn<SPACE>ghdmp<SPACE>qkd<SPACE>ytd<SPACE>r<SPACE>ruuj<SPACE>wt<SPACE>o<SPACE>pyg<SPACE>rug<SPACE>stk<SPACE>rjuq<SPACE>h<SPACE>fcu<SPACE>"<RET><RET>q<SPACE>yi<SPACE>j<SPACE>pyg<SPACE>rug<SPACE>stk<SPACE>kwkw<SPACE><RET><RET><RET>over<SPACE><RET>enjoy<SPACE>my<SPACE>misc<SPACE>.<RET><RET><RET>
```

这里还有最后一个小弯，由提示中的“不使用拼音 ”等信息推测出上文的特殊编码可能是某种拼音之外的古老的输入法，例如五笔，毕竟这也是做keylogger的人需要考虑而且头疼的一个地方。尝试对照着输入，可以得出如下文字：

```php
hello, i am writing something important .  
but i do not use pinyin  
i am old  
​  
大家注意，我要开始输出福拉格了。  
不过是用中文形式输出的。  
你可以把下面这句话的拼音作为福拉格提交上去:  
我就是福拉格哈哈  
​  
over  
enjoy my misc .
```

WIFI流量分析
--------

打开数据包，看到全部是加密的WiFi流量数据。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-26fb9c137cdbcff6cde92c5b83a34521732f91d2.png)

首先，我们用kali自带工具aircrack-ng看它是不是wifi包

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-eef60c609b3efbabd0dfd962f3658011bccc7909.png)

那么使用一个字典对流量包爆破密码

aircrack-ng XXX.pcap -w /usr/share/wordlists/rockyou.txt

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-22198e295460de43133f970063a1e0cdf9947ecd.png)

然后用密码解密流量包：

解密后在该目录下生成一个xxx-dec.cap解密成功的流量包。

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-807cd65352f5009261ade5a455a590ca8b3f7685.png)

打开解密成功的流量包，里面出现各种协议流量

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-495d201d162e179e2be0c1b6b43a4e5a68f02c47.png)

然后进行常规的分析，直接在搜索中搜索flag，发现flag.txt字符串

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-643d389e91edbb2ef2277f447b8d0f9fe69e7232.png)

通过分析流，发现flag.txt是在一个png中的pk压缩包中，那么我们将该原始数据导出，然后利用binwalk去解压。

解压后发现是一个加密压缩包

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-59e38148a88daf34318d32b69c67667bca57f5f3.png)

回到刚才的tcp流中发现cookie中存在一个jwt数据，解密看一下

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-ffee5a3162583a0f9da5bec93d42a82cdf96f84a.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-217489a64455f596f3b287015eec90e0f67ea760.png)

告诉我们密码是刚才ping过的一个网站，那么我们过滤dns流量

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2866ff7c560e28c89d03a852e5b3ce554c03eda2.png)

![图片.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-6cec0a3d58df20e477fe6e752161a796767d86d9.png)

尝试里面每个域名，发现是最后一个域名，然后查看flag。