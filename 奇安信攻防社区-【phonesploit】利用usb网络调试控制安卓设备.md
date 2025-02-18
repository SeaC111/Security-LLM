概述：
===

当大多数安卓开启usb调试会默认开启usb网络调试，这会把你的安卓设备暴露在公网上，本文将演示如何安全工具【phonesploit】以及Shodan扫描暴露在网络上的Adb(Android Debug Bridge)并控制安卓设备。

一、准备阶段:
-------

安全工具：phonesploit  
搜索引擎：shodan  
需要条件：安卓开启usb网络调试

> 注：大多数安卓手机开启usb调试时会默认开启usb网络调试注：大多数安卓手机开启usb调试时会默认开启usb网络调试

二、下载工具：
-------

**我使用的是kali linux系统，以下为linux中phonesploit安装代码**

### LINUX:

```php
git clone https://github.com/01010000-kumar/PhoneSploit
cd PhoneSploit
pip install colorama
python2 main_linux.py
```

> 注：运行pip install colorama时，可能会遇到依赖问题  
> 所以，需要使用命令先安装pip，再安装colorama  
> python2：sudo apt install python-pip  
> python3：sudo apt install python3-pip

### WINDOWS:

```php
git clone https://github.com/01010000-kumar/PhoneSploit
```

### macOS:

```php
brew install git python@3
git clone https://github.com/01010000-kumar/PhoneSploit
cd PhoneSploit
python3 -m pip install colorama
python3 phonesploit.py
```

**安装完成进入后你将看到以下画面：**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-836d693c67febf90c2fa06247e0f6ec30c1d6bac.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-836d693c67febf90c2fa06247e0f6ec30c1d6bac.png)

三、利用阶段：
-------

### 使用shodan搜索：

```php
"Android Debug Bridge" "Device" port:5555 country:"TW"
```

*Android Debug Bridge* 是指安卓调试  
*"Device"* 是指设备  
*port:5555* 是adb调试的端口  
*country:"TW"* 是搜索台湾设备，根据自己需要更换其他国家  
**如下，搜索出台湾网络上的安卓设备**

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-52f0b974f8412de5bb5af546237ffa8ea59c5eb4.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-52f0b974f8412de5bb5af546237ffa8ea59c5eb4.png)

**接下来，我随便选择一个韩国IP粘贴后回车进行连接，连接成功结果如下：**

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-5118e9c2f297ce58fbec6740fd696cc42f6852da.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-5118e9c2f297ce58fbec6740fd696cc42f6852da.png)

> 注：有的设备没有在线，会连接失败，多尝试其他ip

### phonesploit功能如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-ea3ee599c309cb26200fc9e9f6985416d7297ad7.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-ea3ee599c309cb26200fc9e9f6985416d7297ad7.png)

**中文翻译：**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-f2f9c90e9d4db2f4f6c153491e509a47f4ec826c.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-f2f9c90e9d4db2f4f6c153491e509a47f4ec826c.png)

**我这里选择第 \[6\] Screen record a phone 进行录制手机测试：  
提示代码phonesploit(main\_menu) &gt; 时，输入数字 6  
提示代码\[+\]Enter where you would like the screenshot to be saved.\[Default: present working directory\]  
└──&gt;phonesploit(screenshot) &gt; 时，敲击回车默认保存在工具目录下**   
[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-e7a73ffcebd6f8b1f64be2ec848ae536a180da2a.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-e7a73ffcebd6f8b1f64be2ec848ae536a180da2a.png)

**这时文件已经保存在了phonesploit目录下**

> 注：我之前尝试了很多次都保存失败了，那是因为phonesploit没有在root下运行，再测试输入7 进行屏幕截图抓取

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-b393d59fbda977cb580e8062b6ea9551a509acd3.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-b393d59fbda977cb580e8062b6ea9551a509acd3.png)

这人搁这在看电视呢，丝毫不知道我已经控制了他的安卓设备。

除了能截图，还可以shell安卓设备、录制视频、上传apk等等.....  
既然公网能使用phonesploit利用usb网络调试控制安卓，那内网也应该能利用并控制，这个我没有测试。

如何防范：
=====

**这次能控制安卓设备最主要的原因是开启了usb网络调试，据我所知，大多数安卓开启usb调试会默认开启usb网络调试，这会把你的安卓设备暴露在公网上。usb网络调试需要通过adb命令关闭（略微麻烦），所以在不用usb调试时关闭它，这样你的安卓设备就安全了许多。**