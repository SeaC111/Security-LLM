一、IDA下载及安装
----------

官网：[IDA Pro – Hex Rays (hex-rays.com)](https://hex-rays.com/ida-pro/)

其余版本在百度上找

二、IDA使用
-------

### 1、如何加载文件

加载一个`.so`文件，提供了两种解析方法：

1. `.so`文件格式解析
2. `Binary file`二进制文件格式解析

默认选第一种（这里的so文件是在apk中lib目录下随意找的）

![4AODwq.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3251444c3a0c5c484e5002b1113ceedb69051948.png)

### 2、界面介绍

参考：[IDA的初始使用说明和界面简介](https://www.idapro.net.cn/faq/ida-arrm.html)

### 3、快捷键介绍

参考：[逆向so文件调试工具ida基础知识点](https://cloud.tencent.com/developer/article/1706122)

```php
F2      下断点
F4      运行到当前光标处（可应用在跳出 循坏）
F5      转为C语言
F7      单步步入（进函数）
F9      运行到断点处

Alt+T   搜索文本
Alt+B   搜索16进制
ESC     返回上一个操作地址
Space   切换文本视图与图表视图

d       函数识别为数据
c       数据转代码，无end结尾（无法识别堆栈是否已经平衡，所以无法识别函数结束）
p       转函数，有end结尾
u       将函数中的所有代码识别为数据
```

三、IDA动态调试准备工作
-------------

> 这部分是连接手机并IDA动态调试软件前的准备工作，包括上传一些调试文件等。

### 1、检查手机是否连接上

```php
adb devices
```

![4AOBmn.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-86577b03b8c8b4ee13d2f9bbd30d0a1cb6d96b99.png)

如果没有出现设备信息，在手机设置中-开发者选项-开启usb调试和OEM解锁

### 2、拷贝android\_server

#### 1）找到android\_server的位置

![4AOL1e.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6ba7b3d244cb0cf633cdfad9e92c1969b21c7cc2.png)

#### 2）将该程序移动到手机上

移动到`data/local/tmp`目录上

```php
adb push C:\Users\xxx\Desktop\android_server data/local/tmp 
```

![4AOqpD.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-912041c071424e0f77a73678ac1707af8a5f44f9.png)

### 3、赋予可执行权限

#### 1）使用adb命令进入手机内部

```php
adb shell
su
cd data/local/tmp
ls
```

![4AOITx.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91d48a2d31470dbe95ea6b9de4399a4bec24a2d2.png)

成功将`android_server`文件拷贝到目录上

#### 2）赋予程序权限

在abd shell中输入以下命令赋予该程序权限

```php
chmod 777 android_ server
```

![4AOTk6.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6c9fc0872af79a2c6d96871625a0a11b8798d5c8.png)

#### 3）更改android\_server名

由于安卓机制会检查出android\_server，限制调试，将android\_server改为anserver

```php
mv android_server anserver
```

![4AO7tK.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-885d34943bf001297e45513491f5a4dcb17e9002.png)

### 4、运行服务程序

```php
./anserver

./anserver -p1234 指定端口
```

![4AOHfO.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0805eeeb702a2d60e9cab22e768c2b1e8054efd3.png)

### 5、配置端口转发

```php
adb forward tcp:23946 tcp:23946
```

![4AX9tf.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd636995e97fb52e5c8e9584b3898296c90c4509.png)

### 6、安装软件

新开启一个cmd命令框

```php
adb install C:\Users\xxx\Desktop\javandk1.apk
```

![4AXpAP.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ea7a72e3b4aca2edae95497458d50c41a7959c3.png)

在手机上可以看到该软件已安装

四、debugger调试
------------

> 用于后续脱壳

### 1、IDA选择Android调试器类型

![4AXDjH.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d8d0a7fbb1145af5b01adc99089721388f588e10.png)

### 2、选择主机名以及找到包名

在后面的手机进程列表搜NDK，需要软件先运行起来（挂起）

![4AXBge.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e07b6eb556a689d91b35408d02534a8a452423a1.png)

### 3、成功进入IDA调试界面

![4AXsud.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-06e4c981cde9d96b8844fbcbb55dd5e23b22cda0.png)

### 4、设置debugger option选项

![4AXyDA.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7dd003188c8b720b8c870ec8cc5c70e992e535ff.png)

即可开始调试，不过一般都会使用下面的普通调试

五、普通调试
------

### 1、adb命令进入内部启动android\_server程序

```php
su
cd data/local/tmp
./anserver

./anserver -p1234   指定开启端口
```

### 2、配置端口转发

```php
adb forward tcp:23946 tcp:23946
```

这两步骤和前面的相同，就不上图了

### 3、挂起程序

```php
adb shell am start -D -n com.example.javandk1/.MainActivity
```

这里的包名可以通过Android Killer或Jadx查看到，在类前面加上一个斜杆表示相对路径

![4AjPV1.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e02239bf75305ff3c637a3ab2cc16a3c098e9fd0.png)

命令输入后，手机会出现一个`Waiting For Debugger`的提示框

### 4、开启DDMS

新开一个CMD窗口输入`ddms`开启

![4Aj9bR.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-405b5fec0d5940570b51dd0012b17c11b402519d.png)

在设备窗口中可以看到一个红色虫子

![4Ajpr9.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7da2b0002558113396a1759ba372ee0b34ae48bb.png)

### 5、打开debugger

#### 1）选择调试的类型Android调试器

![4AXv2F.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3d4b31a27a5689a3832dea4b1e3e46b6228001fb.png)

#### 2）选择主机名以及找到包名

![4AXj8U.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a2ad44437841f8b14377f60338a15a7018c1a6b7.png)

#### 3）成功进入IDA调试界面

![4AjSKJ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-defb389267575db1aec48515caf2678bec044dcd.png)

#### 4）配置项

选择`Debugger`栏中的`Debugger options`项，如下

![4AjGRS.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-71c5ed5c2d262c23486bc27ebc6dbf842449398e.png)

### 6、点击执行（F9）

按左上角的绿色三角形

![4Avkes.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2ce9ffd34dd92027dc04c2656afedc16fc85cd1b.png)

### 7、IDA加载.so文件

#### 1）查看ddms中的端口号

![4AXxv4.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6645378c1e33e47ff579959672f4078fab1166ec.png)

#### 2）执行命令

```php
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8600
```

### 8、IDA中查看

执行了jdb命令后，一开始只有调用odex文件。这时需要在IDA中左上角**再按下执行按钮**，使得`.so`文件加载成功，查找该so文件双击进去

![4AjJxg.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a27a571ef29097b7262456fc8584206732ebfb01.png)

### 9、在.so文件中搜索JNI\_OnLine分析

搜索JNI\_OnLine，在开始处F2下断点

![4AjNrj.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d0ec0c1188aebb27c0deb60409f0617458ee82a8.png)

**拓展：**

IDA下断点的原理：通过异常

### 10、程序运行

F9执行到断点处

![4AjtMQ.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-89bbd415110697eff9b1b1d6f943e0b743670aca.png)

F7单步步入，单步调试分析

六、动态调试分析so文件
------------

这部分需要能够读懂常见的简单的ARM汇编指令，下一篇文章中会先介绍到ARM汇编指令，再接着动态调试分析so文件，所以这部分内容就安排在了ARM汇编指令介绍之后。