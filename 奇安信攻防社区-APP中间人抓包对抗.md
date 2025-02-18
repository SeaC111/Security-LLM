在平时的一些漏洞挖掘或者数据爬取采集过程中，都会遇到app的数据包抓取，随着攻防两端不断的对抗较量，各大厂商app的防中间人抓包技术都是十分强悍，那么这边主要针对一些app抓包的技术进行梳理，通过以下方法可以实现一些app的数据包抓取。

0x01 本地代理抓包
===========

```php
     本地代理抓包技术其实和平时web抓包的技术是一样的，只是android端需要进行证书安装，那么在Android7以上更是需要将证书安装到系统区域，具体操作如下。
```

1、HTTP/HTTPS代理抓包
----------------

```php
    本地HTTP/HTTPS代理抓包可以根据自己使用的工具进行选择，这边已burpsuite为主进行操作
```

查看PC机本地IP

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-15b9b54bc56b37eaadb9b7ab0c2acce643b5ac7f.png)

burpsuite设置监听IP和对应端口

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3b7007b3c5b11b6b218f0fd33cef735b758c3b61.png)

导出证书

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-670a797e2636d7be57bea24902a9e34586c8447a.png)

将导出的证书利用adb push命令发送到android系统sdcard目录下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b607e8f1ea579962251552add00b67b678ad224b.png)

在android系统安装该证书，打开设置下安全功能，选择从SD卡安装

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bb0c939783ca818960fb80922b3ab5d0ab38719c.png)

选择push上来的证书，点击安装

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f65b2e039a4c371298b33498f99abb96171a0005.png)

进行选择命名安装，至此安装证书完成

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d3edbce60003656437603a225cc9caefab7ead6c.png)

继续为android网络进行代理配置，选择对应的网络，进行修改网络

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-61bfec4236e1f82b1ef6b7ea914ce4b09d002ad9.png)

高级选型下手动进行代理地址和端口的输入，这边以本地PC机的ip进行配置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a2c0cf9dd65145628405964d8bbdaf496b13e1e4.png)

配置完成便可以成功抓包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a41b1cadac6f7b12773fda1054860adb18d9aa7e.png)

2、证书导入系统区域
----------

```php
    Android7以上，系统不再信任用户级的证书，只信任系统级的证书。因此为了正常抓取app应用的数据包，需要将证书安装至系统区域。
```

查看证书为用户权限证书

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6e46f5fc757ddef3fb3aca19566dc452aa9c62b2.png)

进行证书格式转换，当然，这块需要转换的证书可以是burpsuite、fridle或者charles均可以，主要针对你抓包使用的工具来说

```python
openssl x509 -inform DER -in burp.cer -out burp.pem
```

查看转换为pem格式证书的hash值

```python
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-69b060ae5e142163ff3438a5906213ed5e4c81f3.png)

重新命名该证书为9a5ba575.0

```python
mv burp.pem 9a5ba575.0 
```

那么接下来需要将该证书导入系统区域，有些测试机虽然root了，但是启动adb root仍会报错，因此这块利用以下两种方法来实现  
**方法一：**  
adb启动root权限

```python
adb root
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-db0b9d9118a44baa204daee5bbf75b120559c080.png)

重置可写模式

```python
 adb remount
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2b08396f302c23709f1a1e22d6f8074b0fdaecd3.png)

将该文件push到Android端/system/etc/security/cacerts/目录下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b13265f61f90c530d9f6f1abcd625c77c2f6ddee.png)

查看证书已为系统证书

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8c1616193df930122ab89309f419fcb235cf0246.png)

**方法二：**  
将该证书push到Android系统sdcard目录下

```python
adb push /root/Desktop/cer/9a5ba575.0 /sdcard
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5ea0982347a1c0f3a92fea57ca76dcb06691c448.png)

启动adb shell

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-66294c7c67527c4c6e7b9cfc5c8b8b53b44ea5cd.png)

重新装载Android文件系统，使得文件系统可读可写

```python
mount -o rw,remount /system
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-95169bb3ae2dc7603c105bfed0be98aafd159683.png)

将该证书移动到/system/etc/security/cacerts/目录下

```python
mv 9a5ba575.0 /system/etc/security/cacerts/
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-caf75164b8d0361033abfe1998ff2e239cce7513.png)

也是成功实现证书移动到系统区域

0x02 VPN实现socks5代理
==================

```php
    上述本地代理抓包是比较常用的，但是针对一些app对于https协议的检测导致目前很大一部分app是无法进行成功抓包。这时候可以考虑利用VPN软件socks5实现对Android系统的socks5做代理，实现所有流量数据的抓包，一般使用Charles工具更方便
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5acb7d081e8932fb4dac7284cb6528e29b15f7de.png)

选择Proxy Settings进行SOKCKS Proxy进行配置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-588e8ee3f9f51c95c35f5ed2cc3d6cf99adc4234.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-eeef71fcc4907eacf861ed2528ac46eb9021dac9.png)

配置完代理后需要对抓取目标进行配置，host和port都为\*，也就是通过的所有流量都进行拦截

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2005d5266b23b8d6559c2da040416096c85d5314.png)

导出charles证书，在Android系统进行安装，安装方法和上面的本地代理抓包中方法一致

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd8f5c740cd5206f918287a96cea0f5447cb23a5.png)

证书安装完成后在Android端安装Postern工具

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-23c07c25157ca5900b4c9ecdf5e64ae7a382b2cc.png)

进行代理配置，和charles配置的ip以及端口相同，选择SOCKS5代理类型

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1087c16fe12d97e5d92b1afcea217f47627d8048.png)

代理配置完成后配置规则，匹配所有地址都通过上面配置好的代理进行连接

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4c50ed5c1e9eb425f114a0e86c3320b95f66d40e.png)

完成上述配置后，打开代理，charles会提示选择Allow运行就配置完成

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0b6997ab696308e3f6b45f6147f81c0e36dec77c.png)

成功抓到Android端http/https流量

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c6a3c1b6dc38f73c18a9e5a1cd49d64c39737bbb.png)

0x03 SSL pinning绕过
==================

```php
     SSL Pinning即证书锁定，也是目前很多app防止中间人抓包的一类安全措施。其原理是将服务端提供的证书内置于app客户端中，当app发起请求时，通过对比app客户端中证书的信息和服务端证书的信息是否相同来判断该请求的合法性，而决定是否正常通信。
```

那么其中具体的原理和逻辑有兴趣的大家可以自行实现测试，针对SSL Pinning在app抓包过程中，一般可以通过hook技术进行绕过，当然大家可以任选xpose框和frida框架其一进行测试，本次测试主要利用frida框架的集成工具objection中的android sslpinning disable模块实现绕过。  
利用burpsuite打开app进行抓包，发现大量告警提示SSL连接有问题，证书问题，那么就可以知道是SSL证书的问题，接下来利用frida框架进行绕过

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-65915d495233de3532476d2396d6a17eb64a691a.png)

在Android端启动frida server

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5d22b69d2f9d709c2008ce65ed0da7612c2b7f7d.png)

启动objection工具对该app进行hook

```python
objection -g com.xxxx.xxx explore
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b7508108d3c31f1169f7bce38b2fff4821c1c201.png)

hook到后执行以下语句

```python
android sslpinning disable
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5a67bff67e0b6bd8526fcdf00026025e5c3218fe.png)

再次运行app，利用burpsuite进行抓包，成功抓取到交互的数据包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-61f09b5391aafac8b1416f9827f60506279c3ae6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1f561e9733eb6fb16463e6eb71ef0c713e3b36d9.png)

0x04 服务端双向认证绕过
==============

```php
    在App生成过程中，客户端也存放一个证书，https协议握手时客户端把App中保存的证书发送给服务端，这种客户端校验服务端证书，同时服务端也校验客户端证书的方式称为双向校验。
    那么针对这些存在双向校验的app，想要抓包，就需要绕过双向认证的检测，针对app对服务端的检测可以尝试利用SSL Pinning绕过技术进行绕过，但是对于服务端校验客户端证书时，则需要将app客户端中的证书找到，并导入到抓包工具中再进行抓包发包便可以绕过检测，接下来通过实操了解App客户端证书的获取。
```

利用burpsuite进行抓包，发现存在报错

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-138a0f820a5cb7f152849a486845fa3f22c4bbaa.png)

解压apk文件，在assets文件下查找是否存在.p12或者.pfx结尾的证书文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2b13040e781355734a9144a21ca583160649025f.png)

利用jeb对apk进行反编译，查找.p12或者PKCS12

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c0eea26c0de9419e9dc67d9097cd9746a675e93f.png)

对代码进行解码，解码后需要分析证书密码获取的方法函数，这块针对不同的app逻辑也是不一样，具体自行分析便可

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c86f1ebcbfcface315ce3047818ef623e5ddfc38.png)

进行跟进可以看到返回获取密码的方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-95ab200b74fc4ecb524d91f6d76e058308907026.png)

进行跟进，发现是一个native方法，那么便可以判断实际的逻辑在so库，利用java的反射方法实现

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-650391c8fa5c7d61f7c422398f3e015bea701671.png)

向上跟，可以看到具体的so库名称

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a64a4ad364fe55616d2e0e79e5d0ae261b5b102b.png)

利用IDA打开so库，搜索该方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4b0c3e0689fb42af34d929a339f1c397a6f2127a.png)

利用F5方法进行分析，可以看到传入的证书明文密码

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-21e404c0a4bdfabe9f4762077c5bf54eda0828c7.png)

在burpsuite中将assets目录下client.p12证书以及密码进行导入，成功之后便可以利用burpsuite进行抓包了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a28909f1eb9f5ee80e1a497be4a4bb7f79ec721.png)