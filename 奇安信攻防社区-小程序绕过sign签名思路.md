### 漏洞前言：

```php
测试小程序的逻辑漏洞经常会遇到sign签名标识，若不知道sign的生成方式，只篡改参数的值无法修改sign的值，那么漏洞测试就很难进行下一步。本篇分享将围绕如何绕过小程序sign标识展开。
```

### 0X01

##### Sign定义：

sign一般用于参数签名，用来验证数据的完整性和真实性。为校验客户端数据传输合法性，防止用户篡改参数、伪装、重放以及数据泄露等常用sign签名校验。sign标识生成方法一般是是将秘钥、时间戳、特殊字符、随机数等参数经过特定排序后使用某种加密算法进行加密，作为接口中的一个参数sign来传递，也可以将sign放到请求头中。是

一般加密方法有：MD5加密、AES加密、SHA加密等。

##### 绕过sign验证常见手法：

1、观察sign的格式，测试判断是否是弱凭据的形式，比如是base64编码，解码后就可以看到原始数据；或者是MD5格式可以直接解密尝试，是否能解密出原始数据等等。

2、尝试将sign字段删除或者直接置空sign的值，看能否绕过校验。

3、尝试反编译，在反编译出来的源代码中查找加密算法，找到sign的生成方式。

### 0X02

测试涉及到的工具：

解密小程序源码工具：  
<https://share.weiyun.com/uMqNGOXv>

反编译小程序工具：<https://github.com/ezshine/wxapkg-convertor/releases/tag/1.0.1>

### 0X03

##### 测试细节：

**1、** **测试小程序**

打开某某小程序，抓包，任意更改参数发包会报错，发现添加了sign字段。

直接更改其中的参数发现报错：

![](https://shs3.b.qianxin.com/butian_public/f590695ca0435a1fda1a181ea345c03ee122bb9afe6a8.jpg)

尝试直接删除sign字段，报错：

![](https://shs3.b.qianxin.com/butian_public/f566323c65eef08d567e78898ac7f68a9f71b696e2acf.jpg)

尝试解密sign，看是否是弱加密。经过观察发现是32位数猜测是MD5加密，解密发现解不开。

![](https://shs3.b.qianxin.com/butian_public/f938960a6d5be3a61a26ff6d57233efc45a0ec85bfd44.jpg)

尝试无果后，尝试反编译小程序，看能不能找到sign的生成方式。

**2、** **反编译小程序**

首先需要找到该小程序存储位置，针对windows端来说，微信小程序默认的存储位置（C:\\Users{系统用户名}\\Documents\\WeChat  
Files\\Applet{小程序ID}\\），因为这里存储都是以小程序ID进行命令的，因此可以先清空微信中的小程序，再去打开想要测试的小程序。

需要注意的是，一定要等小程序完全打开并且再点几个功能，确保将所有包都运行。找到对应的wxapkg查看是否可以直接反编译，有些会有加密，这时先使用工具Unpacker解密，再使用wxapkgconvertor工具将包反编译出来。

![](https://shs3.b.qianxin.com/butian_public/f918852b75f76b67930835f52f4505adec771f2b73878.jpg)

解密后使用反编译工具进行源码提取：

![](https://shs3.b.qianxin.com/butian_public/f3313358d750b9ff59306b2da93b429f8c39fb91696f5.jpg)

![](https://shs3.b.qianxin.com/butian_public/f27212248bf03cffd0fcdbf7c00a7e9d71f83822df583.jpg)

**3** **、全局搜索加密函数位置**

打开反编译后的源码，全局搜索MD5，找到了主要的加密sign的代码如下：

![](https://shs3.b.qianxin.com/butian_public/f76465838e73af1b37f3d9ee4775525e0bb7c5e81fce4.jpg)

加密sign主要函数内容如下：

先遍历对象t，将其中给的参数进行整理，将其中属性是"biz\_content"的重新赋给变量r，并且将r的参数属性从json格式转换为对象类型。整合后以字符串的形式以 “&amp;” 连接，将字符串再连接一个预设的值 “ihos-xxx-8”。按照字母升序的方式排列，排列后使用MD5的方式加密再转为大写即可。

**4** **、回调代码**

分析完主要加密函数后就可以回调，找对应的函数和参数。

回溯源码看哪里调用了encryptSign，搜索encryptSign查到gatewayRequest函数。继续跟进。

![](https://shs3.b.qianxin.com/butian_public/f79256630f0c55edefda60e7c2f3e9f59e77b49ffa448.jpg)

继续跟进函数gatewayRequest找到如下源代码：

![](https://shs3.b.qianxin.com/butian_public/f64023537c859ef710afd22dc2f3cd67484dfbc3383db.jpg)

继续跟进：

getPatInfoByIdNo

![](https://shs3.b.qianxin.com/butian_public/f330309c41cf21ead7877ddc78e2acecd5a118640a8f1.jpg)

发现传入n是个常量

r是个对象，最后转化为xml格式。

继续跟进generateRequest。

![](https://shs3.b.qianxin.com/butian_public/f579570cfece0394aa18bc024888e995b7bca4bdb9be3.jpg)

跟进l函数：

![](https://shs3.b.qianxin.com/butian_public/f22797398b5ac934b6d422510df06216ea7e86b39a1af.jpg)

找到了sign生成函数里各个参数代表什么。

```php
method: 接口名字,常量

app_id: 0863c0e3-fc0d-04d7-c58c-80b33d636867,

token_type: "api_credentials",

nonce_str: 时间戳

version: “v1.0”,

token: "",(登录后获取)

biz_content: biz_content对应的明文参数
```

特殊字符：ihos-xxx-8

**5** **、得到sign生成方式**

根据主函数推测sign的生成方式，回到第一步的代码，将这些参数按照字母升序排列。

**6** **、测试结果**

将这一串字符用MD5加密并转换为大写，就得到的对应的sign值。放进数据包中测试篡改成功，截图如下。

![](https://shs3.b.qianxin.com/butian_public/f933294ea89fb61001f75062a6ee38a6821bb8498d739.jpg)

### 0x04 总结

小程序测试中碰到sign标识可以先测试是否无效或者是弱加密，如都不是可以尝试通过对源码分析找到sign的生成方式，可以应用在修改支付金额、越权等漏洞更进一步提升危害。

### 0x05 拓展--burpy插件使用

在安全测试中，遇到类似上述讲解中数据包中使用sign签名，在分析加密方式后，不管是自己写脚本或通过网站加解密再粘贴到burp中进行测试，都十分麻烦。因此，可以考虑结合burpy插件来进行漏洞测试。

```php
GitHub:https://github.com/mr-m0nst3r/Burpy

   Burpy是一款能够打通BurpSuite和Python之间的插件，可以让你在Burpsuite中运行自己指定python脚本。在测试中，只需要点击就能达到自动加解密且替换http请求头或请求体中的数据的目的。
```

![](https://shs3.b.qianxin.com/butian_public/f611211602efed27d5db80b589bde506b1387deceb477.jpg)

![](https://shs3.b.qianxin.com/butian_public/f2862401ea8e158f36b4e6729ed52cda1f47c5ab8e9c3.jpg)

在Burpy PY file path:里面指定好你自己的python脚本。Burpy也提供了脚本模板，可以直接在它的脚本模板中进行加解密算法

```php
底下两个开关Enable Processor和Enable Auto Enc/Dec。
```

（1） 打开enable processor之后，在使用Intruder进行暴力破解之类的动作时，如果payload需要进行加密或签名，就可以把加密/签名的算法实现到自己有python脚本的processor函数中。

（2） 打开enable auto  
enc/dec会自动调用encrypt方法，在点击重放时自动进行加解密。

设置好之后，点击start server后，就可以开始正常测试了。

编写脚本：

![](https://shs3.b.qianxin.com/butian_public/f3771408d99251a36860271d69fada9f43a3a0f2509a1.jpg)

![](https://shs3.b.qianxin.com/butian_public/f551683a4c43c65648bbeb30297e547c2da0c14427f77.jpg)

插件运行：

![](https://shs3.b.qianxin.com/butian_public/f669710280e6c89fcf9a9f3d530fbcbf3561ef5e8f7e7.jpg)

关闭enable auto enc/dec的话，可以右键加解密

![](https://shs3.b.qianxin.com/butian_public/f33033949e12f215ad4c28868aee39aab8184dd13e10d.jpg)

![](https://shs3.b.qianxin.com/butian_public/f5055754e310cd175239c656956277afe4aaa2cc5a28c.jpg)

开启后无需右键操作，重放会自动进行加解密操作。