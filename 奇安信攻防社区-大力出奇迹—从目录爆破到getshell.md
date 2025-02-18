0x01 获取备份文件
===========

1、对目标站点进行目录扫描没有什么收获，只有一些403，

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d15ff0d6e35f066cc154b97c46396e65a1af6668.png)

但是总感觉这里会有东西，于是我又重新fuzz了一下目录，把目标的公司名缩写加在了目录名中，果然大力出奇迹，获取到了一个备份文件。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-8f59e4e28b1debd0acb3a15c91b06d53fdb38d91.png)

2、在备份文件中获取到了许多敏感信息

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4107ee03d9aa063ac6fef7814ecaa72cde957968.png)

0x02 通过钉钉KEY和SECRET获取敏感信息
=========================

1、env的文件中有微信小程序、公众号、QQ、钉钉等IM通讯软件的KEY和SECRET

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-55616de0c3ebccd6abb845f435a7d045758c515e.png)

2、微信的KEY和SECRET都尝试利用了，但都没能获取到token，可能是设置的有IP地址限制，但是钉钉的可以成功利用，利用官方的API 获取accessToken

[https://open-dev.dingtalk.com/apiExplorer#/?devType=org&amp;api=oauth2\\\_1.0%23GetAccessToken](https://open-dev.dingtalk.com/apiExplorer#/?devType=org&api=oauth2%5C_1.0%23GetAccessToken)  
![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1c67d72b65a69215bb39ab69185cbc7698655d0d.png)

然后有了token，能够获取的数据就有很多了，这里只演示一下获取部门列表，根据官方API手册，获取部门列表

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4e5e5f90647eb37002b73d9b6a1de9643dfce0f6.png)

成功获取部门列表信息

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-2df85fab25fea2c9a3c6da574458989d03748108.png)

0x03 微信支付宝支付接口信息泄露
==================

1、在Web.config文件中获取到了微信和支付宝支付的接口信息

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-42398b96b7fa43882ce4cb7f20e1a15ce4d9470a.png)

2、支付密钥泄漏，就有可能导致攻击者花1元购买了100元的商品。系统进行验证时，会发现签名正确，商户号正确，订单号支付成功，**若代码没有验证支付金额与订单是否匹配**，将完成攻击者的订单。在许多网站或者App中，曾出现过只验证签名和订单id的情况，没有验证实付金额，因此可以通过这种金额篡改进行攻击。

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-274be236443d12f682a8f0c20a15cb830a8f639b.png)

3、并且文件中还泄漏了证书文件

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-384b91f6f84227c9205d875a821c1e5177d58d9d.png)

有了证书就可以调用微信支付安全级别较高的接口（如：退款、企业红包、企业付款）

4、这里就没有进行利用（害怕ing）

0x04 接口文档泄露导致getshell
=====================

1、泄露的文件中还有一个接口文档，在其中查到了一个文件上传的接口

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-32035bf453bf07b6e0f667877322b7ae6ad91eff.png)

2、测试后发现该接口是未授权访问并且可以上传webshell

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f7ef627b05f29e989c0e68a7dc48239dc70bbb62.png)

但是返回的链接直接拼接到url上并不是正确的shell路径，于是本着大力出奇迹的原则，开始爆破webshell的路径，可以先选择一些常用的上传文件的接口路径进行爆破

```php
file/
fileRealm/
file\_manager/
file\_upload/
fileadmin/
fileadmin/\_processed\_/
fileadmin/\_temp\_/
fileadmin/user\_upload/
upload/
filedump/
filemanager/
filerun/
fileupload/
files/
files/cache/
files/tmp/
logfile/
paket-files/
profile/
profiles/
```

我们发现uploadFile这个路径和其它的不太一样

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-977be6223346f62233e387f3b02a600e7887bfa9.png)

成功连接shell

![](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4eb225f4a28cd442e29dcb876b9b91205fc2a822.png)

0x05 总结：
========

1、本次能有这么多收获，都是从那个备份文件中获取到的信息，fuzz目录这个思路是从密码爆破中学来的，虽然好多公司都要求密码设置强密码，但是还是有一定的逻辑的

比如说

腾讯的系统  
tx@123！  
tc@123456！

可以自己收集一些特定密码，进行爆破，简单写了一个python脚本，还不太完善，大家可以加入一些自己的想法。

```php
#coding=utf-8
import sys
key = sys.argv\[1\]
f = open("%s.txt"%key,"w")
list1 = \[123,321,1234,4321,123456,654321,12345678,123456789,1234567890,888,8888,666,6666,163,521,1314,1,11,111,1111,2,222,3,333,5,555,9,999\]
list2 = \['#123','#1234','#123456','@123','@1234','@123456','@qq.com','qq.com','@123.com','123.com','@163.com','163.com','126.com','!@#','!@#$','!@#$%^','098'\]
for j1 in list1:
    pwd1 =  key + str(j1) + '\\n'
    f.write(pwd1)
for j2 in list2:
    pwd2 =  key+str(j2)+'\\n'
    f.write(pwd2)

for i in range(1000,2021):
    #pwd1 = key + str(i) + '\\n'
    pwd3 = '{}{}{}'.format(key,i,'\\n')
    f.write(pwd3)

f.close()
print (key+' password ok') 
```

2、对于密钥的利用，需注意要区分是企业内部应用还是第三方应用，关于微信密钥的利用可以看下这位大佬的文章：<https://xz.aliyun.com/t/11092>

3、文件上传接口那里，也是花了很长时间，慢慢尝试才成功上传了的。