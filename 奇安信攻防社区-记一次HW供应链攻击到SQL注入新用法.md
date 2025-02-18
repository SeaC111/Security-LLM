0.前言
====

在参加某市攻防演练的时候，发现目标站，经过一系列尝试，包括弱口令、SQL注入等等尝试后，未获得到有效的入口点。在准备放弃之时，看到页脚的banner：xxxxx信息科技有限公司

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4bb1f4a736e75c4236b675c9b6c1a9b5954d052f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4bb1f4a736e75c4236b675c9b6c1a9b5954d052f.png)

然后有了个想法，到fofa里面搜这个banner，找到一些其他使用该站的，但是没有参与攻防演练的（PS：演练前该单位做过整改弱口令全改了）。

1.旁路进站获取未授权接口
=============

经过尝试，果然皇天不负有心人，进入到了其他厂商的后台，于是开始寻找未授权就能访问的接口或者RCE点，脱代码来审计，从而获取目标权限。

找了一圈，后台没有直接RCE的点，无法脱代码来审计，但是发现了一个有趣的点：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e3977568372fe65421d902a135e108a3dbf72c1c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e3977568372fe65421d902a135e108a3dbf72c1c.png)

此处查找联系人的接口，存在未授权访问，数据包为：

```php
POST /HanNeng/SelectHelp HTTP/1.1
Content-Length: 29
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: ASP.NET_SessionId=vd11thy3qnmgz0h4dtyb51ra; rem=1192
Connection: close

Type=User&Field=UserName&Con=

```

经过测试发现该处不仅存在未授权访问，Field参数还存在注入。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-566fad051a64ba8bb66368ecc2ee1ede1c925eab.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-566fad051a64ba8bb66368ecc2ee1ede1c925eab.png)

直接给出部分sql语句：

```php
select count(*) from tb_User where IsDeleted!=1 and Password'
```

测试过程中发现field是列名，证明如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddedf5e72c16431684e8d03cc62a907bf301b9b3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ddedf5e72c16431684e8d03cc62a907bf301b9b3.png)

当我认为可以sqlmap一把梭的时候，却发现了这该死的waf：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e690246717ed178bb917174b36a7fa34df635419.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e690246717ed178bb917174b36a7fa34df635419.png)

3.与waf生死缠斗到和平相处
===============

尝试绕过waf：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-663f37192e74b36c32e30de9ca100d4c75db7bb5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-663f37192e74b36c32e30de9ca100d4c75db7bb5.png)

发现like附近语法错误,这时候想起来根据其他搜索方式，比如工号搜索的时候，应该是模糊匹配的：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ea783c3445f26c5c7ecaa8787289a2ebc7faf997.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ea783c3445f26c5c7ecaa8787289a2ebc7faf997.png)

发现Con参数的内容应该是进行了模糊匹配，也就是说sql语句可能是：

```php
select count(*) from tb_User where IsDeleted!=1 and userid like '%可控点2%';
```

可控点2不存在注入，可控点1存在注入但是有waf，这时候就想到一个特别好玩的方法，我把field传入个password是否能获取到password密文呢？

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-126e713eeebba6afa07abac63d4c1e5794af7e67.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-126e713eeebba6afa07abac63d4c1e5794af7e67.png)

然而并没有，所以呢，猜测此处是这样一个逻辑：

先执行sql语句，确定用户数量：

```php
select count(*) from tb_User where IsDeleted!=1 and userid like '%可控点2%';
```

然后再执行sql语句筛选用户信息，工号和姓名：

```php
select username,userid from tb_User where IsDeleted!=1 and userid like '%可控点2%';
```

所以肯定不可能直接把密码传出的，那么就没得搞了么？要么绕过waf，要么还能。。。

```php
select count(*) from tb_User where IsDeleted!=1 and password like '%可控点2%';
```

这样我只需要构造payload：`Type=User&Field=password&Con={遍历}`就可以一位一位注入密码了，比如：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-72b84560eccab1e2885d672f390729267fa6142a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-72b84560eccab1e2885d672f390729267fa6142a.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d29eff0408ccb1bfc4240a8334824b66c148657.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d29eff0408ccb1bfc4240a8334824b66c148657.png)

用户pageCount数量一直在减少，密码相同的用户一直在减少，但是这里要说明一个点，因为是%可控点%，所以123的前后都有可能有数据，当时我犯了这个错误，导致注入出的md5不全。注入出md5证明如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-994d25cf1fd0a5a1b739b666a90f3f177507f011.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-994d25cf1fd0a5a1b739b666a90f3f177507f011.png)

自此就可以和waf和平共存，你防你的大注入，我搞你的小密码。获取完整md5后解密即可登录后台。