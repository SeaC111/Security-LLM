0x01 引言
=======

NodeJS Node.js 就是运行在服务端的 JavaScript。是一个基于Chrome JavaScript 运行时建立的一个平台。Node.js是一个事件驱动I/O服务端JavaScript环境，基于Google的V8引擎，V8引擎执行Javascript的速度非常快，性能非常好。本文主要是简单探讨NodeJS RCE以及NodeJS RCE的绕过方法。

0x02 NodeJS中的RCE
================

2.1 child\_process 子进程
----------------------

child\_process模块提供了与popen(3)类似但不完全相同的方式衍生子进程的能力。该库通过创建管道、分叉和调用外壳来打开一个进程。以下是其基本使用方法：

1\. child\_process.exec():衍生shell并在该shell中运行命令，完成后将stdout和stderr传给回调函数。

2\. child\_process.spawn():该方法异步衍生子进程，不会阻塞Nodejs事件循环。

3\. child\_process.spawnSync()：该方法以同步方式提供等效的功能，其会阻塞事件循环，知道衍生的进程退出或者终止。

4\. child\_process.execSync():他是child\_process.exec()的同步版本，它会阻塞Nodejs事件循环。

child\_process模块的使用例子如下：

require("child\_process").exec("whoami",function(err,stdout,stderr){console.log(stdout);});

0x03 NodeJS中的RCE ByPass
=======================

3.1 常见Bypass方法
--------------

从上面的使用范例我们可以知道，在NodeJs中调用模块是通过“.”来代替的。假设“.”被过滤的情况下我们可以通过“\[\]”键值对的方式进行调用。例如：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8247db0f50476a107048c4fc6a17cf0ea121588f.png)

我们得知以上性质后可以联想到假设过滤了某些关键字是可以通过字符串拼接的方式绕过的，例如；

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-257c6c0bbd6b8f9081cebf07adaf392d188fbad0.png)

我们也知道JavaScript是支持16进制作为字符串使用的，我们可以使用十六进制进行绕过。例如：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-877fd2ca700933182b90adf4129cf2c134580901.png)

JavaScript除了支持十六进制以外还支持Unicode编码作为字符串使用例如：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5e3869dde43bde973f6493f134ef6b6d8487cd33.png)

亦或者使用ES6模版来代替普通的字符串绕过，例如用反引号里面可以加入模板：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2dac2b8137deae1783f0f880669ebaac56a823a2.png)

除了使用“+”拼接字符串之外还可以使用，concat拼接绕过：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a54cfc99ed929d1f1dd2c562ce6dc1a6973eb966.png)

当然也可以使用Base64进行编码绕过。如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-816fbc35eca1a48da2560ac45e91321c711e3396.png)

3.2 Obejct.values
-----------------

Object.values(obj)返回一个数组，成员是参数对象自身的（不含继承的）所有可遍历属性的键值，有点类似JAVA中的反射例如我们获取child\_process库的所有对象，如果我们要执行命令我们可以选择第4个对象。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f7e7d9686c39459916420e55b097f25603582128.png)

获取对象后执行命令操作例子如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b74029190aac15b805f7c821b22f6fd20af4f691.png)

3.3 Reflect
-----------

什么是Reflect?

MSDN给出的解释：Reflect是一个内建的对象，用来提供方法去拦截JavaScript的操作。

Reflect不是一个函数对象，所以它是不可构造的，也就是说它不是一个构造器，你不能通过new操作符去新建或者将其作为一个函数去调用Reflect对象。Reflect的所有属性和方法都是静态的。

1）Reflect.ownKeys

Reflect.ownKeys() 返回一个由目标对象自身的属性键组成的数组。

我们使用Reflect.ownKeys来获取全局对象global的所有属性，而后使用find方法从中找到我们想要的方法.注：Node.js 中的全局对象是 global，所有全局变量（除了 global 本身以外）都是 global 对象的属性。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d0a0887e1846d1809d562abd4a3644d4fa3ca466.png)