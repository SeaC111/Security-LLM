信息收集
====

首先我是在官网上看到了操作手册

![1722164279953.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-2595c91bcfec34defcbb265c2d2683d3aada0c95.png)

里面写了默认密码

![1722164384370.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-0c5cbf80c7b1cb22e592928308d9590d727184d9.png)

现在就简单多了，直接谷歌语法，这种姓名学号信息还是很好找的

![1722164437270.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-3c130c5876ba9dac06832a34e573d1d799123309.png)

然后找一个比较稀有的名字，不然搜索的时候信息太多，身份证信息有了，直接登录系统成功，下面就是正常的漏洞测试了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-fa067ca2ca994fa2e9057c8fdd8758af8dbad476.png)

漏洞挖掘
====

xss
---

这个没啥好说的，有输入就插，很多地方都存在xss，下面的sql注入比较有意思

![1722164960199.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-5aa14ec738479fc0bf44bab211557b4d9353c5d5.png)

![1722164880544.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-bcf33bac00817dba27c78a5f817fb598120ddc3c.png)

sql注入
-----

直接一个查询的数据包,statusCode字段单引号报错

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-a455b8ba23c40fe986f050a68f25b70a471772ec.png)

再加个单引号正常

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-7061443b4e71099d86bc2503c99997b97c96db43.png)

经过各种测试，exp(709)正常

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-f24c13b8487fd8f65fb9b81a8f92dd49af7af998.png)

exp(710)异常，这里感觉是orcale数据库

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-9ba1f40722cbe31c235f1608b150e189e3398eef.png)

只能进行盲注了，测试各种语句

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-059c7b72b623ca9d4013a173fa7740da29abedf9.png)

decode也被拦截

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-1d04da8c489a912b2eea0dc5a58437d87fa03e22.png)

case when也是异常

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-138891fc5348f8461cabc5035889fe187802ec98.png)

这里注意到只有decode显示的是特殊字符，这说明if和case when并没有被拦截，只是它可能有个规则，在你逗号等于号传进去之后会再给你加一些别的字符让你语句执行失败，这种比较好绕  
直接改成'||case 1 when 1 then 1 else 1 end||'测试，成功返回数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-909683c9af395b679816b9113394dcc94832a71f.png)

先测下uesr函数，没问题可以用，把else后面改成exp(710)就好，这样只有user的长度正确的时候才会返回数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-65fbc5d36dcc75fe89793eeab8aa8f8ec81b6a47.png)

跑出来为8位

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-6cef48ae574e91ffd6905ce05a6277d866d4d6d7.png)

因为逗号也不能用，这里换个写法，还是异常了，不过测试过ascii函数是可以用的

```php
substring(user from 1 for 1)代表从第一位开始，截取长度为1
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-19bd87b80fb01962880869506334a5dca7620145.png)

不过还是异常，跑了很多截取函数都不能用，之前以为是orcale数据库，现在怀疑是PostgreSQL数据库，他俩比较像，PostgreSQL有个函数很少会禁: position函数，这个函数不需要逗号，有两个参数，就是判断第一个字符串在后面字符串中出现的首个位置，从1开始

```php
position('sql' in 'postgresql')返回的是8
position('sq' in 'postgresql')返回的也是8
position('p' in 'postgresql')返回的则是1
```

测试发现没问题

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-e5951dd2c8bda5d73bf9da101ca7f2c6f3823753.png)

不过也不需要ascii函数了，返回的直接就是数字  
这里说明a第一次出现不是在第一位，所以返回的是exp(720),然后异常

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-bbacaed0dd99fbae9129ac7afd42f2e633adfcbd.png)

直接a为变量开始爆破，这说明c出现在第一位，等于1，所以返回了数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-b86ceaeaa5a65f604e32c53835fd2069c59f16ee.png)

第二位为m剩下同理

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/07/attach-34703680fa95e8c289e3381ffb967625f97ad762.png)