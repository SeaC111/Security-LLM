这次也是莫名其妙，没有什么参考价值（因为它看上去不是框架），但是这个洞发现的过程很有意思。

要感谢我的朋友们，给我这个php低手非常好思路。下次KTV我会对着他们唱感恩的心的^ ^。

1 简单难用的跨站脚本
===========

小黄站，不知道为什么我老是在打小黄站- -。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712048402196-f0292b0c-eb50-4b18-be3a-9769f6765036.png)

进去先随便点了点，没发现啥大洞，只找到一个反射型XSS（顺带说一句，comefrom这种参数是XSS大头）：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712114415220-9a5f1928-43e4-4115-8447-a7d4c24b2a22.png)

反射型XSS其实本来也能将就用用，骗骗客服啥的。不过苯人胆子真的很小，能不和对方打照面尽量不去打。所以先放着。

2 难窥门径的反序列化
===========

由于前台没毛病，注册个账号：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712115780195-f28e7600-b70b-456a-b0a2-4491c427aae0.png)

由于我打码了，可能读者没发现什么华点。

但是我把\_\_user放进Decoder里解一下URLencode：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712108431966-92b1c0b5-aadf-4158-881a-ce233c21e9c6.png)

这不就是php反序列化吗？？

虽然php反序列化在不知道源码的情况下，不好利用，只能盲打。但是，如果这玩意就是Cookie的全貌的话，我是否能通过修改内容，伪造任意用户的Cookie？

说干就干。php序列化类似ruby（可能这是脚本语言的特性？），比java的字节码好读多了。它的结构如下：  
`O:strlen(object name):object name:object size:{s:strlen(property name):property name:property definition;(repeated per property)}`  
而这段反序列化，含有以下字段：  
●Nickname  
●Id  
●Hash  
●...  
最开始我想着先看看Id能不能伪造，所以先修改Id字段。修改php的反序列化字符串很容易，修改明文的值，然后更新对应的长度就行。比如说O:14:s:8:"11111111"，改完之后就是O:10:s:8:"4444"。  
改了之后发现无论如何都取不到值。  
正常的\_\_user返回是19632：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712452999815-24705583-b4d2-4353-9a11-d77ec6240090.png?x-oss-process=image%2Fformat%2Cwebp)

随便改一下，比如改了id，就是16574，也没有取到值：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712453089468-af99ece7-cf98-4792-b3f7-448a41430275.png?x-oss-process=image%2Fformat%2Cwebp)

我以为是我反序列化的姿势有问题，问朋友，朋友问我是不是\_\_uniqueId的问题？

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712453357602-718bbfd7-29e8-4bf1-bb36-c79d919d7f3f.png?x-oss-process=image%2Fformat%2Cwebp)

我一看，32位，长得是有点像啊，不过我反应大条了点，晚上到家才发现。

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712453341484-ea8446f0-dbca-4de3-97ab-d2babaccfa2f.png?x-oss-process=image%2Fformat%2Cwebp)

我把\_\_user换成各种形状md5和uniqueId对比，但是没找到对得上的，很烦。  
更烦的是发现删掉uniqueId之后还是能发包：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712453502358-e7e3d9d6-bbe7-4dd8-9e2f-335928566e2b.png?x-oss-process=image%2Fformat%2Cwebp)

试了半天=白试，也是没谁了。不过没关系，记得上面那个Hash吗？那个玩意也是32位，而且名字还叫Hash：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712453586880-25b7f62c-7c21-44c3-8c61-5e942416cff6.png?x-oss-process=image%2Fformat%2Cwebp)

这次我感觉稳了，就算找不到是怎么MD5的，但是肯定是校验了这个^ ^。因为Cookie的其他部分已经被证明为不值一文，而和用户有关的操作又都不存在其他参数：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712453720146-a6fbb4f2-93a3-4f95-a4a9-f5160632195b.png?x-oss-process=image%2Fformat%2Cwebp)

最后证明确实校验的是这个（我去看了源码），不过不是试出来的，因为我在其他地方有了进展。

3 峰回路转的命令执行
===========

3.1 发现黑马程序员
-----------

俗话说得好，当你在一个房间内发现一只蟑螂，那么房间里实际上会有甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱甴曱。。。。。。  
当我在一个网站内发现多个漏洞并且发现程序员疑似脑袋不好（一种直觉，你就想想他会怎么写）的时候，那么我就会怀疑这个网站上还会有更多大漏洞。  
所以我开始从头到尾再测了一遍接口，没想到发现了个大家伙。  
还记得这个包吗？注册用的：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712454585674-c310e1a4-2552-486f-aa6b-49db28747f21.png?x-oss-process=image%2Fformat%2Cwebp)

action，长得有点像thinkphp（很多别的框架里也有，但总的来说基本是一种调用方法），放在往常我是不会仔细测的，但通过之前的测试我知道这是诡计多端的程序员自己实现的一个玩意。所以我直接一改：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712454866653-7a1405cf-6747-4229-8a81-af1862841c53.png?x-oss-process=image%2Fformat%2Cwebp)

妈呀，看到了这辈子很少看到的东西，属实吓了我一跳。这大哥黑马程序员出厂的吧，这都敢写？  
为了确信我看到的不是假的，phpinfo一下：

![image.png](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712455020646-e5d3fdd5-7985-4d13-96c6-36cbc05014fc.png?x-oss-process=image%2Fformat%2Cwebp)

这下瞬间感觉shell了，神清气爽啊^ ^。

3.2 斗折蛇行，呼叫好丽友
--------------

据我推测，这个action对应的代码应该是这么写的：

> eval($\_POST\['action'\]+"()");  
> 所以我一开始认为，只能执行无参函数（要满足后面的括号）。

先用一些显示环境的无参函数：

get\_included\_files：

![微信图片_20240514140520.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-5038741a0be294d14e547f0492b05c7bedbc76cd.png)

get\_defined\_functions：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712455627409-27e64cc3-1aa8-4836-8a70-129648887e82.png)

但是往后，我就不知道咋写了，毕竟你要在没有参数的情况下造成命令执行？于是我又问朋友：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712455702332-a74b1f5e-8e97-467c-99c1-d441f3d9c7c6.png)

在跟朋友掰扯半天这是不是真的能执行命令之后，朋友使用var\_dump告诉我是能执行带参函数的（也是我蠢，最基本的执行顺序都忘了，思路太窄）。

用var\_dump继续尝试执行，发现存在一些过滤，'"\\/+-\*,都不行，最致命的是空格也不行。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712456104244-9d6fb0fd-15e1-47be-ba23-db8d8fffa27a.png)

这导致了，就算执行到shell，也不能执行带有空格的命令。现在就陷入了一个僵局。为了绕过空格去问了另一个朋友，他让我按照CTF空格绕过做，也就是用下面几个字符代替：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712456455700-32bdf77b-935a-4aa2-a9b0-67a310a550e8.png)

前面三个直接被过滤了，最后的%09没有被过滤，但是执行不了。后面发现%2509被拦截，也就是说%实际上也被拦了。

这下又进入死路，离shell这么近，超不甘心- -。

但怎么说在外靠朋友呢，这个时候朋友跟我说他找到shell的方式了：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712457310124-54dc9c23-58c0-4cdd-b533-7db77a5b31f9.png)

怎么个事呢？要回到我之前使用的探测环境函数get\_defined\_functions：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1712122438889-c33e17cb-5c3c-46b2-8f7f-a00a91b5090a.png)

直接用base64编码命令，成功执行：

![微信图片_20240514140755.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-8708e3db92e8a53748c832943282d04132299b0d.png)