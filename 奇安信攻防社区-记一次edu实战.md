0x00 前言
-------

最近刚好不是很忙，想着挖点洞练练手，像我这种菜鸡肯定是挖不到企业或者专属SRC，只能转向教育SRC，找点软柿子捏

0x01 寻找目标
---------

没啥好说的，直接上google语法，我比较喜欢玩逻辑漏洞，所以直接google语法：  
`site:example.com 忘记密码|注册|找回密码.....`  
通常这种地方比较容易出洞，经过一翻查找，物色到了某大学的一个毕业论文管理系统如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ae8939badf30d58fdb31cba37993e476352cece1.png)  
各位师傅看到这种站，肯定是想到google收集该学校的学生学号或者sfz等信息来爆破，但是该站点有验证码防护，所以这里先从验证码入手。

0x02 验证码可复用
-----------

验证码绕过方法最常用的手段无非下面几种：  
1、验证码可重复利用  
2、验证码置空绕过  
3、使用万能验证码，比如：0000,6666  
3、删除验证码字段绕过

先正确填入验证码，将包发送到bp的重发器模块，点击发送之后显示登录信息错误  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-5679d901f99c6687d033b8b266af96172296e2b9.png)  
不修改验证码，修改用户名为admi，再次点击发送之后只显示登录信息错误，未提示验证码错误，表示验证码可复用  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ff50d2b70e6c8e1b595bef8b32fc33240148ecd7.png)  
一个验证码可绕过到手，但是呢，应用也针对可能存在爆破的行为做了防护，一个账号只能爆破5次，超过将会被锁定15分钟，所以爆破这条路基本上是死了。

0x03 任意用户密码重置
-------------

接下来我们把目光转向忘记密码处  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9e7fdc23605c125fbbf5d93bb032e4fc01a06313.png)  
根据图示，先不用急着测试，我们简单分析一下整个密码修改的流程，很明显分为三步：  
1、确认账号：（需要输入登录账号、联系电话和验证码），这一步的目的应该是要确认该账号与你输入的联系电话是否一致。  
2、安全认证：通过预留的手机号码或者邮箱地址发送验证码并校验。  
3、重置密码：成功重置新密码

所以这里要想成功拿到任意用户密码重置，第一步和第二步必须同时存在漏洞才可以

一般这种学校应用的登录账号都是学号，怎么获取某个学校的学号，还是google语法（可自行百度一下），找了一堆先尝试一下，填入一个存在的学号，手机号先填自己的，由于没有找到对应的手机号（太菜了）  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-5c1ed673abb6214f4d0e506e047c0693c079d3a4.png)

果然提示了不匹配，如果学号和手机号都是错误的则提示下面  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-f2cc593b1ed4ca905111e4988e5e0bcce01803c7.png)

这里的验证码和前台登录的验证码校验方式一样，也是可绕过，所以我想着跑一下burp，爆破一下用户名，想收割一个用户名枚举的洞，结果一看数据包，好家伙，发现登录账号字段及联系电话字段均做了加密，假装前端F12打个断点调试了一下，无果，果断放弃。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-a3a6f56bfe815e79fb13b3419ceb5a8731b6c7ae.png)  
没办法，尝试修改返回的参数值无果，然后尝试直接将Phone参数和值删掉看看

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-9ed6071fcf44b0b582833c7bc72dfeb82a385851.png)  
发包，你猜怎么着，真成功绕过了第一步，好轻松  
到了这里我第一个想法是直接爆破验证码，直接burp开搞（怎么全是一个长度返回包），很明显不是4位的验证码，6位就算了，只有一分钟的爆破时间，基本上不太可能

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-87885b07c82d0c110a85dfcfeeb4856739260e78.png)

瞄了一眼获取验证码的数据包，咦这里怎么也有Phone值，这不就是第一步的手机号码加密值吗，直接替换成我的岂不是美滋滋，但是我们要先获取自己手机号的加密值再替换，那不简单，返回第一步，输入自己的手机号，将加密结果copy下来直接替换  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-ea8b88c8a2cea0ade5cf3df73cc8d6703bb8b957.png)

叮咚，这不有了吗  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-e8c9c465ef8be2ef52541194f8ffe5fbc1a59127.png)  
成功来到第三步，重置用户密码，好家伙密码居然还有复杂度和长度的要求，要是直接爆破不得怀疑人生。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-c8bd3a3659bac3019dc79b2ce5a2f2479bc38db0.png)  
修改之后直接登录试一下，欧克了。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2023/02/attach-d05492560f11fb3165c955f715f5cf02120146e3.png)

以上漏洞均已报告给相应学校且已修复

0x04 修复建议
---------

1、验证码缺陷：建议网站严格管控验证码的有效时间和有效次数，不管验证码是不是输入正确，都应该及时销毁验证码，防止二次使用  
2、任意用户密码重置：建议网站每一个步骤都要对前一个步骤进行验证，最后提交新密码时应对当前用户名或 ID、手机号、短信验证码进行二次匹配验证，防止跳过某一步骤