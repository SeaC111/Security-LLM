0x01 厂商描述
=========

用友NC6是用友NC产品的全新系列，是面向集团企业的世界级高端管理软件。市场占有率已经达到亚太第一

0x02 漏洞概述
=========

该漏洞是由于用友NC对外开放了BeanShell接口，任何人都可以在任意环境下未授权访问该接口，攻击者通过构造恶意的数据执行任意代码即可获取服务器高权限

**漏洞特点：** 该漏洞利用难度较低，可造成的危害面较大

**可能造成如下安全问题：**  
服务器被接管，可能导致蠕虫病毒、勒索病毒、挖矿病毒的短时间爆发  
核心敏感数据泄露，造成严重的信息安全泄露事件  
造成主网页被恶意篡改，例如：跳转博彩页面、暗链、涉及其他内容危害的问题

0x03 影响版本
=========

用友NC6.5版本  
严重程度：高  
用友NC 资产分布情况：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4cb375f6954fc61f7ee856ac76846710d2852a13.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4cb375f6954fc61f7ee856ac76846710d2852a13.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e308fcbc13eb0b9042a71254b3ea66c6758c9672.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e308fcbc13eb0b9042a71254b3ea66c6758c9672.png)

0x04 漏洞复现
=========

访问http://example.com:7000 然后 URL拼接  
` /servlet/~ic/bsh.servlet.BshServlet `  
得到如图：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-56c892e531b35b6bff6fce1391d0d3f038001f54.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-56c892e531b35b6bff6fce1391d0d3f038001f54.png)  
我们可以发现这里似乎有执行代码的接口，我们输入Payload 如：exec("whoami");可以看到命令执行成功回显，并返回相关信息

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c5d3e754a08f1476f35c2e2406467726c0b5a0cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c5d3e754a08f1476f35c2e2406467726c0b5a0cc.png)

0x05 补丁修复
=========

由于该漏洞的出现是因第三方jar包的漏洞导致，用友NC官方已发布相关的安全补丁，使用该产品的用户需要及时安装该漏洞补丁包

补丁地址：

```php
http://umc.yonyou.com/ump/querypatchdetailedmng?PK=18981c7af483007db179a236016f594d37c01f22aa5f5d19
```

参考链接：

```php
https://www.cnvd.org.cn/webinfo/show/6491
```