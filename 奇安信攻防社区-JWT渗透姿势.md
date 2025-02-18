0X01 什么是jwt？
------------

> JWT 全称 JSON Web Token，是一种标准化格式，用于在系统之间发送加密签名的 JSON 数据。
> 
> 原始的 Token 只是一个 uuid，没有任何意义。

JWT的结构由三部分组成，分别是Header、Payload和Signature，下面是每一部分的详细介绍和示例：

### Header 部分

在 JWT 中 Header 部分存储的是 Token 类型和加密算法，通常使用JSON对象表示并使用Base64编码，其中包含两个字段：alg和typ

- alg(algorithm)：指定了使用的加密算法，常见的有HMAC、RSA和ECDSA等算法
- typ(type)：指定了JWT的类型，通常为JWT

下面是一个示例Header：

```json
{
  "alg": "HS256", 
  "typ": "JWT"
}
```

### Payload 部分

Payload包含了JWT的主要信息，通常使用JSON对象表示并使用Base64编码，Payload中包含三个类型的字段：注册声明、公共声明和私有声明

- 公共声明：是自定义的字段，用于传递非敏感信息，例如:用户ID、角色等
- 私有声明：是自定义的字段，用于传递敏感信息，例如密码、信用卡号等
- 注册声明：预定义的标准字段，包含了一些JWT的元数据信息，例如:发行者、过期时间等

下面是一个示例Payload：

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

其中sub表示主题，name表示名称，iat表示JWT的签发时间

### Signature 部分

Signature是使用指定算法对Header和Payload进行签名生成的，用于验证JWT的完整性和真实性

- Signature的生成方式通常是将Header和Payload连接起来然后使用指定算法对其进行签名，最终将签名结果与Header和Payload一起组成JWT
- Signature的生成和验证需要使用相同的密钥

下面是一个示例Signature

```php
HMACSHA256(base64UrlEncode(header) + "." +base64UrlEncode(payload),secret)
```

其中HMACSHA256是使用HMAC SHA256算法进行签名，header和payload是经过Base64编码的Header和Payload，secret是用于签名和验证的密钥，最终将Header、Payload和Signature连接起来用句点(.)分隔就形成了一个完整的JWT

### 完整的JWT

第一部分是Header，第二部分是Payload，第三部分是Signature，它们之间由三个 `.` 分隔，注意JWT 中的每一部分都是经过Base64编码的，但并不是加密的，因此JWT中的信息是可以被解密的

下面是一个示例JWT

```php
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

0X02 解密平台
---------

下面是一个JWT在线构造和解构的平台：

<https://jwt.io/>

![image-20231222210239843](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-87de2a74fa167e99251e4ed3900e6b9d65ea66f0.png)

0X03 工作原理
---------

JWT的工作流程如下：

- 用户在客户端登录并将登录信息发送给服务器
- 服务器使用私钥对用户信息进行加密生成JWT并将其发送给客户端
- 客户端将JWT存储在本地，每次向服务器发送请求时携带JWT进行认证
- 服务器使用公钥对JWT进行解密和验证，根据JWT中的信息进行身份验证和授权
- 服务器处理请求并返回响应，客户端根据响应进行相应的操作

0X04 jWT名词
----------

1. JWS（Signed JWT）：JWS是指已签名的JWT。它由JWT的Header、Payload和Signature组成，其中Signature是使用密钥对Header和Payload进行数字签名得到的。通过验证签名，可以确保JWT的完整性和真实性。
2. JWK（JSON Web Key）：JWK是指用于JWT的密钥。它可以是对称加密密钥（例如密码），也可以是非对称加密密钥（例如公钥/私钥对）。JWK用于生成和验证JWT的签名，确保只有拥有正确密钥的一方能够对JWT进行操作。
3. JWE（Encrypted JWT）：JWE是指经过加密的JWT。它是在JWS基础上进行了进一步的加密，将JWT的Payload部分加密后得到的结果。JWE可用于保护敏感信息，确保只有授权的接收方能够解密和读取JWT的内容。
4. JKU（JSON Web Key Set URL）：JKU是JWT Header中的一个字段，该字段包含一个URI，用于指定用于验证令牌密钥的服务器。当需要获取公钥或密钥集合时，可以使用JKU字段指定的URI来获取相关的JWK信息。
5. X5U：X5U是JWT Header中的一个字段，它是一个URL，指向一组X.509公钥证书。类似于JKU，X5U字段用于指定可用于验证JWT的公钥证书的位置。
6. X.509标准：X.509是一种密码学标准，定义了公共密钥基础设施（PKI）中的数字证书格式。这些证书包含有关实体（例如个人、组织或设备）的信息，以及相关的公钥和数字签名。X.509证书在许多互联网协议中广泛使用，如TLS/SSL等。

0x05 JWT 基础安全问题
---------------

### 1、未对签名进行验证

JWT库会通常提供一种验证令牌的方法和一种解码令牌的方法，比如:Node.js库jsonwebtoken有verify()和decode()，有时开发人员会混淆这两种方法，只将传入的令牌传递给decode()方法，这意味着应用程序根本不验证签名

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature>

![image-20231222221236099](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-ca7705ffa3292a4fbb01a3481ff28c3ef406e39c.png)

（1）首先看看通关要求：修改您的会话令牌以访问管理面板`/admin`，然后删除用户`carlos`

（2）前文我们说到，JWT 需要开发者提供一个 Signature（签名），如果我们不对签名进行验证，极有可能产生如下的越权情况。

（3）打开靶场，登录，访问`/admin`

![image-20231222221534305](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-4b6a60f8474fa76bae62ae4f36bc430fcf208440.png)

（4）因为我们使用的jwt，所以权限相关的设置肯定在jwt中。我们抓个包拿到jwt解密看看

![image-20231222221823154](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-514876e12025381d5799788361e0d989c7ac5113.png)

![image-20231222221925066](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-369cc335d08225fa0221b853f1e6cd83bd4ac948.png)

（5）把`wiener`修改成`administrator`

把第二部分payload拿出来base64解密，然后修改，修改万再拼接会jwt中

![image-20231222222217488](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-58bd525d2995c3acdeabca4a6344f6b08a90a497.png)

![image-20231222222319473](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-92eb0a698a6c2bf7c2537d688f1115fbbe78a9e6.png)

![image-20231222222404181](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-3e2fa2caeaea5a5fa6f95c7f58c4f484293c5b48.png)

（6）把修改后的jwt替换原本的jwt

![image-20231222222504138](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-d3ef02f32129a1a965ac3cd348689c9741219158.png)

（7）访问`/admin`，删除`carlos`用户即可通关

![image-20231222222553594](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-d407635e1c8e86a332b0b15b47a1e72227eb8fe7.png)

![image-20231222222634903](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-054474216e6bf1b634aeea1f31f6611de7b4bf7a.png)

### 2、未对加密算法进行强验证

在JWT的Header中alg的值用于告诉服务器使用哪种算法对令牌进行签名，从而告诉服务器在验证签名时需要使用哪种算法，目前可以选择HS256，即HMAC和SHA256，JWT同时也支持将算法设定为"None"，如果"alg"字段设为"None"，则标识不签名，这样一来任何token都是有效的，设定该功能的最初目的是为了方便调试，但是若不在生产环境中关闭该功能，攻击者可以通过将alg字段设置为"None"来伪造他们想要的任何token，接着便可以使用伪造的token冒充任意用户登陆网站

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification>

![image-20231222223126751](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-dad62dd7814f45a13840435458d9970cb5e83961.png)

这关与上边的漏洞原理不同，但最终的效果都是可以`伪造token`，攻击手法与上一关卡相同，唯一不同的是这次是需要`把header中的alg参数的值改为none`即可！

不在演示！

### 3、 弱密钥

在实现JWT应用程序时，开发人员有时会犯一些错误，比如：忘记更改默认密码或占位符密码，他们甚至可能复制并粘贴他们在网上找到的代码片段然后忘记更改作为示例提供的硬编码秘密，在这种情况下攻击者使用众所周知的秘钥来暴力破解服务器的秘钥是很容易的

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key>

![image-20231222224611748](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-59f4c9ac0e06300046dfb445a71e4927323a71e9.png)

（1）打开靶场 --&gt; 登录 --&gt; 抓包 --&gt; 拿到JWT

![image-20231222225235639](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-fb4b3a855b4c0cfe1f583f9d4a7104be155e0703.png)

```js
eyJraWQiOiIwZWMxNmY3ZS0yOGU0LTQxMjUtYjUxMS0yZDc1ZmRjZjRiM2QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTcwMzI2MDMwOH0.t5QY8-kd-bzIqp0PyXg2EUUxg1jPl6-NYKBI4BTw8P0
```

（2）JWT字典：<https://github.com/wallarm/jwt-secrets>

（3）我们使用`jwt_tool`来爆破JWT：[https://github.com/ticarpi/jwt\_tool](https://github.com/ticarpi/jwt_tool)

使用教程：<https://www.cnblogs.com/xiaozi/p/12005929.html>

![image-20231222225046915](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-109d5ee51bb9073b9711bd634cf550508fe4af16.png)

![image-20231222225746340](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-a494896184581b90bae3bacf2a4e5f5462810a59.png)

（4）拿到爆破出来的秘钥`secret1`，我们篡改jwt

![image-20231222230033259](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-c244470820f83392f7ffc09dae811e9e1dff7f1e.png)

（5）修改本地或者抓包修改jwt都可以，然后访问/admin，删除`carlos`用户

![image-20231222230440373](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-a259bbce2db28d21413392bd03b58b9523262073.png)

0X06 JWT 标头注入
-------------

### 1、通过jwk参数注入自签名的JWT

（1）再来回顾一下jwk是什么吧！

JWK（JSON Web Key）：JWK是指用于JWT的密钥。它可以是对称加密密钥（例如密码），也可以是非对称加密密钥（例如公钥/私钥对）

（2）漏洞原理

在理想情况下，服务器应该是只使用公钥白名单来验证JWT签名的，但对于一些相关配置错误的服务器会用JWK参数中嵌入的任何密钥进行验证，攻击者就可以利用这一行为，用自己的RSA私钥对修改过的JWT进行签名，然后在JWK头部中嵌入对应的公钥进行越权操作

（3） RSA加密算法

<https://www.cnblogs.com/pcheng/p/9629621.html>

这位师傅的文章总结的非常好，**公钥加密、私钥解密、私钥签名、公钥验签。**

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection>

![image-20231223025921262](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-ccd88458698428bc78c07d337017665c6b98e836.png)

（1）这个案例我们使用`burpsuite`，首先先去安装一个插件`jwt enditor`

![image-20231223030051079](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-5e930114c1e3e3ffb08192c7f3a946922088df7c.png)

（2）安装好了后我们使用它生成一个新的RSA密钥

![image-20231223030327718](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-d7ce3815d8c37e6768c5128a22527b152ecd8a85.png)

（3）打开靶场 --&gt; 登录 --&gt; bp抓包 --&gt; 发送到`Repeat`模块

![image-20231223030946972](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-be06ae25a6f661efbd9dd397ffa0a0ffa949af1b.png)

（4）将sub内容修改为administrator

![image-20231223031024846](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-1e40d298d98ccb08d0ebc8688b79dc4d0559b067.png)

（5）点击"Attack"，然后选择"Embedded JWK"，

![image-20231223031129929](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-0901155ea34e5bef61a9926aa839711e79ea4f38.png)

（6）出现提示时选择您新生成的RSA密钥

![image-20231223031203432](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-ded5d98df6af9d8f3bf4249e3276adc062072065.png)

（7）复制新生成的jwt

![image-20231223031245153](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-01f22dbe3e9f69933ed94a613100a6b29764afc2.png)

（8）替换本地的jwt

![image-20231223031352592](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-3d0344c8064310afdc3a96b6e1cf6347b6106919.png)

（9）然后访问/admin，删除`carlos`用户

![image-20231223031452606](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-cd2648276a46a352174b552aa3a480f3c92a5781.png)

### 2、通过jku参数注入自签名的JWT

（1）先回顾什么是jku？

JKU（JSON Web Key Set URL）：JKU是JWT Header中的一个字段，该字段包含一个URI，用于指定用于验证令牌密钥的服务器。当需要获取公钥或密钥集合时，可以使用JKU字段指定的URI来获取相关的JWK信息。

（2）看看他长什么样？

![image-20231223034620634](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-cde495761d041254562b07d4d7bc6a41d57e98cb.png)

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection>

（1）分析一下

漏电点都是仅通过公钥判断数据是否被篡改，但公钥在header头中，用户可控！

唯一的区别就是这关中的公钥使用服务器获取的。

（2）那还是之前的流程

- `jwt enditor`生成一个新的RSA密钥，使用之前的也可以
- 打开靶场 --&gt; 登录 --&gt; bp抓包 --&gt; 发送到`Repeat`模块

（3）复制公钥，拿到漏洞利用服务器（在题目中选择"Go eo exploit server"，然后加上key头并保存到exploit的body中）

![image-20231223033528304](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-b8e69cfbc3b6d0286b4c3509fb12eb5f4df1b86b.png)

切记加`key`头

```php
{
    "keys": [

    ]
}
```

![image-20231223041017444](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-3b5a3c7871dd8d33b85c56fa2ff63ad0c778b60b.png)

（4）在bp中需要改动三处

![image-20231223041438999](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-4039610c82aa783435eb4610a046c1307947bc23.png)

- kid：改成我们插件生成的公钥中的kid
- jku：添加jdu字段（漏洞利用服务器地址）![image-20231223034301655](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-45591df776078c96b1572fae5303ea4c280ff1d9.png)
- sub：讲wiener改为administrator

（5）点击下面的sign，选择Don’t modify header模式

![image-20231223034459509](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f1eaaf0cdd74c6219aaa6e25f832fe36ac75659c.png)

（6）之后的流程

替换本地jwt --&gt; 删除`carlos`用户

![image-20231223041239306](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-cf9391c9128751c5d1df72209cac1d6783bbdf82.png)

### 3、通过 kid 注入 JWT，与目录遍历攻击相结合

JWS 规范没有针对 kid 进行严格设置，比如必须是 uuid 的格式或者是其他的，它只是开发人员选择的任意字符串。

那么我们可以通过将 kid 指向数据库中的特定条目，或者是指向文件名，作为验证密钥。

例如：

```json
{
    "kid": "../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

当 JWT 使用的是对称加密算法的时候，极有可能存在目录遍历的漏洞，我们能够强制服务器使用其文件系统中的任意文件作为验证密钥。

我们可以先尝试读取`dev/null`这一文件，`dev/null`这一文件默认为空文件，返回为 null，我们可以在 Symmetric Key 中，将 k 值修改为`AA==`也就是 null，进行攻击。

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal>

![image-20231223163130615](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-788d897f740206b1b7bfe734e430fd294ab0a6e8.png)

（1）使用bp插件`jwt enditor`生成一个 **Symmetric Key**，也就是对称密钥，并将 k 的值修改为`AA==`

![image-20231223162359656](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-0def63c0b39b5c3c872a56b5b0c83480340fb2ed.png)

（2）打开靶场 --&gt; 登录 --&gt; bp抓包 --&gt; 发送到`Repeat`模块

（3）接着，我们在抓到的包中修改 kid 值，尝试用目录遍历读取`dev/null`此文件。并将 sub 修改为 administrator

![image-20231223162825481](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-1edbf54d62fdbdbd3d76ee8112fbe49ff6c0b6b3.png)

（4）点击下面的 Sign，使用 OCT8 的密钥攻击。

![image-20231223162857397](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-abe4a30bd2a219d817d82fe07499f84868843d3f.png)

（5）接着就是：替换本地jwt --&gt; 删除`carlos`用户

因为是目录遍历，所以多尝试。

![image-20231223162953206](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-5c8b06f3f9652922585d2303a9b38fe1cd8d83b2.png)

0X07 JWT算法混淆
------------

### 1、对称加密与非对称加密。

可以使用一系列不同的算法对 JWT 进行签名。其中一些，如HS256（HMAC + SHA-256）使用“对称”密钥。这意味着服务器使用单个密钥对 Token 进行签名和验证。显然，这需要保密，就像密码一样。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-a94491d95a00bf43ba6ca57fe7270f9c6271a5b1.jpeg)

其他算法，例如 RS256 (RSA + SHA-256) 使用“非对称”密钥对。它由服务器用来签署令牌的私钥和可用于验证签名的数学相关的公钥组成。

![](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-be23da66bbcd954fb0b958694bd8b56ed37dfd3f.jpeg)

顾名思义，私钥必须保密，但公钥通常是共享的，以便任何人都可以验证服务器颁发的令牌的签名。

### 2、算法混淆漏洞产生的原因？

算法混乱漏洞通常是由于 `JWT 库的实现有缺陷而引起`的。尽管实际的验证过程因所使用的算法而异，但许多库提供了一种与算法无关的单一方法来验证签名。这些方法依赖于`alg`令牌标头中的参数来确定它们应执行的验证类型。

以下伪代码显示了此泛型`verify()`方法的声明在 JWT 库中的简化示例：

```java
function verify(token, secretOrPublicKey){ 
    algorithm = token.getAlgHeader(); 
    if(algorithm == "RS256")
    { 
        // Use the provided key as an RSA public key 
    }else if (algorithm == "HS256")
    { 
        // Use the provided key as an HMAC secret key 
        } 
}
```

当随后使用此方法的网站开发人员假设它将专门处理使用 RS256 等非对称算法签名的 JWT 时，就会出现问题。由于这个有缺陷的假设，他们可能总是将固定的公钥传递给该方法，如下所示：

```java
publicKey = <public-key-of-server>; 
token = request.getCookie("session"); 
verify(token, publicKey);
```

在这种情况下，如果服务器收到使用 HS256 等对称算法签名的令牌，则库的通用`verify()`方法会将公钥视为 HMAC 密钥。这意味着攻击者可以使用 HS256 和公钥对令牌进行签名，并且服务器将使用相同的公钥来验证签名。

上边是抄官方的话，下边我们用大白话来解释一下：

- 假设开发使用的是`RS256`这非对称加密算法生成的jwt。
- 由于信息泄露等原因攻击者可以拿到这个`公钥`，因为上边说过公钥通常是共享的
- 攻击者使用`HS256`算法伪造一个jwt，用这个`公钥`作为签名的密钥。

程序会使用`verify()`这个方法来验证jwt有没有被篡改。但是这个库设计的有问题（问题：他是通过你jwt头中`alg`来判断是使用那种算法来进行签名的。所以我们可以篡改他的算法），这块就会使用`RS256`生成的公钥作为`HS256`的秘钥来验证攻击者伪造的jwt。这个公钥攻击者可控，所以伪造的jwt就会通过验证。

### 3、执行算法混淆攻击的步骤

算法混淆攻击通常涉及以下高级步骤：

- [获取服务器的公钥](https://portswigger.net/web-security/jwt/algorithm-confusion#step-1-obtain-the-server-s-public-key)
- [将公钥转换为合适的格式](https://portswigger.net/web-security/jwt/algorithm-confusion#step-2-convert-the-public-key-to-a-suitable-format)
- [创建一个恶意 JWT，](https://portswigger.net/web-security/jwt/algorithm-confusion#step-3-modify-your-jwt)其负载经过修改，`alg`标头设置为`HS256`.
- 使用公钥作为秘密，使用 [HS256 对令牌进行签名。](https://portswigger.net/web-security/jwt/algorithm-confusion#step-4-sign-the-jwt-using-the-public-key)

### 4、通过算法混淆绕过 JWT 身份验证

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion>

![image-20231223172704453](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-b1e25cffca92e79dc360c0ab2007f3e81541f52d.png)

（1）获取服务器的公钥

服务器有时通过映射到/jwks.json或/.well-known/jwks.json的端点将它们的公钥公开为JSON Web Key(JWK)对象，比如大家熟知的/jwks.json，这些可能被存储在一个称为密钥的jwk数组中，这就是众所周知的JWK集合

![image-20231223171250162](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-937a1e9baa1fc226811e52da333f9941dfa422dd.png)

（2）将公钥转换为合适的格式

在Burpsuite的`JWT Editor` 中点击"New RSA Key"，用上边获取到泄露的JWK而生成一个新的RSA Key

![image-20231223171605944](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-47dc0f4b3c3e71905da7105852ec741ed5a5f93e.png)

选中"Copy Public Key as PEM"，同时将其进行base64编码操作，保存一下得到的字符串(备注:上下的一串-----END PUBLIC KEY-----不要删掉)

```php
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj+eOXtjDkD6BYr0ftlLo
rnU+xsXB2btxi4REHYghwP4YCiZjX7UsPvEYRWyt8FJzyQap+zUoueiFTWBt/Ngt
qOCQWPUDMv9BQ3Kjpos6yC/PM8TEmJLsg0F2b1OcIoDuPgo9v0JWmSmpS+THqUwH
xgizbwFBbZxS+aGPV9vv0KyULDV2CLjWjbyYh+2sJZFW7DFq1EHWedtqmTcY3/Gt
Sv3CBNdv9Hn/J5d5P9gorrbuKrPnc2qD967poetwrmI/9TxQdCVSEjqLdBqEIzBg
IbLRST2J0DNHX54ESyjcutmfRG833wEm1c8S98bhG3eGx+HpqX5/hkPPlwdZTPTy
9QIDAQAB
-----END PUBLIC KEY-----
```

```php
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFqK2VPWHRqRGtENkJZcjBmdGxMbwpyblUreHNYQjJidHhpNFJFSFlnaHdQNFlDaVpqWDdVc1B2RVlSV3l0OEZKenlRYXArelVvdWVpRlRXQnQvTmd0CnFPQ1FXUFVETXY5QlEzS2pwb3M2eUMvUE04VEVtSkxzZzBGMmIxT2NJb0R1UGdvOXYwSldtU21wUytUSHFVd0gKeGdpemJ3RkJiWnhTK2FHUFY5dnYwS3lVTERWMkNMaldqYnlZaCsyc0paRlc3REZxMUVIV2VkdHFtVGNZMy9HdApTdjNDQk5kdjlIbi9KNWQ1UDlnb3JyYnVLclBuYzJxRDk2N3BvZXR3cm1JLzlUeFFkQ1ZTRWpxTGRCcUVJekJnCkliTFJTVDJKMEROSFg1NEVTeWpjdXRtZlJHODMzd0VtMWM4Uzk4YmhHM2VHeCtIcHFYNS9oa1BQbHdkWlRQVHkKOVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
```

（3）生成一个对称加密的key，把k替换成我们刚修改完格式的公钥

![image-20231223172157829](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-ded1346de1c680585d420ca4f01dbad43e632024.png)

（4）篡改jwt。

![image-20231223172427569](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-afe9b647c9d063b539057dd5b0ed041b970165cd.png)

（5）使用这个公钥签名

![image-20231223172523042](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-31874af231d266601b0b198e01c3b4e7eb4c120f.png)

（6）替换本地jwt --&gt; 删除`carlos`用户

![image-20231223172605282](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-44784c2242650ce02604611aab84c6d0161bc36f.png)

### 5、通过算法混淆（不暴露密钥）绕过 JWT 身份验证

在公钥不可用的情况下您仍然可以通过使用jwt \_ forgery.py之类的工具从一对现有的JWT中获取密钥来测试算法混淆，您可以在rsa\_sign2n GitHub存储库中找到几个有用的脚本

[https://github.com/silentsignal/rsa\_sign2n](https://github.com/silentsignal/rsa_sign2n)

下边我们通过portswigger靶场来演示一下这个漏洞案例：

靶场地址：<https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key>

![image-20231223182733413](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-b8608aa9f55855fa65e3146d4a0a380b89db73ab.png)

（1）打开靶场，首先我们先正常登录、退出，拿到两个jwt

```php
eyJraWQiOiI2YTFkYjRlYS1hNGJmLTQ0NzQtYjQxMC0zYzk5NTc3YzJhMWMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTcwMzMyOTc4OX0.BCzT_VhEaeqfxPoRBYwduIju0AXpmPqJ8HzM-7iqYquyNx2NgPRiJNVvYemspXIPQ8_-sGr67Qn6lVSHgj51xoNd_jTJfYO8AlQWF4oAiz2Hfjfng6DN7VoiuJ7vQCMh9VSWnzLzG30leaEzyRjzHGnbFE9EUZ5Hbu7tXOFJU5IwHE35TuU5Xcnv2DXpRDxTsJpHvk5gKQWPx4XLNOY--8LJncBRUoDXD7jXCW0hdY19DPkIDI_xNKYi27sGkShv8_zf3G5oSVdChCVgSfdGyCivTtuQ3pAeTl1AwmJll9wy7v4MunWSMgXD_-SyiCakBNgPaMm_gWfTlATrrPPT_g
```

```php
eyJraWQiOiI2YTFkYjRlYS1hNGJmLTQ0NzQtYjQxMC0zYzk5NTc3YzJhMWMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTcwMzMyOTgxM30.IeXISe59u7Ju0k-NU2RUXORZlY4uKOOpDQC01TSVq35asYsRSUnh7yKS4bwooI6L5wSiZduaYbFNQeg2Na0RDvJx6-wIYR8LlEVQ9U2n7_8Z7pPkF9QVQDJGF6mUhQAEOS35gBFUOwvYsR2WaayKaOH_nSOJbFiQjOzF8EykR0LEz5vk2NhMYYMDbbO1LGJ5i2QBtIB5SfTwlZPiy7lK9d_Une2a0FwmeaoNA_4dIsiVo4hD3Av-DT_voCN9pSN-AuoofKqJYwolxHatfUGP4ONuVRwcVScJmvaH2UAh4YI1deRCk62nChBhmBt6TTclGn9xzJX7TeGfqsn6wmWQhA
```

（2）随后将其放到靶场提供的docker工具里面运行，运行的命令如下：

```php
docker run --rm -it portswigger/sig2n <token1> <token2>
```

![image-20231223181749611](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-34237b478588b5ee33d7a4ad52faadebcf1eea68.png)

jwt \_ forgery.py脚本会输出一系列token的存在情况值

![image-20231223181803810](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-147b5d1b7c18d30a2b1c5a2f9215ee4c0e2d2463.png)

这里我们尝试每一个Tempered JWT，不过靶场这里给了提示说是X.509 形式的，所以我们只需要将X.509形式的JWT进行验证即可

（3）剩下的步骤结合上一关的一样了，创建恶意的jwt --&gt; 签名 --&gt; 替换本地jwt --&gt; 删除`carlos`用户

![image-20231223182245303](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-d56827420cbfe2c905a7da39785d0e5a6001b338.png)

0X08 一些其他的jwt安全问题
-----------------

就拿我之前碰到过的两个漏洞来说明！严格意义上不能说是jwt的问题，应该是程序设计的问题，但是跟jwt沾了一点边！

### 1、未授权

访问管理后台，/adplanet/PlanetUser页面下有用户管理功能！

![image-20231223183847582](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-cb21e3311a76c21359f9288c5aeae7754505a311.png)

我们访问该页面并抓包，发现api:/square/GetAllSquareUser，用于获取用户信息，包括用户名、密码、邮箱地址等敏感信息！

![img](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-75f52eb43994dceb8bd83e9ef945b74568da5ecd.png)

我们把这个数据包放入webfuzz模块中，删除他的JWT token，然后发送数据包，我们可以发现我们仍然可以获取到用户信息！

![img](https://shs3.b.qianxin.com/attack_forum/2024/02/attach-f6c7609728a8bf5be231e81e66260cc2cd354664.png)

### 2、垂直越权

和上边类似，只是另一个不同的功能带点。

还是抓包后删jwt，但是发现返回401

![image-20231223184051843](https://shs3.b.qianxin.com/attack_forum/2024/01/attach-2599500b413225291678a8c860dc9afa96826d91.png)

此时，我们去前台注册一个普通用户获取他的jwt。携带这个jwt发包！

成功垂直越权！

0X09 JWT漏洞的防护
-------------

- 使用最新的 JWT 库，虽然最新版本的稳定性有待商榷，但是安全性都是较高的。
- 对 jku 标头进行严格的白名单设置。
- 确保 kid 标头不容易受到通过 header 参数进行目录遍历或 SQL 注入的攻击。

0X0A 参考文章
---------

[https://paper.seebug.org/3057/#\_1](https://paper.seebug.org/3057/#_1)

<https://www.freebuf.com/articles/web/337347.html>

<https://www.cnblogs.com/pcheng/p/9629621.html>

<https://www.cnblogs.com/xiaozi/p/12005929.html>

<https://portswigger.net/web-security/jwt/algorithm-confusion>

0X0B 原文地址
---------

转载自公众号：安服仔Yu9  
原文地址：<https://mp.weixin.qq.com/s/3rraOTO3Z-n9GzxFco5FOA>