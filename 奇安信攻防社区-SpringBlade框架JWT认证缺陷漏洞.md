1.前言
====

在某次代码审计项目中，发现项目代码是基于SpringBlade框架实现的，于是在审计的过程中，顺带着挖到了SpringBlade框架的一个0day漏洞。CVE编号：CVE-2021-44910

2.漏洞分析
======

SpringBlade前端通过webpack打包发布的，可以从其中找到app.js获取大量接口：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a6fec4d8176fdaceb9d0209cdab185dd4a6c00bb.jpg)  
然后直接访问接口：api/blade-log/api/list  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-265d7135802908293b5112e18eef152415b0ebb0.jpg)  
直接搜索“请求未授权”，定位到认证文件：springblade/gateway/filter/AuthFilter.java  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f2e0e83004d590a50d32d1271cbace7813c6fde5.jpg)

2.1 错误的认证逻辑
-----------

我们看下代码逻辑：  
（1）首先，从ServerWebExchange类中获取到uri，然后判断是否跳过：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5b18b5a0d04dbdd6fa86365ed6a27bc537238f9c.jpg)  
跟进isSkip函数，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-49ce5c0c194f7001700c72df1d1330c6f581586d.jpg)  
判断路径是否在不需要认证的名单中，跟进getDefaultSkipUrl函数，看不需要认证的名单有哪些：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d468f9bd7b0f21aeca138030406355b86e02403b.jpg)  
只要符合以上路径则不需要权限校验，否则都是需要权限校验的。而程序核心业务逻辑都是在/api/下的，显然需要授权。  
（2）回到AuthFilter，接下来通过两种方式获取token，如果两者都为空时，则提示“缺失令牌，鉴权失败”。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-513f18067d1fb8bb867bae4a859a7e96776e7f6c.jpg)  
我们跟进下AuthProvider.AUTH\_KEY,看需要传入认证字符串的字段名称：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-91b24c955eccdccf1d55ff191d52ec953064974e.jpg)  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-de0fa440966b5554d6c76c4d54e8dfc4f9d822e8.jpg)  
所以需要get或者在headers中有blade-auth，并从其中获取到鉴权字符串。  
（3）解析token，判断token是否合法：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6fc4e431f4d8ac2dc74f08404e292d47341dbc1b.jpg)  
先看下getToken，实现如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-92e8cd48c78d1697fad41cd59c218b06ace2662a.jpg)  
这里解释下，为什么要从第七位取字符串，因为BEARER格式的认证串为：bearer\[空格\]认证字符。  
接着看parseJWT方法的实现：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a8ac368a408b3e0ada6b61957259dc7064a76753.jpg)  
使用jwt密钥，对认证字符串进行解密，然后返回其内容，**如果解密结果不为空，则直接绕过认证。**那么继续往下，找JWT的解密过程及密钥：  
看下JwtUtil.BASE64\_SECURITY的值，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-56ea395cf395996557d579e2c18327964fec06fa.jpg)  
是由TokenConstant.SIGN\_KEY进行base64加密得来的。看一下TokenConstant.SIGN\_KEY：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-320a9fe8623c9f683f512b47e14a1c4778151830.jpg)  
由此，我们可以伪造auth认证字符串了，测试：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d002757b2f0d9e18fa20a26d69e9a99d3a09f565.jpg)  
带入接口测试：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c1a6fd21098780aad5456e78ebab6ed4ba51566d.jpg)  
成功伪造了任意用户进行登录。  
​

**\[其他\]**  
1、/api/blade-log/api/list接口中会泄漏账号密码，只要管理员登录过  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-53529e9f33e46375ff7a447576bc969fb39dfb51.jpg)  
2、部分情况下接口的前缀会被改，blade部分，可以从前端的app.js里面看得到完整接口。

2.2 权限提升
--------

其实刚才伪造的用户只能算是普通用户，在测试时候，发现还有些接口用伪造的token访问不了  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1aa77d132e677c32a7f60a4f86fede0052d915ff.jpg)  
这个接口是查看系统用户的，结果没权限。找下其代码：  
​

![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b34655a21ac1423095c1751b2bec79e5c643a7f0.jpg)  
其中使用了PreAuth接口进行了鉴权，看下其鉴权方式：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ba105581f0db70176e5c09e28c6d3d40ca3d95d9.jpg)  
调用了hasRole函数进行鉴权，找一下hasRole实现方式：（实现代码在：org/springblade/blade-core-secure/3.0.2/blade-core-secure-3.0.2.jar!/org/springblade/core/secure/auth/AuthFun.class）  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1bf6c2828cc457c0cc5de85c783d8cede0623907.jpg)  
跟进this.hasAnyRole方法：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b6a7cc72280b7a645c056cc5f0178f3c917c70b9.jpg)  
跟进一下SecureUtil.\_getUser\_方法，如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-0858b3b7eb7f1bd44bae487adfef87bf63a4dff1.jpg)  
从web容器内部获取BLADE\_USER的相关属性，如果没获取到的话，则会使用另外一个getUser方法，实现如下：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a16870c7b3440fec9e54d23ee578ba7eed2765c6.jpg)  
直接从请求头中获取blade-auth，然后进行jwt解密，将各个属性set给bladeUser类。  
回到AuthFun.class，往下看：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c3d38efbd669aaebd54e404935ef4fc92cdfe99d.jpg)  
其中r的来源是hasAnyRole被调用的时候传入的，我们看下传入的值：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-755828d51c4a447d4203cc6fcd5ff39a23da4ec7.jpg)  
所以，只需要我们在构造jwt的时候，加上role\_name且其值为administrator，则可以实现权限提升。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-757da07cafa541e8fe529a6e59287b43a3a0def9.jpg)  
试试token是否有效：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ff712eccbafdf0173bb4c142f446eb9b7cd4bf2.jpg)  
可见，权限进行了提升。  
**\[注意\]**

1、/api/blade-user/user-list 接口会泄漏所有账号密码，不过需要administrator权限，不加role\_name时，也可以，但无内容。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-628b5532b48792bd71f7bc0509348418fd9cfeaf.jpg)  
恰巧其登录时，直接用md5即可，所以，你懂的。  
2、一般admin默认安装时，对应的id为：1123598811738675201，部分接口需要有对应的user\_id，可以尝试。如：api/blade-user/info接口  
3、jwt的密钥SIGN\_KEY硬编码到jar里面了，而且不是写在配置文件里面，开发根本不会关注到这点，所以使用该框架的项目都受到影响。  
​

3.修复方案
======

1、对于框架使用者而言，其实修改SIGN\_KEY已经就让漏洞无法利用了  
2、对于框架作者而言：  
1）jwt的密钥，放在配置文件中，并提示用户修改。jar包里面硬编码改起来太麻烦  
2）修改认证流程，本质还是认证流程出了问题。建议把用户账号、密码密文放到jwt里面，然后认证过程中，通过jwt里面的账号、密码进行鉴权。