0x0前言
-----

浅谈渗透测试中常见的密码为密文的情况下如何进行利用的方法

0x1案例一
------

进行渗透测试的时候，我们常常遇见登录抓包密码为密文的情况，如下图

![image-20220131005842236.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-3cafe1d62fc62b28553daece450b902d1c5e3f42.png)

这种情况下，我们想直接爆破密码和测试 sql 注入是没法测试的。因为数据传输的过程中，加密是通过前端进行加密，后端再进行解密。例如

```php
明文：123456

前端进行加密：325aa8b6672fca57edcf9638539315299aa59791ff794777cddc6fcbc28cfd11d51652530b35fd107be11795b19ffebf095155e8f524774039053adb6ec3eeb9781eb24e10629645fa9a040f0cbc86ce7573528bb8b364ccaea4d58ec519f8a79888e689e84e948b7ffd8e213552e1bcefbe5187ffdede885f98549bb54e2b81

后端解密为：123456
```

比如测试sql注入，我们需要传入`123456'`，而一般 waf 都会拦截掉或者前端进行限制不允许你这么输入，这个时候只能自己分析出密文去 burpsuite 中进行发包

这里我去下载了通达oa最新版作为示例。首先输入账号密码抓包后请求包如下

![image-20220131012143385.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-710ea512657591fa308e0af2b2fb80aea80af64d.png)

可以看到密码进行加密了，这个时候我们`f12`打开web开发者工具，去调试器中选中文件夹`crtl+shift+f`搜索`PASSWORD`关键字

![image-20220131012416503.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-b34074a512541f18701c5be77ad7a037f365cffe.png)

看到`(index)`中有一个`rsa.encrypt()`函数，定位到此处，然后分别对获取页面表单中的`PASSWORD`语句和调用加密函数的地方打上断点

![image-20220131012535716.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-ba90b1b3b5baa2f8d49e7923cc8a1000a0d382ec.png)

这个时候正常输入账号密码，点击登录就会停在断点这里

![image-20220131012843516.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-85f44964ac0298630dffff3b283ab0283255533f.png)

可以看到`psw`就是我们输入的明文密码123456，并且会调用`rsa.encrypt`进行加密，清楚逻辑之后我们就可以在控制台进行测试

![image-20220131013115682.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2bd867c37b5fbca20431fb757ff779a94fa725a3.png)

这里我设置的管理员密码就是`Admin123456`，可以看到运行代码之后输出了密文，我们复制到 burpsuite 进行发包测试

![image-20220131013230580.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-39d45a597b76e1e5beb75c92875cd539068a41bf.png)

登录成功，证明我们输出的密文没有错。这个时候我们就可以构造 sql 语句进行测试了，也可以写一个明文字典加密成密文字典进行爆破，这里用 js 做个简单示例

![image-20220131013529816.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-8348c49aa8cf7592e20343484692c1982c682681.png)

当然我更喜欢用python来写脚本，觉得更简便一些。前面我们已经在打断点的地方知道了`RSA`的模数和指数，可以构造出公钥

```python
def rsa_ne_key(modulus, exponent):
    #将16进制转成10进制
    rsaExponent = int(exponent, 16)
    rsaModulus = int(modulus, 16)
    key = rsa.PublicKey(rsaModulus, rsaExponent)
    return key
```

接下来跟进`RSA`的加密函数

![image-20220131014229249.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-53dea43617d79d7d3353666cd86d4af0ac249cb7.png)

注意这里看到，最后的话将byte类型转换成了16进制的形式，所以我们写一个加密函数

```python
def rsa_encrypt(text, public_key):
    cipher_text = rsa.encrypt(text, public_key)
    return cipher_text.hex()
```

最后写好的脚本如下

```python
'''
Author: dota_st
blog: www.wlhhlc.top
Date: 2022-01-31 00:04:10
'''
import rsa

#构造公钥
def rsa_ne_key(modulus, exponent):
    #将16进制转成10进制
    rsaModulus = int(modulus, 16)
    rsaExponent = int(exponent, 16)
    key = rsa.PublicKey(rsaModulus, rsaExponent)
    return key

#利用RSA公钥加密明文
def rsa_encrypt(text, public_key):
    cipher_text = rsa.encrypt(text, public_key)
    return cipher_text.hex()

if __name__ == '__main__':
    exponent = "10001"
    modulus = "B87A3BE2184FED0973FFB0B02A862DCAD15A1A29172EC8FF67E841FE26749A6AA04E48E9B02D963ED81DCE2B0086C034F7D47CCBACF8539C36B9445ABA5EF484F3CA32593762641B4C9683C79801D087198370D5719BB4E422FADAA4D883D13874DE67D8B6E883EBAACC53A8480F41EE8BE70D2F70BECF3CB7F1023D2C901CC3"
    key = rsa_ne_key(modulus, exponent)
    result = rsa_encrypt("Admin123456".encode(), key)
    print(result)
```

运行后得到设置的密码密文形式

![image-20220131014534606.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-5f519621842a05ea90717a22d89591bb7be5c4d6.png)

这里只要将脚本改成读入明文字典，然后批量转换成密文字典，就可以到 burpsuite 中进行爆破啦。

0x2案例二
------

某网站用户登录抓包信息如下

![image-20220131120213117.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-19fbaf7b46cbfd8f0c9efbb4bc642ee8a6c9e2c3.png)

对密码进行了加密，我们和前面说的方法一样，在调试器中全局搜索关键字段`loginPwd`

![image-20220131120519936.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a4cd0045fba3c6bf6c430b5d90127443c6850f31.png)

发现只有一个 js 文件匹配到，我们点击定位到该文件。如果不是很会打断点的朋友，可以采用一个办法，就是把所有传参`loginPwd`的地方都打上断点，例如这里

![image-20220131120730465.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-1a31514789a861c05262f165879a1cdb0437677a.png)

打好断点后，正常输入账号密码，会停在打断点的地方

![image-20220131120849015.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-2e2aee032af9796b779662cba9d623c0238514b2.png)

上图中可以看到，`this.loginPwd`是我们的传进来的明文密码`123456`，而前面赋值的变量`this.parame.loginPwd`为密文形式

![image-20220131121024017.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-df5029d265771a0bc735f48b94d68a285cf10c9a.png)

这说明是通过调用`Object(v.a)`这个函数进行的加密，我们在控制台中测试一下

![image-20220131121147064.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-dee825217075337a83c5b6e6dcab2bf25365ffff.png)

输出的密文值和我们前面在 burpsuite 中抓包看到的密文一模一样，说明我们正确找到了加密函数。到这里便可像上一个案例一样生成一个密文字典进行利用了。

0x3案例三
------

下面再看另一个案例  
输入账号密码，burpsuite 抓包如下

![image-20220131015013125.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-a8ed6802023a20631bc38065fb463e010c4261be.png)

继续按前面的思路去看 js 文件，发现直接给了 RSA 公钥，并且对明文进行 RSA 公钥加密

![image-20220131015204551.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-af457d6c4ffe47f929350950c44138446a0a06fd.png)

我们写一个python脚本进行利用

```python
'''
Author: dota_st
Date: 2022-01-31 00:04:10
blog: www.wlhhlc.top
'''
import rsa
import base64
public_key = b'''
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANL378k3RiZHWx5AfJqdH9xRNBmD9wGD
2iRe41HdTNF8RUhNnHit5NpMNtGL0NPTSSpPjjI1kJfVorRvaQerUgkCAwEAAQ==
-----END PUBLIC KEY-----
'''

# RSA公钥加密
def rsa_encrypt(text):
    rsa_key = rsa.PublicKey.load_pkcs1_openssl_pem(public_key)
    info = rsa.encrypt(text, rsa_key)
    cipher_text = base64.b64encode(info)
    return cipher_text

result = rsa_encrypt("admin888".encode())
print(result)
```

运行后得到密文

![image-20220131015545252.png](https://shs3.b.qianxin.com/attack_forum/2022/01/attach-d929f9d5b05c87bda13c786a65c09a8d1c55655b.png)

然后就可以进而构造出我们的密文字典进行爆破

0x4总结
-----

本文对常见的登录框前端 JS 加密介绍了利用的思路和方法，以后在渗透测试的过程中，遇到这种情况就不用慌啦~