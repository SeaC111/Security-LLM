0x0 起因
------

群里的老哥发了套代码说适合小白练练手，对于我这个纯小白来说当然要冲了。  
emm，的确挺适合小白的，漏洞真多，所以下面就简单举个例子。  
下载地址:<https://wwe.lanzoui.com/iShKJqualmj> 密码:9d1b

0x1 SQL注入
---------

### 0x11 代码审计

/view\_package.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5e672ba77c64e5af8bfb4378ef2e458b2ef28963.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5e672ba77c64e5af8bfb4378ef2e458b2ef28963.png)

可以看到`id`直接带入数据库执行了

### 0x12 复现

POC:

```php
http://192.168.10.248/?page=view_package&id=c4ca4238a0b923820dcc509a6f75849b%27%20AND%205829=5829--%20aaa
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b30c8003ea44e2cf23342a0b7094f65d27cfc2ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b30c8003ea44e2cf23342a0b7094f65d27cfc2ee.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ce1de3447172325a0745a956aa752fbf2beb23ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ce1de3447172325a0745a956aa752fbf2beb23ee.png)

0x2 XSS
-------

### 0x21 反射型代码审计

/admin/index.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-76aeacdd1cdfa921c339697892b8617fe2fa1e0e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-76aeacdd1cdfa921c339697892b8617fe2fa1e0e.png)

接收到`page`参数后只替换了下`/`和`_`就直接返回了

### 0x22 反射型复现

POC:

```php
'-prompt(1)-'
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6aa52a563a22e441c44062775d6905cd22e323a3.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6aa52a563a22e441c44062775d6905cd22e323a3.png)

### 0x23 留言板存储型代码审计

/classes/Master.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-694509a65160884a6cdd029c7cff8dbd88044acd.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-694509a65160884a6cdd029c7cff8dbd88044acd.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-11d48484e05d0ebee18997fe31dd4cfdeab6bd46.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-11d48484e05d0ebee18997fe31dd4cfdeab6bd46.png)

留言数据`date`没有实例化或者过滤直接存到数据库。

/admin/inquiries/index.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b0195ce6d0ec473184bf312082ca4a240e5f7b79.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b0195ce6d0ec473184bf312082ca4a240e5f7b79.png)

从数据库取出来后直接输出

### 0x24 留言板存储型复现

POC:

```php
<script>alert(document.cookie)</script>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1aaa32d541101b247e45063a5ef181fb95f43c7b.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1aaa32d541101b247e45063a5ef181fb95f43c7b.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bad3997ea57f863b572da9cb8c36e0a9e09eabcf.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bad3997ea57f863b572da9cb8c36e0a9e09eabcf.png)

0x3 文件操作
--------

### 0x31 任意文件删除代码审计

/classes/Master.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e60b1b15f2e52cc8f1f3b7505ac0db15a54c44d9.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e60b1b15f2e52cc8f1f3b7505ac0db15a54c44d9.png)

直接使用`unlink`函数删除参数`path`

### 0x32 任意文件删除复现

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b74fda69ce3bbe9e5b2df3507a84cc41a0a16b0f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b74fda69ce3bbe9e5b2df3507a84cc41a0a16b0f.png)

返回success即成功

### 0x33 任意文件上传代码审计

/classes/Users.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6ddf709bdba8546008770ddc6c4335b74369be88.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6ddf709bdba8546008770ddc6c4335b74369be88.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e4f3c1d98da2936e6342cdba49e58b09a776ef9e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e4f3c1d98da2936e6342cdba49e58b09a776ef9e.png)

未做任何限制，可以直接上传任意文件

### 0x34 任意文件上传复现

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a47fbb4be648882ca7cab8f4c9b9f0ed78164f61.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a47fbb4be648882ca7cab8f4c9b9f0ed78164f61.png)