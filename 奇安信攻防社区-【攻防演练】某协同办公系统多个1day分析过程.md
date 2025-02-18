0x01 任意文件上传
===========

1.1 代码分析
--------

漏洞出现在`E-mobile/App/Ajax/ajax.php`文件中，是后缀过滤被绕过导致的。

业务逻辑如下：

(1)`$photo = $_FILES["upload_quwan"];` 将上传文件赋值给`$photo`，

(2)`$ext_temp = path_info($photo["name"]);` 获取上传文件后缀

(3) 后缀合法性校验（漏洞核心位置）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0a9d2409e1efb2a856a5b397b2c58c8d2fd6834c.png)

校验过程存在缺陷，只校验了上传文件后缀有没有在黑名单，却未考虑后缀为空的情况，比如`123.php.`，此时取到的后缀为空，不在黑名单。

(4) 拼接路径，完成上传。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1e5487994c84f25c54a54e7c0063e518ce692145.png)

1.2 漏洞利用
--------

`action=mobile_upload_save`直接上传即可

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fe5a2cd4f6d1056a8ea638052eebb6abd636060d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6e01a633ee0910fca84592c72319352534eb4617.png)

0x02 全回显SSRF可RCE
================

2.1 漏洞分析
--------

还是这个文件，继续分析`action`为其他的分支，在`action=dingtalkImg`时，存在该漏洞，我们看下实现过程：

(1) 获取一个result参数，然后传入`GrabImage`函数进行远程文件抓取操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-376d5b7d3afc272837d3be156e59d0950c6159ac.png)

(2) 跟进`GrabImage`，该函数做了几点操作：

- 从url中获取文件名
- 打开url读取图片流
- 打开文件，写入图片流

全程一气呵成，没有做任何文件后缀校验。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-341e01e63a02be253dbbdb75924881a91c1dc726.png)

所以，该处既存在全回显SSRF，同样文件保存在服务器，可以造成RCE

2.2 漏洞利用
--------

服务器上启一个web服务，将代码放进去：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5e7f327248efd41ae16c9e1f573f5c1635d6cd1c.png)

然后构造URL进行请求：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ae76f39f6b60aa15744d9741a1252c86be426041.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a1142016e1880a3fd8452951e2fe711b55bdf59.png)

2.3 类似的接口还有
-----------

`action=outSignImg`时

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-019123063de19c8101eb9397cb256287789c470e.png)

0x03 回显SSRF
===========

3.1 漏洞分析
--------

在`/E-mobile/App/System/File/downfile.php`中

(1)赋值过程(11-18行)

```php
$fileurl      = $_REQUEST["url"];
// ....
$rooturl      = "http://".$_SERVER['HTTP_HOST'];
$checkurl     = explode("/", $fileurl);
```

当`$checkurl`中包含某些特定字符时，则拼接指定的URL：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-abcbf9a1963204c056732a9db6d09c80a78615d7.png)

(2)拼接完整URL，不满足上述两种特定流程时。

```php
else 
{
    $url      = $rooturl.$fileurl;// 将HOST和url参数值拼接
    $filetype = pathinfo($fileurl); // 获取文件后缀
    $type     = $filetype["extension"]; // 将type设置为文件后缀
}
```

(3)`$url`传入`file_get_content`造成SSRF

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0d0f727d4f9b1fdffd62752559bab0253769ad52.png)

3.2 漏洞利用
--------

- 利用方法1:`url=@butian.net`
- 利用方法2:请求包HOST设置为`butian.net`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cffc13c1603340bc1312300f71313cc4637cf4f3.png)