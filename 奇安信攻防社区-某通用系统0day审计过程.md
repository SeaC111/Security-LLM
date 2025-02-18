某通用系统0day审计过程
=============

前言
==

本篇文章首发在先知社区 作者Zjacky(本人) 先知社区名称: `Zjacky` 转载原文链接为https://xz.aliyun.com/t/13866

代码审计篇章都是自己跟几个师傅们一起审计的1day或者0day(当然都是小公司较为简单)，禁止未经允许进行转载，发布到博客的用意主要是想跟师傅们能够交流下审计的思路，毕竟审计的思路也是有说法的，或者是相互源码共享也OK，本次审计的目标是一套也是各大高校使用的通用系统，已经提交相关SRC平台进行修复

路由分析
====

直接看登录接口

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-df623f8f4424f53a875b05ad45e5909cf28ff921.png)​​

路由为 /setting.php/index/login

‍

找对应源码

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-223e84f0506f8eff6baa68c941a86c18d31a450a.png)​​

第一个接口setting对应Application下的文件

第二个接口Index对应Setting下的Controller文件名字

第三个接口为Controller的方法名字

‍

代码审计
====

上传
--

Application\\Admin\\Controller\\UploadController.class.php

在这个路径下继承了一个upload控制器父类

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-b718585d8d3f1d89f0cdb1712cd99693e21886f6.png)​

所以调用的接口如下

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-0ee2fe8ddad5dfabdb84a4251136d847cfd72fb6.png)​

实例化了一个`UploadFile()`​对象然后给他的属性赋值

重点关注以下代码

```php
$upload-&gt;exts = array('jpg', 'gif', 'png', 'jpeg'); // 设置附件上传类型
```

发现这里会调用`UploadFile()`​的魔术方法 跟进

```php
    public function __set($name,$value){
        if(isset($this-&gt;config[$name])) {
            $this-&gt;config[$name]    =   $value;
        }
    }
```

这里其实就是问题的本身，要是传进来的在config里头不存在则返回空，那么我们去看一下config的设置

```php
    private $config =   array(
        'maxSize'           =&gt;  -1,    // 上传文件的最大值
        'supportMulti'      =&gt;  true,    // 是否支持多文件上传
        'allowExts'         =&gt;  array(),    // 允许上传的文件后缀 留空不作后缀检查
        'allowTypes'        =&gt;  array(),    // 允许上传的文件类型 留空不做检查
        'thumb'             =&gt;  false,    // 使用对上传图片进行缩略图处理
        'imageClassPath'    =&gt;  'ORG.Util.Image',    // 图库类包路径
        'thumbMaxWidth'     =&gt;  '',// 缩略图最大宽度
        'thumbMaxHeight'    =&gt;  '',// 缩略图最大高度
        'thumbPrefix'       =&gt;  'thumb_',// 缩略图前缀
        'thumbSuffix'       =&gt;  '',
        'thumbPath'         =&gt;  '',// 缩略图保存路径
        'thumbFile'         =&gt;  '',// 缩略图文件名
        'thumbExt'          =&gt;  '',// 缩略图扩展名    
        'thumbRemoveOrigin' =&gt;  false,// 是否移除原图
        'thumbType'         =&gt;  0, // 缩略图生成方式 1 按设置大小截取 0 按原图等比例缩略
        'zipImages'         =&gt;  false,// 压缩图片文件上传
        'autoSub'           =&gt;  false,// 启用子目录保存文件
        'subType'           =&gt;  'hash',// 子目录创建方式 可以使用hash date custom
        'subDir'            =&gt;  '', // 子目录名称 subType为custom方式后有效
        'dateFormat'        =&gt;  'Ymd',
        'hashLevel'         =&gt;  1, // hash的目录层次
        'savePath'          =&gt;  '',// 上传文件保存路径
        'autoCheck'         =&gt;  true, // 是否自动检查附件
        'uploadReplace'     =&gt;  false,// 存在同名是否覆盖
        'saveRule'          =&gt;  'uniqid',// 上传文件命名规则
        'hashType'          =&gt;  'md5_file',// 上传文件Hash规则函数名
        );
```

emmm根本没有 `exts`​ 所以说后缀根本没有检测，可以从从调用的upload中查看

断到一个叫自动检查附件

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-624cb821dc15bf124befc34d6300b7d7274741e1.png)​

步进一下进入check函数存在检查文件类型

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-213893c9e8f0371a14acc78b79c65712f05b983d.png)​

再次跟进一下checkExt发现是一个很强的校验白名单

```php
    private function checkExt($ext) {
        if(!empty($this-&gt;allowExts))
            return in_array(strtolower($ext),$this-&gt;allowExts,true);
        return true;
    }
```

但是重点是他并没有赋值进去

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-c1a5a3118a8f4c9dc8d21f2acc07372f231532ae.png)​​

在这进行反向验证，讲前面的属性修改为在config里头的内容

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-aae7f3cde3966293bff723cfe380991c16642e30.png)​

再次进行断点跟到最后面的config的地方发现成功修改

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-7f71411015daaafe0f3dfd64e15686d209a3c73c.png)​

所以这套系统只要存在 `$upload-&gt;exts =`​ 这个的上传接口 就存在任意文件上传

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-d9a73fbd85e8f38ccee2876d43119c8655ebadd9.png)​

‍

SQL(绕redis缓存)
-------------

直接看前台控制器了​​

找到这个路由存在sql的问题

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-897b76bd63441fa7eb2958ef5cedf4a1e7b06051.png)​

在这个代码里头，可以发现 `$count`​ 跟 `$listJson`​ 是关键

`$count`​的设置是为了不频繁查询，所以这里只要设置随机伪造的PHPSESSID就可以了

`$listJson`​ 的设置就尤为关键了 if (!$listJson) 这里的语句是 我的redis去查phone就是要查不到 为null才能执行下面的sql语句，所以phone就是要不存在的手机号才行，所以就直接随机phone就可以了，但是他在后续的代码中把这跟手机号给设置进了`redis`​中

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-a1c2ed262185564813514264114fb8b5f60558ce.png)​

所以必须要把这跟`phone`​随机化来绕`redis`​的缓存才能进行正常注入

‍

SSRF
----

这里全局搜索`curl_exec(`​ emm感觉是这里 确实是可控的

\\Application\\Course\\Controller\\DocumentController.class.php

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-c2517f108b261ab94704b8b55a8a6e1ecd68b597.png)​

‍

从逻辑上来看

`$_SERVER['HTTP_AUTHORIZATION']`​ 跟 `$_SERVER['HTTP_X_OSS_PUB_KEY_URL']`​ 这两个值都得存在 他就不会进行403的跳转 那么这两个都是我们可控的只要在header头加入即可，之后就会将我们传入的base64编码的值进行解码后给到curl进行直接curl执行

```xml
Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
X-Oss-Pub-Key-Url: aHR0cDovL2RxM2JlMC5kbnNsb2cuY24=
```

远程测了一下也是完全没问题的

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-c62b0b98abd7c026087910f9dc5bf3ad5bf507eb.png)​​

加入后返回两百

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-df623f8f4424f53a875b05ad45e5909cf28ff921.png)​

最终也是测出了SSRF

![image](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-852291df4b3368fb396c2a8578bb4d53e46583a3.png)​​

‍