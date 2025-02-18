本文仅用于技术讨论与研究，文中的实现方法切勿应用在任何违法场景。如因涉嫌违法造成的一切不良影响，本文作者概不负责。

0x00 漏洞简介
---------

2022年12月出的一个 `CVE` ，漏洞作者在10月左右就写在`thinkphp` 的 `github` 下面了，链接在这：<https://github.com/top-think/framework/issues/2772> ，此漏洞属于框架函数的漏洞，需要开发者编写代码时使用到该函数才有机会利用。

在官方开发手册的示例中，使用了该函数，并且没有任何过滤，因此当开发者使用 [官方示例](https://www.kancloud.cn/manual/thinkphp5_1/354121) 进行开发时，就可以 `getshell`。

0x01 漏洞影响
---------

`thinkphp 5.x` 系列

不影响目前的 `thinkphp6.x`

0x02 环境搭建
---------

使用 `composer` 快速搭建 `thinkphp5.x` 系列最新版环境

```php
composer create-project topthink/think=5.1.* tp5.1.41
```

之后根据官方示例 [https://www.kancloud.cn/manual/thinkphp5\_1/354121](https://www.kancloud.cn/manual/thinkphp5_1/354121) 编写，修改如下文件

```php
application/index/controller/Index.php
```

```php
<?php
namespace app\index\controller;

class Index
{
    public function Index(){
        // 获取表单上传文件 例如上传了001.jpg
        $file = request()->file('image');
        // 移动到框架应用根目录/uploads/ 目录下
        $info = $file->move( '../uploads');
        if($info){
            // 成功上传后 获取上传信息
            // 输出 jpg
            echo $info->getExtension();
            // 输出 20160820/42a79759f284b767dfcb2a0197904287.jpg
            echo $info->getSaveName();
            // 输出 42a79759f284b767dfcb2a0197904287.jpg
            echo $info->getFilename();
        }else{
            // 上传失败获取错误信息
            echo $file->getError();
        }
    }
}
```

0x03 漏洞分析
---------

官方示例文件中注释写的很明白，就是先上传文件，然后将文件移动到根目录的 `uploads` 文件夹下，后面代码就是在输出。

我们先看第一句 `request()->file('image');`

`request()` 直接加载了 `thinkphp/library/think/Request.php` 中的 `Request` 类，然后访问 `file` 方法

![image-20221210185619775.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f536b9d4f67bc8ec7fc60d823486443dd4fcfc00.png)

这里就是取到了 `$_FILES` 与 `$name` ，然后传入 `dealUploadFile` 方法，返回一个 `$array` ，最后会返回一个 `$array[$name]` ，我们跟进 `dealUploadFile` 方法

![image-20221210204622555.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2d3cf6ab3860a758ebe97f9fc3a54cb4bc19a76d.png)

我们传进来的 `$files` 是 `$_FILES` ，因此不满足第一个 `if` 条件，`$file['name']` 就是传入的 `filename` ，不为数组时就会进入最后的 `else` ，正常传入文件就不会出现 `error` ，因此来到 1246 行，这时候进入 `thinkphp/library/think/File.php` 的 `setUploadInfo` 方法，来到这里

![image-20221210204517548.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-67afeb4b75496f828f5e301cce9067c3707981bf.png)

这里返回了 `$this` ，也就是实例化后的 `File` 类。

然后继续返回，可以看到，我们编写的文件中，第一句最后的返回就是这个实例化后的 `File` 类

看到第二句 `$file->move( '../uploads')` ，调用该类的 `move` 方法，参数是 `../uploads` ，跟进该方法

```php
thinkphp/library/think/File.php
```

![image-20221210205857136.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-cbe6f9d943cdfcb8bbfc5718c77999c151991507.png)

这里是 `move` 方法的上半部分，代码都有注释，因此很好理解，涉及到检测的有三个方法，分别是 `isValid` 、`check` 、`chechPath` ，我们依次看看

`isValid` 方法

![image-20221210224032960.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bb52fc28be19ac71fe5f6bda7067bb089497e814.png)

这里只是检测是不是文件或者上传的文件，显然是满足的。

`check` 方法

![image-20221210224209801.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-91d64288e719c7116b24fc1d5827b6fbe65f2d9c.png)

此处的参数是没有传入的，因此 `$rule` 就是空数组

第一句这里，由于 `$rule` 为空，因此会获得 `$this->validate` 的值，这个 `$this->validate` 的值是在 `validate` 方法中设置的，如下

![image-20221210224629725.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9435ec636527c58b13a601d03998fcfd22686aae.png)

按照官方示例的代码，是没有写这个 `validate` 限制的，这里 `validate` 默认也是空数组，因此 `$rule` 的值也还是空的，其实如果要防止这个漏洞的话，也是可以利用这个 `validate` 方法进行设置的。

由于 `$rule` 为空数组，因此前面三个判断都不会生效，只会进行第四个，也就是 `$this->checkImg()` 方法，只要这个方法返回 `true` ，那么就会跳过这里的判断，我们来看到这个方法

![image-20221210225726871.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d7c62a61889a4058ff2b1858baf77e5d7fb8cfef.png)

这个方法检查图片后缀以及图片类型。

首先获取后缀并转为小写，得到 `$extension` ，下面是一个判断，图片后缀为这个数组里面的值并且后面也为 `true` 时就会返回错误，这里的条件很奇葩，当我们的文件后缀为 `php` 时就不满足第一个条件，直接返回 `true`

`chechPath` 方法

![image-20221210231636945.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-aab9a2ed612662371ac302427c6f7dde91ac105d.png)

这里只是判断有没有相应文件夹，没有就创建，因此也可以过

接下来看看 `move` 方法的下半部分

![image-20221210231747613.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f86f41da72b81d5c857035a86a0e1957506cd61a.png)

这里并没有其他的检测了，直接将临时文件移动到了目标文件。

我们直接上传一个 `php` 文件，即可在使用官方示例的条件下 `getshell`

0x04 漏洞复现
---------

由于官方示例没有上传的模板，因此我们自己创建一个

![image-20221210232333208.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fb186c365816529e50ed1114e04979be40cc1262.png)

上传并且抓包，将后面改为 `php`，如图

![image-20221210232409533.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2eaac3b7922bc841e1beeb0d27e57dc781f92c07.png)

![image-20221210232527073.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f75905bea545e09eb0bba50afd99c5d0c0f87411.png)

0x05 总结
-------

这个漏洞是属于`thinkphp`框架的函数的漏洞，因此需要开发者按照官方示例去使用或者类似的用法才会造成 `getshell` 。

但是也会觉得很奇葩，因为此处的实际检测应该就是那处 `checkImg` 方法，但他这里明显就写错，必须属于图片类型才会返回 `false` ，根本上就没有对危险的后缀进行过滤，更让人觉得离谱的是，至少从 `5.0.0` 开始一直到最新版本，都是这样的，没有更改过。