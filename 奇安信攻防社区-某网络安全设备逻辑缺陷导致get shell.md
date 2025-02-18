写在前面
====

听某位师傅说cnvd的证书对就业有帮助，特别是安全厂商类型的cnvd证书含金量更高。听到这里，我便开始跃跃欲试，便有了此篇文章出现。本篇文章就来讲讲这次挖掘安全厂商产品0day通用漏洞的过程。本章中所有漏洞均已提交至cnvd并获得证书。

过程
==

这里首先先到目标主站进行信息收集，看看他们有哪些产品等等。

然后我就用网络空间搜索引擎再次进一步收集信息，最后把目标定在了一个页面看着相对简陋的网络安全设备Web管理界面上：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3af56dc9ab0743b0dbc83ed782ee1047f98ec555.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3af56dc9ab0743b0dbc83ed782ee1047f98ec555.png)

然后这里到网上尝试寻找该安全厂商旗下这个产品的通用弱口令，费了一番功夫算是找到了，可是尝试了以后要不就是提示我`密码不正确！`：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-88d42b995a97bf3255b7675bc245a7b2ed072fe5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-88d42b995a97bf3255b7675bc245a7b2ed072fe5.png)

要不就是提示我：`用户名不存在！`：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f2cf54efba90dc07f6b88099b6d348c390eb50c6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f2cf54efba90dc07f6b88099b6d348c390eb50c6.png)

看来有可能是之前已经有人发现过该问题并提交了通用弱口令漏洞了，安全厂商可能已经修复了。这里为了验证我的观点，我便到cnvd的漏洞列表里进行高级搜索，把这家安全厂商的相关产品关键字输入进去进行查询，果然找到了该产品的弱口令漏洞信息，看来是我晚了一步啊，可惜了。那么这里我们明显不知道修复后的用户账号和相对应的密码，这里必须得开始进一步信息收集了。

经过了一些时间的信息收集，真是功夫不负有心人，我发现存在`http://x.x.x.x/data`，发现该路径下存在目录遍历漏洞。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-65002e80055c76487aaf8bda632218ba8d78eab0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-65002e80055c76487aaf8bda632218ba8d78eab0.png)

这倒给我的信息收集省下了不少的麻烦。这里直接来找找有没有敏感文件和敏感信息泄露。可是找了半天，并没有什么敏感文件，都是一些Web源代码文件。本想着既然找不到敏感文件，那么就来审计下代码，看看会不会存在有漏洞直接打进去，可是这里并不能看到源代码：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-528071599caa274e3c75caf439ca40c77ce7ffc0.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-528071599caa274e3c75caf439ca40c77ce7ffc0.png)

可是这里却暴露了其绝对路径，这里马上便可以推断出其搭建在Windows系统上。再看看文件后缀名均为php，那么这是一个`php+windows`的情况。  
在`php+windows`的情况下：如果`文件名+::$DATA`会把`::$DATA`之后的数据当成文件流处理,不会检测后缀名，且保持`::$DATA`之前的文件名，然后这里便把文件的源代码给展示了出来：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d33e87b3645ba4de853c9bd43c0f80f0306a6235.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d33e87b3645ba4de853c9bd43c0f80f0306a6235.png)

那么这里就开始了代码审计。然后便在/data/login.php，即登录的文件中发现了疑点：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-79794f11e0253e3b1287ab2c92a31012c3de6f0c.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-79794f11e0253e3b1287ab2c92a31012c3de6f0c.png)

这里的部分代码我展示出来：

```php
<?php
/**
        系统登录设置
*/
include(' ../ commmon/ connDb. php');
$dbQuery = new DataBaseQuery();
$userName=$_POST['userName'];
$password=$_POST['password'];
$system=$_POST['system'];
$userInfo = $dbQuery->querySing1eRow('select passward,roleld from user_info   where name="' . $userName. '"' , true);
if($password == "dandain12345")
{
    @session_start();
    $_SESSION['userName’]=$userName;
    $_SESSION['system’]=$system;
    $_SESSION['roleId']=$userInfo['roleId'];
    $mainMenuIds = fetchMainMenu($dbQuery,$userInfo['roleId']);
    $_SESSION['mainMenulds']=$mainMenuIds;
    $subMenuIds = fetchSubMenu($dbQuery,$userInfo['roleId']);
    $_SESSION['subMenuIds']=$subMenuIds;
    modifyXML($system) ;
    echo "0";
    $dbQuery->closeDb() ;
}
else
{
    if(count($userInfo)==0){//用户名不存在
        echo "1";
        $dbQuery->closeDb() ;
        return;
    }else{//用户名存在
        if ($userInfo['password' ] !=$password){//密码不正确
            echo "2";
            $dbQuery->closeDb();
            return;
        }else{//正确登录
            @session_start();
            $_SESSION['userName’]=$userName;
            $_SESSION['system’]=$system;
            $_SESSION['roleId']=$userInfo['roleId'];
            $mainMenuIds = fetchMainMenu($dbQuery,$userInfo['roleId']);
            $_SESSION['mainMenulds']=$mainMenuIds;
            $subMenuIds = fetchSubMenu($dbQuery,$userInfo['roleId']);
            $_SESSION['subMenuIds']=$subMenuIds;
            modifyXML($system) ;
            echo "0";
            $dbQuery->closeDb() ;
}
```

这里发现`if($password == "dandain12345")`语句代码和下面的当用户名存在并正确登录成功的实现的代码完全一样，那么这里理论便有一个逻辑缺陷漏洞了：即不论用户名是否存在，只要随便输入一个用户名，密码输入`dandain12345`，最后都能够成功登录进去。

这里分析完后，马上进行尝试：  
比如：随便输入一个用户名为`test`，密码先随便输。然后提示我`用户名不存在！`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b760f73f73cd1618d0f67c32be5a94daf160c164.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b760f73f73cd1618d0f67c32be5a94daf160c164.png)

那么这里把密码换成输入`dandain12345`，居然成功了。这也证实了我之前的观点:不论用户名是否存在，只要随便输入一个用户名，密码输入`dandain12345`，最后都能够成功登录进去。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f2ad85540b7755da8c4b8e044e3c8a6889262425.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f2ad85540b7755da8c4b8e044e3c8a6889262425.png)

那么这里在选一个存在的用户名`admin`，然后密码随便输。提示我`密码不正确！`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-403ff194dfee69a6cd4c7669ce65ecfb39445e17.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-403ff194dfee69a6cd4c7669ce65ecfb39445e17.png)

这里再把密码换成输入`dandain12345`，也成功了，而且还是管理员权限：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7d546b440fe555e0f161745ac044c17beb28ab30.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7d546b440fe555e0f161745ac044c17beb28ab30.png)

最后我在管理员的权限下经过寻找可用上传点和尝试，最后成功传上去了一句话木马，并用蚁剑成功连接了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-56fd7712fe3dd629f299a1a9307280e5159bce36.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-56fd7712fe3dd629f299a1a9307280e5159bce36.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f5bbd0ab954daad8f237f8c0e8afc7d1f07b40dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f5bbd0ab954daad8f237f8c0e8afc7d1f07b40dc.png)

执行`ipconfig`  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bfa7fb1be78fba5c8725a8a7a1be61dd541c59c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bfa7fb1be78fba5c8725a8a7a1be61dd541c59c3.png)