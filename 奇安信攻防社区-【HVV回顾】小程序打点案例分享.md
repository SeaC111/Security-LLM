0x00 前言
-------

> 刚结束某地HVV，小程序作为低成本易用的信息化系统，成为HVV新型重点突破对象。以下案例均来自于小程序，供大家学习。

0x01 案例一 某政务系统
--------------

### 1.弱口令进入后台

点击小程序，进入公民办事，抓到小程序域名，访问直接是管理员后台，如下页面即为Fastadmin框架 。

![image-20230804233808809](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-2a5fba3396c1a276bc140f7bc766cafb85e172a2.png)

一直有个坑，登录一直显示口令无效，在我要放弃的时候，点击返回上一步提醒我，您已登录，我纳闷了，发现该系统登陆操作后token会刷新，导致下一次登录必须使用上一次token，否则口令无效。因此应该是网络或系统本身有延时，导致未成功使用正确token进行登陆操作，当发现这个问题的时候我已经admin/123456登进了后台。

![image-20230804233928487](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-e446afd11627d19ce32b77d941d08639d73fa88e.png)

内包含数据近20000条公民信息，以及管理员账户几百个，且所有管理员账户中的账户名密码均为admin/123456。与[地级市HVV | 未授权访问合集](https://forum.butian.net/share/1877)中的案例四系统情况类似。（码死）

![image-20230804234620409](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-b9631f66f0293cbc20d834b4ac599881a71f7784.png)

### 2.到处都是SQL注入

前台业务处如下包，debug没有关导致爆出来数据库账户名密码，这个SQL注入太明显了，但此时我处在数据库账密的喜悦中没有搞SQL注入，可是这个数据库不对外，只能本地连接，烦死了。

![image-20230804234900245](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-6d0679aaeb701b9eb1eb8374a3c74aa5017697b8.png)

![image-20230804235223957](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-4ed1411f61d7466da08f47389b6f2a9e2c9632a5.png)

后台查看管理员的时候存在延时注入

![image-20230804235333429](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-e67dc431a9810fbcfb0b11f34e0e101644b75eb3.png)

![image-20230804235520250](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-1cc9a826a1ea7c019050d47dbe4bf35565626bbd.png)

### 3.命令执行拿下服务器和数据库

既然是fastadmin，那有很多拿shell的方法，这次是用在线命令插件漏洞写入PHP Webshell，该漏洞只在1.1.0可用。

但是这个系统是二开的，根本找不到插件的地方，在网上搜罗了一下拼接找到插件页面。

目录为：/addon?ref=addtabs

那该插件的目录就应该是/addon/command?ref=addtabs，但是显示该页面不存在，我以为路由没设置，把这个禁了，直到队友在一个文章发现直接command即可访问该插件，即目录为/command?ref=addtabs

![image-20230805000548485](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d8850d06c2db9eaf1a97e0b2c97628e20d671199.png)

点击一键生成API文档，文件为php，标题写为木马内容即可，测试只有冰蝎马可以，以前有类似案例。

![image-20230805000747580](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-dcbc696189632682e6b5bbc9aba77b9fe1ed8018.png)

连接木马成功

![image-20230805000951036](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-684d7e1943f1e59e55be23f12db13aa5fcccfe53.png)

通过传大马中的nc提权，反弹shell到云服务器拿到root权限。

![image-20230805001343057](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-aac04832a4be9f03e480b9345fd3e22f94715002.png)

大马执行sql语句会报错，乱码，很烦。

数据库账户密码我还记着呢，我通过自己写一个sql执行页面的php文件来连接数据库。证明我拿下数据库权限。

![image-20230805001445813](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-4fb8a2ef54ae5028053a9f32a739027091d3130e.png)

代码如下：

```php

<html>
<head>
    <title>执行MySQL语句</title>
</head>
<body>
    <h1>执行MySQL语句</h1>

    <form method="POST" action="">
        <textarea name="sql_statement" rows="5" cols="50" placeholder="请输入MySQL语句"></textarea>
        <br>
        <input type="submit" value="执行">
    </form>

    <?php
    // 检查是否提交了表单
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // 获取用户输入的MySQL语句
        $sql_statement = $_POST['sql_statement'];

        // 连接MySQL数据库
        $host = 'localhost';
        $username = '';
        $password = '';
        $database = '';

        $connection = mysqli_connect($host, $username, $password, $database);

        // 执行MySQL查询
        $result = mysqli_query($connection, $sql_statement);

        // 检查查询结果
        if ($result) {
            // 回显查询结果
            echo '<h2>查询结果：</h2>';
            while ($row = mysqli_fetch_assoc($result)) {
                echo '';
                print_r($row);
                echo '';
            }
        } else {
            // 显示错误消息
            echo '<h2>错误：</h2>';
            echo '<p>' . mysqli_error($connection) . '</p>';
        }

        // 关闭数据库连接
        mysqli_close($connection);
    }
    ?>

</body>
</html>
```

0x02 案例二 某县医院数据库
----------------

### 1.SQL注入拿下DBA

该医院的SQL注入处于公众号挂号处，当我登录进去点击挂号记录，抓到一个带病人id的包。

![image-20230805001938526](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-38dedc4d5272dfae5344847399a57bee1d645e77.png)

加了个单引号，出现报错order by

![image-20230805002523985](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-8e14f7b56f2a754d56628bb07c242307f80425b7.png)

直接SQLmap跑发现跑不出来，但注入确实存在。发现asp.net框架，说明对方系统为windows。

![image-20230805002955771](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-40ddf255d62824cbbf3ff54b42128ab2143db9db.png)

分别指定数据库MySQL，Oracle，MSSQL。终于在MSSQL时跑出注入，且为DBA权限。

![image-20230805003357942](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-c54f6354383543e073a179d59dd6bacd9906bd6c.png)

想到xp\_cmdshell可以执行命令，但可惜这是HIS，人家做了防护，我无论怎么设置都无法执行命令，放弃换目标。

0x03 案例三 某中学访客系统
----------------

### 1.未授权+信息泄露

打开小程序抓包，直接抓到了所有被访人的信息，一个接口未授权访问。

![image-20230805003829804](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-474312fc772477b2517f9a8f21c6bed2dff3d522.png)

还没登录就这样，登进去还了得。

登进去并添加了一个访问申请![image-20230805004820411](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-6c924a4746cd888c713321d245e8488a44d77d8b.png)

在查看自己的访问申请记录时抓包

![image-20230805004432163](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-f079dd07d05db070c0539e702290d3ad84c8f588.png)

抓到如下链接：app/visitor/getVisitorInfo?viId=1，遍历可得到访客信息几百条，以及访客记录等。认定为平行越权，最后发现甚至是未授权访问，没有权限验证。

![image-20230805004401655](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-d53705ec06515fc4bd3c355ddce15057e50fbe32.png)

0x04 案例四 我打偏了
-------------

这个案例比较好笑，是我在搜小程序，它弹出了差一个字的小程序，没仔细看就开始打，也是一个县医院。

这应该是疫情期间专门为核酸检测预约做的小程序。

### 1.平行越权+信息泄露

![image-20230805005119179](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-8675370e9a33f9552bf6c7d231f463366acf2eea.png)

登录的时候如果身份证姓名不匹配是无法通过验证的，说明里面的身份证信息都是真实的，登进来的习惯性找带用户id的功能，点击就诊人列表抓包。

![image-20230805005822924](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-ff2a042a1946653cfda9ebaccc864e309e4579dc.png)

查到了自己的手机，身份证，名字，性别

![image-20230805010022930](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-69e4ab746cab087d1b5b631fd2393e42ebd3bae4.png)

修改id可以查看其他人的信息，共计十几万条，妥妥的平行越权。

### 2.平行越权的SQL注入

习惯性加个单引号，直接报错，页面显示SQL错误，这不是对应上了嘛，[edu-SQL注入案例分享](https://forum.butian.net/share/2320)最后一条总结，平行越权大概率存在SQL注入。但是我这打歪了，没有授权，就打住放弃了，后续移交平台整改。

![image-20230805010332476](https://shs3.b.qianxin.com/attack_forum/2023/08/attach-7a65ae36b69ee6bc760493c4b4b0f38ddb042afe.png)