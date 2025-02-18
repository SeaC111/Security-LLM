跨目录上传+任意文件读取rce记录
=================

#### 1.跨目录上传

对某系统进行测试时，发现有一处上传附件的功能，常规上传个文件试试

![image-20230626181953442](https://shs3.b.qianxin.com/butian_public/f2930368b1b2e0d6e9cc20eb67f5eb5f76e05e9d7c260.jpg)

发现返回包返回了重命名后的文件名称和系统的绝对路径

继续看上传的文件

![image-20230620155944814](https://shs3.b.qianxin.com/butian_public/f7915768f5fdf989b473619fc7d14376db89870fbf33d.jpg)

只有一个预览的功能，访问直接下载该文件（请求链接为`DownloadServlet?type=W***J&filename=QQ%E5%9B%BE%E7%89%8720230414145425.jpg&pyName=9be6c164-d5a9-4a1e-a555-139ec1ce383d.jpg`），并没有什么用

回头仔细看上传的数据包，发现上传的参数type的值返回在了系统的绝对路径中，猜测type的值即为上传的文件夹，将type改成1尝试，印证了猜想，且是可以直接上传jsp的！

![image-20230626182012905](https://shs3.b.qianxin.com/butian_public/f546893bc2a9a9bb6ace8f50b08dab665c3d30c770af5.jpg)

既然上传文件参数可控，尝试使用../看是否可以跨目录上传，发现也是可以的

![image-20230620162003074](https://shs3.b.qianxin.com/butian_public/f854646b46f54b74f122dcba867003a1e3648a68ac7ef.jpg)

至此得到一个上传路径可控的有效上传点，且通过上传返回的绝对路径知道了当前的user名称（这个后面很关键）。

那么接下来的思路就是寻找系统的web路径，直接上传脚本getshell。尝试了一些常用的手法例如构造报错等均未找到目标，尬住了一会儿后，想到了之前的跨目录上传，既然上传处可以使用../进行跨目录，那么上传后的预览处呢？

#### 2.任意文件读取

回到刚才的上传预览处

![image-20230620163659084](https://shs3.b.qianxin.com/butian_public/f3034180ee0e5a12d522f0f21c787aba9bcc7d6f6c924.jpg)

将预览功能处的请求链接`DownloadServlet?type=W***J&filename=QQ%E5%9B%BE%E7%89%8720230414145425.jpg&pyName=9be6c164-d5a9-4a1e-a555-139ec1ce383d.jpg`中的filename与pyname进行构造尝试，果不其然，发现一处任意文件读取

![image-20230626182033327](https://shs3.b.qianxin.com/butian_public/f1224503e6a4063887b2af93c12bbbe0e77c466bb2385.jpg)

得到任意文件读取后可以通过读取中间件的默认配置文件寻找更多信息，例如

- tomcat  
    `/usr/local/tomcat(tomcat-1.1.1(具体版本号))/conf/tomcat-users.xml`
    
    `/usr/local/tomcat(tomcat-1.1.1(具体版本号))/bin/catalina.sh`(其中日志的配置路径)
- apache
    
    `/var/log/apache2/access.log`  
    `/var/log/apache2/error.log`  
    `/var/log/httpd/access_log`  
    `/etc/httpd/logs/access_log`  
    `/etc/httpd/logs/error_log`  
    `/etc/httpd/logs/error.log`
- nginx
    
    `/var/log/nginx(nginx-1.1.1(具体版本号))/access.log`  
    `/var/log/nginx(nginx-1.1.1(具体版本号))/error.log`  
    `/usr/local/var/log/nginx(nginx-1.1.1(具体版本号))/access.log`  
    `/usr/local/nginx(nginx-1.1.1(具体版本号))/logs`
    
    `/etc/nginx(nginx-1.1.1(具体版本号))/nginx.conf`

通过旁站的其他端口的web指纹，发现使用的是tomcat

![image-20230620165658160](https://shs3.b.qianxin.com/butian_public/f36171045c1b842d789917c89b56fcf687873314b6e71.jpg)

直接尝试读取tomcat的默认配置文件，均失败：）

接着尝试读取操作系统的默认路径，linux下常用路径如下

```php
/etc/passwd                     账户信息
/etc/shadow                     账户密码文件
/etc/my.cnf                     mysql配置文件
/root/.ssh/id_rsa               ssh-rsa私钥
/etc/redhat-release             系统版本 
/root/.bash_history             用户历史命令记录文件
/home/user/.bash_history        特定用户的历史命令记录文件
/root/.mysql_history            mysql历史命令记录文件
/var/lib/mlocate/mlocate.db     全文件路径
/proc/net/fib_trie              内网IP
/proc/self/environ              环境变量
/proc/self/loginuid             当前用户uid
```

最终通过/home/user/.bash\_history中成功找到了tomcat的web路径

![image-20230620173207084](https://shs3.b.qianxin.com/butian_public/f5439071f5ab5a4b0a832daa26a12e1365ce8dc647f09.jpg)

#### 3.getshell

万事具备，直接上传至根目录下，访问

![image-20230626182053187](https://shs3.b.qianxin.com/butian_public/f8344173da9644c2f3350aaa7c7b5b09e870d37d9034c.jpg)

根目录下不解析，直接跳转到了登录页面，但是可以看到跳转目录携带了我们访问的jsp。

这种情况下，有账号的话(本系统提供了注册功能)，直接登录后访问即可

![image-20230626182949192](https://shs3.b.qianxin.com/butian_public/f966704cad6d3100517a2437cea347c5b7e450e451c52.jpg)

#### 4.一些拓展

上述的情况都是登录后测试的，如果上传点是fuzz出来的，没有目标系统的账号，也可以采取如下几种方案。

1.尝试直接上传至系统的静态目录，例如系统自动加载的js文件的目录。

2.尝试绕过fillter的鉴权，一般从fillter对目录的白名单或是文件后缀的白名单两个角度绕过入手。

附一些实战的案例。

目录白名单绕过

![image-20230626180319978](https://shs3.b.qianxin.com/butian_public/f5957366f63ead4b6466ac0a39cd9be0efae9694a6d93.jpg)

![image-20230626180249697](https://shs3.b.qianxin.com/butian_public/f1423024bf4dd74ffce2ad3c563737e1b01288d686025.jpg)

文件后缀白名单绕过

![image-20230626180936719](https://shs3.b.qianxin.com/butian_public/f488235d59ab44233c985104a8cf4a286466b2aafc00a.jpg)

![](https://shs3.b.qianxin.com/butian_public/f66656374c05d56666e044af8acefbefe98efb0d3251a.jpg)

其他情况绕过

![image-20230626174404779](https://shs3.b.qianxin.com/butian_public/f2291652e34a69bedeca92516dfd34d876100bbd0a40c.jpg)

![image-20230626175538621](https://shs3.b.qianxin.com/butian_public/f873168be65449ef7c7daaa0f905e8b5cb19c04bda9eb.jpg)

3.寻找其他的web可以直接访问且知道路径的目录

例如本案例中的

![image-20230626181807657](https://shs3.b.qianxin.com/butian_public/f8544892c8c365dd29f6d5b1fde05ad19f2e43f3ef070.jpg)

![image-20230620175735722](https://shs3.b.qianxin.com/butian_public/f937725f4603fbde32f3b0f5b3e908e0c2be2102ab6c6.jpg)

直接构造上传

![image-20230620180004119](https://shs3.b.qianxin.com/butian_public/f267000c39d1b64daa2964899619f13f90fb6b280477a.jpg)

浏览器访问，成功rce

![image-20230620180348795](https://shs3.b.qianxin.com/butian_public/f5721651ea110cc72eb2da3ea81393bb4203c4d756768.jpg)