BSCAN
=====

bscan的是一款强大、简单、实用、高效的HTTP扫描器。

0x01 项目简介
---------

### 背景

**BSCAN**的前身是WebAliveScan，Github上面的版本更新缓慢且版本较老，但截止目前仍然有500+Star，说明大家还是很喜欢这款高效的HTTP扫描器。经过使用python多次迭代WebAliveScan，但是仍然有很多问题无法解决如安装配置复杂、python线程锁导致并发问题等等，考虑Golang的可以解决很多python无法解决的问题，所以趁着有时间重构了**bscan**。

在如今的渗透测试中，众所周知信息收集在漏洞挖掘中尤为重要。但是收集出来的信息如何最大化利用，如何从当前信息中定位出更脆弱的目标。本人认为作为白帽子在处理收集来的信息时，应该有一套标准化的流程。例如收集到了目标上成百上千个子域名时，就应该给处理子域名指定一套标准化的流程。

1. 对子域名的IP进行整理，标记IP段权重
2. 扫描IP、IP段的常见端口
3. 根据扫描端口过滤出一些脆弱的服务，如：Redis、MongoDB等
4. 扫描子域名、IP、IP段的WEB服务
5. 目录扫描，POC扫描
6. 根据标题，指纹筛选渗透
7. .......

而`bscan`主要应用于4-6步。

`github`:`https://github.com/broken5/bscan`

0x02 功能介绍\*\*
-------------

在Github上有许多WEB扫描器，但我认为它们太过于“传统”，面对现在的WEB环境存在以下问题：

- **缺少黑名单功能，**如果目标使用了CDN开放了几十个无效WEB页面，不能有效地过滤导致扫描结果臃肿
- **跨平台能力差，**多数WEB扫描器使用python编写，不能使用在内网渗透测试中
- **缺少指纹识别，**白帽子不能高效的从扫描结果中过滤出脆弱的目标
- **误报率高，**单纯的靠判断状态码判断文件是否存在

  
bscan\*\*的特性：

- **配置文件采用YAML，**配置文件简洁、可读性高
- **安装简单，**Windows/Linux/Mac下载对应的编译版本即可一键扫描，不用担心环境报错
- **速度快，**在2H4G5M的Linux服务器下，1024线程判断100万条URL存活仅需20分钟
- **自定义，**不管是POC还是默认的HTTP请求，都支持自定义HTTP请求参数、请求头等等
- **指纹识别，**根据自定义的指纹规则对WEB进行标记
- **黑名单过滤**，根据自定义的规则过滤无效页面，例如默认的CDN、WAF页面、500、404、403....
- **最小化扫描，**可以自定义POC过滤规则，对存活WEB对象进行filter处理，防止无效的POC攻击

### 1. 基础参数

`-ports 80,443,8080-8090`指定端口  
`-threads 1024`指定线程  
`-allow-redirects`跟踪重定向  
`-timeout 3`HTTP超时时间  
`-path /admin/index.php`请求路径  
以上参数均可以在配置文件`config.yml`修改默认值

### 2. 指纹识别

指纹库文件路径使用配置文件中的`fingerprint_path`指定或使用`-fp <filepath>`指定。  
指纹支持7个字段：webserver、framework、application、os、desc、lang、expression；`expression`是当前指纹匹配响应的表达式（参考xray），其它字段用于标记该WEB。

指纹识别执行流程伪代码

```python
for fingerprint in fingerprint_list:
    if exec_expr(fingerprint.expression, response) is True:
        aliveweb.webserver = fingerprint.webserver
        aliveweb.framework = fingerprint.framework
        aliveweb.application = fingerprint.application
        aliveweb.os = fingerprint.os
        aliveweb.desc = fingerprint.desc
        aliveweb.lang = fingerprint.lang
return aliveweb
```

`expression`支持`response`对象，用一些简单的例子来解释大部分我们可能用到的表达式

- `response.body.bcontains(b'test')`返回包 body 包含 test，因为 body 是一个 bytes 类型的变量，所以我们需要使用 bcontains 方法，且其参数也是 bytes
- `response.status==200 && response.headers['Content-Type'].icontains('application/octet-stream')`返回包状态码为200并且返回头部的Content-Type包含application/octet-stream，因为返回头部的字段是字符型，所以要用icontains

举例：

```yaml
- webserver: Nginx
  expression: response.headers["Server"].icontains("Nginx") || response.body.bcontains(b"<center>nginx</center>")

- webserver: Apache
  expression: response.headers["Server"].icontains("Apache/")

- webserver: Tomcat
    lang: java
  expression: response.headers["Server"].icontains("Tomcat") || response.headers["Server"].icontains("Apache-Coyote")

- application: phpstudy
  expression: response.body.bcontains(b"phpstudy for windows")
  os: windows
  lang: php
```

![image.png](https://shs3.b.qianxin.com/butian_public/ffb32d6520a2433c06d5d72d4d7100fce.jpg)

### 3. 黑名单机制

黑名单库文件路径使用配置文件中的`blacklist_path`指定或使用`-bp <filepath>`指定。  
黑名单支持2个字段：name、expression；`expression`是当前黑名单匹配响应的表达式（参考xray）。

黑名单执行流程伪代码

```python
response = http(url)
for black in blacklist:
    if exec_expr(black.expression, response) is True:
        return False
get_fingerprint(response)
```

黑名单`expression`同指纹识别一致。

举例：

```yaml
- name: ERROR_CODE
  expression: response.status == 400 || response.status == 503 || response.status == 502

- name: ANHENG_WAF
  expression: response.body.bcontains(b"iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAYAAAA7MK6iAAAABGdBTUEAALGPC")
```


### 4. 自定义POC

POC存放目录使用配置文件中的`pocs_path`指定或使用`-poc <filepath>`指定。  
POC支持4个字段：name、request、filter\_expr、verify\_expr；`request`用于配置HTTP请求，`filter_expr`过滤表达式，`verify_expr`验证表达式

POC执行流程伪代码

```python
for aliveweb in aliveweb_result:
    for poc in poc_list:
        if poc.filter_expr == "" or exec_expr(poc.filter_expr, aliveweb) is True:
            for path in poc.path:
                headers = poc.request.headers
                method = poc.request.method
                query = poc.request.query
                body = poc.request.body
                ...
                response = exploit(method, aliveweb.url, headers, query, body, ...)
                if exec_expr(poc.verify_expr, response) is True:
                    vuln(aliveweb, poc.name)
        else:
            continue
```

`filter_expr`表达式支持`aw`对象，用一些简单的例子来解释大部分我们可能用到的表达式

- `aw.lang=='java' || aw.lang==''`存活WEB的语言标记为java或者为空
- `aw.application=='seeyon-oa'`存活WEB的应用标记seeyon-oa

`verify_expr`同指纹识别一致。

举例：

```yaml
name: druid
request:
  method: GET
  # 路径参数为数组
  path:
    - /druid/login.html
    - /druid/index.html
  headers: 
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
    Referer: http://www.baidu.com/
    Accept-Language: en
    Range: bytes=0-10240
  timeout: 5
  allow_redirects: true

# 只扫描lang标记为java或者标记为空的WEB
filter_expr: aw.lang == "java" || aw.lang == ""
verify_expr: response.body.bcontains(b"Druid Stat Index") || response.body.bcontains(b"druid monitor")
```

0x03 应用指南
---------

下面将介绍漏洞挖掘中**bscan**的使用技巧。

**1. target支持的文件格式**  
`./bscan -target ip.txt -ports 80,443`  
ip.txt支持的输入格式有三种：IP、IP:端口、URL；

```php
www.baidu.com
www.baidu.com:80
http://www.baidu.com/
```

www.baidu.com没有指定端口，就会根据用户自定义的端口80,443生成URL放入扫描队列  
www.baidu.com:80指定了端口，会根据指定的端口80生成URL放入扫描队列  
[http://www.baidu.com/给定了URL，直接放入扫描队列](http://www.baidu.com/%E7%BB%99%E5%AE%9A%E4%BA%86URL%EF%BC%8C%E7%9B%B4%E6%8E%A5%E6%94%BE%E5%85%A5%E6%89%AB%E6%8F%8F%E9%98%9F%E5%88%97)

**2. 快捷过滤**  
`./bscan -target target.txt -ports 80,443 -filter response.status==200`  
可以用-filter参数指定一个临时黑名单过滤HTTP响应  
![image.png](https://shs3.b.qianxin.com/butian_public/ffaea568b70ebf5d166de808ee33cff34.jpg)

可以用这个功能，简单过滤出后台等WEB  
`./bscan -target target.txt -ports 80,443 -filter response.body.bcontains(b"后台") -path /admin/index.html`

**3. 指定单个POC**  
`./bscan -target target.txt -ports 80,443 -exploit -poc pocs/backup.yml`  
只扫描一个POC  
![image.png](https://shs3.b.qianxin.com/butian_public/feaae3e55f9c42a631926faf38063f420.jpg)

**4. 快速扫描OneForAll结果**  
`cat results/*.csv |awk -F , '{print$6}' > <filepath>`  
`./bscan -target <filepath>`  
![image.png](https://shs3.b.qianxin.com/butian_public/f8ff816cac32d8223902b3e50bb8c4db0.jpg)

**5. 识别shiro应用**  
在config.yml定义默认HTTP请求头  
![image.png](https://shs3.b.qianxin.com/butian_public/fbdce611afc0275e7ca0c65182ca49114.jpg)

在指纹库中添加指纹  
![image.png](https://shs3.b.qianxin.com/butian_public/f2ad4225ba6967a0ca346ba4ac1f998c8.jpg)

扫描结果中会显示App  
![image.png](https://shs3.b.qianxin.com/butian_public/f770508dcf44b27ef870b8c5dc56cf349.jpg)

**6. POC过滤**  
在指纹库定义指纹  
![image.png](https://shs3.b.qianxin.com/butian_public/faf48abcb3ed65dd26dbea9e95dd2f5d2.jpg)

在POC中定义filter规则  
![image.png](https://shs3.b.qianxin.com/butian_public/f006c146668e9bdcf3475b8c0618156d7.jpg)

在启用POC扫描时，只有识别到SeeyonOA时才会使用这个POC扫描，提高扫描效率。

0x04 Todo
---------

- **支持更多的输出格式HTML、Json、XML**
- **Fast模式，调用Fofa API获取存活WEB**
- **扫描结果存入数据库，支持导入存活WEB**
- **多节点分布式扫描**