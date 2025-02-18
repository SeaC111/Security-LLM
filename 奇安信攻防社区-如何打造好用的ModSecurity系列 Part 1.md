如何打造好用的ModSecurity
==================

一、 简介
-----

ModSecurity 是一个 Web 应用程序防火墙 (WAF)，并且具有一个强大的持续维护的规则库，其有以下优点。

1. 实时监控和攻击检测
    
    实时监控 HTTP 流量以检测攻击，并且提供可自定义的日志记录功能。
2. 预防攻击和虚拟补丁
    
    可以拦截利用已知漏洞进行的攻击，并且可以打虚拟补丁，对于一些异常的行为可以对其ip等进行打分行为，从而跟踪行为，最终判定是否拦截。
3. 灵活的规则引擎
    
    CRS(coreruleset)是ModSecurity体系的核心，规则体系强大并且灵活，下文也将重点介绍其规则体系。
4. 嵌入式模式部署
    
    ModSecurity 是一个嵌入式 Web 应用程序防火墙，这样可以缩小性能开销，并且对于https流量也能直接处理。
5. 基于网络的部署
    
    可以部署在反向代理服务器上，用于保护后端服务。
6. 可移植性
    
    能够用在各种操作系统上。

二、 安装
-----

安装环境：Ubuntu18.04

### 1.1 Libmodsecurity

```bash
apt-get install g++ flex bison curl doxygen libyajl-dev libgeoip-dev libtool dh-autoreconf libcurl4-gnutls-dev libx ml2 libpcre++-dev libx ml2-dev
cd /opt/
git clone https://github.com/SpiderLabs/ModSecurity
cd ModSecurity/
git checkout -b v3/master origin/v3/master
sh build.sh
git submodule init
git submodule update #[for bindings/python, others/libinjection, test/test-cases/secrules-language-tests]
./configure
make
make install
```

include/lib文件位置：/usr/local/modsecurity  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9444249886cbc2553ee43f844d16e70543b7b4ef.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9444249886cbc2553ee43f844d16e70543b7b4ef.png)

### 1.2 Nginx-modsecurity

安装带有modsec模块的Nginx

```bash
wget http://nginx.org/download/nginx-1.20.1.tar.gz
git clone https://github.com/SpiderLabs/ModSecurity-nginx.git
tar -zxvf nginx-1.20.1.tar.gz
cd nginx-1.20.1/
./configure --add-module=/root/modsecurity-nginx/ --prefix=/usr/local/nginx 
make && make install
/usr/local/nginx/sbin/nginx -t  # test
```

添加规则并配置Nginx

```bash
git clone https://github.com/coreruleset/coreruleset/
cd coreruleset/
cp crs-setup.conf.example crs-setup.conf
cp /root/ModSecurity/modsecurity.conf-recommended /usr/local/nginx/conf/modsecurity.conf
```

修改modsecurity.conf令其加载crs，增加两行

> Include /root/coreruleset/crs-setup.conf
> 
> Include /root/coreruleset/rules/\*.conf

需要直接进行拦截的话，修改SecRuleEngine

> SecRuleEngine On

修改/usr/local/nginx/conf/nginx.con，使Nginx加载modsec并指定配置文件

```nginx
server {
        modsecurity on;
        listen       1001;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            modsecurity_rules_file /usr/local/nginx/conf/modsecurity.conf;
            root   html;
            index  index.html index.htm;
        }
}
```

启动

```bash
/usr/local/nginx/sbin/nginx
```

发现报错

> nginx: \[emerg\] "modsecurity\_rules\_file" directive Rules error. File: /usr/local/nginx/conf/modsecurity.conf. Line: 236. Column: 17. Failed to locate the unicode map file from: unicode.mapping Looking at: 'unicode.mapping', 'unicode.mapping', '/usr/local/nginx/conf/unicode.mapping', '/usr/local/nginx/conf/unicode.mapping'. in /usr/local/nginx/conf/nginx.conf:45

[解决方案](https://github.com/SpiderLabs/ModSecurity/issues/1941)

```bash
cp /root/ModSecurity/unicode.mapping /usr/local/nginx/conf/
```

### 1.3 Apache2-modsecurity

```bash
apt update
apt install apache2
apt-get install libapache2-mod-security2
```

apache2配置文件

> /etc/apache2/mods-enabled/security2.load #加载库
> 
> /etc/apache2/mods-enabled/security2.conf

```php
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier
        IncludeOptional /etc/modsecurity/*.conf     #加载modsec中配置文件

        # Include OWASP ModSecurity CRS rules if installed
        IncludeOptional /usr/share/modsecurity-crs/owasp-crs.load   #加载规则
</IfModule>
```

modsec位置

> /etc/modsecurity

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-da247f18422fd9c671b54a9d7ef3720e83636bd4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-da247f18422fd9c671b54a9d7ef3720e83636bd4.png)

crs位置

> /usr/share/modsecurity-crs

启动apache即可开启modsec

如果安装最新crs，需要按照上面步骤下载，在/etc/apache2/mods-enabled/security2.conf中修改规则位置

> IncludeOptional /root/coreruleset/\*.conf
> 
> IncludeOptional /root/coreruleset/rules/\*.conf

重启

```bash
systemctl restart apache2
```

2. 测试拦截
-------

测试post\_body: a=/bin/bash

### 2.1 nginx log

/usr/local/nginx/logs/error.log

```tex
2021/06/03 15:50:25 [error] 29019#0: *13 
[client 1.1.1.1] 
ModSecurity: Access denied with code 403 (phase 2). 
Matched "Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `8' ) 
[file "/root/coreruleset/rules/REQUEST-949-BLOCKING-E VALUATION.conf"] 
[line "138"] 
[id "949110"]
[rev ""] 
[msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] 
[data ""] 
[severity "2"] 
[ver "OWASP_CRS/3.4.0-dev"] 
[maturity "0"] 
[accuracy "0"] 
[tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] [hostname "192.168.1.59"] 
[uri "/"] 
[unique_id "1622706625"] 
[ref ""], 
client: 1.1.1.1, 
server: localhost, 
request: "POST / HTTP/1.1", 
host: "1.1.1.1:1001"
```

其他modsec详细分析日志，默认放在/var/log/modsec\_audit.log

### 2.2 apache2 log

使用coreruleset规则

/etc/log/apache2/error.log

```php
[Thu Jun 03 16:02:02.896289 2021] [:error] [pid 32696] 
[client 1.1.1.1:37233] [client 1.1.1.1] 
ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. 
[file "/root/coreruleset/rules/REQUEST-949-BLOCKING-E VALUATION.conf"] 
[line "150"] 
[id "949110"] 
[msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] 
[severity "CRITICAL"] 
[ver "OWASP_CRS/3.4.0-dev"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"] 
[hostname "1.1.1.1"] 
[uri "/"] 
[unique_id "YLiMetbycvfIaMD669H-hwAAAAA"]
```

### 三、 参考

<https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Introduction>  
<http://www.modsecurity.cn/chm/>